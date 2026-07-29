/**
 * The one-send-per-authorization ledger.
 *
 * D1, not KV, and not because D1 is fancier: idempotency needs a
 * read-modify-write that two concurrent requests cannot both win. SQLite's
 * `INSERT … ON CONFLICT DO NOTHING RETURNING` gives exactly that in one
 * atomic statement; KV's eventual consistency would let a double-submitted
 * share be mailed twice. It is also the same primitive the Node already uses
 * for this exact key (`share_invitation_authorization_jti`), and it is plain
 * SQLite — so it survives the later move of this Worker into a CVM.
 *
 * A row is RESERVED BEFORE the provider call and only then marked sent. If
 * the Worker dies mid-send the row stays `pending` forever and every replay
 * is refused: an unsent email is a better failure than a duplicate one, and
 * the sender can always mint a fresh authorization.
 *
 * Deliberately stores no mailbox address, no share URL and no document name
 * — only a digest of the recipient, so an operator can answer "did this
 * delivery happen" without the table becoming a PII store.
 */

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<unknown>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}

export type DeliveryStatus = "pending" | "sent" | "failed";

export type ReserveResult =
  | { readonly outcome: "reserved" }
  | { readonly outcome: "duplicate"; readonly providerMessageId: string | null }
  | { readonly outcome: "in-flight" }
  | { readonly outcome: "replayed" }
  | { readonly outcome: "unavailable" };

const RESERVE = `INSERT INTO share_email_deliveries
  (idempotency_key, share_cid, recipient_digest, status, provider_message_id, created_at, updated_at)
  VALUES (?1, ?2, ?3, 'pending', NULL, ?4, ?4)
  ON CONFLICT(idempotency_key) DO NOTHING
  RETURNING idempotency_key`;

const LOAD = `SELECT status, provider_message_id FROM share_email_deliveries WHERE idempotency_key = ?1`;

const FINALIZE = `UPDATE share_email_deliveries
  SET status = ?2, provider_message_id = ?3, updated_at = ?4
  WHERE idempotency_key = ?1 AND status = 'pending'`;

export async function reserveDelivery(
  database: D1DatabaseLike,
  input: {
    readonly idempotencyKey: string;
    readonly shareCid: string;
    readonly recipientDigest: string;
    readonly at: string;
  },
): Promise<ReserveResult> {
  let inserted: unknown;
  try {
    inserted = await database
      .prepare(RESERVE)
      .bind(input.idempotencyKey, input.shareCid, input.recipientDigest, input.at)
      .first();
  } catch {
    return { outcome: "unavailable" };
  }
  if (inserted !== null && inserted !== undefined) return { outcome: "reserved" };

  let existing: { status?: unknown; provider_message_id?: unknown } | null;
  try {
    existing = await database.prepare(LOAD).bind(input.idempotencyKey).first();
  } catch {
    return { outcome: "unavailable" };
  }
  if (existing === null || existing === undefined) return { outcome: "unavailable" };
  if (existing.status === "sent") {
    return {
      outcome: "duplicate",
      providerMessageId:
        typeof existing.provider_message_id === "string" ? existing.provider_message_id : null,
    };
  }
  if (existing.status === "pending") return { outcome: "in-flight" };
  // A previously failed attempt is NOT retried under the same authorization:
  // the failure may have been a timeout on an email that did go out.
  return { outcome: "replayed" };
}

export async function finalizeDelivery(
  database: D1DatabaseLike,
  input: {
    readonly idempotencyKey: string;
    readonly status: Exclude<DeliveryStatus, "pending">;
    readonly providerMessageId: string | null;
    readonly at: string;
  },
): Promise<boolean> {
  try {
    await database
      .prepare(FINALIZE)
      .bind(input.idempotencyKey, input.status, input.providerMessageId, input.at)
      .run();
    return true;
  } catch {
    return false;
  }
}
