import { SHARE_APPLICATION_PREFIX } from "../share/openkey-session.js";
import { createShortLink, deleteShortLink, ShortLinkError, type ShortLinkCreated } from "./client.js";
import { splitInlineToShort } from "./codec.js";

export const SHORT_LINK_UNAVAILABLE_NOTICE = "Short link unavailable: this link is long. Try again later for a shorter one.";

const MIN_TTL_MS = 120_000;
const MAX_TTL_MS = 400 * 24 * 60 * 60 * 1000;

/** The delete record the creator keeps so revoke can delete the short link later. */
export interface ShortLinkRecord {
  readonly id: string;
  readonly deleteToken: string;
}

/** The sealed bytes of the share, as the SDK reports them at publish time. */
export interface ShortLinkMaterial {
  /** base64url of the sealed bytes. Equal to the inline link's `c`. */
  readonly sealedEnvelope: string;
  /** CID of the sealed bytes. Equal to the inline link's `cid`. */
  readonly shareCid: string;
}

export interface ShortLinkPublication {
  /** The short link when the service accepted it, otherwise the inline link. */
  readonly url: string;
  /** Set only when the inline link is used because the short link failed. */
  readonly notice?: string;
}

export interface ShortLinkKv {
  get(key: string): Promise<{ readonly ok: boolean; readonly data?: { readonly data?: unknown } }>;
}

interface ServiceOptions {
  readonly fetchFn?: typeof fetch | undefined;
  readonly timeoutMs?: number | undefined;
}

export function shortLinkRecordPath(shareId: string): string {
  return `${SHARE_APPLICATION_PREFIX}shares/${shareId}/short-link.json`;
}

/** Shown when a revoke succeeded but its short-link record was kept for the next revoke attempt. */
export const SHORT_LINK_KEPT_NOTICE = "The short link will be removed on the next revoke attempt.";

/** Canonical UTC milliseconds, at least 120 s and at most 400 days away. */
export function canonicalShortLinkExpiry(expiresAt: string | undefined, now: number = Date.now()): string {
  if (expiresAt === undefined) throw new ShortLinkError("rejected");
  const ms = Date.parse(expiresAt);
  if (!Number.isFinite(ms) || ms - now < MIN_TTL_MS || ms - now > MAX_TTL_MS) throw new ShortLinkError("rejected");
  return new Date(ms).toISOString();
}

/**
 * Creates the short link for an addressed share and stores its delete record.
 * Any failure (service, CID mismatch, record write) deletes a link that was
 * already created and returns the inline link with a notice. Never throws.
 */
export async function publishShortLinkOrInline(input: {
  readonly inlineUrl: string;
  readonly material: ShortLinkMaterial | undefined;
  readonly expiresAt: string | undefined;
  readonly storeRecord: (record: ShortLinkRecord) => Promise<void>;
} & ServiceOptions): Promise<ShortLinkPublication> {
  const service: ServiceOptions = { fetchFn: input.fetchFn, timeoutMs: input.timeoutMs };
  let created: ShortLinkCreated | undefined;
  try {
    if (input.material === undefined) throw new ShortLinkError("rejected");
    const expiresAt = canonicalShortLinkExpiry(input.expiresAt);
    created = await createShortLink({ ciphertext: input.material.sealedEnvelope, expiresAt }, service);
    if (created.cid !== input.material.shareCid) throw new ShortLinkError("cid_mismatch");
    const url = splitInlineToShort(input.inlineUrl, created.id);
    if (url === undefined) throw new ShortLinkError("invalid_response");
    await input.storeRecord({ id: created.id, deleteToken: created.deleteToken });
    return { url };
  } catch {
    if (created !== undefined) await deleteShortLink(created.id, created.deleteToken, service).catch(() => undefined);
    return { url: input.inlineUrl, notice: SHORT_LINK_UNAVAILABLE_NOTICE };
  }
}

function readRecord(value: unknown): ShortLinkRecord | undefined {
  let parsed: unknown = value;
  if (value instanceof ArrayBuffer) parsed = new TextDecoder().decode(value);
  else if (ArrayBuffer.isView(value)) parsed = new TextDecoder().decode(value);
  if (typeof parsed === "string") {
    try {
      parsed = JSON.parse(parsed);
    } catch {
      return undefined;
    }
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const { id, deleteToken } = parsed as Partial<Record<keyof ShortLinkRecord, unknown>>;
  return typeof id === "string" && typeof deleteToken === "string" ? { id, deleteToken } : undefined;
}

/**
 * Deletes a share's short link after the node revoke has succeeded. The record
 * is kept, so a failed DELETE can be retried by the next revoke. A 404 counts
 * as not deleted: the token or id did not match, so the link may still be live.
 */
export async function revokeStoredShortLink(input: {
  readonly shareId: string;
  readonly kv: ShortLinkKv;
} & ServiceOptions): Promise<"none" | "deleted" | "kept"> {
  const path = shortLinkRecordPath(input.shareId);
  const stored = await input.kv.get(path).catch(() => undefined);
  if (stored === undefined) return "kept";
  if (!stored.ok) return "none";
  const record = readRecord(stored.data?.data);
  if (record === undefined) return "none";
  try {
    await deleteShortLink(record.id, record.deleteToken, { fetchFn: input.fetchFn, timeoutMs: input.timeoutMs });
  } catch {
    return "kept";
  }
  return "deleted";
}
