/**
 * Asks the owner's node whether an addressed share can still open, before the
 * page offers or sends a mailbox code for it.
 *
 * The node publishes `GET /policy/v3/status/<rootCid>` without authentication:
 * the signed liveness checkpoint of a policy root, which "cannot grant or
 * widen authority". The signed invitation carries the node origin and both
 * root CIDs, so the recipient already holds everything this request names, and
 * the request sends no cookie, referrer, key or fragment.
 *
 * Only a definite answer closes the page. A network error, timeout, non-2xx
 * status (including 404 for a root the node does not know), malformed body or
 * a CORS refusal all read as "available": the normal flow runs and the node's
 * own admission decision stays the authority. What this cannot see: a share
 * whose content object was deleted (the node tells that only to an
 * authenticated reader).
 */
export type ShareAvailability = "available" | "revoked" | "expired";

export interface ShareAvailabilityTarget {
  readonly nodeOrigin: string;
  readonly rootCids: readonly string[];
}

export interface ShareAvailabilityOptions {
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly timeoutMs?: number;
}

/** Upper bound the recipient waits for the node before the normal flow runs. */
export const AVAILABILITY_TIMEOUT_MS = 4_000;

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Reads the node origin and the two policy roots from a verified Policy/v3
 * invitation. Anything that does not look like one yields `undefined`, which
 * skips the check.
 */
export function availabilityTarget(envelope: unknown): ShareAvailabilityTarget | undefined {
  if (typeof envelope !== "object" || envelope === null) return undefined;
  const { target, policyRoot, enforcementRoot } = envelope as { target?: { origin?: unknown }; policyRoot?: { cid?: unknown }; enforcementRoot?: { cid?: unknown } };
  const origin = target?.origin;
  if (!nonEmptyString(origin)) return undefined;
  try {
    if (new URL(origin).origin !== origin) return undefined;
  } catch {
    return undefined;
  }
  const rootCids = [policyRoot?.cid, enforcementRoot?.cid].filter(nonEmptyString);
  return rootCids.length === 0 ? undefined : { nodeOrigin: origin, rootCids };
}

async function rootAvailability(nodeOrigin: string, rootCid: string, options: Required<Pick<ShareAvailabilityOptions, "fetch" | "now">>, signal: AbortSignal): Promise<ShareAvailability> {
  try {
    const response = await options.fetch(new URL(`/policy/v3/status/${encodeURIComponent(rootCid)}`, nodeOrigin), {
      method: "GET",
      headers: { accept: "application/json" },
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      redirect: "error",
      signal,
    });
    if (!response.ok) return "available";
    const body: unknown = await response.json();
    if (typeof body !== "object" || body === null) return "available";
    const { rootCid: echoed, state, checkpoint } = body as { rootCid?: unknown; state?: unknown; checkpoint?: { freshUntil?: unknown } };
    if (echoed !== rootCid) return "available";
    if (state === "revoked") return "revoked";
    // For an active root the checkpoint's `freshUntil` is the root's own expiry.
    const expiresAt = typeof checkpoint?.freshUntil === "string" ? Date.parse(checkpoint.freshUntil) : Number.NaN;
    return state === "active" && Number.isFinite(expiresAt) && expiresAt <= options.now() ? "expired" : "available";
  } catch {
    return "available";
  }
}

/**
 * `revoked` if the node reports any of the roots revoked, else `expired` if
 * any root's lifetime is over, else `available`. Never throws.
 */
export async function checkShareAvailability(target: ShareAvailabilityTarget, options: ShareAvailabilityOptions = {}): Promise<ShareAvailability> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? AVAILABILITY_TIMEOUT_MS);
  try {
    const resolved = { fetch: options.fetch ?? globalThis.fetch.bind(globalThis), now: options.now ?? Date.now };
    const states = await Promise.all(target.rootCids.map((cid) => rootAvailability(target.nodeOrigin, cid, resolved, controller.signal)));
    return states.includes("revoked") ? "revoked" : states.includes("expired") ? "expired" : "available";
  } catch {
    return "available";
  } finally {
    clearTimeout(timer);
  }
}
