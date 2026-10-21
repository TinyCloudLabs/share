/** Same-origin client for `/api/share-links`. Never logs or surfaces bodies, tokens, or URLs. */

const ENDPOINT = "/api/share-links";
export const SHORT_LINK_TIMEOUT_MS = 15_000;
const SHORT_ID = /^[a-z2-7]{26}$/;

export interface ShortLinkCreated {
  readonly id: string;
  readonly cid: string;
  readonly deleteToken: string;
}

export type ShortLinkFailure = "network" | "timeout" | "rate_limited" | "capacity" | "rejected" | "server" | "invalid_response" | "cid_mismatch";

export class ShortLinkError extends Error {
  readonly reason: ShortLinkFailure;
  constructor(reason: ShortLinkFailure) {
    super(`short link ${reason}`);
    this.name = "ShortLinkError";
    this.reason = reason;
  }
}

interface ClientOptions {
  readonly fetchFn?: typeof fetch | undefined;
  readonly timeoutMs?: number | undefined;
}

async function send(url: string, init: RequestInit, options: ClientOptions): Promise<Response> {
  const fetchFn = options.fetchFn ?? fetch;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, options.timeoutMs ?? SHORT_LINK_TIMEOUT_MS);
  try {
    return await fetchFn(url, { ...init, credentials: "omit", signal: controller.signal });
  } catch {
    throw new ShortLinkError(timedOut ? "timeout" : "network");
  } finally {
    clearTimeout(timer);
  }
}

function failureFor(status: number): ShortLinkFailure {
  if (status === 429) return "rate_limited";
  if (status === 503) return "capacity";
  if (status === 400) return "rejected";
  return "server";
}

/** Creates a short link. The body carries only the sealed bytes and the expiry. */
export async function createShortLink(input: { readonly ciphertext: string; readonly expiresAt: string }, options: ClientOptions = {}): Promise<ShortLinkCreated> {
  const response = await send(ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ciphertext: input.ciphertext, expiresAt: input.expiresAt }),
  }, options);
  if (response.status !== 201) throw new ShortLinkError(failureFor(response.status));
  const body = (await response.json().catch(() => undefined)) as Partial<Record<keyof ShortLinkCreated, unknown>> | undefined;
  if (body === undefined || typeof body.id !== "string" || !SHORT_ID.test(body.id) || typeof body.cid !== "string" || typeof body.deleteToken !== "string" || body.deleteToken.length === 0) {
    throw new ShortLinkError("invalid_response");
  }
  return { id: body.id, cid: body.cid, deleteToken: body.deleteToken };
}

/**
 * Deletes a short link with its delete token. 204 and 404 both mean the link
 * is gone (404 covers unknown, expired, and already deleted), so both return true.
 */
export async function deleteShortLink(id: string, deleteToken: string, options: ClientOptions = {}): Promise<void> {
  if (!SHORT_ID.test(id)) throw new ShortLinkError("rejected");
  const response = await send(`${ENDPOINT}/${id}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${deleteToken}` },
  }, options);
  if (response.status === 204 || response.status === 404) return;
  throw new ShortLinkError(response.status === 429 ? "rate_limited" : "server");
}
