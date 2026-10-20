import { parseNativeShareUrl } from "@tinycloud/share-sdk";
import { TinyCloudWeb } from "@tinycloud/web-sdk";

type ReceivedAccess = { readonly ok: true; readonly data: { readonly data: unknown; readonly path: string; readonly spaceId: string; readonly host: string; readonly delegation: { readonly expiry: Date | string } } } | { readonly ok: false; readonly error: { readonly message: string; readonly code?: string } };

/**
 * Why a bearer link did not open. Only the first three get their own screen;
 * "unverified" keeps the generic, non-committal copy.
 */
export type NativeBearerFailureReason = "revoked" | "expired" | "unavailable" | "unverified";

export class NativeBearerError extends Error {
  readonly reason: NativeBearerFailureReason;
  /** ISO time from the link's own delegation, when it could be read locally. */
  readonly expiresAt?: string;
  constructor(reason: NativeBearerFailureReason, message: string, expiresAt?: string) {
    super(message);
    this.name = "NativeBearerError";
    this.reason = reason;
    if (expiresAt !== undefined) this.expiresAt = expiresAt;
  }
}

/** The owner node answers a revoked chain with `401 delegation-revoked: <cid>` (or `…-ancestor-revoked`). */
const REVOKED = /delegation-(?:ancestor-)?revoked|\brevoked\b/i;
const EXPIRED = /\bAUTH_EXPIRED\b|\bexpired\b/i;
const UNAVAILABLE = /failed to fetch|networkerror|network request failed|load failed|timed? ?out|unavailable|\b(?:5\d\d|429)\b/i;

export function classifyBearerFailure(error: { readonly message: string; readonly code?: string }): NativeBearerFailureReason {
  const text = `${error.code ?? ""} ${error.message}`;
  if (REVOKED.test(text)) return "revoked";
  if (EXPIRED.test(text)) return "expired";
  if (UNAVAILABLE.test(text)) return "unavailable";
  return "unverified";
}

/** Best-effort local read of the token's own expiry; nothing leaves the page. */
function delegationExpiry(token: string): string | undefined {
  try {
    const payload = token.startsWith("tc1:") ? token.slice(4) : undefined;
    if (payload === undefined) return undefined;
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
    const parsed: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(base64), (char) => char.charCodeAt(0))));
    if (typeof parsed !== "object" || parsed === null || !("delegation" in parsed)) return undefined;
    const delegation = parsed.delegation;
    if (typeof delegation !== "object" || delegation === null || !("expiry" in delegation)) return undefined;
    const date = new Date(String(delegation.expiry));
    return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
  } catch {
    return undefined;
  }
}

/** Receive the fragment token through TinyCloud SDK and invoke the delegated owner path. */
export async function receiveNativeBearerAccess(href: string, receive: (token: string) => Promise<unknown> = (token) => TinyCloudWeb.receiveShare<Uint8Array>(token, undefined, { binary: true })): Promise<{ readonly path: string; readonly spaceId: string; readonly ownerNodeOrigin: string; readonly expiresAt: string; readonly bytes: Uint8Array }> {
  const token = parseNativeShareUrl(href);
  let received: ReceivedAccess;
  try {
    received = await receive(token) as ReceivedAccess;
  } catch (error) {
    const failure = { message: error instanceof Error ? error.message : "request failed" };
    throw new NativeBearerError(classifyBearerFailure(failure), failure.message);
  }
  if (!received.ok) {
    const reason = classifyBearerFailure(received.error);
    throw new NativeBearerError(reason, received.error.message, reason === "expired" ? delegationExpiry(token) : undefined);
  }
  if (!(received.data.data instanceof Uint8Array)) throw new Error("TinyCloud owner node returned invalid shared bytes");
  const expiresAt = new Date(received.data.delegation.expiry);
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("TinyCloud delegation expiry is invalid");
  return { path: received.data.path, spaceId: received.data.spaceId, ownerNodeOrigin: received.data.host, expiresAt: expiresAt.toISOString(), bytes: received.data.data.slice() };
}

export async function receiveNativeBearer(href: string, receive?: (token: string) => Promise<unknown>): Promise<Uint8Array> {
  return (await receiveNativeBearerAccess(href, receive)).bytes;
}
