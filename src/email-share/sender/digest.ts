/**
 * Canonical-bytes digest helpers for the email-claim v1 sender flow
 * (specs/email-claim-v1/schemas.json `$defs.digest` == base64url(sha256(
 * UTF8(JCS(value))))). Reuses the shipping envelope package's RFC 8785 JCS
 * canonicalizer and strict base64url encoder so digests here byte-match the
 * rest of the codebase — no re-implementation of either.
 */
import { canonicalize, toBase64Url } from "@tinycloud/share-envelope";

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const view = new Uint8Array(bytes); // copy: crypto.subtle needs a plain ArrayBuffer-backed view
  const digest = await crypto.subtle.digest("SHA-256", view);
  return new Uint8Array(digest);
}

/** base64url(sha256(UTF8(JCS(value)))) — the contract's `digest` primitive. */
export async function canonicalDigest(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(value));
  return toBase64Url(await sha256(bytes));
}
