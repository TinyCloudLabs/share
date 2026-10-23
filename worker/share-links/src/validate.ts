import { base64UrlDecode } from "./encoding";

export const MAX_CIPHERTEXT_BYTES = 131072;
/** ceil(131072 * 4 / 3): unpadded base64url length of the largest allowed payload. */
export const MAX_CIPHERTEXT_CHARS = 174763;
/** Hard cap on the raw request body, checked before JSON parsing. */
export const MAX_BODY_CHARS = 184320;
export const MIN_TTL_MS = 120_000;
export const MAX_TTL_MS = 400 * 86_400_000;

const CANONICAL_UTC_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export interface CreateInput {
  bytes: Uint8Array;
  expiresAtMs: number;
  expiresAtIso: string;
}

/** Returns null for every invalid body; callers answer 400 {"error":"invalid"}. */
export function parseCreateBody(text: string, nowMs: number): CreateInput | null {
  if (text.length > MAX_BODY_CHARS) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const { ciphertext, expiresAt } = parsed as Record<string, unknown>;
  if (typeof ciphertext !== "string" || typeof expiresAt !== "string") {
    return null;
  }
  if (ciphertext.length > MAX_CIPHERTEXT_CHARS) {
    return null;
  }
  const bytes = base64UrlDecode(ciphertext);
  if (bytes === null || bytes.length < 1 || bytes.length > MAX_CIPHERTEXT_BYTES) {
    return null;
  }
  if (!CANONICAL_UTC_MS.test(expiresAt)) {
    return null;
  }
  const expiresAtMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMs) || new Date(expiresAtMs).toISOString() !== expiresAt) {
    return null;
  }
  const ttl = expiresAtMs - nowMs;
  if (ttl < MIN_TTL_MS || ttl > MAX_TTL_MS) {
    return null;
  }
  return { bytes, expiresAtMs, expiresAtIso: expiresAt };
}
