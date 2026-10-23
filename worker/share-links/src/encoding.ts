const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

/** RFC 4648 base32, lowercase, no padding. */
export function base32Lower(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET.charAt((buffer >>> (bits - 5)) & 31);
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) {
    out += BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 31);
  }
  return out;
}

/** Unpadded base64url. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Strict unpadded base64url decode. Returns null for any character outside the
 * alphabet, for lengths that cannot be produced by the encoder, and for input
 * whose trailing bits are not zero (non-canonical).
 */
export function base64UrlDecode(input: string): Uint8Array | null {
  if (!BASE64URL_RE.test(input) || input.length % 4 === 1) {
    return null;
  }
  const padding = "=".repeat((4 - (input.length % 4)) % 4);
  const binary = atob(input.replace(/-/g, "+").replace(/_/g, "/") + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  if (base64UrlEncode(bytes) !== input) {
    return null;
  }
  return bytes;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** CIDv1, raw codec (0x55), sha2-256, multibase base32 lower ("b" prefix). */
export async function cidForBytes(bytes: Uint8Array): Promise<string> {
  const digest = await sha256(bytes);
  const multihash = new Uint8Array(36);
  multihash.set([0x01, 0x55, 0x12, 0x20], 0);
  multihash.set(digest, 4);
  return "b" + base32Lower(multihash);
}

/** 26 base32 characters carrying the first 130 bits of 17 CSPRNG bytes. */
export function newShareId(): string {
  const random = crypto.getRandomValues(new Uint8Array(17));
  return base32Lower(random).slice(0, 26);
}

/** 32 CSPRNG bytes, base64url (43 characters). */
export function newDeleteToken(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

/** Stored form of a delete token: base64url(sha256(UTF-8 of the token string)). */
export async function hashDeleteToken(token: string): Promise<string> {
  return base64UrlEncode(await sha256(new TextEncoder().encode(token)));
}

/** Equal-length string comparison without early exit. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
