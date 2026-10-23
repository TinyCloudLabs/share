const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

/** RFC 4648 base32, lower case, no padding. */
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

/** Strict lower-case base32 decode (no padding); null on any other character or non-zero trailing bits. */
export function base32LowerDecode(input: string): Uint8Array | null {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of input) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index < 0) {
      return null;
    }
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  return buffer === 0 ? Uint8Array.from(out) : null;
}

/**
 * Strict unpadded base64url decode: null for any character outside the alphabet, for a length no
 * encoder produces, and for input whose trailing bits are not zero (it must re-encode to itself).
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
  return base64UrlEncode(bytes) === input ? bytes : null;
}

/** Exact decoded length of a strict base64url string, or null when the length is impossible. */
export function base64UrlDecodedLength(chars: number): number | null {
  if (chars % 4 === 1) {
    return null;
  }
  return Math.floor((chars * 3) / 4);
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

/** CIDv1, raw codec (0x55), sha2-256, base32 lower with the `b` prefix. */
export async function cidForBytes(bytes: Uint8Array): Promise<string> {
  const digest = await sha256(bytes);
  const multihash = new Uint8Array(36);
  multihash.set([0x01, 0x55, 0x12, 0x20], 0);
  multihash.set(digest, 4);
  return "b" + base32Lower(multihash);
}

/** 26 base32 characters carrying 130 bits from the CSPRNG. */
export function newLinkId(): string {
  return base32Lower(crypto.getRandomValues(new Uint8Array(17))).slice(0, 26);
}

/** Equal-length comparison without early exit; false on a length difference. */
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

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
