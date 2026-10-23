import { ed25519 } from "@noble/curves/ed25519";

/**
 * Ed25519 verification rule of contract section 2.5. A signature is valid only if all hold:
 *   1. S < l;
 *   2. the encodings of A and R are canonical (y < p, and they re-encode to themselves);
 *   3. A and R each have order exactly l (not the identity, not small order, no torsion component);
 *   4. the equation [S]B = R + [k]A holds.
 */

const FIELD_P = 2n ** 255n - 19n;
const ORDER_L = 2n ** 252n + 27742317777372353535851937790883648493n;

function littleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0);
  }
  return n;
}

export type KeyProblem = "noncanonical" | "invalid" | "weak";

/** null when the 32 bytes encode a canonical point of order exactly l. */
export function pointProblem(encoded: Uint8Array): KeyProblem | null {
  if (encoded.length !== 32) {
    return "invalid";
  }
  const y = littleEndian(encoded) & ((1n << 255n) - 1n);
  if (y >= FIELD_P) {
    return "noncanonical";
  }
  let point;
  try {
    point = ed25519.ExtendedPoint.fromHex(encoded, true);
  } catch {
    return "invalid";
  }
  const reencoded = point.toRawBytes();
  for (let i = 0; i < 32; i++) {
    if (reencoded[i] !== encoded[i]) {
      return "noncanonical";
    }
  }
  if (point.equals(ed25519.ExtendedPoint.ZERO) || !point.isTorsionFree()) {
    return "weak";
  }
  return null;
}

/** Strict verification of `signature` over `message` (the SHA-256 digest of the signed bytes). */
export function verifyStrict(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  if (littleEndian(signature.subarray(32)) >= ORDER_L) {
    return false;
  }
  if (pointProblem(publicKey) !== null || pointProblem(signature.subarray(0, 32)) !== null) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DID_KEY_RE = /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/;

function base58Decode(text: string): Uint8Array | null {
  let n = 0n;
  for (const ch of text) {
    const i = BASE58.indexOf(ch);
    if (i < 0) {
      return null;
    }
    n = n * 58n + BigInt(i);
  }
  const body: number[] = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") {
    zeros++;
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...body]);
}

function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  let out = "";
  while (n > 0n) {
    out = BASE58.charAt(Number(n % 58n)) + out;
    n /= 58n;
  }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) {
    zeros++;
  }
  return "1".repeat(zeros) + out;
}

export type DidKeyResult =
  | { readonly ok: true; readonly publicKey: Uint8Array }
  | { readonly ok: false; readonly reason: "format" | "key_type" };

/** Parses an Ed25519 `did:key` (multicodec 0xed01); the text must re-encode to itself. */
export function parseEd25519DidKey(did: string): DidKeyResult {
  if (!DID_KEY_RE.test(did)) {
    return { ok: false, reason: "format" };
  }
  const raw = base58Decode(did.slice("did:key:z".length));
  if (raw === null || raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    return { ok: false, reason: "key_type" };
  }
  if ("did:key:z" + base58Encode(raw) !== did) {
    return { ok: false, reason: "key_type" };
  }
  return { ok: true, publicKey: raw.slice(2) };
}
