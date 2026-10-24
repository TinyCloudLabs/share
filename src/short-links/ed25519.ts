import { ed25519 } from "@noble/curves/ed25519";

/** Order of the prime subgroup (RFC 8032). */
const GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const Point = ed25519.ExtendedPoint;

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]!);
  return value;
}

export type PublicKeyClass = "ok" | "noncanonical" | "invalid" | "weak";

/**
 * `ok`: a canonical encoding of a point of order exactly the group order (not the identity, no small-order
 * or torsion part). The other classes name why a key is refused.
 */
export function classifyPublicKey(encoded: Uint8Array): PublicKeyClass {
  if (encoded.length !== 32) return "invalid";
  let point: InstanceType<typeof Point>;
  try {
    point = Point.fromHex(encoded, false);
  } catch {
    try {
      Point.fromHex(encoded, true);
      return "noncanonical";
    } catch {
      return "invalid";
    }
  }
  return point.equals(Point.ZERO) || !point.isTorsionFree() ? "weak" : "ok";
}

/**
 * Strict Ed25519 verification (contract 2.5): `S < l`, canonical `A` and `R`, both of prime order,
 * then the verification equation.
 */
export function verifyStrict(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  if (littleEndian(signature.subarray(32)) >= GROUP_ORDER) return false;
  if (classifyPublicKey(publicKey) !== "ok" || classifyPublicKey(signature.subarray(0, 32)) !== "ok") return false;
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
