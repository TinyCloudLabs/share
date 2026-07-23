import { ed25519 } from "@noble/curves/ed25519";

import { fromBase64Url, toBase64Url, utf8Bytes } from "./bytes.js";
import { computeCid } from "./cid.js";
import { didKeyFromEd25519PublicKey, ed25519PublicKeyFromDidKey } from "./didkey.js";
import { canonicalize } from "./jcs.js";
import {
  shareEnvelopeSchema,
  unsignedShareEnvelopeSchema,
  type ShareEnvelope,
  type UnsignedShareEnvelope,
} from "./schema.js";

/**
 * Ed25519 verification mode: strict RFC 8032, NOT ZIP-215. `zip215: false`
 * makes @noble/curves reject non-canonical point encodings (y >= p) that the
 * looser ZIP-215 rules accept, so this JS verifier and a strict Rust verifier
 * (e.g. ed25519-dalek `verify_strict`) agree on exactly the same signature
 * set. Chosen deliberately: interop determinism over batch-verification
 * compatibility.
 */
const ED25519_VERIFY_OPTS = { zip215: false } as const;

/** The one canonical envelope signing domain shared by runtime and vectors. */
export const ENVELOPE_SIGNATURE_DOMAIN = "xyz.tinycloud.share/envelope/v1\0";

/** Domain-separated JCS bytes of every envelope field except `signature`. */
function signingBytes(unsigned: UnsignedShareEnvelope): Uint8Array {
  const domain = utf8Bytes(ENVELOPE_SIGNATURE_DOMAIN);
  const body = utf8Bytes(canonicalize(unsigned));
  const bytes = new Uint8Array(domain.length + body.length);
  bytes.set(domain);
  bytes.set(body, domain.length);
  return bytes;
}

/**
 * Sign an envelope body with an ed25519 private key (32-byte seed). The
 * signature covers the domain-separated RFC 8785 canonical JSON of all other fields —
 * including `authorizationTarget.kind` and `target.origin` (blueprint §2.1).
 * Throws if the body does not validate against the strict schema.
 */
export function signEnvelope(
  envelopeWithoutSig: UnsignedShareEnvelope,
  ed25519PrivKey: Uint8Array,
): ShareEnvelope {
  const unsigned = unsignedShareEnvelopeSchema.parse(envelopeWithoutSig);
  const publicKey = ed25519.getPublicKey(ed25519PrivKey);
  const signature = ed25519.sign(signingBytes(unsigned), ed25519PrivKey);
  return {
    ...unsigned,
    signature: {
      signerDid: didKeyFromEd25519PublicKey(publicKey),
      algorithm: "Ed25519",
      value: toBase64Url(signature),
    },
  };
}

export interface VerifyEnvelopeOptions {
  /**
   * The did:key the caller ALREADY trusts to be the sender. REQUIRED:
   * `signature.signerDid` is self-asserted by whoever built the envelope, so
   * verifying against it alone proves nothing — an attacker signs their own
   * "Adam" envelope with their own key and it self-verifies. In later stages
   * the expected signer is the delegation chain's issuer DID; for now the
   * caller supplies it out-of-band.
   */
  expectedSignerDid: string;
}

/**
 * Signature-only check: strict-parse, recompute the JCS signing bytes, and
 * check the ed25519 signature against the key in `signature.signerDid`.
 *
 * WARNING: this only proves the envelope is internally consistent with its
 * OWN self-asserted signer. It binds no trust — use `verifyEnvelope` with an
 * `expectedSignerDid` unless you are doing the binding yourself.
 */
export function verifyEnvelopeSignatureOnly(envelope: ShareEnvelope): boolean {
  const parsed = shareEnvelopeSchema.parse(envelope);
  const { signature, ...unsigned } = parsed;
  const publicKey = ed25519PublicKeyFromDidKey(signature.signerDid);
  return ed25519.verify(
    fromBase64Url(signature.value),
    signingBytes(unsigned),
    publicKey,
    ED25519_VERIFY_OPTS,
  );
}

/**
 * Verify a signed envelope against an EXPECTED signer:
 *
 * 1. strict schema parse (throws on malformed input),
 * 2. `signature.signerDid` must equal `options.expectedSignerDid`,
 * 3. the ed25519 signature must verify (strict RFC 8032) over the domain-separated JCS bytes,
 * 4. for `authorizationTarget.kind === "policy"`, the decoded `policyBytes`
 *    must hash to `policyCid` (CIDv1/raw/sha2-256).
 *
 * Returns false for any trust or integrity failure.
 */
export async function verifyEnvelope(
  envelope: ShareEnvelope,
  options: VerifyEnvelopeOptions,
): Promise<boolean> {
  const parsed = shareEnvelopeSchema.parse(envelope);
  if (parsed.signature.signerDid !== options.expectedSignerDid) return false;
  if (!verifyEnvelopeSignatureOnly(parsed)) return false;
  if (parsed.authorizationTarget.kind === "policy") {
    const policyBytes = fromBase64Url(parsed.authorizationTarget.policyBytes);
    if ((await computeCid(policyBytes)) !== parsed.authorizationTarget.policyCid) {
      return false;
    }
  }
  return true;
}
