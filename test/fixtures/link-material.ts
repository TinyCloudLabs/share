/** Test helpers: a real issuer key, real sealed bytes, and a mock links API wired to a `fetch`. */
import { ed25519 } from "@noble/curves/ed25519";
import { generateKey, seal, toBase64Url } from "@tinycloud/share-envelope";
import { createMockLinksApi } from "./links-mock-api.js";

/** TEST ONLY key from the shared vectors (identity `issuerA`). */
const SEED = Uint8Array.from(Buffer.from("1111111111111111111111111111111111111111111111111111111111111111", "hex"));
export const ISSUER_DID = "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S";
export const signWithIssuer = async (digest: Uint8Array): Promise<Uint8Array> => ed25519.sign(digest, SEED);

export const SHARE_ORIGIN = "https://share.tinycloud.xyz";
export const API_ORIGIN = "https://api.tinycloud.xyz";

export interface SealedMaterial {
  readonly sealedEnvelope: string;
  readonly envelopeKey: string;
  readonly shareCid: string;
  readonly bytes: Uint8Array;
  readonly key: Uint8Array;
}

/** A sealed share body whose plaintext names the test issuer as its envelope signer. */
export async function sealedMaterial(plaintext: Record<string, unknown> = { version: 3, signature: { signerDid: ISSUER_DID, algorithm: "Ed25519", value: "TEST ONLY" } }): Promise<SealedMaterial> {
  const key = generateKey();
  const sealed = await seal(new TextEncoder().encode(JSON.stringify(plaintext)), key);
  return { sealedEnvelope: toBase64Url(sealed.blob), envelopeKey: toBase64Url(key), shareCid: sealed.cid, bytes: sealed.blob, key };
}

/** A mock links API and the `fetch` a page on the Share origin would use to reach it. */
export function mockLinks(now: () => number = Date.now) {
  const api = createMockLinksApi({ now, audience: API_ORIGIN, corsOrigins: [SHARE_ORIGIN] });
  return { api, fetchFn: api.fetchFor(API_ORIGIN, SHARE_ORIGIN) };
}
