import { createPrivateKey, sign } from "node:crypto";
import { base64UrlEncode, sha256, utf8 } from "../../src/bytes.ts";
import { jcs } from "../../src/jcs.ts";
import { READ_AUTH_DOMAIN, READ_AUTH_HEADER } from "../../src/read-auth.ts";
import { AUDIENCE, CLIENT_IP, makeIssuer, type Issuer } from "./client.ts";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** The TEST ONLY seed of the `nodeReadAuth` vectors: 0x33 repeated 32 times. */
export const TEST_NODE_SEED = Buffer.alloc(32, 0x33);
export const TEST_NODE_DID = "did:key:z6Mkg49NtQR2LyYRDCQFK4w1VVHqhypZSSRo7HsyuN7SV7v5";

export interface ReadSignerKey {
  readonly did: string;
  signDigest(digest: Uint8Array): string;
}

export function keyFromSeed(seed: Uint8Array, did: string): ReadSignerKey {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
  return { did, signDigest: (digest) => base64UrlEncode(sign(null, digest, key)) };
}

export const testNodeKey = keyFromSeed(TEST_NODE_SEED, TEST_NODE_DID);

/** A fresh random key, for signers that are not on any list. */
export function randomKey(): ReadSignerKey {
  const issuer: Issuer = makeIssuer();
  return { did: issuer.did, signDigest: (digest) => issuer.signDigest(digest) };
}

export interface ReadAuthOptions {
  readonly key: ReadSignerKey;
  readonly id: string;
  readonly nowMs: number;
  /** Added to `nowMs` for the signed `issuedAt` (default 0). */
  readonly skewMs?: number;
  /** The path that is signed, when it differs from the path of the request. */
  readonly signedPath?: string;
  readonly audience?: string;
  readonly method?: string;
}

/** The header value for `GET /v1/links/<id>`. */
export async function readAuthValue(options: ReadAuthOptions): Promise<string> {
  const issuedAt = new Date(options.nowMs + (options.skewMs ?? 0)).toISOString();
  const signed = {
    audience: options.audience ?? AUDIENCE,
    issuedAt,
    method: options.method ?? "GET",
    path: options.signedPath ?? `/v1/links/${options.id}`,
    signerDid: options.key.did,
  };
  const signature = options.key.signDigest(await sha256(utf8(READ_AUTH_DOMAIN + jcs(signed))));
  return base64UrlEncode(utf8(jcs({ issuedAt, signature, signerDid: options.key.did })));
}

export async function authenticatedGet(options: ReadAuthOptions & { readonly ip?: string; readonly suffix?: string }): Promise<Request> {
  return new Request(`${AUDIENCE}/v1/links/${options.id}${options.suffix ?? ""}`, {
    headers: { "CF-Connecting-IP": options.ip ?? CLIENT_IP, [READ_AUTH_HEADER]: await readAuthValue(options) },
  });
}
