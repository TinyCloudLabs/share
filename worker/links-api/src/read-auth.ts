import { base64UrlDecode, sha256, utf8 } from "./bytes.ts";
import { parseEd25519DidKey, pointProblem, signatureScalarCanonical, verifyStrict } from "./ed25519.ts";
import { jcs } from "./jcs.ts";
import type { ReadSigner } from "./read-signers.ts";
import { hasExactKeys, isPlainObject, parseTimestamp } from "./schemas.ts";

/**
 * The authenticated read (contract 4.11). `evaluateReadAuth` decides whether a `GET /v1/links/{id}` carries a
 * valid `TinyCloud-Read-Auth` header from an allow-listed signer. The answer only chooses which rate-limit
 * bucket the read uses; every other result is an ordinary read.
 */

export const READ_AUTH_HEADER = "TinyCloud-Read-Auth";
export const READ_AUTH_DOMAIN = "xyz.tinycloud.links/read-auth/v1\0";
export const READ_AUTH_MAX_BYTES = 512;
export const READ_AUTH_WINDOW_MS = 120_000;

const READ_PATH_RE = /^\/v1\/links\/[a-z2-7]{26}$/;
const HEADER_FIELDS = ["issuedAt", "signature", "signerDid"];

/** Test labels; they never reach the wire. */
export type ReadAuthRefusal =
  | "missing"
  | "ineligible"
  | "malformed"
  | "unlisted-signer"
  | "stale"
  | "future"
  | "weak-key"
  | "noncanonical-key"
  | "non-canonical-signature"
  | "bad-signature";

export type ReadAuthResult =
  | { readonly authenticated: true; readonly label: string }
  | { readonly authenticated: false; readonly reason: ReadAuthRefusal };

export interface ReadAuthInput {
  /** The raw header value, or null when the request has none. */
  readonly headerValue: string | null;
  readonly method: string;
  /** The request path as received: eligible only as `/v1/links/<lowercase 26-character id>`. */
  readonly pathname: string;
  /** The query string as received (`""` when none); a request with a query string is not eligible. */
  readonly search: string;
  /** This API instance (the configured audience). */
  readonly audience: string;
  readonly nowMs: number;
  readonly signers: readonly ReadSigner[];
}

function refuse(reason: ReadAuthRefusal): ReadAuthResult {
  return { authenticated: false, reason };
}

/** The decoded header object, or null when the value is not exactly the canonical three-field object. */
function decodeHeader(value: string): { issuedAt: string; signature: string; signerDid: string } | null {
  if (value.length > READ_AUTH_MAX_BYTES) {
    return null;
  }
  const bytes = base64UrlDecode(value);
  if (bytes === null || bytes.length > READ_AUTH_MAX_BYTES) {
    return null;
  }
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isPlainObject(parsed) || !hasExactKeys(parsed, HEADER_FIELDS) || jcs(parsed) !== text) {
    return null;
  }
  const { issuedAt, signature, signerDid } = parsed;
  if (typeof issuedAt !== "string" || typeof signature !== "string" || typeof signerDid !== "string") {
    return null;
  }
  return { issuedAt, signature, signerDid };
}

export async function evaluateReadAuth(input: ReadAuthInput): Promise<ReadAuthResult> {
  if (input.headerValue === null) {
    return refuse("missing");
  }
  if (input.method !== "GET" || input.search !== "" || !READ_PATH_RE.test(input.pathname)) {
    return refuse("ineligible");
  }
  const header = decodeHeader(input.headerValue);
  if (header === null || !parseEd25519DidKey(header.signerDid).ok) {
    return refuse("malformed");
  }
  const signer = input.signers.find((s) => s.did === header.signerDid);
  if (signer === undefined) {
    return refuse("unlisted-signer");
  }
  const issuedMs = parseTimestamp(header.issuedAt);
  if (issuedMs === null) {
    return refuse("malformed");
  }
  if (issuedMs < input.nowMs - READ_AUTH_WINDOW_MS) {
    return refuse("stale");
  }
  if (issuedMs > input.nowMs + READ_AUTH_WINDOW_MS) {
    return refuse("future");
  }
  const problem = pointProblem(signer.publicKey);
  if (problem === "weak") {
    return refuse("weak-key");
  }
  if (problem === "noncanonical") {
    return refuse("noncanonical-key");
  }
  const signature = base64UrlDecode(header.signature);
  if (signature === null || signature.length !== 64) {
    return refuse("malformed");
  }
  if (problem !== null) {
    return refuse("bad-signature");
  }
  if (!signatureScalarCanonical(signature)) {
    return refuse("non-canonical-signature");
  }
  const signed = {
    audience: input.audience,
    issuedAt: header.issuedAt,
    method: "GET",
    path: input.pathname,
    signerDid: header.signerDid,
  };
  const digest = await sha256(utf8(READ_AUTH_DOMAIN + jcs(signed)));
  return verifyStrict(signer.publicKey, digest, signature) ? { authenticated: true, label: signer.label } : refuse("bad-signature");
}
