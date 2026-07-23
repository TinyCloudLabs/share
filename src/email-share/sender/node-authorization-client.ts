/**
 * Strict fetch client for the node's invite-authorization endpoint
 * (specs/email-claim-v1/schemas.json `schemas.authorizationRequest` /
 * `schemas.authorizationResponse`). Never trusts an unparsed response: every
 * field of `authorization` and `proof` is structurally checked before the
 * caller ever sees it, and network/HTTP/parse failures are distinct typed
 * errors so the UI can render a generic, privacy-safe state instead of
 * leaking transport detail.
 */
import { assertSqlArgumentsDigest, isContentSourceShape } from "./content-source.js";
import {
  SenderHttpError,
  SenderInvalidResponseError,
  SenderNetworkError,
} from "./errors.js";
import type {
  AuthorizationRequestBody,
  InviteAuthorization,
  Proof,
} from "./invitation-input.js";

export interface AuthorizationResponse {
  readonly authorization: InviteAuthorization;
  readonly proof: Proof;
}

export interface RequestNodeAuthorizationOptions {
  readonly fetchFn?: typeof globalThis.fetch;
}

// Frozen wire-shape patterns (specs/email-claim-v1/schemas.json $defs) — every
// echoed-back field is checked against its exact pattern, never accepted just
// because it type-checks as a string.
const B64_16 = /^[A-Za-z0-9_-]{21}[AQgw]$/; // $defs.b64_16 — jti, reportAbuseToken
const B64_32 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/; // $defs.b64_32 — digest
const B64_64 = /^[A-Za-z0-9_-]{85}[AQgw]$/; // $defs.b64_64 — proof.signature
const CID = /^bafkrei[a-z2-7]{52}$/; // $defs.cid
const SHARE_ID = /^[A-Za-z0-9._~-]+$/; // $defs.shareId
const TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/; // $defs.time
const ORIGIN =
  /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[1-9][0-9]{0,4})?$/; // $defs.origin
const DID = /^did:(?:web:[A-Za-z0-9.:%_-]+|pkh:[A-Za-z0-9:._-]+|key:z[1-9A-HJ-NP-Za-km-z]+)$/; // $defs.did
const KID = /^did:(?:web:[A-Za-z0-9.:%_-]+|key:z[1-9A-HJ-NP-Za-km-z]+)#[^#\s]+$/; // $defs.kid
const CANONICAL_EMAIL =
  /^(?=[\x00-\x7F]{3,254}$)(?=[^@]{1,64}@[^@]{1,253}$)[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/; // $defs.email
const DOCUMENT_NAME = /^[^\u0000-\u001F\u007F]+$/; // $defs.documentName

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isJti(value: unknown): value is string {
  return isString(value) && B64_16.test(value);
}

function isDigest(value: unknown): value is string {
  return isString(value) && B64_32.test(value);
}

function isCid(value: unknown): value is string {
  return isString(value) && CID.test(value);
}

function isShareId(value: unknown): value is string {
  return isString(value) && value.length >= 1 && value.length <= 128 && SHARE_ID.test(value);
}

function isTimestamp(value: unknown): value is string {
  return isString(value) && TIME.test(value);
}

function isOrigin(value: unknown): value is string {
  return isString(value) && ORIGIN.test(value);
}

function isDid(value: unknown): value is string {
  return isString(value) && DID.test(value);
}

function isCanonicalEmail(value: unknown): value is string {
  return isString(value) && CANONICAL_EMAIL.test(value);
}

function isDocumentName(value: unknown): value is string {
  if (!isString(value) || value.length < 1 || !DOCUMENT_NAME.test(value)) return false;
  return new TextEncoder().encode(value).length <= 200;
}

function isKid(value: unknown): value is string {
  return isString(value) && value.length >= 8 && value.length <= 256 && KID.test(value);
}

function isSignature(value: unknown): value is string {
  return isString(value) && B64_64.test(value);
}

function isValidProof(value: unknown): value is Proof {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.alg === "EdDSA" &&
    isKid(record.kid) &&
    isSignature(record.signature) &&
    Object.keys(record).length === 3
  );
}

function isValidInviteAuthorization(value: unknown): value is InviteAuthorization {
  if (typeof value !== "object" || value === null) return false;
  const r = value as Record<string, unknown>;
  const validShape =
    r.type === "TinyCloudShareInviteAuthorization" &&
    r.version === 1 &&
    isJti(r.jti) &&
    isDid(r.senderDid) &&
    isCid(r.shareCid) &&
    isShareId(r.shareId) &&
    isCid(r.policyCid) &&
    isCanonicalEmail(r.recipientEmail) &&
    isOrigin(r.targetOrigin) &&
    isDid(r.nodeAudience) &&
    r.returnOrigin === "https://share.tinycloud.xyz" &&
    isDocumentName(r.documentName) &&
    (r.senderTrust === "verified" || r.senderTrust === "unverified") &&
    isContentSourceShape(r.contentSource) &&
    isDigest(r.contentSourceDigest) &&
    isTimestamp(r.shareExpiresAt) &&
    isTimestamp(r.issuedAt) &&
    isTimestamp(r.expiresAt) &&
    isJti(r.reportAbuseToken) &&
    Object.keys(r).length === 19;
  return validShape;
}

async function hasValidSqlArgumentsDigest(authorization: InviteAuthorization): Promise<boolean> {
  if (authorization.contentSource.kind !== "sql") return true;
  try {
    await assertSqlArgumentsDigest(authorization.contentSource);
    return true;
  } catch {
    return false;
  }
}

/** Keep the async source-integrity check separate from the synchronous shape guard. */
/**
 * POST the prepared authorization request to the node at `url` and return
 * its strictly-validated signed authorization + proof. Throws
 * {@link SenderNetworkError} on transport failure, {@link SenderHttpError}
 * on a non-2xx status, and {@link SenderInvalidResponseError} on a body
 * that is not valid JSON or does not match the strict authorization/proof
 * shape.
 */
export async function requestNodeAuthorization(
  url: string,
  body: AuthorizationRequestBody,
  options: RequestNodeAuthorizationOptions = {},
): Promise<AuthorizationResponse> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  let response: Response;
  try {
    response = await fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new SenderNetworkError(
      error instanceof Error ? error.message : "node authorization request failed",
    );
  }
  if (!response.ok) {
    throw new SenderHttpError("node authorization request failed", response.status);
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    throw new SenderInvalidResponseError("node authorization response is not JSON");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new SenderInvalidResponseError("node authorization response is not an object");
  }
  const record = parsed as Record<string, unknown>;
  if (Object.keys(record).length !== 2 || !isValidInviteAuthorization(record.authorization)) {
    throw new SenderInvalidResponseError("node authorization response.authorization is malformed");
  }
  const authorization = record.authorization;
  if (!(await hasValidSqlArgumentsDigest(authorization))) {
    throw new SenderInvalidResponseError("node authorization response.authorization is malformed");
  }
  if (!isValidProof(record.proof)) {
    throw new SenderInvalidResponseError("node authorization response.proof is malformed");
  }
  return { authorization, proof: record.proof };
}
