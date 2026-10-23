import { sha256 } from "@noble/hashes/sha256";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, ed25519PublicKeyFromDidKey, fromBase64Url, isCanonicalRawCid, open, toBase64Url } from "@tinycloud/share-envelope";
import type { LinkType } from "./codec.js";
import { classifyPublicKey, verifyStrict } from "./ed25519.js";

export const HEADER_DOMAIN = "xyz.tinycloud.links/header/v1\0";
export const DELETE_DOMAIN = "xyz.tinycloud.links/delete/v1\0";

/** Per-type body caps (decoded bytes) and life caps (seconds). */
export const LINK_TYPES: Readonly<Record<LinkType, { readonly maxBody: number; readonly maxLifeSeconds: number }>> = Object.freeze({
  "openkey-login": { maxBody: 16_384, maxLifeSeconds: 600 },
  courier: { maxBody: 32_768, maxLifeSeconds: 604_800 },
  share: { maxBody: 131_072, maxLifeSeconds: 2_592_000 },
});
export const MIN_BODY_BYTES = 30;
export const MIN_LIFE_SECONDS = 120;

export interface LinkHeader {
  readonly version: 1;
  readonly type: LinkType;
  readonly issuer: string;
  readonly audience: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly size: number;
  readonly bodyCid: string;
  readonly nonce: string;
}

export interface LinkSignature {
  readonly algorithm: "Ed25519";
  readonly value: string;
}

/** A record as a reader holds it: the header, its signature when there is one, and the sealed body bytes. */
export interface LinkRecord {
  readonly header: LinkHeader;
  readonly signature?: LinkSignature;
  readonly body: Uint8Array;
}

export type RecordRefusal =
  | "record_shape" | "record_fields" | "header_shape" | "header_fields" | "header_version" | "unknown_type"
  | "issuer_format" | "issuer_method_not_allowed" | "issuer_key_type" | "issuer_key_noncanonical" | "issuer_key_invalid" | "issuer_weak_key" | "issuer_service_format"
  | "audience_format" | "timestamp_format" | "nonce_format" | "size_format" | "body_cid_format"
  | "unsigned_not_allowed" | "body_encoding" | "size_mismatch" | "body_over_type_cap" | "body_too_small" | "body_hash_mismatch"
  | "bad_signature" | "expired" | "body_open_failed" | "plaintext_schema" | "issuer_binding_mismatch"
  | "type_path_mismatch" | "link_cid_mismatch" | "full_non_share";

const HEADER_KEYS = ["audience", "bodyCid", "expiresAt", "issuedAt", "issuer", "nonce", "size", "type", "version"];
const AUDIENCE = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/;
const SERVICE_ISSUER = /^service:[a-z0-9][a-z0-9-]{0,31}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;
const ID = /^[a-z2-7]{26}$/;
const encoder = new TextEncoder();

function strictDecode(text: string): Uint8Array | undefined {
  try {
    return fromBase64Url(text);
  } catch {
    return undefined;
  }
}

function timestampMs(value: unknown): number | undefined {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === value ? ms : undefined;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The issuer key a signed header names, or the reason it cannot be used. */
export function issuerKey(issuer: string): { readonly key: Uint8Array } | { readonly refusal: RecordRefusal } {
  if (!issuer.startsWith("did:key:")) return { refusal: "issuer_method_not_allowed" };
  let key: Uint8Array;
  try {
    key = ed25519PublicKeyFromDidKey(issuer);
  } catch {
    return { refusal: "issuer_key_type" };
  }
  if (key.length !== 32 || didKeyFromEd25519PublicKey(key) !== issuer) return { refusal: "issuer_format" };
  const quality = classifyPublicKey(key);
  if (quality === "noncanonical") return { refusal: "issuer_key_noncanonical" };
  if (quality === "invalid") return { refusal: "issuer_key_invalid" };
  if (quality === "weak") return { refusal: "issuer_weak_key" };
  return { key };
}

/** Header structure and field grammar, without the signature. `signed` selects the issuer rule. */
export function checkHeader(value: unknown, signed: boolean): { readonly header: LinkHeader } | { readonly refusal: RecordRefusal } {
  if (!isObject(value)) return { refusal: "header_shape" };
  const keys = Object.keys(value).sort();
  if (keys.length !== HEADER_KEYS.length || keys.some((key, index) => key !== HEADER_KEYS[index])) return { refusal: "header_fields" };
  if (value["version"] !== 1) return { refusal: "header_version" };
  const type = value["type"];
  if (typeof type !== "string" || !Object.hasOwn(LINK_TYPES, type)) return { refusal: "unknown_type" };
  const issuer = value["issuer"];
  if (typeof issuer !== "string") return { refusal: "issuer_format" };
  if (signed) {
    const key = issuerKey(issuer);
    if ("refusal" in key) return key;
  } else if (!SERVICE_ISSUER.test(issuer)) {
    return { refusal: "issuer_service_format" };
  }
  const audience = value["audience"];
  if (typeof audience !== "string" || !AUDIENCE.test(audience)) return { refusal: "audience_format" };
  if (timestampMs(value["issuedAt"]) === undefined || timestampMs(value["expiresAt"]) === undefined) return { refusal: "timestamp_format" };
  const nonce = value["nonce"];
  if (typeof nonce !== "string" || !NONCE.test(nonce) || strictDecode(nonce)?.length !== 16) return { refusal: "nonce_format" };
  const size = value["size"];
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 1) return { refusal: "size_format" };
  const bodyCid = value["bodyCid"];
  if (typeof bodyCid !== "string" || !isCanonicalRawCid(bodyCid)) return { refusal: "body_cid_format" };
  return { header: value as unknown as LinkHeader };
}

/** `SHA-256(utf8(domain) || utf8(JCS(object)))`: the bytes the issuer signs (contract 2.5). */
export function signingDigest(domain: string, object: unknown): Uint8Array {
  return sha256(encoder.encode(`${domain}${canonicalize(object)}`));
}

export interface HeaderInput {
  readonly type: LinkType;
  readonly issuer: string;
  readonly audience: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly body: Uint8Array;
}

/** Builds a header for `body`: size and CID from the bytes, a fresh 16-byte nonce. */
export async function buildHeader(input: HeaderInput): Promise<LinkHeader> {
  return {
    version: 1,
    type: input.type,
    issuer: input.issuer,
    audience: input.audience,
    issuedAt: input.issuedAt.toISOString(),
    expiresAt: input.expiresAt.toISOString(),
    size: input.body.byteLength,
    bodyCid: await computeCid(input.body),
    nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
}

/** Signs `object` under `domain` with the issuer's session key. `sign` receives the 32-byte digest. */
export async function signObject(domain: string, object: unknown, sign: (digest: Uint8Array) => Promise<Uint8Array>): Promise<LinkSignature> {
  const value = await sign(signingDigest(domain, object));
  if (value.byteLength !== 64) throw new TypeError("signature has the wrong length");
  return { algorithm: "Ed25519", value: toBase64Url(value) };
}

/** True when `signature` verifies for `object` under `domain` against the key in `issuer` (strict rule, contract 2.5). */
export function verifySignature(domain: string, object: unknown, issuer: string, signature: unknown): boolean {
  if (!isObject(signature) || Object.keys(signature).sort().join(",") !== "algorithm,value" || signature["algorithm"] !== "Ed25519" || typeof signature["value"] !== "string") return false;
  const key = issuerKey(issuer);
  if ("refusal" in key) return false;
  const bytes = strictDecode(signature["value"]);
  return bytes !== undefined && bytes.length === 64 && verifyStrict(key.key, signingDigest(domain, object), bytes);
}

/** A signed delete request (contract 6.1). */
export interface DeleteRequest {
  readonly version: 1;
  readonly op: "delete";
  readonly id: string;
  readonly issuer: string;
  readonly audience: string;
  readonly issuedAt: string;
  readonly nonce: string;
}

export function buildDeleteRequest(input: { readonly id: string; readonly issuer: string; readonly audience: string; readonly issuedAt: Date }): DeleteRequest {
  if (!ID.test(input.id)) throw new TypeError("link id is malformed");
  return {
    version: 1, op: "delete", id: input.id, issuer: input.issuer, audience: input.audience,
    issuedAt: input.issuedAt.toISOString(), nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
}

/**
 * The reader checks on a record (contract 7.5 step 3 and 4): header, size, CID, expiry, signature,
 * then the seal and the issuer binding. Returns the opened plaintext object.
 */
export async function checkRecord(
  record: { readonly header: unknown; readonly signature?: unknown; readonly body: Uint8Array },
  options: { readonly now: number; readonly key: Uint8Array },
): Promise<{ readonly header: LinkHeader; readonly plaintext: Record<string, unknown> } | { readonly refusal: RecordRefusal }> {
  const signed = record.signature !== undefined;
  const checked = checkHeader(record.header, signed);
  if ("refusal" in checked) return checked;
  const { header } = checked;
  if (!signed && header.type !== "openkey-login") return { refusal: "unsigned_not_allowed" };
  const { body } = record;
  if (body.byteLength !== header.size) return { refusal: "size_mismatch" };
  if (body.byteLength > LINK_TYPES[header.type].maxBody) return { refusal: "body_over_type_cap" };
  if (body.byteLength < MIN_BODY_BYTES) return { refusal: "body_too_small" };
  if ((await computeCid(body)) !== header.bodyCid) return { refusal: "body_hash_mismatch" };
  if (signed && !verifySignature(HEADER_DOMAIN, header, header.issuer, record.signature)) return { refusal: "bad_signature" };
  if ((timestampMs(header.expiresAt) ?? 0) <= options.now) return { refusal: "expired" };
  let opened: Uint8Array;
  try {
    opened = await open(body, options.key);
  } catch {
    return { refusal: "body_open_failed" };
  }
  let plaintext: unknown;
  try {
    plaintext = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(opened));
  } catch {
    return { refusal: "plaintext_schema" };
  }
  if (!isObject(plaintext)) return { refusal: "plaintext_schema" };
  // The sealed plaintext names the issuer; a share names its envelope signer (contract 3).
  const named = header.type === "share" ? (isObject(plaintext["signature"]) ? plaintext["signature"]["signerDid"] : undefined) : plaintext["issuer"];
  if (typeof named !== "string" || named !== header.issuer) return { refusal: "issuer_binding_mismatch" };
  return { header, plaintext };
}
