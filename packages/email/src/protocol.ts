/** The email service verifies intent; it never owns content or authority. */
import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "multiformats/bases/base58";
import { verifyOwnerNodeBinding } from "@tinycloud/sdk-core";
import { canonicalize, computeCid, shareEnvelopeV3Schema, verifyEnvelopeV3, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";

export const CREDENTIAL_INVITATION_REQUEST_DOMAIN = "xyz.tinycloud.credentials/invitation-request/v1\0";
export const DELIVERY_ADMISSION_DOMAIN = "xyz.tinycloud.policy/delivery-admission/v0\0";
export const MAX_AUTHORIZATION_TTL_MS = 5 * 60 * 1000;
export const CLOCK_SKEW_MS = 60 * 1000;

const REQUEST_KEYS = ["schema", "policyId", "recipient", "resource", "credentialType", "returnLink", "envelopeRef", "label", "shareExpiresAt", "audience", "issuedAt", "expiresAt", "nonce"] as const;
const ADMISSION_KEYS = ["schema", "policyId", "ownerDid", "recipient", "resource", "actions", "credentialType", "returnLink", "envelopeRef", "label", "shareExpiresAt", "senderKeyDid", "audience", "issuedAt", "expiresAt", "nonce", "signature"] as const;
const EMAIL = /^[^@\s]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const B64URL_16 = /^[A-Za-z0-9_-]{22}$/;
const B64URL_64 = /^[A-Za-z0-9_-]{86}$/;
const SHA256_RAW_CID = /^bafkrei[a-z2-7]{52}$/;

export type RefusalReason = "configuration-unavailable" | "malformed" | "untrusted" | "expired" | "share-url-invalid" | "replayed" | "in-flight" | "store-unavailable" | "provider-unavailable";
export interface Refusal { readonly ok: false; readonly reason: RefusalReason }
export const refuse = (reason: RefusalReason): Refusal => ({ ok: false, reason });

export interface InvitationRequest {
  readonly schema: "xyz.tinycloud.credentials/invitation-request/v1";
  readonly policyId: string;
  readonly recipient: string;
  readonly resource: string;
  readonly credentialType: "opencredentials.email/v1";
  readonly returnLink: string;
  readonly envelopeRef: string;
  readonly label: string;
  readonly shareExpiresAt: string;
  readonly audience: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
}

export interface DeliveryAdmission extends Omit<InvitationRequest, "schema"> {
  readonly schema: "xyz.tinycloud.policy/delivery-admission/v0";
  readonly ownerDid: string;
  readonly actions: readonly ["tinycloud.kv/get"];
  readonly senderKeyDid: string;
  readonly signature: { readonly suite: "eddsa-ed25519-sha256-jcs-v1"; readonly signerDid: string; readonly value: string };
}

export interface DeliveryReceipt {
  readonly request: InvitationRequest;
  readonly admission: DeliveryAdmission;
  readonly proof: { readonly alg: "EdDSA"; readonly kid: string; readonly signature: string };
}

export interface DeliveryTrust {
  readonly deliveryAudience: string;
  readonly shareOrigin: string;
  readonly registryOrigin: string;
  readonly fetch?: typeof fetch;
}

export interface VerifiedDelivery {
  readonly ok: true;
  readonly receipt: DeliveryReceipt;
  readonly recipient: string;
  readonly shareCid: string;
  readonly shareUrl: string;
  readonly label: string;
  readonly shareExpiresAt: string;
  readonly idempotencyKey: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!isPlainObject(value)) return null;
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)) ? value : null;
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(`${normalized}${"=".repeat((4 - normalized.length % 4) % 4)}`);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function toBase64Url(value: Uint8Array): string {
  let binary = "";
  value.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

export async function digest(value: string): Promise<string> { return toBase64Url(await sha256(value)); }

function didKeyBytes(did: string): Uint8Array | null {
  if (!did.startsWith("did:key:z") || /[#/?]/.test(did.slice("did:key:".length))) return null;
  try {
    const decoded = base58btc.decode(did.slice("did:key:".length));
    return decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01 ? decoded.slice(2) : null;
  } catch { return null; }
}

function displayLabel(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && new TextEncoder().encode(value).byteLength <= 200 && !/[\u0000-\u001f\u007f]/.test(value);
}

async function parseShareUrl(raw: string, shareOrigin: string, envelopeRef: string): Promise<ShareEnvelopeV3 | null> {
  if (raw.length > 64 * 1024 || raw.includes("%")) return null;
  let url: URL;
  try { url = new URL(raw); } catch { return null; }
  const encoded = url.searchParams.size === 1 ? url.searchParams.get("tc2") : null;
  if (url.origin !== shareOrigin || url.pathname !== "/viewer" || url.hash !== "" || encoded === null || url.search !== `?tc2=${encoded}`) return null;
  try {
    const bytes = fromBase64Url(encoded);
    if (toBase64Url(bytes) !== encoded) return null;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(text) as unknown;
    const payload = exactObject(value, ["c", "cid", "v"]);
    if (payload === null || canonicalize(payload) !== text || payload.v !== 2 || payload.cid !== envelopeRef || typeof payload.c !== "string") return null;
    const envelopeBytes = fromBase64Url(payload.c);
    if (toBase64Url(envelopeBytes) !== payload.c || await computeCid(envelopeBytes) !== envelopeRef) return null;
    const envelopeText = new TextDecoder("utf-8", { fatal: true }).decode(envelopeBytes);
    const envelope = shareEnvelopeV3Schema.parse(JSON.parse(envelopeText) as unknown);
    if (canonicalize(envelope) !== envelopeText || !await verifyEnvelopeV3(envelope, { expectedSignerDid: envelope.policy.ownerDid })) return null;
    return envelope;
  } catch { return null; }
}

export function parseDeliveryRequest(value: unknown): DeliveryReceipt | null {
  const root = exactObject(value, ["admission", "proof", "request"]);
  if (root === null) return null;
  const request = exactObject(root.request, REQUEST_KEYS);
  const admission = exactObject(root.admission, ADMISSION_KEYS);
  const proof = exactObject(root.proof, ["alg", "kid", "signature"]);
  const signature = admission === null ? null : exactObject(admission.signature, ["signerDid", "suite", "value"]);
  if (request === null || admission === null || proof === null || signature === null) return null;
  return { request, admission, proof } as unknown as DeliveryReceipt;
}

export async function verifyDeliveryAuthorization(receipt: DeliveryReceipt, trust: DeliveryTrust, now: number): Promise<VerifiedDelivery | Refusal> {
  const { request, admission, proof } = receipt;
  const envelope = await parseShareUrl(request.returnLink, trust.shareOrigin, request.envelopeRef);
  if (envelope === null) return refuse("share-url-invalid");
  try {
    await verifyOwnerNodeBinding({
      registryUrl: trust.registryOrigin,
      ownerDid: envelope.policy.ownerDid,
      nodeOrigin: envelope.target.origin,
      nodeDid: envelope.attestedEnforcerBinding.nodeAudience,
      ...(trust.fetch === undefined ? {} : { fetch: trust.fetch }),
    });
  } catch {
    return refuse("untrusted");
  }
  const nodeKey = didKeyBytes(envelope.attestedEnforcerBinding.nodeAudience);
  const { signature, ...unsignedAdmission } = admission;
  const nodeDigest = await sha256(`${DELIVERY_ADMISSION_DOMAIN}${canonicalize(unsignedAdmission)}`);
  if (nodeKey === null || signature.signerDid !== envelope.attestedEnforcerBinding.nodeAudience || signature.suite !== "eddsa-ed25519-sha256-jcs-v1" || !B64URL_64.test(signature.value) || !ed25519.verify(fromBase64Url(signature.value), nodeDigest, nodeKey)) return refuse("untrusted");

  const senderKey = didKeyBytes(admission.senderKeyDid);
  const senderDigest = await sha256(`${CREDENTIAL_INVITATION_REQUEST_DOMAIN}${canonicalize(request)}`);
  if (senderKey === null || proof.alg !== "EdDSA" || proof.kid !== admission.senderKeyDid || !B64URL_64.test(proof.signature) || !ed25519.verify(fromBase64Url(proof.signature), senderDigest, senderKey)) return refuse("untrusted");

  const shared = ["policyId", "recipient", "resource", "credentialType", "returnLink", "envelopeRef", "label", "shareExpiresAt", "audience", "issuedAt", "expiresAt", "nonce"] as const;
  const credentialRequirement = envelope.policy.schema === "xyz.tinycloud.policy/policy/v2"
    ? envelope.policy.credentialRequirement
    : undefined;
  if (request.schema !== "xyz.tinycloud.credentials/invitation-request/v1"
    || admission.schema !== "xyz.tinycloud.policy/delivery-admission/v0"
    || shared.some((field) => request[field] !== admission[field])
    || request.credentialType !== "opencredentials.email/v1"
    || admission.actions.length !== 1 || admission.actions[0] !== "tinycloud.kv/get"
    || admission.audience !== trust.deliveryAudience
    || !EMAIL.test(request.recipient)
    || !SHA256_RAW_CID.test(request.envelopeRef)
    || !displayLabel(request.label)
    || !B64URL_16.test(request.nonce)
    || request.nonce !== admission.nonce
    || admission.ownerDid !== envelope.policy.ownerDid
    || envelope.signature.signerDid !== admission.ownerDid
    || envelope.policyCid !== request.policyId
    || envelope.recipientMatcher.kind !== "exactEmail"
    || envelope.recipientMatcher.value !== request.recipient
    || envelope.deliveryEmail !== request.recipient
    || envelope.contentSource.kvResource !== request.resource
    || credentialRequirement?.credentialType.id !== request.credentialType
    || envelope.display.filename !== request.label
    || envelope.metadata.filename !== request.label
    || envelope.expiry !== request.shareExpiresAt) return refuse("untrusted");

  const issuedAt = Date.parse(request.issuedAt);
  const expiresAt = Date.parse(request.expiresAt);
  const shareExpiresAt = Date.parse(request.shareExpiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || !Number.isFinite(shareExpiresAt) || issuedAt > now + CLOCK_SKEW_MS || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > MAX_AUTHORIZATION_TTL_MS || shareExpiresAt <= now) return refuse("expired");
  return { ok: true, receipt, recipient: request.recipient, shareCid: request.envelopeRef, shareUrl: request.returnLink, label: request.label, shareExpiresAt: request.shareExpiresAt, idempotencyKey: request.nonce };
}
