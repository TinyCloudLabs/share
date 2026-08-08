/**
 * The delivery-authorization contract this Worker verifies.
 *
 * The sending half of addressed sharing is authorized by the Node, not by the
 * caller: `TinyCloudNode.authorizeShareDelivery` (node-sdk 2.10.0) returns a
 * `{ authorization, proof }` receipt whose `authorization` object the Node
 * signed with its enrolled invitation key over
 * `V2_DELIVERY_DOMAIN || jcs(authorization)` (tinycloud-node-server
 * `src/share_v2.rs`, `signed_value` + `authorize_delivery_v2`).
 *
 * That receipt — not a bearer token, not the caller's origin — is what makes
 * this service safe to expose. It binds the recipient, the share, the target
 * origin, three distinct audiences, a five-minute expiry and a single-use
 * idempotency key. Everything in here re-derives those bindings against
 * OPERATOR-CONFIGURED trust and refuses when any of them is absent, stale or
 * unverifiable. There is deliberately no path that sends without a valid
 * proof, and no fallback that "accepts anything" when a key is unset.
 */

import { canonicalize } from "@tinycloud/share-envelope";

/** Matches `V2_DELIVERY_DOMAIN` in `tinycloud-node-server/src/share_v2.rs`. */
export const DELIVERY_AUTHORIZATION_DOMAIN =
  "xyz.tinycloud.share/delivery-authorization/v2\0";
export const DELIVERY_AUTHORIZATION_V3_DOMAIN =
  "xyz.tinycloud.share/delivery-authorization/v3\0";

/**
 * The Node caps `expiresAt` at five minutes from issuance; we re-impose the
 * same ceiling so a Node that mints a longer-lived authorization (or a clock
 * that has been pushed forward) cannot widen the replay window here.
 */
export const MAX_AUTHORIZATION_TTL_MS = 5 * 60 * 1000;

/** Tolerance for `issuedAt` being slightly ahead of this Worker's clock. */
export const CLOCK_SKEW_MS = 60 * 1000;

/** The exact key set the Node emits. Extra or missing keys are refused. */
export const AUTHORIZATION_KEYS = [
  "actions",
  "authorityMaterialDigest",
  "authorityMaterialHandle",
  "contentSource",
  "contentSourceDigest",
  "dataAuthority",
  "deliveryEmail",
  "delegationCid",
  "documentName",
  "enforcementDelegationCid",
  "envelopeCid",
  "expiresAt",
  "holder",
  "idempotencyKey",
  "issuedAt",
  "jti",
  "nodeAudience",
  "openCredentialsAudience",
  "policyCid",
  "recipientMatcher",
  "registrationCid",
  "reportAbuseToken",
  "requestBodyDigest",
  "resource",
  "returnOrigin",
  "senderDid",
  "senderTrust",
  "shareCid",
  "shareExpiresAt",
  "shareId",
  "shareUrl",
  "targetOrigin",
  "type",
  "version",
] as const;

/** Exact key set emitted by `/share/v3/deliveries/authorize`. */
export const AUTHORIZATION_V3_KEYS = [
  "actions",
  "contentSource",
  "contentSourceDigestHex",
  "dataAuthority",
  "deliveryEmail",
  "documentName",
  "enforcementRootCid",
  "enforcerDid",
  "expiresAt",
  "holder",
  "idempotencyKey",
  "issuedAt",
  "jti",
  "nodeAudience",
  "openCredentialsAudience",
  "policyCid",
  "policyRootCid",
  "recipientMatcher",
  "reportAbuseToken",
  "requestBodyDigest",
  "resource",
  "returnOrigin",
  "senderDid",
  "senderTrust",
  "shareCid",
  "shareExpiresAt",
  "shareId",
  "shareUrl",
  "targetOrigin",
  "type",
  "version",
] as const;

const AUTHORIZATION_KEY_SET = new Set<string>(AUTHORIZATION_KEYS);
const AUTHORIZATION_V3_KEY_SET = new Set<string>(AUTHORIZATION_V3_KEYS);
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,256}$/;

/**
 * Every reason this service refuses to send. They are distinguishable on
 * purpose — an operator must be able to tell "you never provisioned the
 * trusted key" from "that authorization expired" from "you already sent
 * this" — with one deliberate exception: everything that would reveal
 * whether a particular key is enrolled collapses into `untrusted`, mirroring
 * the OpenCredentials witness's single generic `UntrustedNode`.
 */
export type RefusalReason =
  | "configuration-unavailable"
  | "malformed"
  | "untrusted"
  | "expired"
  | "share-url-invalid"
  | "replayed"
  | "in-flight"
  | "store-unavailable"
  | "provider-unavailable";

export interface Refusal {
  readonly ok: false;
  readonly reason: RefusalReason;
}

export const refuse = (reason: RefusalReason): Refusal => ({ ok: false, reason });

/** Exact mirror of `ShareDeliveryAuthorization` in `@tinycloud/sdk-core`. */
export interface DeliveryAuthorization {
  readonly type: "TinyCloudShareDeliveryAuthorization";
  readonly version: 2;
  readonly jti: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly registrationCid: string;
  readonly delegationCid: string;
  readonly enforcementDelegationCid: string;
  readonly envelopeCid: string;
  readonly policyCid: string;
  readonly nodeAudience: string;
  readonly targetOrigin: string;
  readonly openCredentialsAudience: string;
  readonly holder: string;
  readonly recipientMatcher: unknown;
  readonly deliveryEmail: string;
  readonly shareUrl: string;
  readonly returnOrigin: string;
  readonly documentName: string;
  readonly senderDid: string;
  readonly senderTrust: string;
  readonly contentSource: unknown;
  readonly contentSourceDigest: string;
  readonly shareExpiresAt: string;
  readonly issuedAt: string;
  readonly reportAbuseToken: string;
  readonly actions: readonly string[];
  readonly resource: string;
  readonly authorityMaterialHandle: string;
  readonly authorityMaterialDigest: string;
  readonly requestBodyDigest: string;
  readonly idempotencyKey: string;
  readonly expiresAt: string;
  readonly dataAuthority: false;
}

export interface DeliveryAuthorizationV3 {
  readonly type: "TinyCloudShareDeliveryAuthorization";
  readonly version: 3;
  readonly jti: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly policyRootCid: string;
  readonly enforcementRootCid: string;
  readonly nodeAudience: string;
  readonly enforcerDid: string;
  readonly targetOrigin: string;
  readonly openCredentialsAudience: string;
  readonly holder: string;
  readonly recipientMatcher: unknown;
  readonly deliveryEmail: string;
  readonly shareUrl: string;
  readonly returnOrigin: string;
  readonly documentName: string;
  readonly senderDid: string;
  readonly senderTrust: string;
  readonly contentSource: unknown;
  readonly contentSourceDigestHex: string;
  readonly shareExpiresAt: string;
  readonly issuedAt: string;
  readonly reportAbuseToken: string;
  readonly actions: readonly string[];
  readonly resource: string;
  readonly requestBodyDigest: string;
  readonly idempotencyKey: string;
  readonly expiresAt: string;
  readonly dataAuthority: false;
}

export type AnyDeliveryAuthorization = DeliveryAuthorization | DeliveryAuthorizationV3;

export interface DeliveryProof {
  readonly alg: "EdDSA";
  readonly kid: string;
  readonly signature: string;
}

/**
 * The request body. Identical in shape to what `src/share/main.ts` already
 * POSTs today, so wiring `notify` to this Worker is an origin swap and
 * nothing else.
 */
export interface DeliveryRequest {
  readonly authorization: AnyDeliveryAuthorization;
  readonly proof: DeliveryProof;
  readonly shareUrl: string;
}

/** Operator-configured trust. Every field is required; none has a default. */
export interface DeliveryTrust {
  /** The Node's enrolled invitation key id, e.g. `did:web:node.tinycloud.xyz#invitation-key-1`. */
  readonly nodeInvitationKid: string;
  /** Its raw 32-byte Ed25519 public key, base64url. */
  readonly nodeInvitationPublicKey: string;
  /** The Node's origin, e.g. `https://node.tinycloud.xyz`. */
  readonly nodeOrigin: string;
  /**
   * The audience the Node stamps into `openCredentialsAudience`. Checked
   * against configuration rather than against the authorization's own
   * `nodeAudience`/`returnOrigin`, exactly as
   * `validateShareDeliveryAuthorizationBytes` does, so a Node that mislabels
   * its audience fails closed here instead of silently inheriting an
   * unrelated identity.
   */
  readonly deliveryAudience: string;
  /** Share's own page origin, e.g. `https://share.tinycloud.xyz`. */
  readonly shareOrigin: string;
}

export interface VerifiedDelivery {
  readonly ok: true;
  readonly authorization: AnyDeliveryAuthorization;
  /** `${shareOrigin}/s/<cid>` — the URL with its secret fragment removed. */
  readonly shareUrlWithoutFragment: string;
}

const B64URL_16 = /^[A-Za-z0-9_-]{22}$/;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const B64URL_64 = /^[A-Za-z0-9_-]{86}$/;
const SHA256_RAW_CID = /^bafkrei[a-z2-7]{52}$/;
const BLAKE3_RAW_CID = /^bafkr4i[a-z2-7]{52}$/;
const DID_WEB_HOST = /^[A-Za-z0-9.-]+$/;
const EMAIL = /^[^@\s]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const DOMAIN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isCanonicalHttpsOrigin(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 253) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin === value && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}

function timestamp(value: unknown): number | null {
  if (typeof value !== "string" || !RFC3339.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/** Bounded, printable display name. Same 200-byte cap as the witness. */
function isDisplayName(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  if (new TextEncoder().encode(value).byteLength > 200) return false;
  // eslint-disable-next-line no-control-regex -- control characters are exactly what we reject
  return !/[\u0000-\u001f\u007f]/.test(value);
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (normalized.length % 4)) % 4;
  const decoded = atob(`${normalized}${"=".repeat(padding)}`);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

/**
 * The one share-URL shape this service will put in an email.
 *
 * The Node checks only that `shareUrl` is non-empty, so this is the boundary
 * that keeps an authorization from steering a recipient somewhere else. Same
 * grammar the OpenCredentials witness froze in `parse_share_url`: https, the
 * exact configured share origin, no userinfo, no port, no query, `/s/<cid>`,
 * and a fragment that is exactly `k=<43-char base64url>`.
 *
 * Inline links (`#v=2&p=…`) are refused: they carry the whole ciphertext in
 * the fragment, are unbounded in size, and the frozen claim contract never
 * accepted them either.
 */
export function parseShareUrl(raw: unknown, shareOrigin: string): { readonly cid: string } | null {
  if (typeof raw !== "string" || raw.length > 2048 || raw.includes("%")) return null;
  const afterOrigin = raw.startsWith(shareOrigin) ? raw.slice(shareOrigin.length) : null;
  if (afterOrigin === null || !afterOrigin.startsWith("/s/")) return null;
  const rest = afterOrigin.slice("/s/".length);
  const hash = rest.indexOf("#");
  if (hash < 0) return null;
  const path = rest.slice(0, hash);
  const fragment = rest.slice(hash + 1);
  if (path.includes("/") || path.includes("?") || !SHA256_RAW_CID.test(path)) return null;
  if (!fragment.startsWith("k=")) return null;
  const key = fragment.slice("k=".length);
  if (key.includes("&") || key.includes("=") || !B64URL_32.test(key)) return null;
  return { cid: path };
}

function matcherAdmits(matcher: unknown, email: string): boolean {
  if (!isPlainObject(matcher)) return false;
  const value = matcher.value;
  const local = email.slice(0, email.lastIndexOf("@"));
  const domain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
  if (matcher.kind === "exactEmail") {
    if (typeof value !== "string" || Object.keys(matcher).length !== 2) return false;
    const expectedDomain = value.slice(value.lastIndexOf("@") + 1).toLowerCase();
    const expectedLocal = value.slice(0, value.lastIndexOf("@"));
    return expectedLocal === local && expectedDomain === domain;
  }
  if (matcher.kind === "emailDomain") {
    if (typeof value !== "string" || Object.keys(matcher).length !== 2) return false;
    return DOMAIN.test(value.toLowerCase()) && value.toLowerCase() === domain;
  }
  // `bearer` and `policyDigest` shares are not addressed to a mailbox and so
  // can never authorize an email.
  return false;
}

/** Structural check only: is this the exact `{ authorization, proof, shareUrl }` envelope? */
export function parseDeliveryRequest(body: unknown): DeliveryRequest | null {
  if (!isPlainObject(body)) return null;
  if (Object.keys(body).sort().join(",") !== "authorization,proof,shareUrl") return null;
  const { authorization, proof, shareUrl } = body;
  if (!isPlainObject(authorization) || !isPlainObject(proof) || typeof shareUrl !== "string") return null;
  const keys = Object.keys(authorization);
  const expectedKeys = authorization.version === 3 ? AUTHORIZATION_V3_KEYS : AUTHORIZATION_KEYS;
  const expectedKeySet = authorization.version === 3 ? AUTHORIZATION_V3_KEY_SET : AUTHORIZATION_KEY_SET;
  if (keys.length !== expectedKeys.length || keys.some((key) => !expectedKeySet.has(key))) return null;
  if (Object.keys(proof).sort().join(",") !== "alg,kid,signature") return null;
  if (proof.alg !== "EdDSA" || typeof proof.kid !== "string" || typeof proof.signature !== "string") return null;
  if (!B64URL_64.test(proof.signature)) return null;
  return {
    authorization: authorization as unknown as AnyDeliveryAuthorization,
    proof: proof as unknown as DeliveryProof,
    shareUrl,
  };
}

/**
 * Verify the Node's proof, then every binding, then freshness — in that
 * order, and only in that order.
 *
 * Proof first: until the signature checks out we have no reason to believe
 * anything in the object, and answering "your audience is wrong" to an
 * unsigned blob would turn this endpoint into a configuration oracle. Once
 * the Node has vouched for the bytes, the remaining refusals are safe to
 * distinguish because only the Node could have produced them.
 */
export async function verifyDeliveryAuthorization(
  request: DeliveryRequest,
  trust: DeliveryTrust,
  now: number,
): Promise<VerifiedDelivery | Refusal> {
  if (
    !B64URL_32.test(trust.nodeInvitationPublicKey) ||
    trust.nodeInvitationKid.length === 0 ||
    !isCanonicalHttpsOrigin(trust.nodeOrigin) ||
    !isCanonicalHttpsOrigin(trust.deliveryAudience) ||
    !isCanonicalHttpsOrigin(trust.shareOrigin)
  ) {
    return refuse("configuration-unavailable");
  }

  const authorization = request.authorization as unknown as Record<string, unknown>;
  let preimage: ArrayBuffer;
  try {
    const domain = request.authorization.version === 3
      ? DELIVERY_AUTHORIZATION_V3_DOMAIN
      : DELIVERY_AUTHORIZATION_DOMAIN;
    preimage = new TextEncoder()
      .encode(`${domain}${canonicalize(authorization)}`)
      .slice().buffer as ArrayBuffer;
  } catch {
    // `canonicalize` throws on anything JSON/JCS cannot represent.
    return refuse("malformed");
  }

  let verified = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      base64UrlToBytes(trust.nodeInvitationPublicKey).slice().buffer as ArrayBuffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    verified =
      request.proof.kid === trust.nodeInvitationKid &&
      (await crypto.subtle.verify(
        "Ed25519",
        key,
        base64UrlToBytes(request.proof.signature).slice().buffer as ArrayBuffer,
        preimage,
      ));
  } catch {
    verified = false;
  }
  // One generic result for "not enrolled", "wrong key" and "bad signature",
  // so this seam cannot be used as an enrollment oracle.
  if (!verified) return refuse("untrusted");

  const nodeHost = new URL(trust.nodeOrigin).hostname;
  if (
    authorization.type !== "TinyCloudShareDeliveryAuthorization" ||
    (authorization.version !== 2 && authorization.version !== 3) ||
    authorization.dataAuthority !== false ||
    // Three audiences that must never be conflated, each pinned independently.
    authorization.openCredentialsAudience !== trust.deliveryAudience ||
    authorization.returnOrigin !== trust.shareOrigin ||
    authorization.targetOrigin !== trust.nodeOrigin ||
    authorization.nodeAudience !== `did:web:${nodeHost}` ||
    !DID_WEB_HOST.test(nodeHost) ||
    !trust.nodeInvitationKid.startsWith(`did:web:${nodeHost}#`)
  ) {
    return refuse("untrusted");
  }

  const { jti, idempotencyKey, reportAbuseToken, deliveryEmail } = authorization;
  if (
    typeof jti !== "string" ||
    !B64URL_16.test(jti) ||
    typeof idempotencyKey !== "string" ||
    !IDEMPOTENCY_KEY.test(idempotencyKey) ||
    reportAbuseToken !== jti ||
    typeof deliveryEmail !== "string" ||
    deliveryEmail.length > 254 ||
    !EMAIL.test(deliveryEmail) ||
    !matcherAdmits(authorization.recipientMatcher, deliveryEmail) ||
    !isDisplayName(authorization.documentName) ||
    typeof authorization.senderDid !== "string" ||
    authorization.senderDid.length === 0 ||
    (authorization.senderTrust !== "verified" && authorization.senderTrust !== "unverified") ||
    !SHA256_RAW_CID.test(String(authorization.shareCid)) ||
    (authorization.version === 2
      ? !B64URL_32.test(String(authorization.contentSourceDigest))
        || !B64URL_32.test(String(authorization.authorityMaterialDigest))
      : !/^[0-9a-f]{64}$/.test(String(authorization.contentSourceDigestHex))
        || !BLAKE3_RAW_CID.test(String(authorization.policyRootCid))
        || !BLAKE3_RAW_CID.test(String(authorization.enforcementRootCid))
        || typeof authorization.enforcerDid !== "string"
        || !authorization.enforcerDid.startsWith("did:")) ||
    !B64URL_32.test(String(authorization.requestBodyDigest)) ||
    !Array.isArray(authorization.actions) ||
    authorization.actions.length === 0
  ) {
    return refuse("malformed");
  }

  // The signed `shareUrl` and the transport-level one must agree, so a caller
  // cannot sign one link and deliver another.
  if (authorization.shareUrl !== request.shareUrl) return refuse("malformed");
  const parsed = parseShareUrl(request.shareUrl, trust.shareOrigin);
  if (parsed === null) return refuse("share-url-invalid");
  if (parsed.cid !== authorization.shareCid) return refuse("share-url-invalid");

  const expiresAt = timestamp(authorization.expiresAt);
  const issuedAt = timestamp(authorization.issuedAt);
  const shareExpiresAt = timestamp(authorization.shareExpiresAt);
  if (expiresAt === null || issuedAt === null || shareExpiresAt === null) return refuse("malformed");
  if (
    expiresAt <= now ||
    expiresAt > now + MAX_AUTHORIZATION_TTL_MS ||
    issuedAt > now + CLOCK_SKEW_MS ||
    shareExpiresAt <= now
  ) {
    return refuse("expired");
  }

  return {
    ok: true,
    authorization: request.authorization,
    shareUrlWithoutFragment: `${trust.shareOrigin}/s/${parsed.cid}`,
  };
}

/**
 * SHA-256, base64url. Used to record WHICH mailbox a delivery went to
 * without storing the address itself.
 */
export async function digest(value: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
