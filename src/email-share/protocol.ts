import {
  canonicalize,
  computeCid,
  didKeyFromEd25519PublicKey,
  ENVELOPE_SIGNATURE_DOMAIN,
  encodeShareUrl,
  fromBase64Url,
  generateKey,
  seal,
  shareEnvelopeSchema,
  toBase64Url,
  type ShareEnvelope,
  type UnsignedShareEnvelope,
  unsignedShareEnvelopeSchema,
} from "@tinycloud/share-envelope";

export const PROTOCOL = "tinycloud.share-email-claim/v1" as const;
export const MARKDOWN_LIMIT = 1_048_576;
export const MAX_SQL_ARGUMENTS = 32;
export const INVITATION_AUTHORIZATION_TTL_SECONDS = 300;
export const MAGIC_TOKEN_TTL_SECONDS = 604_800;
export const OTP_TTL_SECONDS = 600;
export const MAX_ACCESS_TTL_SECONDS = 2_592_000;

export const SIGNATURE_DOMAINS = Object.freeze({
  envelope: ENVELOPE_SIGNATURE_DOMAIN,
  inviteAuthorization: "xyz.tinycloud.share/invite-authorization/v1\0",
  holderBinding: "xyz.tinycloud.share/email-claim-holder-binding/v1\0",
  policyChallenge: "xyz.tinycloud.share/policy-challenge/v1\0",
  policyPresentation: "xyz.tinycloud.share/policy-presentation/v1\0",
  policySession: "xyz.tinycloud.share/policy-session/v1\0",
  readInvocation: "xyz.tinycloud.share/read-invocation/v1\0",
  readResponse: "xyz.tinycloud.share/read-response/v1\0",
} as const);

export type ShareAction = "tinycloud.kv/get" | "tinycloud.sql/read";

export interface KvSource {
  readonly kind: "kv";
  readonly space: string;
  readonly path: string;
  readonly action: "tinycloud.kv/get";
}

export interface NamedSqlSource {
  readonly kind: "sql";
  readonly space: string;
  readonly database: string;
  readonly path: string;
  readonly statement: string;
  readonly arguments: Readonly<Record<string, number>>;
  readonly argumentsDigest: string;
  readonly action: "tinycloud.sql/read";
}

export type ContentSource = KvSource | NamedSqlSource;

export interface SenderScope {
  /** Authenticated Node #117 policy owner; deliberately distinct from senderDid. */
  readonly policyOwnerDid: string;
  readonly senderDid: string;
  /** Opaque capability metadata; signing remains in the authenticated host. */
  readonly signingCapability: SenderSigningCapability;
  readonly signer: SenderSigner;
  readonly shareOrigin: string;
  readonly delegation: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: "amh_kv_001" | "amh_sql_001";
  readonly authorityMaterialDigest: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly spaceId: string;
  readonly documentName: string;
  readonly senderTrust: "verified" | "unverified";
  /** Server-derived bounds for the sender's selectable access expiry. */
  readonly expiryMin?: string;
  readonly expiryMax?: string;
  readonly expiryDefault?: string;
  /** Legacy-compatible upper bound emitted by existing capability providers. */
  readonly expiresAt?: string;
  readonly trustedNode: TrustedNode;
  /** The authenticated authority bundle supplied by the host, never user input. */
  readonly authorityMaterial: Readonly<Record<string, unknown>>;
}

export interface SenderSigningCapability {
  readonly capabilityId: string;
  readonly publicKey: Uint8Array;
}

export interface SenderSigner {
  readonly publicKey: Uint8Array;
  sign(input: { readonly purpose: "envelope" | "inviteAuthorization"; readonly message: string; readonly binding: Record<string, unknown> }): Promise<Uint8Array>;
}

export interface TrustedNode {
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly invitationKid: string;
  readonly invitationPublicKey: Uint8Array;
  readonly keyVersion: number;
  readonly enabled: boolean;
}

export interface InvitationDraft {
  readonly email: string;
  readonly source: ContentSource;
  readonly sourceDigest: string;
  readonly policyCid: string;
  readonly policyBytes: string;
  readonly envelope: ShareEnvelope;
  readonly shareCid: string;
  readonly shareUrl: string;
  readonly invitationJti: string;
  readonly reportAbuseToken: string;
}

export interface AuthoritativePolicyMaterial {
  readonly policyCid: string;
  readonly policyBytes: string;
  readonly policyDigest: string;
  /** CIDs of the two owner-signed Node parent delegations bound to this policy. */
  readonly policyAuthorityCid: string;
  readonly policyAuthorityBytes: string;
  readonly policyEnforcementCid: string;
  readonly policyEnforcementBytes: string;
}

export interface SignedProof {
  readonly alg: "EdDSA";
  readonly kid: string;
  readonly signature: string;
}

export interface SignedArtifact {
  readonly name: string;
  readonly domain: string;
  readonly signerDid: string;
  readonly message: Record<string, unknown>;
  readonly jcs: string;
  readonly messageDigest: string;
  readonly signedBytesDigest: string;
  readonly signatureDigest: string;
  readonly signature: {
    readonly alg: "EdDSA";
    readonly kid: string;
    readonly value: string;
  };
}

export interface InvitationAuthorization {
  readonly type: "TinyCloudShareInviteAuthorization";
  readonly version: 1;
  readonly jti: string;
  readonly senderDid: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: string;
  readonly authorityMaterialDigest: string;
  readonly recipientEmail: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly returnOrigin: string;
  readonly documentName: string;
  readonly senderTrust: "verified" | "unverified";
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly shareExpiresAt: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly reportAbuseToken: string;
}

export interface AuthorizedInvitation {
  readonly authorization: InvitationAuthorization;
  readonly proof: SignedProof;
}

export function boundedExpiry(input: { readonly issuedAt: string; readonly accessExpiresAt: string; readonly ttlSeconds: number }): string {
  const issuedAt = Date.parse(input.issuedAt);
  const accessExpiresAt = Date.parse(input.accessExpiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(accessExpiresAt) || accessExpiresAt <= issuedAt || input.ttlSeconds <= 0) {
    throw new TypeError("Invalid expiry equation.");
  }
  return new Date(Math.min(accessExpiresAt, issuedAt + input.ttlSeconds * 1000)).toISOString();
}

export function invitationAuthorizationExpiry(issuedAt: string, accessExpiresAt: string): string {
  return boundedExpiry({ issuedAt, accessExpiresAt, ttlSeconds: INVITATION_AUTHORIZATION_TTL_SECONDS });
}

export function magicTokenExpiry(issuedAt: string, accessExpiresAt: string): string {
  return boundedExpiry({ issuedAt, accessExpiresAt, ttlSeconds: MAGIC_TOKEN_TTL_SECONDS });
}

export function otpExpiry(issuedAt: string, accessExpiresAt: string): string {
  return boundedExpiry({ issuedAt, accessExpiresAt, ttlSeconds: OTP_TTL_SECONDS });
}

export function canonicalEmail(value: string): string {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length < 3 || bytes.length > 254 || !/^[\x00-\x7f]*$/.test(value)) {
    throw new TypeError("Enter a valid email address.");
  }
  const at = value.indexOf("@");
  if (at <= 0 || at !== value.lastIndexOf("@")) throw new TypeError("Enter a valid email address.");
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  const atext = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$/;
  if (new TextEncoder().encode(local).length > 64 || local.split(".").some((part) => !atext.test(part))) {
    throw new TypeError("Enter a valid email address.");
  }
  if (new TextEncoder().encode(domain).length > 253 || domain.split(".").some((label) =>
    label.length === 0 || label.length > 63 || label.startsWith("-") || label.endsWith("-") || !/^[A-Za-z0-9-]+$/.test(label))) {
    throw new TypeError("Enter a valid email address.");
  }
  return `${local}@${domain.toLowerCase()}`;
}

export function canonicalPath(value: string): string {
  if (!value || /[\u0000-\u001f\u007f\\]/.test(value) || /%2f|%5c|%2e/i.test(value) ||
    value.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new TypeError("Choose a concrete resource path.");
  }
  return value;
}

function assertSafeArguments(args: Readonly<Record<string, number>>): void {
  const keys = Object.keys(args);
  if (keys.length > MAX_SQL_ARGUMENTS || keys.some((key) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) ||
    Object.values(args).some((value) => !Number.isSafeInteger(value) || Object.is(value, -0))) {
    throw new TypeError("Named SQL parameters must be safe integer values.");
  }
}

export function validateSource(source: ContentSource): ContentSource {
  if (source.kind === "kv") {
    return Object.freeze({ ...source, path: canonicalPath(source.path) });
  }
  if (!source.database || !source.statement || !source.path) throw new TypeError("Choose a named SQL source.");
  assertSafeArguments(source.arguments);
  return Object.freeze({ ...source, path: canonicalPath(source.path), arguments: { ...source.arguments } });
}

async function sha256Digest(bytes: Uint8Array): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer)));
}

export async function canonicalDigest(value: unknown): Promise<string> {
  return sha256Digest(new TextEncoder().encode(canonicalize(value)));
}

export async function sourceDigest(source: ContentSource): Promise<string> {
  return canonicalDigest(validateSource(source));
}

export async function createInvitationDraft(input: {
  readonly email: string;
  readonly source: ContentSource;
  readonly scope: SenderScope;
  readonly shareId: string;
  readonly expiresAt: string;
  readonly policy: AuthoritativePolicyMaterial;
  readonly uploadEnvelope: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void>;
  readonly now?: string;
}): Promise<InvitationDraft> {
  const email = canonicalEmail(input.email);
  const issuedAt = input.now ?? new Date().toISOString();
  const issuedTime = Date.parse(issuedAt);
  const accessExpiry = Date.parse(input.expiresAt);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(issuedAt) || !Number.isFinite(issuedTime) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(input.expiresAt) || !Number.isFinite(accessExpiry) ||
      accessExpiry <= issuedTime || accessExpiry - issuedTime > MAX_ACCESS_TTL_SECONDS * 1000) {
    throw new TypeError("Choose an access expiry within the allowed policy window.");
  }
  const validated = validateSource(input.source);
  const source: ContentSource = validated.kind === "sql"
    ? { ...validated, argumentsDigest: await canonicalDigest(validated.arguments) }
    : validated;
  if (input.scope.spaceId !== source.space) throw new TypeError("The selected resource is outside the authorized space.");
  const target = new URL(input.scope.targetOrigin);
  if (target.protocol !== "https:" || target.origin !== input.scope.targetOrigin) throw new TypeError("The selected node origin is not trusted.");
  if (!input.scope.policyOwnerDid.startsWith("did:pkh:") || input.scope.policyOwnerDid === input.scope.senderDid) throw new TypeError("Policy owner and invitation sender must be distinct trusted identities.");
  if (source.kind === "kv" && input.scope.authorityMaterialHandle !== "amh_kv_001") throw new TypeError("KV authority material is required.");
  if (source.kind === "sql" && input.scope.authorityMaterialHandle !== "amh_sql_001") throw new TypeError("SQL authority material is required.");
  if (input.scope.documentName.length === 0 || new TextEncoder().encode(input.scope.documentName).length > 200) throw new TypeError("Document name is too long.");
  if (input.policy === undefined) throw new TypeError("An already-created authoritative policy is required.");
  const digest = await sourceDigest(source);
  const policyBytes = input.policy.policyBytes;
  if (typeof policyBytes !== "string" || typeof input.policy.policyCid !== "string" || typeof input.policy.policyDigest !== "string" ||
      typeof input.policy.policyAuthorityCid !== "string" || typeof input.policy.policyAuthorityBytes !== "string" ||
      typeof input.policy.policyEnforcementCid !== "string" || typeof input.policy.policyEnforcementBytes !== "string") {
    throw new TypeError("The authoritative policy material is incomplete.");
  }
  try {
    const policyRaw = fromBase64Url(policyBytes);
    const policyText = new TextDecoder("utf-8", { fatal: true }).decode(policyRaw);
    if (canonicalize(JSON.parse(policyText)) !== policyText || await computeCid(policyRaw) !== input.policy.policyCid ||
        await canonicalDigest(JSON.parse(policyText)) !== input.policy.policyDigest) throw new Error("policy binding");
  } catch {
    throw new TypeError("The authoritative policy bytes are not canonical or do not match their identifiers.");
  }
  const envelopeKey = generateKey();
  const unsigned: UnsignedShareEnvelope = {
    version: 1,
    shareId: input.shareId,
    delegation: input.scope.delegation,
    authorizationTarget: { kind: "policy", policyCid: input.policy.policyCid, policyBytes },
    target: {
      origin: input.scope.targetOrigin,
      nodeAudience: input.scope.nodeAudience,
      spaceId: input.scope.spaceId,
      resource: { kind: "exact", path: source.path },
    },
    display: { senderName: "TinyCloud sender", filename: input.scope.documentName, recipientHint: `${email.slice(0, 1)}***@${email.split("@")[1]}` },
    expiry: input.expiresAt,
  };
  unsignedShareEnvelopeSchema.parse(unsigned);
  const signature = await input.scope.signer.sign({
    purpose: "envelope",
    message: canonicalize(unsigned),
    binding: {
      shareId: input.shareId, recipientEmail: email, action: source.action, resource: source.path, expiresAt: input.expiresAt,
      policyCid: input.policy.policyCid, policyDigest: input.policy.policyDigest,
      policyAuthorityCid: input.policy.policyAuthorityCid, policyAuthorityBytes: input.policy.policyAuthorityBytes,
      policyEnforcementCid: input.policy.policyEnforcementCid, policyEnforcementBytes: input.policy.policyEnforcementBytes,
      delegation: input.scope.delegation, targetOrigin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience,
      returnOrigin: input.scope.shareOrigin,
    },
  });
  if (signature.length !== 64) throw new TypeError("Sender signer returned an invalid envelope signature.");
  const signerDid = didKeyFromEd25519PublicKey(input.scope.signingCapability.publicKey);
  const envelope: ShareEnvelope = {
    ...unsigned,
    signature: { signerDid, algorithm: "Ed25519", value: toBase64Url(signature) },
  };
  const sealed = await seal(new Uint8Array(new TextEncoder().encode(canonicalize(envelope))), envelopeKey);
  await input.uploadEnvelope(sealed.cid, sealed.blob, input.expiresAt);
  const jti = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const reportAbuseToken = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const shareUrl = encodeShareUrl({ origin: input.scope.shareOrigin, ciphertextCid: sealed.cid, key32: envelopeKey });
  envelopeKey.fill(0);
  return { email, source, sourceDigest: digest, policyCid: input.policy.policyCid, policyBytes, envelope, shareCid: sealed.cid, shareUrl, invitationJti: jti, reportAbuseToken };
}

export async function signedInvitationProof(
  draft: InvitationDraft,
  scope: SenderScope,
): Promise<{ request: Record<string, unknown>; proof: SignedProof }> {
  const requestBody = {
    shareCid: draft.shareCid,
    shareId: draft.envelope.shareId,
    policyCid: draft.policyCid,
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
    recipientEmail: draft.email,
    targetOrigin: scope.targetOrigin,
    nodeAudience: scope.nodeAudience,
    action: draft.source.action,
    resource: draft.source.path,
  } as const;
  const request = {
    jti: draft.invitationJti,
    reportAbuseToken: draft.reportAbuseToken,
    senderDid: scope.senderDid,
    shareCid: draft.shareCid,
    shareId: draft.envelope.shareId,
    delegationCid: scope.delegationCid,
    policyCid: draft.policyCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
    recipientEmail: draft.email,
    targetOrigin: scope.targetOrigin,
    nodeAudience: scope.nodeAudience,
    documentName: scope.documentName,
    senderTrust: scope.senderTrust,
    contentSource: draft.source,
    contentSourceDigest: draft.sourceDigest,
    shareExpiresAt: draft.envelope.expiry,
    requestBodyDigest: await canonicalDigest(requestBody),
  };
  const signerDid = didKeyFromEd25519PublicKey(scope.signingCapability.publicKey);
  if (signerDid !== scope.senderDid) throw new TypeError("Sender proof key does not match the authorized sender.");
  const signature = await scope.signer.sign({
    purpose: "inviteAuthorization",
    message: canonicalize(request),
    binding: {
      ...request,
      expiresAt: request.shareExpiresAt,
      policyDigest: await canonicalDigest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(draft.policyBytes)))),
      policyAuthorityCid: scope.authorityMaterial.policyAuthorityCid,
      policyAuthorityBytes: scope.authorityMaterial.policyAuthorityBytes,
      policyEnforcementCid: scope.authorityMaterial.policyEnforcementCid,
      policyEnforcementBytes: scope.authorityMaterial.policyEnforcementBytes,
    },
  });
  if (signature.length !== 64) throw new TypeError("Sender signer returned an invalid authorization signature.");
  return { request, proof: { alg: "EdDSA", kid: `${signerDid}#${signerDid.slice("did:key:".length)}`, signature: toBase64Url(signature) } };
}
