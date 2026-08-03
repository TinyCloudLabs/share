import {
  canonicalize,
  computeCid,
  fromBase64Url,
  toBase64Url,
  shareEnvelopeV2Schema,
  shareEnvelopeV3Schema,
  verifyEnvelopeV2,
  verifyEnvelopeV3,
  ed25519PublicKeyFromDidKey,
  signCompactUcanAuthorization,
  verifyCompactUcanAuthorization,
  type ShareEnvelopeV2,
  type ShareEnvelopeV3,
  type ShareAction,
  type ResourceSelector,
} from "@tinycloud/share-envelope";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { assertNodeTime, digest, digestBytes, digestText, verifyNodeProof } from "../../../src/email-share/node-verifier.js";
import { SIGNATURE_DOMAINS, type SignedProof, type TrustedNode } from "../../../src/email-share/protocol.js";

export function normalizeExactEmail(value: string): string {
  const at = value.indexOf("@");
  if (at <= 0 || at !== value.lastIndexOf("@")) throw new TypeError("email");
  const local = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();
  if (!/^[^@\s]+$/.test(local) || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(domain)) throw new TypeError("email");
  return `${local}@${domain}`;
}

function resourceCovers(outer: ResourceSelector, inner: ResourceSelector): boolean {
  const outerPath = outer.kind === "prefix" ? outer.path.replace(/\/$/, "") : outer.path;
  const innerPath = inner.kind === "prefix" ? inner.path.replace(/\/$/, "") : inner.path;
  if (outer.kind === "exact") return inner.kind === "exact" && outerPath === innerPath;
  return innerPath === outerPath || innerPath.startsWith(`${outerPath}/`);
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalHashHex(value: string): string {
  return hex(sha256(new TextEncoder().encode(canonicalize(value))));
}

async function aesGcmDecrypt(key: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 32 || blob.length < 28) throw new Error("encrypted content is malformed");
  const cryptoKey = await crypto.subtle.importKey("raw", key as unknown as BufferSource, "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) as unknown as BufferSource }, cryptoKey, blob.slice(12) as unknown as BufferSource));
}

async function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 32) throw new Error("encrypted content key is malformed");
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", key as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as unknown as BufferSource }, cryptoKey, plaintext as unknown as BufferSource));
  const output = new Uint8Array(nonce.length + ciphertext.length);
  output.set(nonce);
  output.set(ciphertext, nonce.length);
  return output;
}

interface V3InlineEncryptedEnvelope {
  readonly v: 1;
  readonly networkId: string;
  readonly alg: "x25519-aes256gcm/v1";
  readonly keyVersion: number;
  readonly encryptedSymmetricKey: string;
  readonly encryptedSymmetricKeyHash: string;
  readonly ciphertext: string;
  readonly metadata?: Readonly<Record<string, string>>;
}

function parseV3InlineEncryptedEnvelope(bytes: Uint8Array, expected: ShareEnvelopeV3): V3InlineEncryptedEnvelope {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new Error("encrypted content envelope is malformed"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("encrypted content envelope is malformed");
  const object = value as Record<string, unknown>;
  const allowed = ["v", "networkId", "alg", "keyVersion", "encryptedSymmetricKey", "encryptedSymmetricKeyHash", "ciphertext", "metadata"];
  if (Object.keys(object).some((key) => !allowed.includes(key))
    || object.v !== 1 || object.networkId !== expected.encryptionNetwork
    || object.alg !== "x25519-aes256gcm/v1" || object.keyVersion !== expected.contentSource.keyVersion
    || typeof object.encryptedSymmetricKey !== "string" || typeof object.encryptedSymmetricKeyHash !== "string"
    || object.encryptedSymmetricKeyHash !== expected.contentSource.encryptedSymmetricKeyDigestHex
    || object.encryptedSymmetricKeyHash !== canonicalHashHex(object.encryptedSymmetricKey)
    || typeof object.ciphertext !== "string"
    || object.metadata !== undefined && (object.metadata === null || typeof object.metadata !== "object" || Array.isArray(object.metadata) || Object.values(object.metadata).some((entry) => typeof entry !== "string"))) {
    throw new Error("encrypted content envelope binding is invalid");
  }
  return object as unknown as V3InlineEncryptedEnvelope;
}

export interface ParsedAddressedEnvelope {
  readonly envelope: ShareEnvelopeV2 | ShareEnvelopeV3;
  readonly policy: Record<string, unknown>;
  readonly policyCid: string;
}

export async function parseAddressedEnvelope(value: unknown): Promise<ParsedAddressedEnvelope> {
  if (typeof value === "object" && value !== null && !Array.isArray(value) && (value as Record<string, unknown>).version === 3) {
    const envelope = shareEnvelopeV3Schema.parse(value);
    if (envelope.policyCid.length === 0) throw new TypeError("v3 policy CID");
    if (envelope.policy.signature.signerDid !== envelope.policy.ownerDid) throw new TypeError("v3 policy signer");
    if (await computeCid(new TextEncoder().encode(canonicalize(envelope.policy))) !== envelope.policyCid) throw new TypeError("v3 policy CID");
    const { signature: policySignature, ...unsignedPolicyWithId } = envelope.policy;
    const unsignedPolicy = { ...unsignedPolicyWithId } as Record<string, unknown>;
    delete unsignedPolicy.policyId;
    const policySignatureBytes = fromBase64Url(policySignature.value);
    const policyDigest = sha256(new TextEncoder().encode(`xyz.tinycloud.policy/policy/v1\0${canonicalize(unsignedPolicy)}`));
    if (policySignatureBytes.length !== 64 || !ed25519.verify(policySignatureBytes, policyDigest, ed25519PublicKeyFromDidKey(policySignature.signerDid), { zip215: false })) throw new TypeError("v3 policy signature");
    if (!await verifyEnvelopeV3(envelope, { expectedSignerDid: envelope.policy.ownerDid })) throw new TypeError("v3 envelope signature");
    return { envelope, policy: envelope.policy as unknown as Record<string, unknown>, policyCid: envelope.policyCid };
  }
  const envelope = shareEnvelopeV2Schema.parse(value);
  if (envelope.authorizationTarget.kind !== "policy") throw new TypeError("addressed envelope target");
  const policyBytes = fromBase64Url(envelope.authorizationTarget.policyBytes);
  if (toBase64Url(policyBytes) !== envelope.authorizationTarget.policyBytes) throw new TypeError("addressed policy encoding");
  if (await computeCid(policyBytes) !== envelope.authorizationTarget.policyCid) throw new TypeError("addressed policy CID");
  let policy: Record<string, unknown>;
  try {
    const decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(policyBytes)) as unknown;
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) throw new Error("policy");
    policy = decoded as Record<string, unknown>;
  } catch { throw new TypeError("addressed policy bytes"); }
  const ownerRoot = policy.domain === "xyz.tinycloud.share/policy/v2\0" && typeof policy.policy === "object" && policy.policy !== null && !Array.isArray(policy.policy) ? policy.policy as Record<string, unknown> : undefined;
  if (ownerRoot !== undefined) {
    const ownerPolicy = ownerRoot as { readonly shareKeyDid: string; readonly shareId: string; readonly target: Record<string, unknown>; readonly resource: Record<string, unknown>; readonly actions: readonly string[]; readonly contentSource: Record<string, unknown>; readonly contentSourceDigest: string; readonly expiresAt: string };
    const authority = (envelope as unknown as Record<string, unknown>).ownerAuthority;
    if (typeof authority !== "object" || authority === null || Array.isArray(authority)) throw new TypeError("owner authority");
    const ownerAuthority = authority as Record<string, unknown>;
    const outer = ownerAuthority.outerEnvelope;
    const enforcement = ownerAuthority.enforcementDelegation;
    if (typeof outer !== "object" || outer === null || Array.isArray(outer) || typeof enforcement !== "object" || enforcement === null || Array.isArray(enforcement)) throw new TypeError("owner authority");
    const outerRecord = outer as Record<string, unknown>;
    const outerSignature = outerRecord.signature;
    if (typeof outerSignature !== "object" || outerSignature === null || Array.isArray(outerSignature)) throw new TypeError("owner envelope signature");
    const signature = outerSignature as Record<string, unknown>;
    const { signature: _signature, ...outerUnsigned } = outerRecord;
    if (outerRecord.schema !== "xyz.tinycloud.share/envelope/v2" || outerRecord.version !== 2 || signature.algorithm !== "Ed25519" || signature.signerDid !== ownerPolicy.shareKeyDid || ownerAuthority.shareCid !== outerRecord.shareCid || ownerAuthority.envelopeCid !== outerRecord.envelopeCid || ownerAuthority.registrationCid === outerRecord.envelopeCid || outerRecord.shareCid === outerRecord.envelopeCid || outerRecord.shareId !== ownerPolicy.shareId || outerRecord.policyCid !== envelope.authorizationTarget.policyCid || canonicalize(outerRecord.target) !== canonicalize(ownerPolicy.target) || canonicalize(outerRecord.resource) !== canonicalize(ownerPolicy.resource) || canonicalize(outerRecord.actions) !== canonicalize(ownerPolicy.actions) || canonicalize(outerRecord.contentSource) !== canonicalize(ownerPolicy.contentSource) || outerRecord.contentSourceDigest !== ownerPolicy.contentSourceDigest || outerRecord.expiresAt !== ownerPolicy.expiresAt) throw new TypeError("owner authority binding");
    const key = ed25519PublicKeyFromDidKey(ownerPolicy.shareKeyDid);
    const outerSignatureBytes = fromBase64Url(String(signature.value));
    if (outerSignatureBytes.length !== 64 || !ed25519.verify(outerSignatureBytes, new TextEncoder().encode(`xyz.tinycloud.share/envelope/v2\0${canonicalize(outerUnsigned)}`), key)) throw new TypeError("owner envelope signature");
    if (!await verifyEnvelopeV2(envelope, { expectedSignerDid: ownerPolicy.shareKeyDid })) throw new TypeError("addressed envelope signature");
    return { envelope, policy: ownerRoot, policyCid: envelope.authorizationTarget.policyCid };
  }
  const keys = ["type", "version", "issuerDid", "recipientMatcher", "contentSource", "contentSourceDigest", "resource", "actions", "expiresAt"];
  if (Object.keys(policy).some((key) => !keys.includes(key)) || keys.some((key) => !Object.hasOwn(policy, key)) || policy.type !== "TinyCloudSharePolicy" || policy.version !== 2 || typeof policy.issuerDid !== "string" || canonicalize(policy) !== new TextDecoder("utf-8", { fatal: true }).decode(policyBytes) || typeof policy.resource !== "object" || policy.resource === null || Array.isArray(policy.resource) || typeof policy.contentSource !== "object" || policy.contentSource === null || Array.isArray(policy.contentSource) || !Array.isArray(policy.actions) || typeof policy.contentSourceDigest !== "string" || typeof policy.expiresAt !== "string") throw new TypeError("addressed policy scope");
  const policyResource = policy.resource as Record<string, unknown>;
  const expectedResource = { kind: envelope.resource.kind, value: envelope.resource.path.replace(/\/$/, "") };
  const policyActions = policy.actions;
  const expectedActions = envelope.actions.map(nativeAction);
  const policyMatcherBound = envelope.recipientMatcher.kind === "policyDigest"
    ? envelope.recipientMatcher.value === await digestBytes(policyBytes) && typeof policy.recipientMatcher === "object"
    : canonicalize(policy.recipientMatcher) === canonicalize(envelope.recipientMatcher);
  if (!policyMatcherBound || canonicalize(policyResource) !== canonicalize(expectedResource) || canonicalize(policy.contentSource) !== canonicalize(envelope.contentSource) || policy.contentSourceDigest !== envelope.contentSourceDigest || canonicalize(policyActions) !== canonicalize(expectedActions) || policy.expiresAt !== envelope.expiry || envelope.delegationCid.length === 0 || envelope.authorityMaterialDigest.length !== 43) throw new TypeError("addressed policy attenuation");
  if (!await verifyEnvelopeV2(envelope, { expectedSignerDid: policy.issuerDid })) throw new TypeError("addressed envelope signature");
  return { envelope, policy, policyCid: envelope.authorizationTarget.policyCid };
}

export interface PolicyChallenge {
  readonly type: string;
  readonly version: number;
  readonly challengeId: string;
  readonly nonce: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly delegationCid: string;
  readonly authorityMaterialDigest: string;
  readonly contentSource: Record<string, unknown>;
  readonly contentSourceDigest: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly actions: readonly ShareAction[];
  readonly resource: string;
  readonly requestBodyDigest: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly enforcerDid: string;
  readonly [key: string]: unknown;
}

export interface PolicySession {
  readonly type: string;
  readonly version: number;
  readonly sessionId: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly holderDid: string;
  readonly actions: readonly ShareAction[];
  readonly resource: ResourceSelector;
  readonly expiresAt: string;
  readonly [key: string]: unknown;
}

export interface PolicyPresentationMaterial {
  readonly holderDid: string;
  readonly credential: string;
  readonly credentialDigest?: string;
  readonly holderBinding: Record<string, unknown>;
  readonly proof: Record<string, unknown>;
  readonly email?: string;
  readonly sign?: (bytes: Uint8Array) => Promise<Uint8Array>;
  /** v3 ceremony output: an ordinary policy-session UCAN Authorization. */
  readonly authorization?: string;
  readonly claim?: Record<string, unknown>;
  readonly presentation?: Record<string, unknown>;
}

export interface ShareRecipientClientOptions {
  readonly nodeOrigin: string;
  readonly fetchFn?: typeof fetch;
  readonly envelope: ShareEnvelopeV2 | ShareEnvelopeV3;
  readonly shareCid: string;
  readonly trustedNode: TrustedNode;
  readonly holderDid: string;
  readonly buildPresentation: (input: { readonly challenge: PolicyChallenge; readonly envelope: ShareEnvelopeV2 | ShareEnvelopeV3; readonly policy: Record<string, unknown> }) => Promise<PolicyPresentationMaterial | Record<string, unknown>>;
}

type NativeAction = "tinycloud.kv/get" | "tinycloud.kv/metadata" | "tinycloud.kv/list" | "tinycloud.kv/put" | "tinycloud.encryption/decrypt";

function nativeAction(value: ShareAction): NativeAction {
  if (value === "read") return "tinycloud.kv/get";
  if (value === "list") return "tinycloud.kv/list";
  return "tinycloud.kv/put";
}

function requestedNativeAction(value: unknown): NativeAction {
  if (value === "tinycloud.encryption/decrypt" || value === "decrypt") return "tinycloud.encryption/decrypt";
  if (value === "metadata" || value === "tinycloud.kv/metadata") return "tinycloud.kv/metadata";
  if (value === "list" || value === "tinycloud.kv/list") return "tinycloud.kv/list";
  if (value === "put" || value === "tinycloud.kv/put") return "tinycloud.kv/put";
  return "tinycloud.kv/get";
}

function uiAction(value: unknown): ShareAction {
  if (value === "tinycloud.kv/list") return "list";
  if (value === "tinycloud.kv/put") return "edit";
  return "read";
}

function isPresentationMaterial(value: PolicyPresentationMaterial | Record<string, unknown>): value is PolicyPresentationMaterial {
  return typeof value === "object" && value !== null && typeof (value as Record<string, unknown>).holderDid === "string" && typeof (value as Record<string, unknown>).credential === "string" && typeof (value as Record<string, unknown>).holderBinding === "object" && typeof (value as Record<string, unknown>).proof === "object";
}

function exactWrapped(value: unknown, key: "challenge" | "session"): { readonly artifact: Record<string, unknown>; readonly proof: SignedProof } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`policy ${key} response is not wrapped`);
  const outer = value as Record<string, unknown>;
  if (Object.keys(outer).length !== 2 || typeof outer[key] !== "object" || outer[key] === null || typeof outer.proof !== "object" || outer.proof === null) throw new Error(`policy ${key} response is not wrapped`);
  return { artifact: outer[key] as Record<string, unknown>, proof: outer.proof as SignedProof };
}

async function rejectPolicyResponse(response: Response, stage: "challenge" | "session"): Promise<never> {
  let code = "unknown";
  try {
    const value = await response.clone().json() as unknown;
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      const error = (value as Record<string, unknown>).error;
      if (typeof error === "object" && error !== null && !Array.isArray(error) && typeof (error as Record<string, unknown>).code === "string") code = String((error as Record<string, unknown>).code);
    }
  } catch {
    // Keep the client error sanitized when an upstream response is malformed.
  }
  throw new Error(`policy ${stage} rejected (${response.status}:${code})`);
}

export class ShareRecipientClient {
  private readonly fetchFn: typeof fetch;
  private verified?: ParsedAddressedEnvelope;
  private session?: PolicySession;
  private holderProof?: Record<string, unknown>;
  private nativeSigner: ((bytes: Uint8Array) => Promise<Uint8Array>) | undefined;
  private v3Authorization: string | undefined;
  private v3ContentKey: Uint8Array | undefined;
  private v3ContentEnvelope: V3InlineEncryptedEnvelope | undefined;

  constructor(private readonly options: ShareRecipientClientOptions) {
    this.fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  async establishPolicySession(): Promise<PolicySession> {
    this.verified ??= await parseAddressedEnvelope(this.options.envelope);
    const envelope = this.options.envelope;
    if (envelope.version === 3) return this.establishPolicySessionV3(envelope);
    const ownerAuthority = envelope.ownerAuthority;
    if (ownerAuthority !== undefined) {
      const outer = ownerAuthority.outerEnvelope as Record<string, unknown>;
      const enforcement = ownerAuthority.enforcementDelegation as Record<string, unknown>;
      const target = outer.target as Record<string, unknown>;
      const outerResource = outer.resource as Record<string, unknown>;
      const source = outer.contentSource as Record<string, unknown>;
      const ownerShareCid = ownerAuthority.shareCid;
      const action = envelope.actions.includes("list") ? "tinycloud.kv/list" : envelope.actions.includes("edit") ? "tinycloud.kv/put" : "tinycloud.kv/get";
      const actions = [...new Set(envelope.actions.map(nativeAction))].sort();
      const challengeBody = {
        envelopeCid: ownerAuthority.envelopeCid,
        shareCid: ownerShareCid,
        shareId: envelope.shareId,
        registrationCid: ownerAuthority.registrationCid,
        delegationCid: envelope.delegationCid,
        policyCid: envelope.authorizationTarget.kind === "policy" ? envelope.authorizationTarget.policyCid : "",
        enforcementDelegationCid: String(enforcement.cid),
        enforcementDelegation: enforcement,
        outerEnvelope: outer,
        contentSource: source,
        contentSourceDigest: String(outer.contentSourceDigest),
        holderDid: this.options.holderDid,
        targetOrigin: String(target.origin),
        nodeAudience: String(target.nodeAudience),
        action,
        actions,
        resource: String(outerResource.path),
      };
      const requestBodyDigest = await digest(challengeBody);
      const challengeResponse = await this.fetchFn(new URL("/share/v2/policy/challenges", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ ...challengeBody, requestBodyDigest }) });
      if (!challengeResponse.ok) await rejectPolicyResponse(challengeResponse, "challenge");
      const wrapped = exactWrapped(await challengeResponse.json(), "challenge");
      await verifyNodeProof(wrapped.artifact, wrapped.proof, this.options.trustedNode, "xyz.tinycloud.share/policy-challenge/v2\0");
      const challenge = wrapped.artifact as unknown as PolicyChallenge;
      if (challenge.type !== "TinyCloudSharePolicyChallenge" || challenge.version !== 2 || challenge.shareCid !== ownerShareCid || challenge.shareId !== envelope.shareId || challenge.registrationCid !== ownerAuthority.registrationCid || challenge.envelopeCid !== ownerAuthority.envelopeCid || challenge.policyCid !== challengeBody.policyCid || challenge.enforcementDelegationCid !== enforcement.cid || challenge.requestBodyDigest !== requestBodyDigest || challenge.contentSourceDigest !== challengeBody.contentSourceDigest || canonicalize(challenge.contentSource) !== canonicalize(source) || challenge.holderDid !== this.options.holderDid || challenge.targetOrigin !== target.origin || challenge.nodeAudience !== target.nodeAudience || challenge.action !== action || canonicalize(challenge.actions) !== canonicalize(actions) || challenge.resource !== outerResource.path) throw new Error("policy challenge is not bound");
      assertNodeTime(challenge.issuedAt, challenge.expiresAt, Date.now(), 120);
      const material = await this.options.buildPresentation({ challenge, envelope, policy: this.verified.policy });
      if (!isPresentationMaterial(material)) throw new Error("full-email presentation material is required");
      this.holderProof = material.proof;
      this.nativeSigner = material.sign;
      const presentation = {
        type: "TinyCloudSharePolicyPresentation",
        version: 2,
        challengeId: challenge.challengeId,
        nonce: challenge.nonce,
        shareCid: ownerShareCid,
        shareId: envelope.shareId,
        delegationCid: envelope.delegationCid,
        policyCid: challengeBody.policyCid,
        contentSource: source,
        contentSourceDigest: challengeBody.contentSourceDigest,
        holderDid: material.holderDid,
        targetOrigin: target.origin,
        nodeAudience: target.nodeAudience,
        enforcerDid: challenge.enforcerDid,
        credentialDigest: material.credentialDigest ?? await digestText(material.credential),
        action,
        actions,
        resource: outerResource.path,
        requestBodyDigest,
        issuedAt: new Date().toISOString(),
        expiresAt: challenge.expiresAt,
        jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
      };
      const presentationProof = { alg: "EdDSA", kid: `${material.holderDid}#${material.holderDid.slice("did:key:".length)}`, signature: toBase64Url(await material.sign!(new TextEncoder().encode(`xyz.tinycloud.share/policy-session/v2\0${canonicalize(presentation)}`))) };
      const sessionResponse = await this.fetchFn(new URL("/share/v2/policy/session", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ challengeId: challenge.challengeId, nonce: challenge.nonce, presentation, credential: material.credential, proof: presentationProof, holderBinding: material.holderBinding, readSignerDid: material.holderDid }) });
      if (!sessionResponse.ok) await rejectPolicyResponse(sessionResponse, "session");
      const sessionWrapped = exactWrapped(await sessionResponse.json(), "session");
      await verifyNodeProof(sessionWrapped.artifact, sessionWrapped.proof, this.options.trustedNode, "xyz.tinycloud.share/policy-session/v2\0");
      const session = sessionWrapped.artifact as unknown as PolicySession;
      if (session.type !== "TinyCloudSharePolicySession" || session.version !== 2 || session.sessionId === undefined || session.shareCid !== ownerShareCid || session.shareId !== envelope.shareId || session.registrationCid !== ownerAuthority.registrationCid || session.envelopeCid !== ownerAuthority.envelopeCid || session.policyCid !== challengeBody.policyCid || session.delegationCid !== envelope.delegationCid || session.holderDid !== this.options.holderDid || String(session.resource) !== outerResource.path || session.expiresAt === undefined) throw new Error("policy session is not fully bound");
      this.session = { ...session, actions: actions.map(uiAction), resource: { kind: "exact", path: String(session.resource) } } as unknown as PolicySession;
      return this.session;
    }
    const selected = envelope.resource.kind === "prefix" && envelope.actions.includes("list")
      ? "list"
      : envelope.actions.includes("read") ? "read" : envelope.actions[0];
    if (selected === undefined) throw new Error("addressed share has no action");
    const action = nativeAction(selected);
    const resource = envelope.resource.path.replace(/\/$/, "");
    const body = {
      shareCid: this.options.shareCid,
      shareId: envelope.shareId,
      policyCid: envelope.authorizationTarget.kind === "policy" ? envelope.authorizationTarget.policyCid : "",
      delegationCid: envelope.delegationCid,
      authorityMaterialHandle: envelope.authorityMaterialHandle,
      authorityMaterialDigest: envelope.authorityMaterialDigest,
      contentSource: envelope.contentSource,
      contentSourceDigest: envelope.contentSourceDigest,
      holderDid: this.options.holderDid,
      targetOrigin: envelope.target.origin,
      nodeAudience: envelope.target.nodeAudience,
      action,
      actions: envelope.actions.map(nativeAction).sort(),
      resource,
    };
    const requestBodyDigest = await digest(body);
    const response = await this.fetchFn(new URL("/share/v1/policy/challenges", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ ...body, requestBodyDigest }) });
    if (!response.ok) await rejectPolicyResponse(response, "challenge");
    const wrapped = exactWrapped(await response.json(), "challenge");
    await verifyNodeProof(wrapped.artifact, wrapped.proof, this.options.trustedNode, SIGNATURE_DOMAINS.policyChallenge);
    const challenge = wrapped.artifact as unknown as PolicyChallenge;
    const expectedActions = envelope.actions.map(nativeAction).sort();
    if (challenge.type !== "TinyCloudSharePolicyChallenge" || challenge.version !== 1 || challenge.shareCid !== this.options.shareCid || challenge.shareId !== envelope.shareId || challenge.policyCid !== body.policyCid || challenge.requestBodyDigest !== requestBodyDigest || challenge.delegationCid !== envelope.delegationCid || challenge.authorityMaterialHandle !== envelope.authorityMaterialHandle || challenge.authorityMaterialDigest !== envelope.authorityMaterialDigest || canonicalize(challenge.contentSource) !== canonicalize(envelope.contentSource) || challenge.contentSourceDigest !== envelope.contentSourceDigest || challenge.holderDid !== this.options.holderDid || challenge.targetOrigin !== envelope.target.origin || challenge.nodeAudience !== envelope.target.nodeAudience || challenge.action !== action || canonicalize(challenge.actions) !== canonicalize(expectedActions) || challenge.resource !== resource) throw new Error("policy challenge is not bound");
    assertNodeTime(challenge.issuedAt, challenge.expiresAt, Date.now(), 120);
    const material = await this.options.buildPresentation({ challenge, envelope, policy: this.verified.policy });
    if (isPresentationMaterial(material)) { this.holderProof = material.proof; this.nativeSigner = material.sign; }
    const presentation = isPresentationMaterial(material)
      ? {
        type: "TinyCloudSharePolicyPresentation", version: 1, challengeId: challenge.challengeId, nonce: challenge.nonce,
        shareCid: this.options.shareCid, shareId: envelope.shareId, delegationCid: envelope.delegationCid, policyCid: body.policyCid,
        authorityMaterialHandle: envelope.authorityMaterialHandle, authorityMaterialDigest: envelope.authorityMaterialDigest,
        contentSource: envelope.contentSource, contentSourceDigest: envelope.contentSourceDigest, holderDid: material.holderDid,
        targetOrigin: envelope.target.origin, nodeAudience: envelope.target.nodeAudience, enforcerDid: challenge.enforcerDid,
        credentialDigest: material.credentialDigest ?? await digestText(material.credential), action, actions: expectedActions, resource,
        requestBodyDigest, issuedAt: new Date().toISOString(), expiresAt: challenge.expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
      }
      : material;
    const presentationProof = isPresentationMaterial(material) && material.sign
      ? { alg: "EdDSA", kid: `${material.holderDid}#${material.holderDid.slice("did:key:".length)}`, signature: toBase64Url(await material.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.policyPresentation}${canonicalize(presentation)}`))) }
      : material.proof;
    if (!isPresentationMaterial(material)) throw new Error("full-email presentation material is required");
    const sessionResponse = await this.fetchFn(new URL("/share/v1/policy/session", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ presentation, credential: material.credential, proof: presentationProof, holderBinding: material.holderBinding, readSignerDid: material.holderDid }) });
    if (!sessionResponse.ok) await rejectPolicyResponse(sessionResponse, "session");
    const sessionWrapped = exactWrapped(await sessionResponse.json(), "session");
    await verifyNodeProof(sessionWrapped.artifact, sessionWrapped.proof, this.options.trustedNode, SIGNATURE_DOMAINS.policySession);
    const session = sessionWrapped.artifact as unknown as PolicySession;
    if (session.type !== "TinyCloudSharePolicySession" || session.version !== 1 || session.sessionId === undefined || session.shareCid !== this.options.shareCid || session.shareId !== envelope.shareId || session.delegationCid !== envelope.delegationCid || session.authorityMaterialHandle !== envelope.authorityMaterialHandle || session.authorityMaterialDigest !== envelope.authorityMaterialDigest || canonicalize(session.contentSource) !== canonicalize(envelope.contentSource) || session.contentSourceDigest !== envelope.contentSourceDigest || session.holderDid !== this.options.holderDid || session.targetOrigin !== envelope.target.origin || session.nodeAudience !== envelope.target.nodeAudience || typeof session.action !== "string" || canonicalize(session.actions) !== canonicalize(expectedActions) || typeof session.resource !== "string" || session.resource !== resource || session.expiresAt === undefined) throw new Error("policy session is not fully bound");
    const sessionAction = uiAction(session.action);
    if (!envelope.actions.includes(sessionAction) || !resourceCovers(envelope.resource, { kind: envelope.resource.kind, path: session.resource })) throw new Error("policy session attenuation is invalid");
    // The Node session is the canonical, signed action ceiling. Preserve the
    // complete set so later invocations carry the same binding admitted by
    // challenge and session establishment.
    this.session = { ...session, actions: expectedActions.map(uiAction), resource: { kind: envelope.resource.kind, path: session.resource } } as unknown as PolicySession;
    return this.session;
  }

  private async establishPolicySessionV3(envelope: ShareEnvelopeV3): Promise<PolicySession> {
    const { claimUnifiedDelegation, requestUnifiedChallenge } = await import("../../../src/share/unified-delegation.js");
    const challenge = await requestUnifiedChallenge({ nodeOrigin: this.options.nodeOrigin, policyCid: envelope.policyCid, recipientDid: this.options.holderDid, requestedCapabilities: envelope.policy.capabilityCeiling, fetchFn: this.fetchFn });
    const material = await this.options.buildPresentation({ challenge: {
      type: "TinyCloudSharePolicyChallenge", version: 3, challengeId: String(challenge.challengeId), nonce: String(challenge.nonce), shareCid: this.options.shareCid, shareId: envelope.shareId,
      delegationCid: envelope.policyRoot.cid, authorityMaterialDigest: envelope.contentSourceDigestHex, contentSource: envelope.contentSource as unknown as Record<string, unknown>, contentSourceDigest: envelope.contentSourceDigestHex,
      targetOrigin: envelope.target.origin, nodeAudience: envelope.target.nodeAudience, actions: envelope.actions, resource: envelope.resource.path, requestBodyDigest: "", issuedAt: envelope.policy.createdAt, expiresAt: envelope.expiry, enforcerDid: "",
    }, envelope: envelope as unknown as ShareEnvelopeV2, policy: envelope.policy as unknown as Record<string, unknown> });
    if (!isPresentationMaterial(material)) throw new Error("v3 policy ceremony did not return a verified presentation");
    this.holderProof = material.proof;
    this.nativeSigner = material.sign;
    if (material.sign === undefined) throw new Error("v3 recipient signer is required");
    if (material.claim === undefined || material.presentation === undefined) {
      throw new Error("v3 ceremony requires exact verified claim and presentation objects");
    }
    const delegation = await claimUnifiedDelegation({
      nodeOrigin: this.options.nodeOrigin,
      recipientDid: this.options.holderDid,
      policyCid: envelope.policyCid,
      policyRootCid: envelope.policyRoot.cid,
      enforcementRootCid: envelope.enforcementRoot.cid,
      requestedCapabilities: envelope.policy.capabilityCeiling,
      challenge,
      claim: material.claim,
      presentation: material.presentation,
      fetchFn: this.fetchFn,
    });
    this.v3Authorization = delegation.delegationHeader.Authorization;
    return { type: "TinyCloudSharePolicySession", version: 3 as 3, sessionId: delegation.cid, shareCid: this.options.shareCid, shareId: envelope.shareId, holderDid: this.options.holderDid, actions: envelope.actions, resource: envelope.resource, expiresAt: envelope.expiry } as unknown as PolicySession;
  }

  /** Decrypt a v3 KV value through a fresh ordinary decrypt invocation. */
  async decryptV3Content(bytes: Uint8Array): Promise<{ readonly bytes: Uint8Array; readonly mediaType: string }> {
    const envelope = this.options.envelope;
    if (envelope.version !== 3 || this.session === undefined || this.v3Authorization === undefined || this.nativeSigner === undefined) throw new Error("v3 policy session signer is required");
    const encrypted = parseV3InlineEncryptedEnvelope(bytes, envelope);
    const receiverPrivateKey = crypto.getRandomValues(new Uint8Array(32));
    const receiverPublicKeyBytes = x25519.getPublicKey(receiverPrivateKey);
    const receiverPublicKey = toBase64Url(receiverPublicKeyBytes);
    const receiverPublicKeyHash = canonicalHashHex(receiverPublicKey);
    const body = {
      type: "tinycloud.encryption.decrypt/v1",
      targetNode: envelope.target.nodeAudience,
      networkId: encrypted.networkId,
      alg: encrypted.alg,
      keyVersion: encrypted.keyVersion,
      encryptedSymmetricKey: encrypted.encryptedSymmetricKey,
      encryptedSymmetricKeyHash: encrypted.encryptedSymmetricKeyHash,
      receiverPublicKey,
      receiverPublicKeyHash,
    };
    const bodyHash = hex(sha256(new TextEncoder().encode(canonicalize(body))));
    const session = verifyCompactUcanAuthorization(this.v3Authorization, this.session.sessionId);
    const now = Math.floor(Date.now() / 1000);
    const signed = await signCompactUcanAuthorization({
      issuerDid: this.options.holderDid,
      audienceDid: envelope.target.nodeAudience,
      attenuation: { [encrypted.networkId]: { "tinycloud.encryption/decrypt": [{}] } },
      facts: [{ type: body.type, targetNode: body.targetNode, networkId: body.networkId, bodyHash, encryptedSymmetricKeyHash: body.encryptedSymmetricKeyHash, receiverPublicKeyHash, alg: body.alg, keyVersion: body.keyVersion }],
      proofs: [session.cid],
      notBefore: now,
      expiresAt: Math.min(now + 60, session.payload.exp),
      nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
      sign: this.nativeSigner,
    });
    try {
      const response = await this.fetchFn(new URL("/invoke", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json", Authorization: signed.authorization }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error(`v3 decrypt invocation rejected (${response.status})`);
      const result = await response.json() as unknown;
      if (result === null || typeof result !== "object" || Array.isArray(result)) throw new Error("v3 decrypt response is malformed");
      const value = result as Record<string, unknown>;
      const allowed = ["type", "targetNode", "networkId", "invocationCid", "encryptedSymmetricKeyHash", "receiverPublicKeyHash", "wrappedKey", "alg", "keyVersion", "requestHash", "nodeId", "nodeSignature"];
      if (Object.keys(value).length !== allowed.length || Object.keys(value).some((key) => !allowed.includes(key))
        || value.type !== "tinycloud.encryption.decrypt-result/v1" || value.targetNode !== body.targetNode || value.nodeId !== body.targetNode
        || value.networkId !== body.networkId || value.invocationCid !== signed.cid
        || value.encryptedSymmetricKeyHash !== body.encryptedSymmetricKeyHash || value.receiverPublicKeyHash !== receiverPublicKeyHash
        || value.alg !== body.alg || value.keyVersion !== body.keyVersion
        || value.requestHash !== hex(sha256(new TextEncoder().encode(`${signed.cid}${bodyHash}`)))
        || typeof value.wrappedKey !== "string" || typeof value.nodeSignature !== "string") throw new Error("v3 decrypt response binding is invalid");
      const unsigned = { ...value };
      delete unsigned.nodeSignature;
      const signature = fromBase64Url(value.nodeSignature);
      if (signature.length !== 64 || !ed25519.verify(signature, new TextEncoder().encode(canonicalize(unsigned)), ed25519PublicKeyFromDidKey(body.targetNode), { zip215: false })) throw new Error("v3 decrypt response signature is invalid");
      const wrapped = fromBase64Url(value.wrappedKey);
      if (wrapped.length < 60) throw new Error("v3 wrapped content key is malformed");
      const shared = x25519.getSharedSecret(receiverPrivateKey, wrapped.slice(0, 32));
      const symmetricKey = await aesGcmDecrypt(shared, wrapped.slice(32));
      shared.fill(0);
      if (symmetricKey.length !== 32) throw new Error("v3 content key is malformed");
      const plaintext = await aesGcmDecrypt(symmetricKey, fromBase64Url(encrypted.ciphertext));
      this.v3ContentKey?.fill(0);
      this.v3ContentKey = symmetricKey;
      this.v3ContentEnvelope = encrypted;
      return { bytes: plaintext, mediaType: encrypted.metadata?.contentType ?? envelope.metadata.mediaType ?? "application/octet-stream" };
    } finally {
      receiverPrivateKey.fill(0);
    }
  }

  /** Re-encrypt edited v3 content with the admitted wrapped content key. */
  async encryptV3Content(bytes: Uint8Array, mediaType: string): Promise<Uint8Array> {
    if (this.options.envelope.version !== 3 || this.v3ContentKey === undefined || this.v3ContentEnvelope === undefined) throw new Error("v3 content must be decrypted before it can be saved");
    const ciphertext = await aesGcmEncrypt(this.v3ContentKey, bytes);
    return new TextEncoder().encode(canonicalize({
      ...this.v3ContentEnvelope,
      ciphertext: toBase64Url(ciphertext),
      metadata: { ...(this.v3ContentEnvelope.metadata ?? {}), contentType: mediaType },
    }));
  }

  private async nativeInvokeV2(request: Record<string, unknown>, envelope: ShareEnvelopeV2): Promise<Response> {
    if (this.session === undefined || envelope.ownerAuthority === undefined) throw new Error("policy session is required");
    const authority = envelope.ownerAuthority;
    const outer = authority.outerEnvelope as Record<string, unknown>;
    const target = outer.target as Record<string, unknown>;
    const source = outer.contentSource as Record<string, unknown>;
    const action = requestedNativeAction(request.action);
    const selector = request.resource as Record<string, unknown> | undefined;
    const resource = typeof selector?.path === "string" ? selector.path : String(outer.resource && (outer.resource as Record<string, unknown>).path);
    const actions = [...new Set(this.session.actions.map(nativeAction).concat(action === "tinycloud.kv/metadata" ? ["tinycloud.kv/metadata"] : []))].sort() as NativeAction[];
    if (!actions.includes(action) || resource.length === 0) throw new Error("requested operation is outside the verified share");
    const bodyBytes = Array.isArray(request.body) ? Uint8Array.from(request.body as number[]) : undefined;
    const bodyDigest = bodyBytes === undefined ? undefined : await digestBytes(bodyBytes);
    const invocationBase: Record<string, unknown> = {
      type: "TinyCloudShareReadInvocation", version: 2, sessionId: this.session.sessionId, envelopeCid: authority.envelopeCid, shareCid: authority.shareCid, shareId: envelope.shareId, registrationCid: authority.registrationCid, delegationCid: envelope.delegationCid, policyCid: envelope.authorizationTarget.kind === "policy" ? envelope.authorizationTarget.policyCid : "", enforcementDelegationCid: String((authority.enforcementDelegation as Record<string, unknown>).cid), contentSource: source, contentSourceDigest: String(outer.contentSourceDigest), holderDid: this.session.holderDid, nodeAudience: String(target.nodeAudience), action, actions, resource, issuedAt: new Date().toISOString(), expiresAt: new Date(Math.min(Date.now() + 60_000, Date.parse(this.session.expiresAt))).toISOString(), jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), ...(bodyDigest === undefined ? {} : { bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }),
    };
    const invocation = { ...invocationBase, requestBodyDigest: await digest(invocationBase) };
    if (this.nativeSigner === undefined) throw new Error("native holder signer is required");
    const proof = { alg: "EdDSA", kid: `${this.session.holderDid}#${this.session.holderDid.slice("did:key:".length)}`, signature: toBase64Url(await this.nativeSigner(new TextEncoder().encode(`xyz.tinycloud.share/invocation/v2\0${canonicalize(invocation)}`))) };
    const signed = { request: { sessionId: this.session.sessionId, envelopeCid: authority.envelopeCid, shareCid: authority.shareCid, shareId: envelope.shareId, registrationCid: authority.registrationCid, delegationCid: envelope.delegationCid, policyCid: envelope.authorizationTarget.kind === "policy" ? envelope.authorizationTarget.policyCid : "", enforcementDelegationCid: String((authority.enforcementDelegation as Record<string, unknown>).cid), contentSource: source, contentSourceDigest: String(outer.contentSourceDigest), holderDid: this.session.holderDid, nodeAudience: String(target.nodeAudience), action, actions, resource, requestBodyDigest: invocation.requestBodyDigest, invocation, proof }, ...(bodyBytes === undefined ? {} : { body: toBase64Url(bodyBytes), bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }) };
    return this.fetchFn(new URL("/share/v2/invoke", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/vnd.tinycloud.share+json", "content-type": "application/vnd.tinycloud.share+json" }, body: JSON.stringify(signed) });
  }

  async nativeInvoke(request: Record<string, unknown>): Promise<Response> {
    if (this.session === undefined) throw new Error("policy session is required");
    const envelope = this.options.envelope;
    if (envelope.version === 3) {
      if (this.v3Authorization === undefined || this.nativeSigner === undefined) {
        throw new Error("v3 policy session signer is required");
      }
      const session = verifyCompactUcanAuthorization(this.v3Authorization, this.session.sessionId);
      if (session.payload.aud !== this.options.holderDid) throw new Error("v3 session recipient mismatch");
      const action = requestedNativeAction(request.action);
      const requested = request.resource;
      const selector = typeof requested === "object" && requested !== null && !Array.isArray(requested)
        ? requested as Record<string, unknown>
        : envelope.resource;
      const path = typeof selector.path === "string" ? selector.path : envelope.resource.path;
      const selectedCapability = action === "tinycloud.encryption/decrypt"
        ? envelope.policy.capabilityCeiling.find((capability) => capability.kind === "encryption")
        : envelope.policy.capabilityCeiling.find((capability) => capability.kind === "kv");
      if (selectedCapability === undefined) throw new Error("v3 requested capability is not in the signed policy");
      let resource: string;
      let caveat: Record<string, unknown>;
      if (selectedCapability.kind === "encryption") {
        if (action !== selectedCapability.action) throw new Error("v3 decrypt action is outside the signed policy");
        resource = selectedCapability.resource;
        caveat = {};
      } else {
        if (!selectedCapability.actions.includes(action as never)) throw new Error("v3 KV action is outside the signed policy");
        const marker = "/kv/";
        const split = selectedCapability.resource.indexOf(marker);
        if (split < 0) throw new Error("v3 KV resource is invalid");
        const root = selectedCapability.resource.slice(split + marker.length).replace(/\/$/, "");
        const cleanPath = path.replace(/^\//, "").replace(/\/$/, "");
        if (cleanPath !== root && !cleanPath.startsWith(`${root}/`)) throw new Error("v3 KV request is outside the signed selector");
        resource = `${selectedCapability.resource.slice(0, split + marker.length)}${cleanPath}`;
        caveat = { kind: selector.kind ?? "exact", type: "xyz.tinycloud.resource/selector", value: resource };
      }
      const now = Math.floor(Date.now() / 1000);
      const expiration = Math.min(now + 60, session.payload.exp);
      if (expiration <= now) throw new Error("v3 policy session expired");
      let facts: Readonly<Record<string, unknown>> = { type: "tinycloud.policy.invocation/v1", policyCid: envelope.policyCid, sessionCid: session.cid };
      if (action === "tinycloud.encryption/decrypt") {
        const decryptBody = request.body;
        if (typeof decryptBody !== "object" || decryptBody === null || Array.isArray(decryptBody)) throw new Error("v3 decrypt request body is invalid");
        const value = decryptBody as Record<string, unknown>;
        const required = ["type", "targetNode", "networkId", "alg", "keyVersion", "encryptedSymmetricKey", "encryptedSymmetricKeyHash", "receiverPublicKey", "receiverPublicKeyHash"] as const;
        if (required.some((key) => !(key in value)) || value.type !== "tinycloud.encryption.decrypt/v1" || value.targetNode !== envelope.target.nodeAudience || value.networkId !== resource) throw new Error("v3 decrypt request binding is invalid");
        const bodyHash = [...sha256(new TextEncoder().encode(canonicalize(value)))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
        facts = { type: value.type, targetNode: value.targetNode, networkId: value.networkId, bodyHash, encryptedSymmetricKeyHash: value.encryptedSymmetricKeyHash, receiverPublicKeyHash: value.receiverPublicKeyHash, alg: value.alg, keyVersion: value.keyVersion };
      }
      const signed = await signCompactUcanAuthorization({
        issuerDid: this.options.holderDid,
        audienceDid: envelope.target.nodeAudience,
        attenuation: { [resource]: { [action]: [caveat] } },
        facts: [facts],
        proofs: [session.cid],
        notBefore: now,
        expiresAt: expiration,
        nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
        sign: this.nativeSigner,
      });
      const headers = new Headers({ accept: "application/json", Authorization: signed.authorization });
      let body: BodyInit | undefined;
      if (action === "tinycloud.encryption/decrypt") {
        headers.set("content-type", "application/json");
        body = JSON.stringify(request.body ?? request);
      } else if (action === "tinycloud.kv/put") {
        const bytes = Array.isArray(request.body) ? Uint8Array.from(request.body as number[]) : undefined;
        if (bytes === undefined) throw new Error("v3 KV put requires bytes");
        headers.set("content-type", typeof request.contentType === "string" ? request.contentType : "application/octet-stream");
        if (typeof request.ifMatch === "string") headers.set("if-match", request.ifMatch);
        body = bytes as BodyInit;
      }
      return this.fetchFn(new URL("/invoke", this.options.nodeOrigin), {
        method: "POST",
        redirect: "error",
        headers,
        ...(body === undefined ? {} : { body }),
      });
    }
    if (envelope.version !== 2) throw new Error("unsupported share envelope version");
    if (envelope.version === 2 && envelope.ownerAuthority !== undefined) return this.nativeInvokeV2(request, envelope);
    const action = requestedNativeAction(request.action);
    const requestedResource = request.resource;
    const resourceSelector = typeof requestedResource === "object" && requestedResource !== null && !Array.isArray(requestedResource) && typeof (requestedResource as Record<string, unknown>).path === "string"
      ? requestedResource as { readonly kind: "exact" | "prefix"; readonly path: string }
      : this.session.resource;
    if (!resourceCovers(envelope.resource, resourceSelector) || !resourceCovers(this.session.resource, resourceSelector)) throw new Error("requested resource is outside the verified share");
    if (requestedResource !== undefined && resourceSelector.kind !== this.session.resource.kind && !(this.session.resource.kind === "prefix" && resourceSelector.kind === "exact")) throw new Error("requested resource kind is invalid");
    const resource = resourceSelector.path;
    const bodyBytes = Array.isArray(request.body) ? Uint8Array.from(request.body as number[]) : undefined;
    const bodyDigest = bodyBytes === undefined ? undefined : await digestBytes(bodyBytes);
    const limit = typeof request.limit === "number" ? request.limit : 100;
    const cursor = typeof request.cursor === "string" ? request.cursor : undefined;
    const issuedAt = new Date();
    const expiresAt = new Date(Math.min(issuedAt.getTime() + 60_000, Date.parse(this.session.expiresAt))).toISOString();
    const actions = [...new Set(this.session.actions.map(nativeAction).concat(action === "tinycloud.kv/metadata" ? ["tinycloud.kv/metadata"] : []))].sort() as NativeAction[];
    const invocationBase = { type: "TinyCloudShareReadInvocation", version: 2, sessionId: this.session.sessionId, shareCid: this.options.shareCid, shareId: envelope.shareId, policyCid: envelope.authorizationTarget.kind === "policy" ? envelope.authorizationTarget.policyCid : "", delegationCid: envelope.delegationCid, authorityMaterialHandle: envelope.authorityMaterialHandle, authorityMaterialDigest: envelope.authorityMaterialDigest, contentSource: envelope.contentSource, contentSourceDigest: envelope.contentSourceDigest, holderDid: this.session.holderDid, targetOrigin: envelope.target.origin, nodeAudience: envelope.target.nodeAudience, action, actions, resource, ...(action === "tinycloud.kv/list" ? { limit, ...(cursor === undefined ? {} : { cursor }) } : {}), ...(bodyDigest === undefined ? { } : { bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }), issuedAt: issuedAt.toISOString(), expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))) };
    // The Node boundary recomputes this digest from the complete signed
    // request wrapper after removing only `proof` and both digest fields.
    // Keep the outer action set in the preimage; omitting it makes an
    // otherwise valid v2 invocation fail closed at the native route.
    const requestBodyDigest = await digest({ sessionId: this.session.sessionId, delegationCid: envelope.delegationCid, authorityMaterialHandle: envelope.authorityMaterialHandle, authorityMaterialDigest: envelope.authorityMaterialDigest, contentSource: envelope.contentSource, contentSourceDigest: envelope.contentSourceDigest, action, actions: invocationBase.actions, resource, invocation: invocationBase });
    const invocation = { ...invocationBase, requestBodyDigest };
    if (this.holderProof === undefined || this.nativeSigner === undefined) throw new Error("native holder signer is required");
    const invocationBytes = new TextEncoder().encode(`${SIGNATURE_DOMAINS.readInvocation}${canonicalize(invocation)}`);
    const nativeProof = { ...this.holderProof, signature: toBase64Url(await this.nativeSigner(invocationBytes)) };
    const signed = { request: { sessionId: this.session.sessionId, delegationCid: envelope.delegationCid, authorityMaterialHandle: envelope.authorityMaterialHandle, authorityMaterialDigest: envelope.authorityMaterialDigest, contentSource: envelope.contentSource, contentSourceDigest: envelope.contentSourceDigest, action, actions: invocation.actions, resource, requestBodyDigest, invocation, proof: nativeProof }, ...(action === "tinycloud.kv/list" ? { limit, ...(cursor === undefined ? {} : { cursor }) } : {}), ...(bodyBytes === undefined ? {} : { body: toBase64Url(bodyBytes), bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }) };
    return this.fetchFn(new URL("/invoke", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/vnd.tinycloud.share+json", "content-type": "application/vnd.tinycloud.share+json" }, body: JSON.stringify(signed) });
  }
}
