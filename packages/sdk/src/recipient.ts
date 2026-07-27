import {
  canonicalize,
  computeCid,
  fromBase64Url,
  toBase64Url,
  shareEnvelopeV2Schema,
  verifyEnvelopeV2,
  ed25519PublicKeyFromDidKey,
  type ShareEnvelopeV2,
  type ShareAction,
  type ResourceSelector,
} from "@tinycloud/share-envelope";
import { ed25519 } from "@noble/curves/ed25519";
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

export interface ParsedAddressedEnvelope {
  readonly envelope: ShareEnvelopeV2;
  readonly policy: Record<string, unknown>;
  readonly policyCid: string;
}

export async function parseAddressedEnvelope(value: unknown): Promise<ParsedAddressedEnvelope> {
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
}

export interface ShareRecipientClientOptions {
  readonly nodeOrigin: string;
  readonly fetchFn?: typeof fetch;
  readonly envelope: ShareEnvelopeV2;
  readonly shareCid: string;
  readonly trustedNode: TrustedNode;
  readonly holderDid: string;
  readonly buildPresentation: (input: { readonly challenge: PolicyChallenge; readonly envelope: ShareEnvelopeV2; readonly policy: Record<string, unknown> }) => Promise<PolicyPresentationMaterial | Record<string, unknown>>;
}

type NativeAction = "tinycloud.kv/get" | "tinycloud.kv/metadata" | "tinycloud.kv/list" | "tinycloud.kv/put";

function nativeAction(value: ShareAction): NativeAction {
  if (value === "read") return "tinycloud.kv/get";
  if (value === "list") return "tinycloud.kv/list";
  return "tinycloud.kv/put";
}

function requestedNativeAction(value: unknown): NativeAction {
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

  constructor(private readonly options: ShareRecipientClientOptions) {
    this.fetchFn = options.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  async establishPolicySession(): Promise<PolicySession> {
    this.verified ??= await parseAddressedEnvelope(this.options.envelope);
    const envelope = this.options.envelope;
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

  private async nativeInvokeV2(request: Record<string, unknown>): Promise<Response> {
    if (this.session === undefined || this.options.envelope.ownerAuthority === undefined) throw new Error("policy session is required");
    const authority = this.options.envelope.ownerAuthority;
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
      type: "TinyCloudShareReadInvocation", version: 2, sessionId: this.session.sessionId, envelopeCid: authority.envelopeCid, shareCid: authority.shareCid, shareId: this.options.envelope.shareId, registrationCid: authority.registrationCid, delegationCid: this.options.envelope.delegationCid, policyCid: this.options.envelope.authorizationTarget.kind === "policy" ? this.options.envelope.authorizationTarget.policyCid : "", enforcementDelegationCid: String((authority.enforcementDelegation as Record<string, unknown>).cid), contentSource: source, contentSourceDigest: String(outer.contentSourceDigest), holderDid: this.session.holderDid, nodeAudience: String(target.nodeAudience), action, actions, resource, issuedAt: new Date().toISOString(), expiresAt: new Date(Math.min(Date.now() + 60_000, Date.parse(this.session.expiresAt))).toISOString(), jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), ...(bodyDigest === undefined ? {} : { bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }),
    };
    const invocation = { ...invocationBase, requestBodyDigest: await digest(invocationBase) };
    if (this.nativeSigner === undefined) throw new Error("native holder signer is required");
    const proof = { alg: "EdDSA", kid: `${this.session.holderDid}#${this.session.holderDid.slice("did:key:".length)}`, signature: toBase64Url(await this.nativeSigner(new TextEncoder().encode(`xyz.tinycloud.share/invocation/v2\0${canonicalize(invocation)}`))) };
    const signed = { request: { sessionId: this.session.sessionId, envelopeCid: authority.envelopeCid, shareCid: authority.shareCid, shareId: this.options.envelope.shareId, registrationCid: authority.registrationCid, delegationCid: this.options.envelope.delegationCid, policyCid: this.options.envelope.authorizationTarget.kind === "policy" ? this.options.envelope.authorizationTarget.policyCid : "", enforcementDelegationCid: String((authority.enforcementDelegation as Record<string, unknown>).cid), contentSource: source, contentSourceDigest: String(outer.contentSourceDigest), holderDid: this.session.holderDid, nodeAudience: String(target.nodeAudience), action, actions, resource, requestBodyDigest: invocation.requestBodyDigest, invocation, proof }, ...(bodyBytes === undefined ? {} : { body: toBase64Url(bodyBytes), bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }) };
    return this.fetchFn(new URL("/share/v2/invoke", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/vnd.tinycloud.share+json", "content-type": "application/vnd.tinycloud.share+json" }, body: JSON.stringify(signed) });
  }

  async nativeInvoke(request: Record<string, unknown>): Promise<Response> {
    if (this.session === undefined) throw new Error("policy session is required");
    if (this.options.envelope.ownerAuthority !== undefined) return this.nativeInvokeV2(request);
    const action = requestedNativeAction(request.action);
    const requestedResource = request.resource;
    const resourceSelector = typeof requestedResource === "object" && requestedResource !== null && !Array.isArray(requestedResource) && typeof (requestedResource as Record<string, unknown>).path === "string"
      ? requestedResource as { readonly kind: "exact" | "prefix"; readonly path: string }
      : this.session.resource;
    if (!resourceCovers(this.options.envelope.resource, resourceSelector) || !resourceCovers(this.session.resource, resourceSelector)) throw new Error("requested resource is outside the verified share");
    if (requestedResource !== undefined && resourceSelector.kind !== this.session.resource.kind && !(this.session.resource.kind === "prefix" && resourceSelector.kind === "exact")) throw new Error("requested resource kind is invalid");
    const resource = resourceSelector.path;
    const bodyBytes = Array.isArray(request.body) ? Uint8Array.from(request.body as number[]) : undefined;
    const bodyDigest = bodyBytes === undefined ? undefined : await digestBytes(bodyBytes);
    const limit = typeof request.limit === "number" ? request.limit : 100;
    const cursor = typeof request.cursor === "string" ? request.cursor : undefined;
    const issuedAt = new Date();
    const expiresAt = new Date(Math.min(issuedAt.getTime() + 60_000, Date.parse(this.session.expiresAt))).toISOString();
    const actions = [...new Set(this.session.actions.map(nativeAction).concat(action === "tinycloud.kv/metadata" ? ["tinycloud.kv/metadata"] : []))].sort() as NativeAction[];
    const invocationBase = { type: "TinyCloudShareReadInvocation", version: 2, sessionId: this.session.sessionId, shareCid: this.options.shareCid, shareId: this.options.envelope.shareId, policyCid: this.options.envelope.authorizationTarget.kind === "policy" ? this.options.envelope.authorizationTarget.policyCid : "", delegationCid: this.options.envelope.delegationCid, authorityMaterialHandle: this.options.envelope.authorityMaterialHandle, authorityMaterialDigest: this.options.envelope.authorityMaterialDigest, contentSource: this.options.envelope.contentSource, contentSourceDigest: this.options.envelope.contentSourceDigest, holderDid: this.session.holderDid, targetOrigin: this.options.envelope.target.origin, nodeAudience: this.options.envelope.target.nodeAudience, action, actions, resource, ...(action === "tinycloud.kv/list" ? { limit, ...(cursor === undefined ? {} : { cursor }) } : {}), ...(bodyDigest === undefined ? { } : { bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }), issuedAt: issuedAt.toISOString(), expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))) };
    // The Node boundary recomputes this digest from the complete signed
    // request wrapper after removing only `proof` and both digest fields.
    // Keep the outer action set in the preimage; omitting it makes an
    // otherwise valid v2 invocation fail closed at the native route.
    const requestBodyDigest = await digest({ sessionId: this.session.sessionId, delegationCid: this.options.envelope.delegationCid, authorityMaterialHandle: this.options.envelope.authorityMaterialHandle, authorityMaterialDigest: this.options.envelope.authorityMaterialDigest, contentSource: this.options.envelope.contentSource, contentSourceDigest: this.options.envelope.contentSourceDigest, action, actions: invocationBase.actions, resource, invocation: invocationBase });
    const invocation = { ...invocationBase, requestBodyDigest };
    if (this.holderProof === undefined || this.nativeSigner === undefined) throw new Error("native holder signer is required");
    const invocationBytes = new TextEncoder().encode(`${SIGNATURE_DOMAINS.readInvocation}${canonicalize(invocation)}`);
    const nativeProof = { ...this.holderProof, signature: toBase64Url(await this.nativeSigner(invocationBytes)) };
    const signed = { request: { sessionId: this.session.sessionId, delegationCid: this.options.envelope.delegationCid, authorityMaterialHandle: this.options.envelope.authorityMaterialHandle, authorityMaterialDigest: this.options.envelope.authorityMaterialDigest, contentSource: this.options.envelope.contentSource, contentSourceDigest: this.options.envelope.contentSourceDigest, action, actions: invocation.actions, resource, requestBodyDigest, invocation, proof: nativeProof }, ...(action === "tinycloud.kv/list" ? { limit, ...(cursor === undefined ? {} : { cursor }) } : {}), ...(bodyBytes === undefined ? {} : { body: toBase64Url(bodyBytes), bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }) };
    return this.fetchFn(new URL("/invoke", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/vnd.tinycloud.share+json", "content-type": "application/vnd.tinycloud.share+json" }, body: JSON.stringify(signed) });
  }
}
