import {
  canonicalize,
  computeCid,
  fromBase64Url,
  toBase64Url,
  shareEnvelopeV2Schema,
  verifyEnvelopeV2,
  type ShareEnvelopeV2,
  type ShareAction,
  type ResourceSelector,
} from "@tinycloud/share-envelope";
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
  if (await computeCid(policyBytes) !== envelope.authorizationTarget.policyCid) throw new TypeError("addressed policy CID");
  let policy: Record<string, unknown>;
  try {
    const decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(policyBytes)) as unknown;
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) throw new Error("policy");
    policy = decoded as Record<string, unknown>;
  } catch { throw new TypeError("addressed policy bytes"); }
  if (typeof policy.issuerDid !== "string" || typeof policy.resource !== "object" || policy.resource === null || typeof policy.target !== "object" || policy.target === null || !resourceCovers(policy.resource as ResourceSelector, envelope.resource)) throw new TypeError("addressed policy scope");
  const policyActions = Array.isArray(policy.actions) ? policy.actions.filter((action): action is ShareAction => action === "read" || action === "list" || action === "edit") : [];
  if (policy.expiresAt !== envelope.expiry || policyActions.length !== (Array.isArray(policy.actions) ? policy.actions.length : 0) || envelope.actions.some((action) => !policyActions.includes(action)) || envelope.delegationCid !== policy.delegationCid || envelope.authorityMaterialDigest !== policy.authorityMaterialDigest || envelope.contentSourceDigest !== policy.contentSourceDigest) throw new TypeError("addressed policy attenuation");
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

function nativeAction(value: ShareAction): "tinycloud.kv/get" | "tinycloud.kv/list" | "tinycloud.kv/put" {
  if (value === "read") return "tinycloud.kv/get";
  if (value === "list") return "tinycloud.kv/list";
  return "tinycloud.kv/put";
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
    const selected = envelope.actions.includes("read") ? "read" : envelope.actions[0];
    if (selected === undefined) throw new Error("addressed share has no action");
    const action = nativeAction(selected);
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
      ...(envelope.actions.length > 1 ? { actions: envelope.actions.map(nativeAction).sort() } : {}),
      resource: envelope.resource.path,
    };
    const requestBodyDigest = await digest(body);
    const response = await this.fetchFn(new URL("/share/v1/policy/challenges", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ ...body, requestBodyDigest }) });
    if (!response.ok) throw new Error("policy challenge rejected");
    const wrapped = exactWrapped(await response.json(), "challenge");
    await verifyNodeProof(wrapped.artifact, wrapped.proof, this.options.trustedNode, SIGNATURE_DOMAINS.policyChallenge);
    const challenge = wrapped.artifact as unknown as PolicyChallenge;
    if (challenge.shareCid !== this.options.shareCid || challenge.requestBodyDigest !== requestBodyDigest || challenge.delegationCid !== envelope.delegationCid || challenge.authorityMaterialHandle !== envelope.authorityMaterialHandle || challenge.authorityMaterialDigest !== envelope.authorityMaterialDigest || challenge.contentSourceDigest !== envelope.contentSourceDigest || challenge.holderDid !== this.options.holderDid || challenge.targetOrigin !== envelope.target.origin || challenge.nodeAudience !== envelope.target.nodeAudience || challenge.action !== action || challenge.resource !== envelope.resource.path) throw new Error("policy challenge is not bound");
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
        credentialDigest: material.credentialDigest ?? await digestText(material.credential), action, ...(envelope.actions.length > 1 ? { actions: envelope.actions.map(nativeAction).sort() } : {}), resource: envelope.resource.path,
        requestBodyDigest, issuedAt: new Date().toISOString(), expiresAt: challenge.expiresAt, jti: crypto.randomUUID(),
      }
      : material;
    const presentationProof = isPresentationMaterial(material) && material.sign
      ? { alg: "EdDSA", kid: `${material.holderDid}#${material.holderDid.slice("did:key:".length)}`, signature: toBase64Url(await material.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.policyPresentation}${canonicalize(presentation)}`))) }
      : material.proof;
    if (!isPresentationMaterial(material)) throw new Error("full-email presentation material is required");
    const sessionResponse = await this.fetchFn(new URL("/share/v1/policy/session", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ presentation, credential: material.credential, proof: presentationProof, holderBinding: material.holderBinding, readSignerDid: material.holderDid }) });
    if (!sessionResponse.ok) throw new Error("policy session rejected");
    const sessionWrapped = exactWrapped(await sessionResponse.json(), "session");
    await verifyNodeProof(sessionWrapped.artifact, sessionWrapped.proof, this.options.trustedNode, SIGNATURE_DOMAINS.policySession);
    const session = sessionWrapped.artifact as unknown as PolicySession;
    if (session.sessionId === undefined || session.shareCid !== this.options.shareCid || session.holderDid !== this.options.holderDid || typeof session.action !== "string" || typeof session.resource !== "string" || session.expiresAt === undefined) throw new Error("policy session is not fully bound");
    const sessionAction = uiAction(session.action);
    if (!envelope.actions.includes(sessionAction) || !resourceCovers(envelope.resource, { kind: envelope.resource.kind, path: session.resource })) throw new Error("policy session attenuation is invalid");
    this.session = { ...session, actions: [sessionAction], resource: { kind: envelope.resource.kind, path: session.resource } } as unknown as PolicySession;
    return this.session;
  }

  async nativeInvoke(request: Record<string, unknown>): Promise<Response> {
    if (this.session === undefined) throw new Error("policy session is required");
    const requested = String(request.action ?? "get");
    const action = requested === "list" ? "tinycloud.kv/list" : requested === "put" ? "tinycloud.kv/put" : "tinycloud.kv/get";
    const resource = this.session.resource.path;
    const bodyBytes = Array.isArray(request.body) ? Uint8Array.from(request.body as number[]) : undefined;
    const bodyDigest = bodyBytes === undefined ? undefined : await digestBytes(bodyBytes);
    const limit = typeof request.limit === "number" ? request.limit : 100;
    const cursor = typeof request.cursor === "string" ? request.cursor : undefined;
    const invocationBase = { type: "TinyCloudShareReadInvocation", version: 1, sessionId: this.session.sessionId, shareCid: this.options.shareCid, shareId: this.options.envelope.shareId, policyCid: this.options.envelope.authorizationTarget.kind === "policy" ? this.options.envelope.authorizationTarget.policyCid : "", delegationCid: this.options.envelope.delegationCid, authorityMaterialHandle: this.options.envelope.authorityMaterialHandle, authorityMaterialDigest: this.options.envelope.authorityMaterialDigest, contentSource: this.options.envelope.contentSource, contentSourceDigest: this.options.envelope.contentSourceDigest, holderDid: this.session.holderDid, targetOrigin: this.options.envelope.target.origin, nodeAudience: this.options.envelope.target.nodeAudience, action, resource, ...(action === "tinycloud.kv/list" ? { limit, ...(cursor === undefined ? {} : { cursor }) } : {}), ...(bodyDigest === undefined ? {} : { bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }), issuedAt: new Date().toISOString(), expiresAt: this.session.expiresAt, jti: crypto.randomUUID() };
    const requestBodyDigest = await digest({ sessionId: this.session.sessionId, delegationCid: this.options.envelope.delegationCid, authorityMaterialHandle: this.options.envelope.authorityMaterialHandle, authorityMaterialDigest: this.options.envelope.authorityMaterialDigest, contentSource: this.options.envelope.contentSource, contentSourceDigest: this.options.envelope.contentSourceDigest, action, resource, invocation: invocationBase });
    const invocation = { ...invocationBase, requestBodyDigest };
    if (this.holderProof === undefined) throw new Error("holder proof is required");
    const invocationBytes = new TextEncoder().encode(`${SIGNATURE_DOMAINS.readInvocation}${canonicalize(invocation)}`);
    const nativeProof = this.nativeSigner === undefined ? this.holderProof : { ...this.holderProof, signature: toBase64Url(await this.nativeSigner(invocationBytes)) };
    const signed = { request: { sessionId: this.session.sessionId, delegationCid: this.options.envelope.delegationCid, authorityMaterialHandle: this.options.envelope.authorityMaterialHandle, authorityMaterialDigest: this.options.envelope.authorityMaterialDigest, contentSource: this.options.envelope.contentSource, contentSourceDigest: this.options.envelope.contentSourceDigest, action, resource, requestBodyDigest, invocation, proof: nativeProof }, ...(action === "tinycloud.kv/list" ? { limit, ...(cursor === undefined ? {} : { cursor }) } : {}), ...(bodyBytes === undefined ? {} : { body: toBase64Url(bodyBytes), bodyDigest, ifMatch: request.ifMatch, contentType: request.contentType }) };
    return this.fetchFn(new URL("/invoke", this.options.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/vnd.tinycloud.share+json", "content-type": "application/vnd.tinycloud.share+json" }, body: JSON.stringify(signed) });
  }
}
