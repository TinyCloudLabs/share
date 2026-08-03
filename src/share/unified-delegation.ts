import {
  canonicalize,
  computeCid,
  ed25519PublicKeyFromDidKey,
  fromBase64Url,
  shareEnvelopeV3Schema,
  unsignedShareEnvelopeV3Schema,
  toBase64Url,
  type ShareEnvelopeV3,
  type PolicyCredentialRequirementV1,
  type UnifiedContentSource,
  type UnifiedPolicy,
  type UnifiedPolicyCapability,
  type UnifiedRoot,
  type UnsignedShareEnvelopeV3,
} from "@tinycloud/share-envelope";
import {
  parseCompactUcanAuthorization as verifyCompactUcanAuthorization,
  signCompactUcanAuthorization,
} from "@tinycloud/sdk-core/policy";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import type { ResourceSelector, RecipientMatcher, ShareAction } from "@tinycloud/share-envelope";

export const POLICY_V1_DOMAIN = "xyz.tinycloud.policy/policy/v1\0";
export const POLICY_V2_DOMAIN = "xyz.tinycloud.policy/policy/v2\0";
export const CONTENT_SOURCE_V1_DOMAIN = "xyz.tinycloud.policy/ContentSource/v1\0";
export const NATIVE_PROJECTION_V1_DOMAIN = "xyz.tinycloud.policy/NativeProjection/v1\0";
export const POLICY_CAPABILITY_V1_DOMAIN = "xyz.tinycloud.policy/PolicyCapability/v1\0";
export const POLICY_SESSION_UCAN_V1_PROFILE = "policy-session-ucan/v1";
export const LAST_V2_CREATE_AT = "2026-09-30T00:00:00Z";
export const MAX_LEGACY_ENVELOPE_EXPIRES_AT = "2026-12-29T00:00:00Z";
export const LAST_V2_READ_AT = "2027-01-05T00:00:00Z";
const textEncoder = new TextEncoder();

export type UnifiedKvCapability = Extract<UnifiedPolicyCapability, { readonly kind: "kv" }>;
export type UnifiedEncryptionCapability = Extract<UnifiedPolicyCapability, { readonly kind: "encryption" }>;

export interface PortableDelegationLike {
  readonly cid: string;
  readonly delegationHeader: { readonly Authorization: string };
  readonly delegateDID: string;
  readonly spaceId: string;
  readonly path: string;
  readonly actions: readonly string[];
  readonly expiry: Date;
  readonly resources?: readonly Record<string, unknown>[];
}

export interface UnifiedPolicyInput {
  readonly policyId: string;
  readonly ownerDid: string;
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly contentSource: UnifiedContentSource;
  readonly capabilityCeiling: readonly UnifiedPolicyCapability[];
  readonly credentialRequirement?: PolicyCredentialRequirementV1;
}

export interface OwnerRootInput {
  readonly ownerDid: string;
  readonly role: "policy-authority" | "policy-enforcement";
  readonly audienceDid: string;
  readonly policyId: string;
  readonly policyDigestHex: string;
  readonly policyCid: string;
  readonly contentSourceDigestHex: string;
  readonly capabilityCeilingHashHex: string;
  readonly nativeProjectionHashHex: string;
  readonly expiresAt: Date;
  readonly nodeAudience: string;
  readonly capabilities: readonly UnifiedPolicyCapability[];
}

/** The additive SDK hook used by Share; it is deliberately not a share read/session API. */
export interface UnifiedOwnerRootFactory {
  createOwnerRoot(input: OwnerRootInput): Promise<PortableDelegationLike>;
}

export interface UnifiedPolicyRegistration {
  readonly policyCid: string;
  readonly policyRootCid: string;
  readonly enforcementRootCid: string;
}

type AttestedEnforcerBindingV2 = ShareEnvelopeV3["attestedEnforcerBinding"];

export interface UnifiedPolicyClaim {
  readonly claim: Record<string, unknown>;
  readonly presentation: Record<string, unknown>;
  /** Exact ordinary policy-session UCAN Authorization returned by the ceremony. */
  readonly authorization: string;
}

export interface UnifiedClaimTransport {
  readonly fetchFn?: typeof fetch;
  readonly nodeOrigin: string;
  readonly recipientDid: string;
  readonly importDelegation?: (delegation: PortableDelegationLike) => Promise<unknown>;
  readonly importOrdinaryDelegation?: (authorization: string) => Promise<unknown>;
  readonly challenge?: Record<string, unknown>;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function digestHex(value: unknown, domain: string): string {
  return hex(sha256(textEncoder.encode(`${domain}${canonicalize(value)}`)));
}

function sortByCanonicalJson<T>(values: readonly T[]): readonly T[] {
  return [...values]
    .map((value) => ({ value, canonical: canonicalize(value) }))
    .sort((left, right) => left.canonical < right.canonical ? -1 : left.canonical > right.canonical ? 1 : 0)
    .map(({ value }) => value);
}

function base32Lower(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let output = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}

function policyIdForDigest(digest: string): string {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new TypeError("policy digest is not SHA-256 hex");
  return `pol_${base32Lower(Uint8Array.from(digest.match(/../g)!, (byte) => Number.parseInt(byte, 16)))}`;
}

function assertV3Time(value: string, label: string): void {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new TypeError(`${label} is not canonical UTC time`);
}

function assertCapabilityCeiling(capabilities: readonly UnifiedPolicyCapability[], source: UnifiedContentSource): void {
  if (capabilities.length !== 2) throw new TypeError("v3 policy must contain exactly one KV and one decrypt ceiling");
  let kv: UnifiedKvCapability | undefined;
  let encryption: UnifiedEncryptionCapability | undefined;
  for (const capability of capabilities) {
    if (capability.kind === "kv") kv = capability;
    else if (capability.kind === "encryption") encryption = capability;
  }
  if (kv === undefined || kv.resource !== source.kvResource || kv.selector !== source.selector || kv.actions.length === 0) throw new TypeError("v3 policy must contain one KV ceiling");
  if (encryption === undefined || encryption.resource !== source.encryptionNetwork || encryption.action !== "tinycloud.encryption/decrypt") throw new TypeError("v3 policy must contain exact decrypt ceiling");
}

export function createUnifiedPolicy(input: UnifiedPolicyInput & { readonly sign: (bytes: Uint8Array) => Promise<Uint8Array> }): Promise<{ readonly policy: UnifiedPolicy; readonly bytes: Uint8Array; readonly policyDigestHex: string; readonly policyCid: string }> {
  assertV3Time(input.createdAt, "policy.createdAt");
  if (input.expiresAt !== undefined) assertV3Time(input.expiresAt, "policy.expiresAt");
  assertCapabilityCeiling(input.capabilityCeiling, input.contentSource);
  const policyFields = {
    ownerDid: input.ownerDid,
    createdAt: input.createdAt,
    ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
    contentSource: input.contentSource,
    capabilityCeiling: [...input.capabilityCeiling],
  };
  const unsigned = input.credentialRequirement === undefined
    ? { schema: "xyz.tinycloud.policy/policy/v1" as const, ...policyFields }
    : { schema: "xyz.tinycloud.policy/policy/v2" as const, ...policyFields, credentialRequirement: input.credentialRequirement };
  const signatureDomain = input.credentialRequirement === undefined ? POLICY_V1_DOMAIN : POLICY_V2_DOMAIN;
  const policyDigestHex = digestHex(unsigned, signatureDomain);
  const policyId = input.policyId || policyIdForDigest(policyDigestHex);
  if (policyId !== policyIdForDigest(policyDigestHex)) throw new TypeError("policyId does not match policy digest");
  return (async () => {
    // The policy-engine contract signs SHA-256(domain || JCS(unsigned)), not
    // the variable-length preimage.  Keeping this byte boundary here makes
    // the browser signer and Rust verifier use the same golden-vector input.
    const signatureDigest = sha256(textEncoder.encode(`${signatureDomain}${canonicalize(unsigned)}`));
    const signature = await input.sign(signatureDigest);
    if (signature.length !== 64) throw new TypeError("policy signature must be Ed25519");
    const policy: UnifiedPolicy = {
      ...unsigned,
      policyId,
      signature: { suite: "Ed25519", signerDid: input.ownerDid, value: toBase64Url(signature) },
    };
    const bytes = textEncoder.encode(canonicalize(policy));
    const policyCid = await computeCid(bytes);
    return { policy, bytes, policyDigestHex, policyCid };
  })();
}

export function nativeProjectionHashHex(capabilities: readonly UnifiedPolicyCapability[]): string {
  const projection = sortByCanonicalJson(capabilities.map((capability) => capability.kind === "encryption"
    ? { service: "tinycloud.encryption", space: capability.resource, path: capability.resource, actions: [capability.action] }
    : { service: "tinycloud.kv", space: capability.resource.slice("tinycloud://".length).split("/")[0], path: capability.resource.split("/kv/")[1], actions: [...capability.actions], caveat: { type: "xyz.tinycloud.resource/selector", kind: capability.selector, value: capability.resource } }));
  return digestHex(projection, NATIVE_PROJECTION_V1_DOMAIN);
}

function rootFromDelegation(value: PortableDelegationLike, input: OwnerRootInput): UnifiedRoot {
  const authorization = value.delegationHeader.Authorization.replace(/^Bearer\s+/i, "");
  const compact = verifyCompactUcanAuthorization(authorization, value.cid);
  const fact = compact.payload.fct[0];
  if (fact === undefined) throw new TypeError("owner root signed projection mismatch");
  const expectedAttenuation = attenuationForCapabilities(input.capabilities);
  const principal = compact.payload.iss.split("#", 1)[0];
  const expectedMode = input.role === "policy-authority" ? "policy-source" : "conditional-mint";
  const required = {
    role: input.role,
    mode: expectedMode,
    ownerDid: input.ownerDid,
    policyId: input.policyId,
    policyDigestHex: input.policyDigestHex,
    policyCid: input.policyCid,
    contentSourceDigestHex: input.contentSourceDigestHex,
    capabilityCeilingHashHex: input.capabilityCeilingHashHex,
    nativeProjectionHashHex: input.nativeProjectionHashHex,
    nodeAudience: input.nodeAudience,
  };
  if (principal !== input.ownerDid || compact.payload.aud !== input.audienceDid || compact.payload.prf.length !== 0 || compact.payload.exp !== Math.floor(input.expiresAt.getTime() / 1000) || canonicalize(compact.payload.att) !== canonicalize(expectedAttenuation) || Object.entries(required).some(([key, expected]) => fact[key] !== expected) || (input.role === "policy-enforcement" ? fact.enforcerDid !== input.audienceDid : "enforcerDid" in fact)) throw new TypeError("owner root signed projection mismatch");
  return { cid: value.cid, authorization, role: input.role };
}

function attenuationForCapabilities(capabilities: readonly UnifiedPolicyCapability[]): Record<string, Record<string, readonly Record<string, unknown>[]>> {
  const attenuation: Record<string, Record<string, readonly Record<string, unknown>[]>> = {};
  for (const capability of capabilities) {
    if (capability.kind === "encryption") attenuation[capability.resource] = { [capability.action]: [{}] };
    else attenuation[capability.resource] = Object.fromEntries(capability.actions.map((action) => [action, [{ kind: capability.selector, type: "xyz.tinycloud.resource/selector", value: capability.resource }]]));
  }
  return attenuation;
}

export async function createSiblingRoots(input: {
  readonly factory: UnifiedOwnerRootFactory;
  readonly ownerDid: string;
  readonly policy: UnifiedPolicy;
  readonly policyCid: string;
  readonly policyDigestHex: string;
  readonly contentSourceDigestHex: string;
  readonly nativeProjectionHashHex: string;
  readonly enforcerDid: string;
  readonly nodeAudience: string;
  readonly expiresAt: Date;
}): Promise<{ readonly policyRoot: UnifiedRoot; readonly enforcementRoot: UnifiedRoot }> {
  const capabilityCeiling = sortByCanonicalJson(input.policy.capabilityCeiling);
  const common = {
    ownerDid: input.ownerDid,
    policyId: input.policy.policyId,
    policyDigestHex: input.policyDigestHex,
    policyCid: input.policyCid,
    contentSourceDigestHex: input.contentSourceDigestHex,
    capabilityCeilingHashHex: digestHex(capabilityCeiling, POLICY_CAPABILITY_V1_DOMAIN),
    nativeProjectionHashHex: input.nativeProjectionHashHex,
    expiresAt: input.expiresAt,
    nodeAudience: input.nodeAudience,
    capabilities: capabilityCeiling,
  };
  const policyRoot = await input.factory.createOwnerRoot({ ...common, role: "policy-authority", audienceDid: `did:tinycloud:policy:${input.policyDigestHex}` });
  const enforcementRoot = await input.factory.createOwnerRoot({ ...common, role: "policy-enforcement", audienceDid: input.enforcerDid });
  return {
    policyRoot: rootFromDelegation(policyRoot, { ...common, role: "policy-authority", audienceDid: `did:tinycloud:policy:${input.policyDigestHex}` }),
    enforcementRoot: rootFromDelegation(enforcementRoot, { ...common, role: "policy-enforcement", audienceDid: input.enforcerDid }),
  };
}

export function contentSourceDigestHex(source: UnifiedContentSource): string {
  return digestHex(source, CONTENT_SOURCE_V1_DOMAIN);
}

export async function signV3Envelope(input: {
  readonly unsigned: UnsignedShareEnvelopeV3;
  readonly signerDid: string;
  readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;
}): Promise<ShareEnvelopeV3> {
  unsignedShareEnvelopeV3Schema.parse(input.unsigned);
  const signature = await input.sign(sha256(textEncoder.encode(`xyz.tinycloud.share/envelope/v3\0${canonicalize(input.unsigned)}`)));
  if (signature.length !== 64) throw new TypeError("v3 envelope signature must be Ed25519");
  const envelope = { ...input.unsigned, signature: { signerDid: input.signerDid, algorithm: "Ed25519" as const, value: toBase64Url(signature) } };
  return shareEnvelopeV3Schema.parse(envelope);
}

export async function registerUnifiedPolicy(input: {
  readonly nodeOrigin: string;
  readonly policy: UnifiedPolicy;
  readonly policyCid: string;
  readonly policyRoot: UnifiedRoot;
  readonly enforcementRoot: UnifiedRoot;
  readonly contentSourceDigestHex: string;
  readonly nativeProjectionHashHex: string;
  readonly attestedEnforcerBinding: AttestedEnforcerBindingV2;
  readonly fetchFn?: typeof fetch;
}): Promise<UnifiedPolicyRegistration> {
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const response = await fetchFn(new URL("/share/v3/policies", input.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ policyCid: input.policyCid, policy: input.policy, policyRoot: input.policyRoot.authorization, enforcementRoot: input.enforcementRoot.authorization, contentSourceDigestHex: input.contentSourceDigestHex, nativeProjectionHashHex: input.nativeProjectionHashHex, attestedEnforcerBinding: input.attestedEnforcerBinding }) });
  if (!response.ok) throw new Error(`v3 policy registration rejected (${response.status})`);
  const value = await response.json() as Record<string, unknown>;
  if (value.policyCid !== input.policyCid || value.policyRootCid !== input.policyRoot.cid || value.enforcementRootCid !== input.enforcementRoot.cid) throw new Error("v3 policy registration binding mismatch");
  return { policyCid: input.policyCid, policyRootCid: input.policyRoot.cid, enforcementRootCid: input.enforcementRoot.cid };
}

export async function requestAttestedEnforcerBinding(input: {
  readonly nodeOrigin: string;
  readonly rootExpiresAt: string;
  readonly fetchFn?: typeof fetch;
}): Promise<AttestedEnforcerBindingV2> {
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const response = await fetchFn(new URL("/share/v3/enforcer-bindings", input.nodeOrigin), {
    method: "POST",
    redirect: "error",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ rootExpiresAt: input.rootExpiresAt }),
  });
  if (!response.ok) throw new Error(`v3 enforcer binding rejected (${response.status})`);
  const value = await response.json() as unknown;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("v3 enforcer binding is invalid");
  const binding = value as Record<string, unknown>;
  const signature = binding.signature;
  if (Object.keys(binding).length !== 7 || binding.schema !== "xyz.tinycloud.policy/attested-enforcer/v2" || typeof binding.enforcerDid !== "string" || binding.nodeAudience !== binding.enforcerDid || typeof signature !== "object" || signature === null || Array.isArray(signature)) throw new Error("v3 enforcer binding is invalid");
  const proof = signature as Record<string, unknown>;
  if (Object.keys(proof).length !== 3 || proof.suite !== "Ed25519" || proof.signerDid !== binding.enforcerDid || typeof proof.value !== "string") throw new Error("v3 enforcer binding signature is invalid");
  const expectedBindingDigest = hex(sha256(textEncoder.encode(canonicalize({ enforcerDid: binding.enforcerDid, nodeAudience: binding.nodeAudience }))));
  if (binding.attestationBindingDigestHex !== expectedBindingDigest) throw new Error("v3 enforcer binding digest is invalid");
  const { signature: _signature, ...unsigned } = binding;
  const digest = sha256(textEncoder.encode(`xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0${canonicalize(unsigned)}`));
  if (!ed25519.verify(fromBase64Url(proof.value), digest, ed25519PublicKeyFromDidKey(binding.enforcerDid), { zip215: false })) throw new Error("v3 enforcer binding signature is invalid");
  return binding as unknown as AttestedEnforcerBindingV2;
}

export async function requestUnifiedChallenge(input: {
  readonly nodeOrigin: string;
  readonly policyCid: string;
  readonly recipientDid: string;
  readonly requestedCapabilities: readonly UnifiedPolicyCapability[];
  readonly fetchFn?: typeof fetch;
}): Promise<Record<string, unknown>> {
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const response = await fetchFn(new URL("/share/v3/policy/challenges", input.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ policyCid: input.policyCid, recipientDid: input.recipientDid, requestedCapabilities: input.requestedCapabilities }) });
  if (!response.ok) throw new Error(`v3 policy challenge rejected (${response.status})`);
  const challenge = await response.json() as Record<string, unknown>;
  if (typeof challenge.challengeId !== "string" || typeof challenge.nonce !== "string" || challenge.policyCid !== input.policyCid || challenge.recipientDid !== input.recipientDid) throw new Error("v3 policy challenge binding mismatch");
  return challenge;
}

export async function claimUnifiedDelegation(input: UnifiedClaimTransport & { readonly policyCid: string; readonly policyRootCid: string; readonly enforcementRootCid: string; readonly requestedCapabilities: readonly UnifiedPolicyCapability[]; readonly claim: Record<string, unknown>; readonly presentation: Record<string, unknown> }): Promise<PortableDelegationLike> {
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const challenge = input.challenge ?? await requestUnifiedChallenge({ nodeOrigin: input.nodeOrigin, policyCid: input.policyCid, recipientDid: input.recipientDid, requestedCapabilities: input.requestedCapabilities, fetchFn });
  if (typeof challenge.challengeId !== "string" || typeof challenge.nonce !== "string" || challenge.policyCid !== input.policyCid || challenge.recipientDid !== input.recipientDid) throw new Error("v3 policy challenge binding mismatch");
  const response = await fetchFn(new URL("/share/v3/policy/delegations", input.nodeOrigin), { method: "POST", redirect: "error", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ policyCid: input.policyCid, challengeId: challenge.challengeId, nonce: challenge.nonce, claim: input.claim, presentation: input.presentation }) });
  if (!response.ok) throw new Error(`v3 policy delegation rejected (${response.status})`);
  const value = await response.json() as Record<string, unknown>;
  if (value.admitted !== true || typeof value.authorization !== "string") throw new Error("v3 policy delegation response is not admitted");
  if (typeof value.sessionCid !== "string") throw new Error("v3 policy delegation CID is missing");
  const compact = verifyCompactUcanAuthorization(value.authorization, value.sessionCid);
  const fact = compact.payload.fct[0];
  if (fact === undefined) throw new Error("v3 policy delegation signed binding mismatch");
  if (compact.payload.aud !== input.recipientDid
    || fact.recipientDid !== input.recipientDid
    || fact.policyCid !== input.policyCid
    || fact.policyDelegationCid !== input.policyRootCid
    || fact.enforcementDelegationCid !== input.enforcementRootCid
    || fact.profile !== POLICY_SESSION_UCAN_V1_PROFILE
    || compact.payload.prf.length !== 2
    || compact.payload.prf[0] !== input.policyRootCid
    || compact.payload.prf[1] !== input.enforcementRootCid
    || compact.payload.exp - compact.payload.nbf > 60) throw new Error("v3 policy delegation signed binding mismatch");
  const resources = Object.entries(compact.payload.att).map(([resource, abilities]) => {
    if (abilities === null || typeof abilities !== "object" || Array.isArray(abilities)) throw new Error("v3 policy delegation attenuation is invalid");
    const actions = Object.keys(abilities);
    if (actions.length === 0) throw new Error("v3 policy delegation attenuation is empty");
    if (resource.startsWith("urn:tinycloud:encryption:")) return { service: "tinycloud.encryption", space: resource, path: resource, actions };
    const match = /^tinycloud:\/\/([^/]+)\/kv\/(.+)$/.exec(resource);
    if (match === null) throw new Error("v3 policy delegation resource is invalid");
    return { service: "tinycloud.kv", space: match[1]!, path: match[2]!, actions };
  });
  const primary = resources.find((resource) => resource.service === "tinycloud.kv") ?? resources[0];
  if (primary === undefined) throw new Error("v3 policy delegation has no resources");
  const delegation: PortableDelegationLike = { cid: value.sessionCid, delegationHeader: { Authorization: value.authorization }, delegateDID: input.recipientDid, spaceId: primary.space, path: primary.path, actions: primary.actions, resources, expiry: new Date(compact.payload.exp * 1000) };
  if (input.importOrdinaryDelegation !== undefined) await input.importOrdinaryDelegation(value.authorization);
  else if (input.importDelegation !== undefined) await input.importDelegation(delegation);
  else {
    const imported = await fetchFn(new URL("/delegate", input.nodeOrigin), { method: "POST", redirect: "error", headers: { Authorization: value.authorization } });
    if (!imported.ok) throw new Error(`ordinary delegation import rejected (${imported.status})`);
  }
  return delegation;
}

/** All post-claim data goes through a fresh recipient-signed ordinary invocation. */
export async function invokeUnifiedDelegation(input: {
  readonly nodeOrigin: string;
  readonly sessionAuthorization: string;
  readonly sessionCid: string;
  readonly recipientDid: string;
  readonly nodeAudience: string;
  readonly resource: string;
  readonly action: string;
  readonly caveat?: Readonly<Record<string, unknown>>;
  readonly request?: Record<string, unknown> | Uint8Array;
  readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;
  readonly now?: number;
  readonly fetchFn?: typeof fetch;
}): Promise<Response> {
  const fetchFn = input.fetchFn ?? globalThis.fetch.bind(globalThis);
  const session = verifyCompactUcanAuthorization(input.sessionAuthorization, input.sessionCid);
  if (session.payload.aud !== input.recipientDid) throw new Error("v3 policy session recipient mismatch");
  const sessionFact = session.payload.fct[0];
  if (sessionFact === undefined) throw new Error("v3 policy session facts are missing");
  const now = input.now ?? Math.floor(Date.now() / 1000);
  let facts: Readonly<Record<string, unknown>> = { type: "tinycloud.policy.invocation/v1", policyCid: sessionFact.policyCid, sessionCid: session.cid };
  if (input.action === "tinycloud.encryption/decrypt") {
    if (input.request === undefined || input.request instanceof Uint8Array) throw new Error("decrypt invocation requires the canonical request body");
    const body = input.request;
    const required = ["type", "targetNode", "networkId", "alg", "keyVersion", "encryptedSymmetricKey", "encryptedSymmetricKeyHash", "receiverPublicKey", "receiverPublicKeyHash"] as const;
    if (required.some((key) => !(key in body)) || body.type !== "tinycloud.encryption.decrypt/v1" || body.targetNode !== input.nodeAudience || body.networkId !== input.resource) throw new Error("decrypt invocation body binding is invalid");
    facts = { type: body.type, targetNode: body.targetNode, networkId: body.networkId, bodyHash: hex(sha256(textEncoder.encode(canonicalize(body)))), encryptedSymmetricKeyHash: body.encryptedSymmetricKeyHash, receiverPublicKeyHash: body.receiverPublicKeyHash, alg: body.alg, keyVersion: body.keyVersion };
  }
  const invocation = await signCompactUcanAuthorization({
    issuerDid: input.recipientDid,
    audienceDid: input.nodeAudience,
    attenuation: { [input.resource]: { [input.action]: [input.caveat ?? {}] } },
    facts: [facts],
    proofs: [session.cid],
    notBefore: now,
    expiresAt: Math.min(now + 60, session.payload.exp),
    nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
    sign: input.sign,
  });
  const json = input.request !== undefined && !(input.request instanceof Uint8Array);
  return fetchFn(new URL("/invoke", input.nodeOrigin), {
    method: "POST",
    redirect: "error",
    headers: { accept: "application/json", ...(json ? { "content-type": "application/json" } : {}), Authorization: invocation.authorization },
    ...(input.request === undefined ? {} : { body: json ? JSON.stringify(input.request) : input.request as BodyInit }),
  });
}

export function rejectV3Downgrade(value: unknown): asserts value is { readonly version: 3 } {
  if (value === null || typeof value !== "object" || Array.isArray(value) || (value as Record<string, unknown>).version !== 3) throw new Error("v3 share requires an explicit version-3 envelope");
}

export function isExactDecryptCapability(capability: UnifiedPolicyCapability, network: string): boolean {
  return capability.kind === "encryption" && capability.resource === network && capability.action === "tinycloud.encryption/decrypt";
}

export type { RecipientMatcher, ResourceSelector, ShareAction };
