import {
  canonicalize,
  computeCid,
  didKeyFromEd25519PublicKey,
  ed25519PublicKeyFromDidKey,
  fromBase64Url,
  isCanonicalRawCid,
  isCanonicalHttpsOrigin,
  isCanonicalPathSegment,
  toBase64Url,
} from "@tinycloud/share-envelope";
import { blake3 } from "@noble/hashes/blake3";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { ed25519 } from "@noble/curves/ed25519";

import {
  canonicalEmail,
  canonicalDigest,
  validateSource,
  type ContentSource,
  type SenderScope,
} from "./protocol.js";

const PARENT_SCHEMA = "xyz.tinycloud.policy/enforcement-delegation/v1";
const PARENT_DOMAIN = "xyz.tinycloud.policy/enforcement-delegation/v1\0";
const EIP191_PREFIX = "\x19Ethereum Signed Message:\n32";
const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const HEX_256 = /^[0-9a-f]{64}$/;

export interface ValidatedShareAuthority {
  readonly policyCid: string;
  readonly policyDigest: string;
  readonly contentSourceDigest: string;
  readonly policyBytes: string;
  readonly policyAuthorityCid: string;
  readonly policyAuthorityBytes: string;
  readonly policyEnforcementCid: string;
  readonly policyEnforcementBytes: string;
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} is invalid.`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TypeError(`${label} has an invalid field set.`);
}

function exactString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} is required.`);
  return value;
}

function digest(value: unknown, label: string): void {
  if (typeof value !== "string" || !B64_256.test(value)) throw new TypeError(`${label} must be a canonical SHA-256 digest.`);
  try {
    const bytes = fromBase64Url(value);
    if (bytes.length !== 32 || toBase64Url(bytes) !== value) throw new Error("wrong length");
  } catch {
    throw new TypeError(`${label} must be a canonical SHA-256 digest.`);
  }
}

function canonicalTime(value: unknown, label: string): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) throw new TypeError(`${label} must be canonical UTC.`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== (value.includes(".") ? value : value.replace("Z", ".000Z"))) throw new TypeError(`${label} must be canonical UTC.`);
  return parsed;
}

function canonicalJsonBytes(value: unknown, label: string): { readonly bytes: Uint8Array; readonly object: Record<string, unknown> } {
  if (typeof value !== "string") throw new TypeError(`${label} must be canonical base64url JSON.`);
  let bytes: Uint8Array;
  let parsed: unknown;
  try {
    bytes = fromBase64Url(value);
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError(`${label} must be canonical base64url JSON.`);
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (canonicalize(parsed) !== text) throw new TypeError(`${label} must be canonical JCS.`);
  return { bytes, object: objectValue(parsed, label) };
}

function nodeCid(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const multihash = Uint8Array.of(0x1e, 0x20, ...blake3(bytes));
  const cidBytes = Uint8Array.of(1, 0x55, ...multihash);
  let buffer = 0;
  let bits = 0;
  let encoded = "b";
  for (const byte of cidBytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      encoded += alphabet[(buffer >>> bits) & 31];
    }
  }
  if (bits !== 0) encoded += alphabet[(buffer << (5 - bits)) & 31];
  return encoded;
}

function assertNodeCid(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !/^bafkr4[a-z2-7]{53}$/.test(value)) throw new TypeError(`${label} is not a canonical Node delegation CID.`);
}

function ethereumDid(publicKey: Uint8Array): string {
  return `did:pkh:eip155:1:0x${Array.from(keccak_256(publicKey.slice(1)).slice(-20), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer));
}

async function verifyOwnerSignature(artifact: Record<string, unknown>, ownerDid: string): Promise<void> {
  const signature = objectValue(artifact.signature, "policy parent signature");
  exactKeys(signature, ["suite", "value"], "policy parent signature");
  if (signature.suite !== "eip191-secp256k1-sha256-jcs-v1" || typeof signature.value !== "string") throw new TypeError("The policy parent signature suite is invalid.");
  let signatureBytes: Uint8Array;
  try { signatureBytes = fromBase64Url(signature.value); } catch { throw new TypeError("The policy parent signature is invalid."); }
  if (signatureBytes.length !== 65 || signatureBytes[64] === undefined || signatureBytes[64] > 1) throw new TypeError("The policy parent signature is not standard EIP-191.");
  const unsigned = { ...artifact };
  delete unsigned.signature;
  delete unsigned.delegationCid;
  const unsignedText = canonicalize(unsigned);
  const signedDigest = await sha256(new TextEncoder().encode(`${PARENT_DOMAIN}${unsignedText}`));
  const messageHash = keccak_256(new Uint8Array([...new TextEncoder().encode(EIP191_PREFIX), ...signedDigest]));
  try {
    const parsed = secp256k1.Signature.fromBytes(signatureBytes.slice(0, 64), "compact");
    if (parsed.hasHighS()) throw new Error("high-S signature");
    const recovered = parsed.addRecoveryBit(signatureBytes[64]).recoverPublicKey(messageHash).toRawBytes(false);
    if (ethereumDid(recovered) !== ownerDid) throw new Error("owner mismatch");
  } catch {
    throw new TypeError("The policy parent is not signed by the authenticated policy owner.");
  }
}

function assertCapability(value: unknown, source: ContentSource): void {
  const capability = objectValue(value, "policy parent capability");
  exactKeys(capability, ["actions", "path", "service", "space"], "policy parent capability");
  if (capability.path !== source.path || capability.space !== source.space || capability.service !== (source.kind === "kv" ? "tinycloud.kv" : "tinycloud.sql") || !Array.isArray(capability.actions) || capability.actions.length !== 1 || capability.actions[0] !== source.action) throw new TypeError("The policy parent capability is not bound to the requested source.");
}

async function verifyParent(input: {
  readonly bytes: Uint8Array;
  readonly cid: unknown;
  readonly role: "policy-authority" | "policy-enforcement";
  readonly source: ContentSource;
  readonly ownerDid: string;
  readonly nodeAudience: string;
  readonly policyDigest: string;
  readonly expiresAt: string;
  readonly now: string;
}): Promise<string> {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(input.bytes);
  const artifact = objectValue(JSON.parse(text), "policy parent");
  exactKeys(artifact, ["audienceDid", "capabilities", "delegationCid", "delegationMode", "expiresAt", "facts", "issuerDid", "notBefore", "proofCids", "role", "schema", "signature"], "policy parent");
  assertNodeCid(artifact.delegationCid, "policy parent delegation CID");
  if (artifact.delegationCid !== input.cid || nodeCid(new TextEncoder().encode(canonicalize(Object.fromEntries(Object.entries(artifact).filter(([key]) => key !== "delegationCid"))))) !== artifact.delegationCid) throw new TypeError("The policy parent CID does not match its canonical raw delegation bytes.");
  if (artifact.schema !== PARENT_SCHEMA || artifact.role !== input.role || artifact.issuerDid !== input.ownerDid || typeof artifact.audienceDid !== "string") throw new TypeError("The policy parent identity binding is invalid.");
  const facts = objectValue(artifact.facts, "policy parent facts");
  if (typeof facts["xyz.tinycloud.policy/ownerDid"] !== "string" || facts["xyz.tinycloud.policy/ownerDid"] !== input.ownerDid || typeof facts["xyz.tinycloud.policy/policyDigestHex"] !== "string" || facts["xyz.tinycloud.policy/policyDigestHex"] !== Array.from(fromBase64Url(input.policyDigest), (byte) => byte.toString(16).padStart(2, "0")).join("")) throw new TypeError("The policy parent policy binding is invalid.");
  if (canonicalTime(artifact.notBefore, "policy parent notBefore") > canonicalTime(input.now, "current time") || canonicalTime(artifact.expiresAt, "policy parent expiresAt") < canonicalTime(input.expiresAt, "share expiresAt")) throw new TypeError("The policy parent expiry is outside the requested share window.");
  if (!Array.isArray(artifact.proofCids) || artifact.proofCids.length !== 0 || !Array.isArray(artifact.capabilities) || artifact.capabilities.length === 0) throw new TypeError("The policy parent capability chain is invalid.");
  artifact.capabilities.forEach((capability) => assertCapability(capability, input.source));
  if (input.role === "policy-authority") {
    if (artifact.audienceDid !== input.nodeAudience) throw new TypeError("The policy authority parent is not addressed to the trusted node.");
  } else {
    if (typeof facts["xyz.tinycloud.policy/enforcerDid"] !== "string" || artifact.audienceDid !== facts["xyz.tinycloud.policy/enforcerDid"] || facts["xyz.tinycloud.policy/nodeAudience"] !== input.nodeAudience) throw new TypeError("The policy enforcement parent is not bound to the authenticated enforcer.");
  }
  await verifyOwnerSignature(artifact, input.ownerDid);
  return artifact.delegationCid;
}

function assertEnrollment(material: Record<string, unknown>, scope: SenderScope): Record<string, unknown> {
  const enrollment = objectValue(material.enrollment, "policy authority enrollment");
  exactKeys(enrollment, ["enabled", "invitationKid", "invitationPublicKey", "keyVersion", "nodeAudience", "targetOrigin"], "policy authority enrollment");
  if (enrollment.enabled !== true || enrollment.targetOrigin !== scope.targetOrigin || enrollment.nodeAudience !== scope.nodeAudience || enrollment.invitationKid !== scope.trustedNode.invitationKid || enrollment.keyVersion !== scope.trustedNode.keyVersion || enrollment.invitationPublicKey !== toBase64Url(scope.trustedNode.invitationPublicKey)) throw new TypeError("The enrollment invitation key, kid, version, or target is not trusted.");
  if (scope.trustedNode.keyVersion < 1 || !scope.trustedNode.invitationKid.startsWith(`${scope.nodeAudience}#`) || scope.trustedNode.invitationPublicKey.length !== 32) throw new TypeError("The authenticated enrollment is invalid.");
  return enrollment;
}

function signerDidFromKid(value: unknown, label: string): string {
  if (typeof value !== "string") throw new TypeError(`${label} is invalid.`);
  const separator = value.indexOf("#");
  if (separator <= 0 || separator !== value.lastIndexOf("#")) throw new TypeError(`${label} is invalid.`);
  return value.slice(0, separator);
}

function verifyEd25519Evidence(value: Record<string, unknown>, signature: Record<string, unknown>, domain: string, trustedDid: string, label: string): void {
  if (signature.alg !== "EdDSA" || typeof signature.kid !== "string" || typeof signature.value !== "string") throw new TypeError(`${label} signature is invalid.`);
  const signerDid = signerDidFromKid(signature.kid, `${label} signer key`);
  if (signerDid !== trustedDid || signature.kid !== `${trustedDid}#${trustedDid.slice("did:key:".length)}`) throw new TypeError(`${label} signer identity is not trusted.`);
  let publicKey: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    publicKey = ed25519PublicKeyFromDidKey(signerDid);
    signatureBytes = fromBase64Url(signature.value);
  } catch {
    throw new TypeError(`${label} signature key is invalid.`);
  }
  if (didKeyFromEd25519PublicKey(publicKey) !== signerDid || signatureBytes.length !== 64 || toBase64Url(signatureBytes) !== signature.value ||
      !ed25519.verify(signatureBytes, new TextEncoder().encode(`${domain}${canonicalize(value)}`), publicKey)) throw new TypeError(`${label} signature is not authentic.`);
}

async function assertAttestation(material: Record<string, unknown>, scope: SenderScope, enrollment: Record<string, unknown>, now: string): Promise<Record<string, unknown>> {
  const attestation = objectValue(material.attestation, "runtime attestation");
  exactKeys(attestation, ["enforcerDid", "enforcerKid", "enrollmentDigest", "expiresAt", "keyVersion", "localSignerDid", "localSignerKid", "measurement", "measurementDigest", "nodeAudience", "publicKey", "signature", "targetOrigin", "type", "version"], "runtime attestation");
  if (attestation.type !== "TinyCloudShareEnrollmentRuntimeAttestation" || attestation.version !== 1 || attestation.targetOrigin !== scope.targetOrigin || attestation.nodeAudience !== scope.nodeAudience || attestation.publicKey !== enrollment.invitationPublicKey || attestation.keyVersion !== enrollment.keyVersion || typeof attestation.enforcerDid !== "string" || typeof attestation.enforcerKid !== "string" || attestation.localSignerDid !== attestation.enforcerDid || typeof attestation.localSignerKid !== "string" || !attestation.localSignerKid.startsWith(`${attestation.localSignerDid}#`) || typeof attestation.measurement !== "string" || typeof attestation.measurementDigest !== "string" || typeof attestation.enrollmentDigest !== "string") throw new TypeError("The runtime attestation is not bound to the trusted node.");
  digest(attestation.measurementDigest, "runtime measurementDigest");
  digest(attestation.enrollmentDigest, "runtime enrollmentDigest");
  if (attestation.measurementDigest !== await canonicalDigest({ measurement: attestation.measurement }) || attestation.enrollmentDigest !== await canonicalDigest(enrollment)) throw new TypeError("The runtime attestation digest binding is invalid.");
  if (canonicalTime(attestation.expiresAt, "runtime attestation expiresAt") <= canonicalTime(now, "current time")) throw new TypeError("The runtime attestation is expired.");
  const signature = objectValue(attestation.signature, "runtime attestation signature");
  exactKeys(signature, ["alg", "kid", "value"], "runtime attestation signature");
  if (signature.kid !== attestation.localSignerKid) throw new TypeError("The runtime attestation signer key is not bound.");
  verifyEd25519Evidence(Object.fromEntries(Object.entries(attestation).filter(([key]) => key !== "signature")), signature, "xyz.tinycloud.share/enrollment-attestation/v1\0", String(attestation.localSignerDid), "runtime attestation");
  return attestation;
}

function assertStatus(material: Record<string, unknown>, authorityCid: string, enforcementCid: string, signerDid: string, now: string): void {
  if (!Array.isArray(material.statusObservations) || material.statusObservations.length !== 2) throw new TypeError("Authority status observations are incomplete.");
  const expected = new Set([authorityCid, enforcementCid]);
  for (const value of material.statusObservations) {
    const status = objectValue(value, "authority status observation");
    exactKeys(status, ["checkedAt", "freshUntil", "parentCid", "revokedAt", "sequence", "signerKid", "signerVersion", "state", "type", "version", "signature"], "authority status observation");
    const checkedAt = canonicalTime(status.checkedAt, "authority status checkedAt");
    const freshUntil = canonicalTime(status.freshUntil, "authority status freshUntil");
    const current = canonicalTime(now, "current time");
    if (status.type !== "TinyCloudShareAuthorityStatusObservation" || status.version !== 1 || status.state !== "active" || status.revokedAt !== null || typeof status.parentCid !== "string" || !expected.delete(status.parentCid) || typeof status.sequence !== "number" || !Number.isSafeInteger(status.sequence) || status.sequence < 1 || checkedAt > current || freshUntil < current || freshUntil < checkedAt || freshUntil - checkedAt > 300_000 || typeof status.signerKid !== "string" || status.signerVersion !== 1) throw new TypeError("Authority status observation is invalid.");
    const signature = objectValue(status.signature, "authority status signature");
    exactKeys(signature, ["alg", "kid", "value"], "authority status signature");
    if (signature.kid !== status.signerKid) throw new TypeError("Authority status signer key is not bound.");
    verifyEd25519Evidence(Object.fromEntries(Object.entries(status).filter(([key]) => key !== "signature")), signature, "xyz.tinycloud.share/authority-status/v1\0", signerDid, "authority status");
  }
  if (expected.size !== 0) throw new TypeError("Authority status observations do not cover both parents.");
}

/** The single authorizing validation primitive for SDK share-link creation. */
export async function validateShareAuthority(input: {
  readonly policy: unknown;
  readonly email: string;
  readonly source: ContentSource;
  readonly scope: SenderScope;
  readonly expiresAt: string;
  readonly now: string;
}): Promise<ValidatedShareAuthority> {
  const policy = objectValue(input.policy, "authoritative policy");
  const policyKeys = ["action", "authorityMaterialDigest", "contentSourceDigest", "delegationCid", "expiresAt", "policyAuthorityBytes", "policyAuthorityCid", "policyBytes", "policyCid", "policyDigest", "policyEnforcementBytes", "policyEnforcementCid", "recipientEmail", "resource", "source", "target"];
  exactKeys(policy, policyKeys, "authoritative policy contract");
  if (policy.recipientEmail !== canonicalEmail(input.email) || policy.action !== input.source.action || policy.resource !== input.source.path || policy.expiresAt !== input.expiresAt || policy.delegationCid !== input.scope.delegationCid || policy.authorityMaterialDigest !== input.scope.authorityMaterialDigest) throw new TypeError("The supplied policy binding does not match the request.");
  digest(policy.policyDigest, "policyDigest");
  digest(policy.contentSourceDigest, "contentSourceDigest");
  digest(policy.authorityMaterialDigest, "authorityMaterialDigest");
  if (!isCanonicalRawCid(String(policy.policyCid))) throw new TypeError("The authoritative policy CID is not canonical.");
  const policyData = canonicalJsonBytes(policy.policyBytes, "policyBytes");
  const policyCid = await computeCid(policyData.bytes);
  const policyDigest = toBase64Url(await sha256(policyData.bytes));
  if (policyCid !== policy.policyCid || policyDigest !== policy.policyDigest) throw new TypeError("The supplied policy CID or digest does not match its canonical bytes.");
  const policyDocument = policyData.object;
  exactKeys(policyDocument, ["action", "contentSource", "contentSourceDigest", "expiresAt", "issuerDid", "recipientEmail", "resource", "type", "version"], "policy document");
  const policySource = validateSource(policyDocument.contentSource as ContentSource);
  if (policyDocument.type !== "TinyCloudSharePolicy" || policyDocument.version !== 1 || policyDocument.issuerDid !== input.scope.senderDid || policyDocument.recipientEmail !== input.email || policyDocument.action !== input.source.action || policyDocument.resource !== input.source.path || policyDocument.expiresAt !== input.expiresAt || canonicalize(policySource) !== canonicalize(input.source) || policyDocument.contentSourceDigest !== policy.contentSourceDigest) throw new TypeError("The authoritative policy is not bound to the request.");
  if (canonicalize(policy.source) !== canonicalize(input.source) || canonicalize(policy.target) !== canonicalize({ origin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, spaceId: input.scope.spaceId })) throw new TypeError("The supplied policy target or source is not authenticated.");

  exactString(input.scope.delegation, "delegation");
  if (/\s/.test(input.scope.delegation) || !isCanonicalPathSegment(input.scope.spaceId) || !isCanonicalHttpsOrigin(input.scope.targetOrigin) || input.scope.trustedNode.targetOrigin !== input.scope.targetOrigin || input.scope.trustedNode.nodeAudience !== input.scope.nodeAudience) throw new TypeError("The authenticated delegation target is invalid.");
  if (!isCanonicalRawCid(input.scope.delegationCid)) throw new TypeError("The enforcement delegation CID is not canonical.");
  const material = objectValue(input.scope.authorityMaterial, "authenticated policy authority material");
  exactKeys(material, ["attestation", "enrollment", "handle", "mapping", "policyAuthorityBytes", "policyAuthorityCid", "policyEnforcementBytes", "policyEnforcementCid", "policyOwnerDid", "relationship", "senderDid", "statusObservations", "type", "version"], "authority material");
  if (await canonicalDigest(material) !== input.scope.authorityMaterialDigest || material.type !== "TinyCloudShareAuthorityMaterial" || material.version !== 1 || material.handle !== input.scope.authorityMaterialHandle || material.policyOwnerDid !== input.scope.policyOwnerDid || material.senderDid !== input.scope.senderDid) throw new TypeError("The authority material identity or digest binding is invalid.");
  const relationship = objectValue(material.relationship, "authority relationship");
  exactKeys(relationship, ["authenticated", "policyOwnerDid", "senderDid"], "authority relationship");
  if (relationship.authenticated !== true || relationship.policyOwnerDid !== input.scope.policyOwnerDid || relationship.senderDid !== input.scope.senderDid) throw new TypeError("The authority relationship is not authenticated.");
  const mapping = objectValue(material.mapping, "authority mapping");
  exactKeys(mapping, ["policyAuthorityCid", "policyEnforcementCid", "shareDelegationCid", "sharePolicyCid"], "authority mapping");
  assertNodeCid(material.policyAuthorityCid, "policy authority CID");
  assertNodeCid(material.policyEnforcementCid, "policy enforcement CID");
  if (mapping.sharePolicyCid !== policyCid || mapping.shareDelegationCid !== input.scope.delegationCid || mapping.policyAuthorityCid !== material.policyAuthorityCid || mapping.policyEnforcementCid !== material.policyEnforcementCid) throw new TypeError("The authority mapping is not bound to the request.");
  const enrollment = assertEnrollment(material, input.scope);
  const attestation = await assertAttestation(material, input.scope, enrollment, input.now);
  const authority = canonicalJsonBytes(material.policyAuthorityBytes, "policyAuthorityBytes");
  const enforcement = canonicalJsonBytes(material.policyEnforcementBytes, "policyEnforcementBytes");
  const policyAuthorityCid = await verifyParent({ bytes: authority.bytes, cid: material.policyAuthorityCid, role: "policy-authority", source: input.source, ownerDid: input.scope.policyOwnerDid, nodeAudience: input.scope.nodeAudience, policyDigest, expiresAt: input.expiresAt, now: input.now });
  const policyEnforcementCid = await verifyParent({ bytes: enforcement.bytes, cid: material.policyEnforcementCid, role: "policy-enforcement", source: input.source, ownerDid: input.scope.policyOwnerDid, nodeAudience: input.scope.nodeAudience, policyDigest, expiresAt: input.expiresAt, now: input.now });
  if (policy.policyAuthorityCid !== policyAuthorityCid || policy.policyEnforcementCid !== policyEnforcementCid || policy.policyAuthorityBytes !== material.policyAuthorityBytes || policy.policyEnforcementBytes !== material.policyEnforcementBytes) throw new TypeError("The supplied owner-signed parent material is not bound to the request.");
  const enforcementObject = objectValue(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(enforcement.bytes)), "policy enforcement parent");
  const enforcementFacts = objectValue(enforcementObject.facts, "policy enforcement facts");
  if (enforcementFacts["xyz.tinycloud.policy/enforcerDid"] !== attestation.enforcerDid || enforcementFacts["xyz.tinycloud.policy/enforcerDid"] !== attestation.localSignerDid || typeof enforcementFacts["xyz.tinycloud.policy/attestationBindingDigestHex"] !== "string" || enforcementFacts["xyz.tinycloud.policy/attestationBindingDigestHex"] !== await canonicalDigest({ targetOrigin: attestation.targetOrigin, nodeAudience: attestation.nodeAudience, enforcerDid: attestation.enforcerDid, enforcerKid: attestation.enforcerKid, keyVersion: attestation.keyVersion })) throw new TypeError("The enforcement parent is not bound to the runtime attestation.");
  assertStatus(material, policyAuthorityCid, policyEnforcementCid, String(attestation.localSignerDid), input.now);
  return { policyCid, policyDigest, contentSourceDigest: String(policy.contentSourceDigest), policyBytes: String(policy.policyBytes), policyAuthorityCid, policyAuthorityBytes: String(material.policyAuthorityBytes), policyEnforcementCid, policyEnforcementBytes: String(material.policyEnforcementBytes) };
}
