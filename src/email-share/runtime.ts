import { canonicalize, computeCid, fromBase64Url, toBase64Url, verifyEnvelope, type ShareEnvelope } from "@tinycloud/share-envelope";
import type { CredentialTrust } from "./claim.js";
import type { ShareTransport } from "./transport.js";
import type { TrustedNode } from "./protocol.js";
import { canonicalEmail, sourceDigest, validateSource, type ContentSource, type SenderScope } from "./protocol.js";
import type { SharePublicBinding, SharePublicConfig } from "./config.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";

export function assertProductionTrustedNode(value: TrustedNode): void {
  if (value.enabled !== true || value.keyVersion < 1 || !/^https:\/\/[^/?#:@]+$/.test(value.targetOrigin) || !/^did:web:[^/#?]+$/.test(value.nodeAudience) || !value.invitationKid.startsWith(`${value.nodeAudience}#`) || value.invitationPublicKey.length !== 32) {
    throw new TypeError("The configured node is not enrolled for production sharing.");
  }
}

export function assertProductionCredentialTrust(value: CredentialTrust): void {
  if (!/^did:web:[^/#?]+$/.test(value.issuerDid) || value.vct !== "opencredentials.email/v1" || value.issuerPublicKey.length !== 32) {
    throw new TypeError("The configured credential issuer is not trusted for production sharing.");
  }
}

export function assertProductionAuthorityMaterial(scope: SenderScope): void {
  const material = scope.authorityMaterial;
  if (material === undefined || material === null || Array.isArray(material)) throw new TypeError("Authenticated authority material is required.");
  const required = ["type", "version", "handle", "policyOwnerDid", "senderDid", "relationship", "mapping", "policyAuthorityBytes", "policyAuthorityCid", "policyEnforcementBytes", "policyEnforcementCid", "statusObservations", "enrollment", "attestation"];
  if (Object.keys(material).length !== required.length || required.some((key) => !Object.hasOwn(material, key))) throw new TypeError("Authority material profile is incomplete.");
  if (material.type !== "TinyCloudShareAuthorityMaterial" || material.version !== 1 || material.handle !== scope.authorityMaterialHandle || material.policyOwnerDid !== scope.policyOwnerDid || material.senderDid !== scope.senderDid) throw new TypeError("Authority material identity binding is invalid.");
  const relationship = material.relationship;
  if (typeof relationship !== "object" || relationship === null || Array.isArray(relationship)) throw new TypeError("Authority material relationship is not authenticated.");
  const relationshipObject = relationship as Record<string, unknown>;
  if (Object.keys(relationshipObject).length !== 3 || relationshipObject.policyOwnerDid !== scope.policyOwnerDid || relationshipObject.senderDid !== scope.senderDid || relationshipObject.authenticated !== true) throw new TypeError("Authority material relationship is not authenticated.");
  const enrollment = material.enrollment;
  if (typeof enrollment !== "object" || enrollment === null || Array.isArray(enrollment)) throw new TypeError("Authority material enrollment is not trusted.");
  const enrollmentObject = enrollment as Record<string, unknown>;
  if (enrollmentObject.targetOrigin !== scope.targetOrigin || enrollmentObject.nodeAudience !== scope.nodeAudience || enrollmentObject.invitationKid !== scope.trustedNode.invitationKid || enrollmentObject.keyVersion !== scope.trustedNode.keyVersion || enrollmentObject.enabled !== true || typeof enrollmentObject.invitationPublicKey !== "string" || enrollmentObject.invitationPublicKey !== toBase64Url(scope.trustedNode.invitationPublicKey)) throw new TypeError("Authority material enrollment is not trusted.");
  const mapping = material.mapping;
  if (typeof mapping !== "object" || mapping === null || Array.isArray(mapping)) throw new TypeError("Authority material mapping is missing.");
  const mappingObject = mapping as Record<string, unknown>;
  if (Object.keys(mappingObject).length !== 4 || mappingObject.shareDelegationCid !== scope.delegationCid || typeof mappingObject.sharePolicyCid !== "string" || !/^b[a-z2-7]{58}$/.test(String(mappingObject.policyAuthorityCid)) || !/^b[a-z2-7]{58}$/.test(String(mappingObject.policyEnforcementCid))) throw new TypeError("Authority material mapping is invalid.");
  if (!/^bafkrei[a-z2-7]{52}$/.test(scope.delegationCid) || !/^[A-Za-z0-9_-]{43}$/.test(scope.authorityMaterialDigest)) throw new TypeError("Authority material digest binding is invalid.");
}

/**
 * The browser-side recipient adapter. It verifies the signed envelope and
 * policy before any claim call is possible; browser tests may replace only
 * the delivery transport, never this verifier.
 */
export async function verifyProductionEmailShare(input: {
  readonly envelope: ShareEnvelope;
  readonly shareCid: string;
  readonly policy: Record<string, unknown>;
  readonly config: SharePublicConfig;
  readonly binding: SharePublicBinding;
}): Promise<VerifiedExactEmailShare> {
  const { envelope, shareCid, policy, config, binding } = input;
  if (envelope.authorizationTarget.kind !== "policy") throw new TypeError("policy target required");
  const policyBytes = fromBase64Url(envelope.authorizationTarget.policyBytes);
  const parsedPolicy = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(policyBytes)) as unknown;
  if (canonicalize(parsedPolicy) !== canonicalize(policy)) throw new TypeError("policy bytes do not match resolved policy");
  if (await computeCid(policyBytes) !== envelope.authorizationTarget.policyCid) throw new TypeError("policy CID is invalid");
  if (policy.type !== "TinyCloudSharePolicy" || policy.version !== 1 || typeof policy.issuerDid !== "string" || policy.issuerDid !== envelope.signature.signerDid || typeof policy.recipientEmail !== "string" || typeof policy.expiresAt !== "string" || typeof policy.action !== "string" || typeof policy.resource !== "string" || typeof policy.contentSourceDigest !== "string") throw new TypeError("policy shape is invalid");
  const source = validateSource(policy.contentSource as ContentSource);
  if (source.action !== policy.action || source.path !== policy.resource || await sourceDigest(source) !== policy.contentSourceDigest) throw new TypeError("policy source binding is invalid");
  canonicalEmail(policy.recipientEmail);
  if (envelope.shareId === undefined || envelope.expiry !== policy.expiresAt || envelope.target.origin !== config.nodeOrigin || envelope.target.nodeAudience !== config.nodeAudience || envelope.target.spaceId !== source.space || envelope.target.resource.kind !== "exact" || envelope.target.resource.path !== source.path || Date.parse(envelope.expiry) <= Date.now()) throw new TypeError("envelope scope is invalid");
  if (!(await verifyEnvelope(envelope, { expectedSignerDid: policy.issuerDid }))) throw new TypeError("envelope signature is invalid");
  if (binding.shareId !== envelope.shareId || binding.policyCid !== envelope.authorizationTarget.policyCid || binding.recipientEmail !== policy.recipientEmail || binding.expiry !== envelope.expiry || canonicalize(binding.contentSource) !== canonicalize(source) || binding.contentSourceDigest !== policy.contentSourceDigest || binding.action !== source.action || binding.resource !== source.path) throw new TypeError("public authority binding is invalid");
  if ((source.kind === "kv" && binding.authorityMaterialHandle !== "amh_kv_001") || (source.kind === "sql" && binding.authorityMaterialHandle !== "amh_sql_001")) throw new TypeError("authority material kind is invalid");
  const trustedNode = {
    targetOrigin: config.nodeOrigin,
    nodeAudience: config.nodeAudience,
    invitationKid: config.nodeInvitationKid,
    invitationPublicKey: fromBase64Url(config.nodeInvitationPublicKey),
    keyVersion: 1,
    enabled: true as const,
  };
  return {
    shareId: envelope.shareId,
    shareCid,
    policyCid: envelope.authorizationTarget.policyCid,
    recipientEmail: policy.recipientEmail,
    recipientHint: envelope.display.recipientHint ?? `${policy.recipientEmail.slice(0, 1)}***@${policy.recipientEmail.split("@")[1]}`,
    expiry: envelope.expiry,
    nodeOrigin: config.nodeOrigin,
    nodeAudience: config.nodeAudience,
    requestOrigin: config.shareOrigin,
    delegationCid: binding.delegationCid,
    authorityMaterialHandle: binding.authorityMaterialHandle,
    authorityMaterialDigest: binding.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: policy.contentSourceDigest,
    action: source.action,
    resource: source.path,
    trustedNode,
  };
}
