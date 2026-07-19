import { fromBase64Url } from "@tinycloud/share-envelope";
import type { CredentialTrust } from "./claim.js";
import type { ShareTransport } from "./transport.js";
import type { TrustedNode } from "./protocol.js";
import type { SenderScope } from "./protocol.js";

/** Production endpoints are contract constants, never page-controlled URLs. */
export const PRODUCTION_ENDPOINTS = Object.freeze({
  shareOrigin: "https://share.tinycloud.xyz",
  nodeOrigin: "https://node.example",
  credentialsOrigin: "https://witness.credentials.org",
  nodeAudience: "did:web:node.example",
  issuerDid: "did:web:issuer.credentials.org",
  issuerVct: "opencredentials.email/v1" as const,
});

const NODE_INVITATION_KEY = fromBase64Url("IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI");
const ISSUER_KEY = fromBase64Url("Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY");

export const PRODUCTION_TRUSTED_NODE: TrustedNode = Object.freeze({
  targetOrigin: PRODUCTION_ENDPOINTS.nodeOrigin,
  nodeAudience: PRODUCTION_ENDPOINTS.nodeAudience,
  invitationKid: "did:web:node.example#invitation-key-1",
  invitationPublicKey: NODE_INVITATION_KEY,
  keyVersion: 1,
  enabled: true,
});

export const PRODUCTION_CREDENTIAL_TRUST: CredentialTrust = Object.freeze({
  issuerDid: PRODUCTION_ENDPOINTS.issuerDid,
  vct: PRODUCTION_ENDPOINTS.issuerVct,
  issuerPublicKey: ISSUER_KEY,
});

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function assertProductionTrustedNode(value: TrustedNode): void {
  if (value.targetOrigin !== PRODUCTION_TRUSTED_NODE.targetOrigin || value.nodeAudience !== PRODUCTION_TRUSTED_NODE.nodeAudience || value.invitationKid !== PRODUCTION_TRUSTED_NODE.invitationKid || value.keyVersion !== PRODUCTION_TRUSTED_NODE.keyVersion || value.enabled !== true || !sameBytes(value.invitationPublicKey, PRODUCTION_TRUSTED_NODE.invitationPublicKey)) {
    throw new TypeError("The configured node is not enrolled for production sharing.");
  }
}

export function assertProductionCredentialTrust(value: CredentialTrust): void {
  if (value.issuerDid !== PRODUCTION_CREDENTIAL_TRUST.issuerDid || value.vct !== PRODUCTION_CREDENTIAL_TRUST.vct || !sameBytes(value.issuerPublicKey, PRODUCTION_CREDENTIAL_TRUST.issuerPublicKey)) {
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
  if (enrollmentObject.targetOrigin !== PRODUCTION_ENDPOINTS.nodeOrigin || enrollmentObject.nodeAudience !== PRODUCTION_ENDPOINTS.nodeAudience || enrollmentObject.invitationKid !== PRODUCTION_TRUSTED_NODE.invitationKid || enrollmentObject.keyVersion !== PRODUCTION_TRUSTED_NODE.keyVersion || enrollmentObject.enabled !== true || typeof enrollmentObject.invitationPublicKey !== "string" || enrollmentObject.invitationPublicKey !== "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI") throw new TypeError("Authority material enrollment is not trusted.");
  const mapping = material.mapping;
  if (typeof mapping !== "object" || mapping === null || Array.isArray(mapping)) throw new TypeError("Authority material mapping is missing.");
  const mappingObject = mapping as Record<string, unknown>;
  if (Object.keys(mappingObject).length !== 4 || mappingObject.shareDelegationCid !== scope.delegationCid || typeof mappingObject.sharePolicyCid !== "string" || !/^bafkrei[a-z2-7]{52}$/.test(String(mappingObject.policyAuthorityCid)) || !/^bafkrei[a-z2-7]{52}$/.test(String(mappingObject.policyEnforcementCid))) throw new TypeError("Authority material mapping is invalid.");
  if (!/^bafkrei[a-z2-7]{52}$/.test(scope.delegationCid) || !/^[A-Za-z0-9_-]{43}$/.test(scope.authorityMaterialDigest)) throw new TypeError("Authority material digest binding is invalid.");
}

export function productionTransport(create: (input: { nodeOrigin: string; credentialsOrigin: string }) => ShareTransport): ShareTransport {
  return create({ nodeOrigin: PRODUCTION_ENDPOINTS.nodeOrigin, credentialsOrigin: PRODUCTION_ENDPOINTS.credentialsOrigin });
}
