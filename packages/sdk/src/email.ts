import { canonicalize, type ShareEnvelope } from "@tinycloud/share-envelope";
import {
  signedInvitationProof,
  type AuthorizedInvitation,
  type SenderScope,
  SIGNATURE_DOMAINS,
} from "../../../src/email-share/protocol.js";
import { assertTrustedNodeScope, verifyNodeProof } from "../../../src/email-share/node-verifier.js";
import type { ShareTransport } from "../../../src/email-share/transport.js";
import { draftForGeneratedShareLink, type GeneratedShareLink } from "./link.js";

/**
 * Opaque output of the link lane. Email delivery cannot manufacture or
 * replace this value; it can only submit the already generated artifact.
 */
export type PreGeneratedShareLink = GeneratedShareLink;

export interface ShareEmailAdapter {
  readonly authorizeInvitation: ShareTransport["authorizeInvitation"];
  readonly requestDelivery: ShareTransport["requestDelivery"];
}

export interface ShareEmailDeliveryReceipt {
  readonly status: "accepted";
  readonly state: "queued";
  readonly retryAfterSeconds: number;
  readonly shareCid: string;
  readonly shareId: string;
  readonly recipientEmail: string;
}

function asVerifiedShare(draft: Awaited<ReturnType<typeof draftForGeneratedShareLink>>, scope: SenderScope) {
  return {
    shareId: draft.envelope.shareId,
    shareCid: draft.shareCid,
    policyCid: draft.policyCid,
    recipientEmail: draft.email,
    recipientHint: draft.envelope.display.recipientHint ?? "",
    expiry: draft.envelope.expiry,
    nodeOrigin: scope.targetOrigin,
    nodeAudience: scope.nodeAudience,
    requestOrigin: scope.shareOrigin,
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
    contentSource: draft.source,
    contentSourceDigest: draft.sourceDigest,
    action: draft.source.action,
    resource: draft.source.path,
    trustedNode: scope.trustedNode,
  } as const;
}

/**
 * Authorize the exact share at the trusted Node and queue that same link at
 * OpenCredentials. The injected adapter is the only delivery boundary.
 */
export async function sendShareEmail(input: {
  readonly share: PreGeneratedShareLink;
  readonly scope: SenderScope;
  readonly adapters: ShareEmailAdapter;
}): Promise<ShareEmailDeliveryReceipt> {
  const draft = draftForGeneratedShareLink(input.share);
  const trustedShare = asVerifiedShare(draft, input.scope);
  assertTrustedNodeScope(trustedShare, input.scope.trustedNode);
  const signed = await signedInvitationProof(draft, input.scope);
  const authorized: AuthorizedInvitation = await input.adapters.authorizeInvitation({ request: signed.request, proof: signed.proof });
  await verifyNodeProof(authorized.authorization, authorized.proof, input.scope.trustedNode, SIGNATURE_DOMAINS.inviteAuthorization);
  const expected: Record<string, unknown> = {
    type: "TinyCloudShareInviteAuthorization",
    version: 1,
    senderDid: input.scope.senderDid,
    shareCid: draft.shareCid,
    shareId: draft.envelope.shareId,
    policyCid: draft.policyCid,
    delegationCid: input.scope.delegationCid,
    authorityMaterialHandle: input.scope.authorityMaterialHandle,
    authorityMaterialDigest: input.scope.authorityMaterialDigest,
    recipientEmail: draft.email,
    targetOrigin: input.scope.targetOrigin,
    nodeAudience: input.scope.nodeAudience,
    returnOrigin: input.scope.shareOrigin,
    documentName: input.scope.documentName,
    senderTrust: input.scope.senderTrust,
    contentSource: draft.source,
    contentSourceDigest: draft.sourceDigest,
    shareExpiresAt: draft.envelope.expiry,
    reportAbuseToken: draft.reportAbuseToken,
  };
  for (const [key, value] of Object.entries(expected)) {
    const actual = (authorized.authorization as unknown as Record<string, unknown>)[key];
    if (typeof value === "object" ? canonicalize(actual) !== canonicalize(value) : actual !== value) throw new Error("invitation-authorization-mismatch");
  }
  const accepted = await input.adapters.requestDelivery({ authorization: authorized.authorization, proof: authorized.proof, shareUrl: draft.shareUrl });
  return { status: "accepted", state: "queued", retryAfterSeconds: accepted.retryAfterSeconds, shareCid: draft.shareCid, shareId: draft.envelope.shareId, recipientEmail: draft.email };
}
