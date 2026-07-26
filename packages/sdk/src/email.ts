import { canonicalize, didKeyFromEd25519PublicKey, toBase64Url, type ShareEnvelope } from "@tinycloud/share-envelope";
import {
  canonicalDigest,
  type AuthorizedInvitation,
  type SenderScope,
  SIGNATURE_DOMAINS,
} from "../../../src/email-share/protocol.js";
import { assertTrustedNodeScope, verifyNodeProof } from "../../../src/email-share/node-verifier.js";
import type { ShareTransport } from "../../../src/email-share/transport.js";
import { draftForGeneratedShareLink, type GeneratedShareLink } from "./link.js";
import { type AddressedShareLink } from "./addressed-link.js";

/**
 * Opaque output of the link lane. Email delivery cannot manufacture or
 * replace this value; it can only submit the already generated artifact.
 */
export type PreGeneratedShareLink = GeneratedShareLink;
export type PreGeneratedAddressedShareLink = AddressedShareLink;

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
  readonly share: PreGeneratedShareLink | PreGeneratedAddressedShareLink;
  readonly scope: SenderScope;
  readonly adapters: ShareEmailAdapter;
}): Promise<ShareEmailDeliveryReceipt> {
  if ("recipientMatcher" in input.share) return sendAddressedShareEmail(input as { readonly share: PreGeneratedAddressedShareLink; readonly scope: SenderScope; readonly adapters: ShareEmailAdapter });
  const draft = draftForGeneratedShareLink(input.share);
  const trustedShare = asVerifiedShare(draft, input.scope);
  assertTrustedNodeScope(trustedShare, input.scope.trustedNode);
  const recipientMatcher = { kind: "exactEmail" as const, value: draft.email };
  const actions = [draft.source.action];
  const resource = draft.source.path;
  const idempotencyKey = await canonicalDigest({ shareUrl: draft.shareUrl, recipientEmail: draft.email });
  const requestWithoutDigest = {
    version: 2,
    jti: draft.invitationJti,
    reportAbuseToken: draft.reportAbuseToken,
    senderDid: input.scope.senderDid,
    shareCid: draft.shareCid,
    shareId: draft.envelope.shareId,
    policyCid: draft.policyCid,
    delegationCid: input.scope.delegationCid,
    authorityMaterialHandle: input.scope.authorityMaterialHandle,
    authorityMaterialDigest: input.scope.authorityMaterialDigest,
    recipientMatcher,
    deliveryEmail: draft.email,
    shareUrl: draft.shareUrl,
    targetOrigin: input.scope.targetOrigin,
    nodeAudience: input.scope.nodeAudience,
    documentName: input.scope.documentName,
    senderTrust: input.scope.senderTrust,
    contentSource: draft.source,
    contentSourceDigest: draft.sourceDigest,
    actions,
    resource,
    shareExpiresAt: draft.envelope.expiry,
    idempotencyKey,
  } as const;
  const request = { ...requestWithoutDigest, requestBodyDigest: await canonicalDigest(requestWithoutDigest) } as const;
  const signature = await input.scope.signer.sign({ purpose: "inviteAuthorization", message: canonicalize(request), binding: request });
  const signerDid = didKeyFromEd25519PublicKey(input.scope.signingCapability.publicKey);
  if (signerDid !== input.scope.senderDid || signature.length !== 64) throw new Error("sender authorization proof is invalid");
  const proof = { alg: "EdDSA" as const, kid: `${signerDid}#${signerDid.slice("did:key:".length)}`, signature: toBase64Url(signature) };
  const authorized: AuthorizedInvitation = await input.adapters.authorizeInvitation({ request, proof });
  await verifyNodeProof(authorized.authorization, authorized.proof, input.scope.trustedNode, SIGNATURE_DOMAINS.inviteAuthorization);
  const expected: Record<string, unknown> = {
    type: "TinyCloudShareInviteAuthorization",
    version: 2,
    senderDid: input.scope.senderDid,
    shareCid: draft.shareCid,
    shareId: draft.envelope.shareId,
    policyCid: draft.policyCid,
    delegationCid: input.scope.delegationCid,
    authorityMaterialHandle: input.scope.authorityMaterialHandle,
    authorityMaterialDigest: input.scope.authorityMaterialDigest,
    recipientMatcher,
    deliveryEmail: draft.email,
    shareUrl: draft.shareUrl,
    targetOrigin: input.scope.targetOrigin,
    nodeAudience: input.scope.nodeAudience,
    returnOrigin: input.scope.shareOrigin,
    documentName: input.scope.documentName,
    senderTrust: input.scope.senderTrust,
    contentSource: draft.source,
    contentSourceDigest: draft.sourceDigest,
    actions,
    resource,
    shareExpiresAt: draft.envelope.expiry,
    requestBodyDigest: request.requestBodyDigest,
    idempotencyKey,
    reportAbuseToken: draft.reportAbuseToken,
  };
  for (const [key, value] of Object.entries(expected)) {
    const actual = (authorized.authorization as unknown as Record<string, unknown>)[key];
    if (typeof value === "object" ? canonicalize(actual) !== canonicalize(value) : actual !== value) throw new Error("invitation-authorization-mismatch");
  }
  const accepted = await input.adapters.requestDelivery({ authorization: authorized.authorization, proof: authorized.proof, shareUrl: draft.shareUrl, idempotencyKey });
  return { status: "accepted", state: "queued", retryAfterSeconds: accepted.retryAfterSeconds, shareCid: draft.shareCid, shareId: draft.envelope.shareId, recipientEmail: draft.email };
}

/** The v2 path uses the same authorize → verify → delivery transaction as v1.
 * There is intentionally no notification endpoint: delivery receives the
 * already-generated URL and a stable idempotency key at OpenCredentials. */
async function sendAddressedShareEmail(input: { readonly share: PreGeneratedAddressedShareLink; readonly scope: SenderScope; readonly adapters: ShareEmailAdapter }): Promise<ShareEmailDeliveryReceipt> {
  if (input.share.deliveryEmail === undefined) throw new Error("addressed delivery email is required");
  const jti = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const reportAbuseToken = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const actions = input.share.actions.map((action) => action === "read" ? "tinycloud.kv/get" : action === "list" ? "tinycloud.kv/list" : "tinycloud.kv/put");
  const resource = input.share.resource.path.replace(/\/$/, "");
  // The complete possession link is the authority.  Bind delivery retries to
  // that exact link, not merely its ciphertext CID (which would allow a
  // different fragment key to share an idempotency slot).
  const idempotencyKey = await canonicalDigest({ shareUrl: input.share.shareUrl, recipientEmail: input.share.deliveryEmail });
  const requestWithoutDigest = {
    version: 2,
    jti, reportAbuseToken, senderDid: input.scope.senderDid, shareCid: input.share.shareCid, shareId: input.share.envelope.shareId,
    policyCid: input.share.envelope.authorizationTarget.kind === "policy" ? input.share.envelope.authorizationTarget.policyCid : "",
    delegationCid: input.share.envelope.delegationCid, authorityMaterialHandle: input.scope.authorityMaterialHandle, authorityMaterialDigest: input.share.envelope.authorityMaterialDigest,
    recipientMatcher: input.share.recipientMatcher, deliveryEmail: input.share.deliveryEmail,
    shareUrl: input.share.shareUrl,
    targetOrigin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, documentName: input.scope.documentName, senderTrust: input.scope.senderTrust,
    actions, resource,
    contentSource: input.share.source, contentSourceDigest: input.share.envelope.contentSourceDigest,
    shareExpiresAt: input.share.expiresAt, idempotencyKey,
  } as const;
  // Node's addressed v2 route hashes the complete request object (minus the
  // digest field). This is intentionally different from the compact legacy
  // exact-email preimage.
  const request = { ...requestWithoutDigest, requestBodyDigest: await canonicalDigest(requestWithoutDigest) } as const;
  const signature = await input.scope.signer.sign({ purpose: "inviteAuthorization", message: canonicalize(request), binding: request });
  const signerDid = didKeyFromEd25519PublicKey(input.scope.signingCapability.publicKey);
  if (signerDid !== input.scope.senderDid || signature.length !== 64) throw new Error("sender authorization proof is invalid");
  const proof = { alg: "EdDSA" as const, kid: `${signerDid}#${signerDid.slice("did:key:".length)}`, signature: toBase64Url(signature) };
  const authorized = await input.adapters.authorizeInvitation({ request, proof });
  await verifyNodeProof(authorized.authorization, authorized.proof, input.scope.trustedNode, SIGNATURE_DOMAINS.inviteAuthorization);
  const authorization = authorized.authorization as unknown as Record<string, unknown>;
  const requiredBindings: Record<string, unknown> = {
    type: "TinyCloudShareInviteAuthorization",
    version: 2,
    senderDid: input.scope.senderDid,
    shareCid: input.share.shareCid,
    shareId: input.share.envelope.shareId,
    policyCid: input.share.envelope.authorizationTarget.kind === "policy" ? input.share.envelope.authorizationTarget.policyCid : "",
    delegationCid: input.share.envelope.delegationCid,
    authorityMaterialHandle: input.scope.authorityMaterialHandle,
    authorityMaterialDigest: input.share.envelope.authorityMaterialDigest,
    recipientMatcher: input.share.recipientMatcher,
    deliveryEmail: input.share.deliveryEmail,
    shareUrl: input.share.shareUrl,
    targetOrigin: input.scope.targetOrigin,
    nodeAudience: input.scope.nodeAudience,
    documentName: input.scope.documentName,
    senderTrust: input.scope.senderTrust,
    contentSource: input.share.source,
    contentSourceDigest: input.share.envelope.contentSourceDigest,
    actions,
    resource,
    shareExpiresAt: input.share.expiresAt,
    requestBodyDigest: request.requestBodyDigest,
    idempotencyKey,
    returnOrigin: input.scope.shareOrigin,
  };
  for (const [key, expected] of Object.entries(requiredBindings)) {
    const actual = authorization[key];
    if (typeof expected === "object" ? canonicalize(actual) !== canonicalize(expected) : actual !== expected) throw new Error("invitation-authorization-mismatch");
  }
  const accepted = await input.adapters.requestDelivery({ authorization: authorized.authorization, proof: authorized.proof, shareUrl: input.share.shareUrl, idempotencyKey });
  return { status: "accepted", state: "queued", retryAfterSeconds: accepted.retryAfterSeconds, shareCid: input.share.shareCid, shareId: input.share.envelope.shareId, recipientEmail: input.share.deliveryEmail };
}
