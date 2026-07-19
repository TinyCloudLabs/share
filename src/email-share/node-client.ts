import { canonicalize, toBase64Url } from "@tinycloud/share-envelope";
import type { ClaimMaterial } from "./claim.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import type { ShareTransport } from "./transport.js";
import { SIGNATURE_DOMAINS } from "./protocol.js";
import {
  assertCommonNodeBinding,
  assertCredentialDigest,
  assertNodeTime,
  assertReadResponseBinding,
  assertSourceBinding,
  assertTrustedNodeScope,
  digest,
  digestText,
  verifyNodeProof,
  readResponseBody,
} from "./node-verifier.js";

const READ_TTL_MS = 60_000;

async function holderProof(material: ClaimMaterial, domain: string, value: unknown): Promise<{ readonly alg: "EdDSA"; readonly kid: string; readonly signature: string }> {
  const domainBytes = new TextEncoder().encode(domain);
  const message = new TextEncoder().encode(canonicalize(value));
  const bytes = new Uint8Array(domainBytes.length + message.length);
  bytes.set(domainBytes);
  bytes.set(message, domainBytes.length);
  return {
    alg: "EdDSA",
    kid: `${material.holder.did}#${material.holder.did.slice("did:key:".length)}`,
    signature: toBase64Url(new Uint8Array(await crypto.subtle.sign("Ed25519", material.holder.privateKey, bytes))),
  };
}

function nowIso(): string { return new Date().toISOString(); }

function boundedReadExpiry(sessionExpiresAt: string, shareExpiry: string): string {
  const expiresAt = Math.min(Date.now() + READ_TTL_MS, Date.parse(sessionExpiresAt), Date.parse(shareExpiry));
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new Error("session-expired");
  return new Date(expiresAt).toISOString();
}

export async function readClaimedShare(input: {
  readonly share: VerifiedExactEmailShare;
  readonly claim: ClaimMaterial;
  readonly transport: ShareTransport;
}): Promise<string> {
  assertTrustedNodeScope(input.share, input.share.trustedNode);
  const source = input.share.contentSource;
  const requestBody = {
    shareCid: input.share.shareCid,
    shareId: input.share.shareId,
    delegationCid: input.share.delegationCid,
    policyCid: input.share.policyCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle,
    authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: input.share.contentSourceDigest,
    holderDid: input.claim.holder.did,
    targetOrigin: input.share.nodeOrigin,
    nodeAudience: input.share.nodeAudience,
    action: input.share.action,
    resource: input.share.resource,
  } as const;
  const requestBodyDigest = await digest(requestBody);
  const request = { ...requestBody, requestBodyDigest };
  assertSourceBinding(request.contentSource, source, input.share.contentSourceDigest);

  const challengeResponse = await input.transport.policyChallenge(request);
  const challenge = challengeResponse.challenge as Record<string, unknown>;
  await verifyNodeProof(challenge, challengeResponse.proof, input.share.trustedNode, SIGNATURE_DOMAINS.policyChallenge);
  assertCommonNodeBinding(challenge, input.share, input.claim.holder.did);
  if (challenge.challengeId === undefined || challenge.nonce === undefined || challenge.requestBodyDigest !== requestBodyDigest) throw new Error("challenge-binding-invalid");
  assertNodeTime(challenge.issuedAt, challenge.expiresAt, Date.now(), 120);

  const credentialDigest = await digestText(input.claim.credential);
  const presentation = {
    type: "TinyCloudSharePolicyPresentation",
    version: 1,
    challengeId: challenge.challengeId,
    nonce: challenge.nonce,
    shareCid: input.share.shareCid,
    shareId: input.share.shareId,
    delegationCid: input.share.delegationCid,
    policyCid: input.share.policyCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle,
    authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: input.share.contentSourceDigest,
    holderDid: input.claim.holder.did,
    targetOrigin: input.share.nodeOrigin,
    nodeAudience: input.share.nodeAudience,
    credentialDigest,
    action: input.share.action,
    resource: input.share.resource,
    requestBodyDigest,
    issuedAt: nowIso(),
    expiresAt: challenge.expiresAt,
    jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const sessionResponse = await input.transport.policySession({ presentation, credential: input.claim.credential, proof: await holderProof(input.claim, SIGNATURE_DOMAINS.policyPresentation, presentation) });
  const session = sessionResponse.session as Record<string, unknown>;
  await verifyNodeProof(session, sessionResponse.proof, input.share.trustedNode, SIGNATURE_DOMAINS.policySession);
  assertCommonNodeBinding(session, input.share, input.claim.holder.did);
  assertCredentialDigest(session.credentialDigest, credentialDigest);
  assertNodeTime(session.issuedAt, session.expiresAt, Date.now(), 300);
  if (session.sessionId === undefined || typeof session.sessionId !== "string") throw new Error("session-invalid");

  const invocationBase = {
    type: "TinyCloudShareReadInvocation",
    version: 1,
    sessionId: session.sessionId,
    shareCid: input.share.shareCid,
    shareId: input.share.shareId,
    policyCid: input.share.policyCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle,
    authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: input.share.contentSourceDigest,
    holderDid: input.claim.holder.did,
    targetOrigin: input.share.nodeOrigin,
    nodeAudience: input.share.nodeAudience,
    action: input.share.action,
    resource: input.share.resource,
    issuedAt: nowIso(),
    expiresAt: boundedReadExpiry(String(session.expiresAt), input.share.expiry),
    jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const readPreimage = {
    sessionId: session.sessionId,
    delegationCid: input.share.delegationCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle,
    authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: input.share.contentSourceDigest,
    action: input.share.action,
    resource: input.share.resource,
    invocation: invocationBase,
  };
  const readRequestBodyDigest = await digest(readPreimage);
  const invocation = { ...invocationBase, requestBodyDigest: readRequestBodyDigest };
  assertNodeTime(invocation.issuedAt, invocation.expiresAt, Date.now(), 60);
  const readRequestBody = {
    sessionId: session.sessionId,
    delegationCid: input.share.delegationCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle,
    authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: input.share.contentSourceDigest,
    action: input.share.action,
    resource: input.share.resource,
    requestBodyDigest: readRequestBodyDigest,
    invocation,
    proof: await holderProof(input.claim, SIGNATURE_DOMAINS.readInvocation, invocation),
  };
  const response = await input.transport.read(readRequestBody);
  await verifyNodeProof(readResponseBody(response as unknown as Record<string, unknown>), response.proof, input.share.trustedNode, SIGNATURE_DOMAINS.readResponse);
  const verified = assertReadResponseBinding(response, input.share, { sessionId: session.sessionId, holderDid: input.claim.holder.did, credentialDigest, requestBodyDigest: readRequestBodyDigest, requestJti: invocation.jti });
  if (verified.bodyDigest !== await digestText(verified.content)) throw new Error("read-body-digest-invalid");
  return verified.content;
}
