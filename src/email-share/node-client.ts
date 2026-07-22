import { canonicalize, toBase64Url } from "@tinycloud/share-envelope";
import type { ClaimMaterial } from "./claim.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import type { ShareTransport } from "./transport.js";
import { canonicalEmail, SIGNATURE_DOMAINS, type SignedArtifact } from "./protocol.js";
import {
  assertCommonNodeBinding,
  assertCredentialDigest,
  assertNodeTime,
  assertReadResponseBinding,
  assertSourceBinding,
  digestBytes,
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

async function holderBindingArtifact(input: {
  readonly material: ClaimMaterial;
  readonly share: VerifiedExactEmailShare;
  readonly challenge: Record<string, unknown>;
  readonly credentialDigest: string;
  readonly challengeRequestDigest: string;
}): Promise<SignedArtifact> {
  const now = Date.now();
  const issuedAt = new Date(now).toISOString();
  const expiresAt = new Date(Math.min(
    now + READ_TTL_MS * 2,
    Date.parse(String(input.challenge.expiresAt)),
    Date.parse(input.share.expiry),
    Date.parse(input.material.expiresAt),
  )).toISOString();
  if (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= now) throw new Error("holder-binding-expired");
  const nonce = String(input.challenge.nonce);
  const message = {
    type: "TinyCloudEmailClaimHolderBinding",
    version: 1,
    redemptionId: input.share.shareId,
    invitationId: input.share.shareCid,
    claimNonce: nonce,
    challengeNonce: nonce,
    shareCid: input.share.shareCid,
    shareId: input.share.shareId,
    policyCid: input.share.policyCid,
    contentSource: input.share.contentSource,
    contentSourceDigest: input.share.contentSourceDigest,
    emailHash: await digestText(canonicalEmail(input.share.recipientEmail)),
    holderDid: input.material.holder.did,
    credentialDigest: input.credentialDigest,
    targetOrigin: input.share.nodeOrigin,
    nodeAudience: input.share.nodeAudience,
    audience: input.share.nodeAudience,
    enforcerDid: input.challenge.enforcerDid,
    requestOrigin: input.share.nodeOrigin,
    challengeId: input.challenge.challengeId,
    challengeRequestDigest: input.challengeRequestDigest,
    issuedAt,
    expiresAt,
    jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const jcs = canonicalize(message);
  const domain = SIGNATURE_DOMAINS.holderBinding;
  const signedBytes = new TextEncoder().encode(`${domain}${jcs}`);
  const signatureBytes = new Uint8Array(await crypto.subtle.sign("Ed25519", input.material.holder.privateKey, signedBytes));
  const signature = toBase64Url(signatureBytes);
  return {
    name: "holderBinding",
    domain,
    signerDid: input.material.holder.did,
    message,
    jcs,
    messageDigest: await digestText(jcs),
    signedBytesDigest: await digestBytes(signedBytes),
    signatureDigest: await digestBytes(signatureBytes),
    signature: {
      alg: "EdDSA",
      kid: `${input.material.holder.did}#${input.material.holder.did.slice("did:key:".length)}`,
      value: signature,
    },
  };
}

function nowIso(): string { return new Date().toISOString(); }

function boundedReadExpiry(sessionExpiresAt: string, shareExpiry: string, now = Date.now()): string {
  const expiresAt = Math.min(now + READ_TTL_MS, Date.parse(sessionExpiresAt), Date.parse(shareExpiry));
  if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new Error("session-expired");
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
  if (typeof challenge.challengeId !== "string" || typeof challenge.nonce !== "string" || typeof challenge.enforcerDid !== "string" || challenge.requestBodyDigest !== requestBodyDigest) throw new Error("challenge-binding-invalid");
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
    enforcerDid: challenge.enforcerDid,
    credentialDigest,
    action: input.share.action,
    resource: input.share.resource,
    requestBodyDigest,
    issuedAt: nowIso(),
    expiresAt: challenge.expiresAt,
    jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const holderBinding = await holderBindingArtifact({ material: input.claim, share: input.share, challenge, credentialDigest, challengeRequestDigest: requestBodyDigest });
  const sessionResponse = await input.transport.policySession({
    presentation,
    credential: input.claim.credential,
    proof: await holderProof(input.claim, SIGNATURE_DOMAINS.policyPresentation, presentation),
    holderBinding,
    readSignerDid: input.claim.holder.did,
  });
  const session = sessionResponse.session as Record<string, unknown>;
  await verifyNodeProof(session, sessionResponse.proof, input.share.trustedNode, SIGNATURE_DOMAINS.policySession);
  assertCommonNodeBinding(session, input.share, input.claim.holder.did);
  assertCredentialDigest(session.credentialDigest, credentialDigest);
  assertNodeTime(session.issuedAt, session.expiresAt, Date.now(), 300);
  if (session.sessionId === undefined || typeof session.sessionId !== "string") throw new Error("session-invalid");

  const readNow = Date.now();
  const invocationBase = {
    type: "TinyCloudShareReadInvocation",
    version: 1,
    sessionId: session.sessionId,
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
    issuedAt: new Date(readNow).toISOString(),
    expiresAt: boundedReadExpiry(String(session.expiresAt), input.share.expiry, readNow),
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
  assertNodeTime(invocation.issuedAt, invocation.expiresAt, readNow, 60);
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
