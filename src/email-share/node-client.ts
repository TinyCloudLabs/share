import { canonicalize, toBase64Url } from "@tinycloud/share-envelope";
import type { ClaimMaterial } from "./claim.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import type { ShareTransport } from "./transport.js";

const PRESENTATION_DOMAIN = "xyz.tinycloud.share/policy-presentation/v1\0";
const READ_DOMAIN = "xyz.tinycloud.share/read-invocation/v1\0";

async function digest(value: unknown): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(value)))));
}

async function proof(material: ClaimMaterial, domain: string, value: unknown): Promise<{ readonly alg: "EdDSA"; readonly kid: string; readonly signature: string }> {
  const domainBytes = new TextEncoder().encode(domain);
  const message = new TextEncoder().encode(canonicalize(value));
  const bytes = new Uint8Array(domainBytes.length + message.length); bytes.set(domainBytes); bytes.set(message, domainBytes.length);
  return { alg: "EdDSA", kid: `${material.holder.did}#${material.holder.did.slice("did:key:".length)}`, signature: toBase64Url(new Uint8Array(await crypto.subtle.sign("Ed25519", material.holder.privateKey, bytes))) };
}

export async function readClaimedShare(input: { readonly share: VerifiedExactEmailShare; readonly claim: ClaimMaterial; readonly transport: ShareTransport }): Promise<string> {
  const source = input.share.contentSource;
  const request = {
    shareCid: input.share.shareCid, shareId: input.share.shareId, delegationCid: input.share.delegationCid, policyCid: input.share.policyCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle, authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source, contentSourceDigest: input.share.contentSourceDigest, holderDid: input.claim.holder.did,
    targetOrigin: input.share.nodeOrigin, nodeAudience: input.share.nodeAudience, action: input.share.action, resource: input.share.resource,
    requestBodyDigest: await digest({ source, action: input.share.action, resource: input.share.resource }),
  };
  const challengeResponse = await input.transport.policyChallenge(request);
  const challenge = challengeResponse.challenge;
  const presentation = {
    type: "TinyCloudSharePolicyPresentation", version: 1, challengeId: challenge.challengeId, nonce: challenge.nonce,
    shareCid: input.share.shareCid, shareId: input.share.shareId, delegationCid: input.share.delegationCid, policyCid: input.share.policyCid,
    authorityMaterialHandle: input.share.authorityMaterialHandle, authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source, contentSourceDigest: input.share.contentSourceDigest, holderDid: input.claim.holder.did,
    targetOrigin: input.share.nodeOrigin, nodeAudience: input.share.nodeAudience, credentialDigest: await digest(input.claim.credential),
    action: input.share.action, resource: input.share.resource, requestBodyDigest: request.requestBodyDigest,
    issuedAt: new Date().toISOString(), expiresAt: challenge.expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const sessionResponse = await input.transport.policySession({ presentation, credential: input.claim.credential, proof: await proof(input.claim, PRESENTATION_DOMAIN, presentation) });
  const session = (sessionResponse.session ?? sessionResponse) as Record<string, unknown>;
  const invocation = {
    type: "TinyCloudShareReadInvocation", version: 1, sessionId: session.sessionId, shareCid: input.share.shareCid, shareId: input.share.shareId,
    policyCid: input.share.policyCid, authorityMaterialHandle: input.share.authorityMaterialHandle, authorityMaterialDigest: input.share.authorityMaterialDigest,
    contentSource: source, contentSourceDigest: input.share.contentSourceDigest, holderDid: input.claim.holder.did, targetOrigin: input.share.nodeOrigin,
    nodeAudience: input.share.nodeAudience, action: input.share.action, resource: input.share.resource, requestBodyDigest: request.requestBodyDigest,
    issuedAt: new Date().toISOString(), expiresAt: session.expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const response = await input.transport.read({ sessionId: session.sessionId, contentSource: source, contentSourceDigest: input.share.contentSourceDigest, action: input.share.action, resource: input.share.resource, requestBodyDigest: request.requestBodyDigest, invocation, proof: await proof(input.claim, READ_DOMAIN, invocation) });
  return response.content;
}
