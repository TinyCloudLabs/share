import {ed25519} from "@noble/curves/ed25519";
import {describe, expect, it, vi} from "vitest";
import {
  canonicalize,
  didKeyFromEd25519PublicKey,
  toBase64Url,
} from "@tinycloud/share-envelope";
import {
  createShareLink,
  type ShareArtifact,
} from "../../share-sdk/src/index.js";
import {SIGNATURE_DOMAINS, type SenderScope} from "../../../src/email-share/protocol.js";
import {
  sendShareEmail,
  type ShareEmailAdapter,
} from "../src/email.js";

const senderSeed = new Uint8Array(32).fill(7);
const nodeSeed = new Uint8Array(32).fill(2);
const senderPublicKey = ed25519.getPublicKey(senderSeed);
const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
const source = {
  kind: "kv" as const,
  space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
  path: "documents/plan.md",
  action: "tinycloud.kv/get" as const,
};

const scope: SenderScope = {
  policyOwnerDid: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
  senderDid,
  signingCapability: {capabilityId: "A".repeat(22), publicKey: senderPublicKey},
  signer: {
    publicKey: senderPublicKey,
    sign: async ({purpose, message}) => ed25519.sign(
      new TextEncoder().encode(`${purpose === "envelope" ? SIGNATURE_DOMAINS.envelope : SIGNATURE_DOMAINS.inviteAuthorization}${message}`),
      senderSeed,
    ),
  },
  shareOrigin: "https://share.tinycloud.xyz",
  delegation: "uCAESA.kv.terminal",
  delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
  authorityMaterialHandle: "amh_kv_001",
  authorityMaterialDigest: "A".repeat(43),
  targetOrigin: "https://node.example",
  nodeAudience: "did:web:node.example",
  spaceId: source.space,
  documentName: "Project plan.md",
  senderTrust: "verified",
  trustedNode: {
    targetOrigin: "https://node.example",
    nodeAudience: "did:web:node.example",
    invitationKid: "did:web:node.example#invitation-key-1",
    invitationPublicKey: ed25519.getPublicKey(nodeSeed),
    keyVersion: 1,
    enabled: true,
  },
};

async function generatedShare(): Promise<ShareArtifact> {
  return createShareLink({
    email: "Alice+Notes@EXAMPLE.COM",
    source,
    scope,
    shareId: "share-sdk-email-test",
    expiresAt: "2026-07-23T12:00:00.000Z",
    now: "2026-07-20T12:00:00.000Z",
    adapters: {uploadEnvelope: async () => undefined},
  });
}

function adapterFor(
  modifyAuthorization: (authorization: Record<string, unknown>) => Record<string, unknown> = (authorization) => authorization,
): ShareEmailAdapter & {readonly authorize: ReturnType<typeof vi.fn>; readonly deliver: ReturnType<typeof vi.fn>} {
  const authorize = vi.fn(async (input: Record<string, unknown>) => {
    const request = input.request as Record<string, unknown>;
    const authorization = modifyAuthorization({
      type: "TinyCloudShareInviteAuthorization",
      version: 1,
      jti: request.jti,
      senderDid: request.senderDid,
      shareCid: request.shareCid,
      shareId: request.shareId,
      policyCid: request.policyCid,
      delegationCid: request.delegationCid,
      authorityMaterialHandle: request.authorityMaterialHandle,
      authorityMaterialDigest: request.authorityMaterialDigest,
      recipientEmail: request.recipientEmail,
      targetOrigin: request.targetOrigin,
      nodeAudience: request.nodeAudience,
      returnOrigin: scope.shareOrigin,
      documentName: request.documentName,
      senderTrust: request.senderTrust,
      contentSource: request.contentSource,
      contentSourceDigest: request.contentSourceDigest,
      shareExpiresAt: request.shareExpiresAt,
      issuedAt: "2026-07-20T12:00:00.000Z",
      expiresAt: "2026-07-20T12:05:00.000Z",
      reportAbuseToken: request.reportAbuseToken,
    });
    return {
      authorization: authorization as never,
      proof: {
        alg: "EdDSA" as const,
        kid: scope.trustedNode.invitationKid,
        signature: toBase64Url(ed25519.sign(
          new TextEncoder().encode(`${SIGNATURE_DOMAINS.inviteAuthorization}${canonicalize(authorization)}`),
          nodeSeed,
        )),
      },
    };
  });
  const deliver = vi.fn(async () => ({
    status: "accepted" as const,
    retryAfterSeconds: 20,
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
  }));
  return {
    authorizeInvitation: authorize,
    requestDelivery: deliver,
    authorize,
    deliver,
  } as ShareEmailAdapter & {readonly authorize: typeof authorize; readonly deliver: typeof deliver};
}

describe("email SDK lane", () => {
  it("delivers the identical pre-generated link exactly once after real Node authorization", async () => {
    const share = await generatedShare();
    const adapter = adapterFor();

    await expect(sendShareEmail({share, scope, adapters: adapter})).resolves.toMatchObject({
      status: "accepted",
      state: "queued",
      shareCid: share.shareCid,
      shareId: share.shareId,
      recipientEmail: share.recipientEmail,
    });

    expect(adapter.authorize).toHaveBeenCalledTimes(1);
    expect(adapter.deliver).toHaveBeenCalledTimes(1);
    const delivery = adapter.deliver.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(delivery.shareUrl).toBe(share.shareUrl);
    expect(delivery.authorization).toMatchObject({
      recipientEmail: share.recipientEmail,
      policyCid: share.policyCid,
      contentSource: source,
      targetOrigin: scope.targetOrigin,
      nodeAudience: scope.nodeAudience,
      shareExpiresAt: share.expiresAt,
    });
  });

  it.each([
    ["recipient", {recipientEmail: "other@example.com"}],
    ["policy", {policyCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
    ["resource", {contentSource: {...source, path: "documents/other.md"}}],
    ["action", {contentSource: {...source, action: "tinycloud.sql/read"}}],
    ["expiry", {shareExpiresAt: "2026-07-24T12:00:00.000Z"}],
    ["target", {targetOrigin: "https://other.example"}],
  ] as const)("denies Node authorization %s substitution before delivery", async (_name, change) => {
    const share = await generatedShare();
    const adapter = adapterFor((authorization) => ({...authorization, ...change}));

    await expect(sendShareEmail({share, scope, adapters: adapter})).rejects.toThrow(/invitation-authorization-mismatch/);
    expect(adapter.authorize).toHaveBeenCalledTimes(1);
    expect(adapter.deliver).not.toHaveBeenCalled();
  });

  it("rejects a substituted link artifact before contacting Node or OpenCredentials", async () => {
    const share = await generatedShare();
    const adapter = adapterFor();
    const substituted = {...share, shareUrl: `${share.shareUrl}&link=substituted`} as ShareArtifact;

    await expect(sendShareEmail({share: substituted, scope, adapters: adapter})).rejects.toThrow(/generated exact-email link/);
    expect(adapter.authorize).not.toHaveBeenCalled();
    expect(adapter.deliver).not.toHaveBeenCalled();
  });
});
