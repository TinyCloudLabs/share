import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize, didKeyFromEd25519PublicKey, toBase64Url } from "@tinycloud/share-envelope";
import {
  accessSharedContent,
  createShareLink,
  sendShareEmail,
  type ContentAccessDependencies,
  type ShareArtifact,
  type ShareTransport,
} from "../src/index.js";
import { SIGNATURE_DOMAINS, type SenderScope } from "../../../src/email-share/protocol.js";

const senderSeed = new Uint8Array(32).fill(7);
const nodeSeed = new Uint8Array(32).fill(2);
const senderPublicKey = ed25519.getPublicKey(senderSeed);
const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
const source = { kind: "kv" as const, space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", path: "documents/plan.md", action: "tinycloud.kv/get" as const };

const scope: SenderScope = {
  policyOwnerDid: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
  senderDid,
  signingCapability: { capabilityId: "A".repeat(22), publicKey: senderPublicKey },
  signer: {
    publicKey: senderPublicKey,
    sign: async ({ purpose, message }) => ed25519.sign(new TextEncoder().encode(`${purpose === "envelope" ? SIGNATURE_DOMAINS.envelope : SIGNATURE_DOMAINS.inviteAuthorization}${message}`), senderSeed),
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
  trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: ed25519.getPublicKey(nodeSeed), keyVersion: 1, enabled: true },
};

function deliveryTransport(authorizeInvitation: ShareTransport["authorizeInvitation"]): ShareTransport {
  return {
    authorizeInvitation,
    requestDelivery: vi.fn(async () => ({ status: "accepted" as const, retryAfterSeconds: 20, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest })),
    resend: vi.fn(),
    activate: vi.fn(),
    claimChallenge: vi.fn(),
    claimRedeem: vi.fn(),
    policyChallenge: vi.fn(),
    policySession: vi.fn(),
    read: vi.fn(),
  };
}

async function generatedShare(): Promise<{ share: ShareArtifact; uploads: number; deliveries: ReturnType<typeof vi.fn> }> {
  let uploads = 0;
  const share = await createShareLink({
    email: "Alice+Notes@EXAMPLE.COM",
    source,
    scope,
    shareId: "share-sdk-test",
    expiresAt: "2026-07-23T12:00:00.000Z",
    now: "2026-07-20T12:00:00.000Z",
    adapters: { uploadEnvelope: async () => { uploads += 1; } },
  });
  const deliveries = vi.fn();
  return { share, uploads, deliveries };
}

describe("@tinycloud/share-sdk", () => {
  it("keeps link generation independent from email delivery", async () => {
    const result = await generatedShare();
    expect(result.uploads).toBe(1);
    expect(result.share.shareUrl).toMatch(/^https:\/\/share\.tinycloud\.xyz\/s\/b[a-z2-7]+#k=[A-Za-z0-9_-]{43}$/);
    expect(result.share.action).toBe(source.action);
    expect(result.share.recipientEmail).toBe("Alice+Notes@example.com");
  });

  it("delivers the exact pre-generated link once after signed Node authorization", async () => {
    const { share } = await generatedShare();
    let deliveredUrl: string | undefined;
    const authorizeInvitation = vi.fn(async (input: Record<string, unknown>) => {
      const request = input.request as Record<string, unknown>;
      const authorization = {
        type: "TinyCloudShareInviteAuthorization", version: 1, jti: request.jti, senderDid: request.senderDid, shareCid: request.shareCid, shareId: request.shareId, policyCid: request.policyCid, delegationCid: request.delegationCid, authorityMaterialHandle: request.authorityMaterialHandle, authorityMaterialDigest: request.authorityMaterialDigest, recipientEmail: request.recipientEmail, targetOrigin: request.targetOrigin, nodeAudience: request.nodeAudience, returnOrigin: scope.shareOrigin, documentName: request.documentName, senderTrust: request.senderTrust, contentSource: request.contentSource, contentSourceDigest: request.contentSourceDigest, shareExpiresAt: request.shareExpiresAt, issuedAt: "2026-07-20T12:00:00.000Z", expiresAt: "2026-07-20T12:05:00.000Z", reportAbuseToken: request.reportAbuseToken,
      };
      return { authorization: authorization as never, proof: { alg: "EdDSA" as const, kid: scope.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.inviteAuthorization}${canonicalize(authorization)}`), nodeSeed)) } };
    });
    const transport = deliveryTransport(authorizeInvitation);
    const originalDelivery = transport.requestDelivery;
    transport.requestDelivery = vi.fn(async (input) => { deliveredUrl = String(input.shareUrl); return originalDelivery(input); });
    const receipt = await sendShareEmail({ share, scope, adapters: transport });
    expect(receipt).toMatchObject({ status: "accepted", state: "queued", shareCid: share.shareCid, shareId: share.shareId });
    expect(deliveredUrl).toBe(share.shareUrl);
    expect(authorizeInvitation).toHaveBeenCalledTimes(1);
    expect(transport.requestDelivery).toHaveBeenCalledTimes(1);
  });

  it("rejects authorization substitution before delivery", async () => {
    const { share } = await generatedShare();
    const authorizeInvitation = vi.fn(async (input: Record<string, unknown>) => {
      const request = input.request as Record<string, unknown>;
      const authorization = { ...request, type: "TinyCloudShareInviteAuthorization", version: 1, recipientEmail: "wrong@example.com", returnOrigin: scope.shareOrigin, issuedAt: "2026-07-20T12:00:00.000Z", expiresAt: "2026-07-20T12:05:00.000Z" };
      return { authorization: authorization as never, proof: { alg: "EdDSA" as const, kid: scope.trustedNode.invitationKid, signature: toBase64Url(ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.inviteAuthorization}${canonicalize(authorization)}`), nodeSeed)) } };
    });
    const transport = deliveryTransport(authorizeInvitation);
    await expect(sendShareEmail({ share, scope, adapters: transport })).rejects.toThrow(/invitation-authorization-mismatch/);
    expect(transport.requestDelivery).not.toHaveBeenCalled();
  });

  it("runs content access independently with synchronous scrub and injected protocol seams", async () => {
    const { share } = await generatedShare();
    const events: string[] = [];
    const fakeController = {
      state: { state: "claimed", claim: { holder: { did: "did:key:z6MkhHolder", privateKey: {} as CryptoKey }, credential: "credential", expiresAt: "2026-07-23T12:00:00.000Z", persisted: false } } as const,
      subscribe: () => () => undefined,
      openDocument: async () => { events.push("claim"); },
      read: async () => "# Project plan\n",
      retry: async () => undefined,
      useOtp: () => undefined,
      submitOtp: async () => undefined,
      resend: async () => undefined,
      forget: () => undefined,
    };
    const dependencies: ContentAccessDependencies = {
      registryBaseUrl: "https://registry.tinycloud.xyz",
      transport: {} as ShareTransport,
      credentialTrust: {} as never,
      scrub: () => events.push("scrub"),
      resolve: async () => ({ state: "policy-email-claim-required", envelope: {} as never, shareCid: share.shareCid, policy: { type: "TinyCloudSharePolicy" } }),
      verifyShare: async () => { events.push("verify"); return { shareId: share.shareId, shareCid: share.shareCid, policyCid: share.policyCid, recipientEmail: share.recipientEmail, recipientHint: "A***@example.com", expiry: share.expiresAt, nodeOrigin: scope.targetOrigin, nodeAudience: scope.nodeAudience, requestOrigin: scope.shareOrigin, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest, contentSource: source, contentSourceDigest: "A".repeat(43), action: source.action, resource: source.path, trustedNode: scope.trustedNode }; },
      createController: () => fakeController,
    };
    const result = await accessSharedContent({ shareUrl: `${share.shareUrl}&i=${"B".repeat(22)}&c=${"C".repeat(43)}`, confirmAccess: () => { events.push("confirm"); return true; }, dependencies });
    expect(result.content).toBe("# Project plan\n");
    expect(events).toEqual(["scrub", "verify", "confirm", "claim"]);
  });
});
