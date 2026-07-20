import { ed25519 } from "@noble/curves/ed25519";
import {
  didKeyFromEd25519PublicKey,
  open,
  parseShareUrl,
  shareEnvelopeSchema,
  verifyEnvelope,
} from "@tinycloud/share-envelope";
import { describe, expect, it, vi } from "vitest";

import {
  assertGeneratedShareLink,
  createShareLink,
  type CreateShareLinkInput,
  type GeneratedShareLink,
} from "../src/link.js";
import { SIGNATURE_DOMAINS, type SenderScope } from "../../../src/email-share/protocol.js";

const senderSeed = new Uint8Array(32).fill(7);
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
  signingCapability: { capabilityId: "A".repeat(22), publicKey: senderPublicKey },
  signer: {
    publicKey: senderPublicKey,
    sign: async (input) => ed25519.sign(new TextEncoder().encode(`${SIGNATURE_DOMAINS.envelope}${input.message}`), senderSeed),
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
    invitationPublicKey: new Uint8Array(32).fill(2),
    keyVersion: 1,
    enabled: true,
  },
};

function request(overrides: Partial<CreateShareLinkInput> = {}): CreateShareLinkInput {
  return {
    email: "Alice+Notes@EXAMPLE.COM",
    source,
    scope,
    shareId: "share-sdk-test",
    expiresAt: "2026-07-23T12:00:00.000Z",
    now: "2026-07-20T12:00:00.000Z",
    adapters: { uploadEnvelope: vi.fn(async () => undefined) },
    ...overrides,
  };
}

describe("link-generation SDK lane", () => {
  it("generates a verified policy envelope and performs no mail/provider work", async () => {
    const uploadEnvelope = vi.fn(async (_cid: string, _blob: Uint8Array, _deleteAfter: string) => undefined);
    const mail = vi.fn();
    const provider = vi.fn();
    const result = await createShareLink(request({ adapters: { uploadEnvelope } }));

    expect(uploadEnvelope).toHaveBeenCalledTimes(1);
    expect(mail).not.toHaveBeenCalled();
    expect(provider).not.toHaveBeenCalled();
    expect(result.recipientEmail).toBe("Alice+Notes@example.com");
    expect(result.action).toBe("tinycloud.kv/get");
    expect(result.resource).toBe(source.path);
    expect(result.provenance).toMatchObject({
      senderDid,
      delegationCid: scope.delegationCid,
      authorityMaterialHandle: scope.authorityMaterialHandle,
      target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
    });
    expect(JSON.stringify(result)).not.toMatch(/private|claimSecret|reportAbuseToken|invitationJti/i);

    const { ciphertextCid, key32 } = parseShareUrl(result.shareUrl, { expectedOrigin: scope.shareOrigin });
    const blob = uploadEnvelope.mock.calls[0]?.[1];
    expect(blob).toBeDefined();
    const envelope = shareEnvelopeSchema.parse(JSON.parse(new TextDecoder().decode(await open(blob!, key32))));
    expect(ciphertextCid).toBe(result.shareCid);
    expect(envelope.authorizationTarget.kind).toBe("policy");
    await expect(verifyEnvelope(envelope, { expectedSignerDid: senderDid })).resolves.toBe(true);
  });

  it("rejects recipient, policy, source, action, expiry, and target substitutions before upload", async () => {
    const cases: Array<Partial<CreateShareLinkInput>> = [
      { email: " Alice@example.com" },
      { policy: { recipientEmail: "Mallory@example.com", source, action: source.action, resource: source.path, expiresAt: "2026-07-23T12:00:00.000Z", target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId } } },
      { policy: { recipientEmail: "Alice+Notes@example.com", source: { ...source, path: "documents/other.md" }, action: source.action, resource: "documents/other.md", expiresAt: "2026-07-23T12:00:00.000Z", target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId } } },
      { source: { ...source, action: "tinycloud.sql/read" as never } },
      { expiresAt: "2026-07-19T12:00:00.000Z" },
      { target: { origin: "https://other.example", nodeAudience: scope.nodeAudience, spaceId: scope.spaceId } },
      { scope: { ...scope, senderDid: "did:key:z6Mkwrong" } },
      { scope: { ...scope, trustedNode: { ...scope.trustedNode, targetOrigin: "https://other.example" } } },
      { scope: { ...scope, nodeAudience: "did:web:other.example" } },
      { scope: { ...scope, spaceId: "spaces/alias" } },
      { scope: { ...scope, expiryMin: "2026-07-24T00:00:00.000Z" } },
      { scope: { ...scope, expiryMax: "2026-07-22T00:00:00.000Z" } },
      { scope: { ...scope, expiresAt: "2026-07-22T00:00:00.000Z" } },
    ];

    for (const overrides of cases) {
      const uploadEnvelope = vi.fn(async () => undefined);
      await expect(createShareLink(request({ ...overrides, adapters: { uploadEnvelope } }))).rejects.toThrow();
      expect(uploadEnvelope).not.toHaveBeenCalled();
    }
  });

  it("rejects a substituted link artifact without network access", async () => {
    const link = await createShareLink(request());
    const substituted = { ...link, shareUrl: link.shareUrl.replace("#k=", "?k=") } as GeneratedShareLink;

    expect(() => assertGeneratedShareLink(substituted)).toThrow();
    expect(() => assertGeneratedShareLink(link)).not.toThrow();
  });
});
