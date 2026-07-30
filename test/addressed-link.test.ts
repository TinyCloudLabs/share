import { describe, expect, it } from "vitest";
import { didKeyFromEd25519PublicKey, parseInlineShareUrl, shareEnvelopeV2Schema } from "@tinycloud/share-envelope";
import { createAddressedShareLink, normalizeExactEmail } from "@tinycloud/share-app-compat";

const publicKey = new Uint8Array(32).fill(7);
const source = { kind: "kv" as const, space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" as const };
const scope = {
  policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
  senderDid: didKeyFromEd25519PublicKey(publicKey),
  signingCapability: { capabilityId: "capability", publicKey },
  signer: { publicKey, sign: async () => new Uint8Array(64).fill(8) },
  shareOrigin: "https://share.tinycloud.xyz",
  delegation: "delegation",
  delegationCid: "delegation-cid",
  authorityMaterialHandle: "amh_kv_001" as const,
  authorityMaterialDigest: "A".repeat(43),
  targetOrigin: "https://node.tinycloud.xyz",
  nodeAudience: "did:web:node.tinycloud.xyz",
  spaceId: "space-1",
  documentName: "readme.md",
  senderTrust: "verified" as const,
  trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "kid", invitationPublicKey: publicKey, keyVersion: 1, enabled: true },
  authorityMaterial: {},
};

describe("v2 addressed share creation", () => {
  it("treats expiryMin as an inclusive lower bound", async () => {
    const boundedScope = { ...scope, expiryMin: "2026-07-30T00:00:00.000Z", expiryMax: "2026-08-01T00:00:00.000Z" };
    const input = {
      matcher: { kind: "emailDomain" as const, value: "example.com" }, source, scope: boundedScope,
      policy: { policyCid: "policy-cid", policyBytes: "cG9saWN5" }, actions: ["read" as const], resource: { kind: "exact" as const, path: source.path }, shareId: "expiry-boundary", filename: "", mediaType: "application/octet-stream", byteLength: 0, encrypted: false, format: "inline" as const, uploadEnvelope: async () => undefined,
    };
    await expect(createAddressedShareLink({ ...input, matcher: { kind: "policyDigest", value: "A".repeat(43) }, expiresAt: boundedScope.expiryMin })).resolves.toBeDefined();
    await expect(createAddressedShareLink({ ...input, matcher: { kind: "policyDigest", value: "A".repeat(43) }, expiresAt: "2026-07-29T23:59:59.999Z" })).rejects.toThrow(/minimum/);
    await expect(createAddressedShareLink({ ...input, matcher: { kind: "policyDigest", value: "A".repeat(43) }, expiresAt: boundedScope.expiryMax })).resolves.toBeDefined();
  });

  it("binds domain, actions, and prefix to the signed envelope and honors inline format", async () => {
    const result = await createAddressedShareLink({
      matcher: { kind: "emailDomain", value: "example.com" },
      deliveryEmail: "reader@example.com",
      source,
      scope,
      policy: { policyCid: "policy-cid", policyBytes: "eyJpc3N1ZXJEaWQiOiJkaWQ6a2V5OnoxIn0" },
      actions: ["edit", "read", "list"],
      resource: { kind: "prefix", path: "docs/" },
      shareId: "share-1",
      expiresAt: "2026-07-30T00:00:00.000Z",
      filename: "readme.md",
      mediaType: "text/markdown",
      byteLength: 12,
      encrypted: true,
      format: "inline",
      uploadEnvelope: async () => { throw new Error("inline links do not upload"); },
    });
    expect(result.envelope.recipientMatcher).toEqual({ kind: "emailDomain", value: "example.com" });
    expect(result.envelope.actions).toEqual(["read", "list", "edit"]);
    expect(result.envelope.resource).toEqual({ kind: "prefix", path: "docs/" });
    expect(result.envelope.target).toEqual({ origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId });
    expect(result.envelope.delegationCid).toBe(scope.delegationCid);
    expect(result.envelope.authorityMaterialDigest).toBe(scope.authorityMaterialDigest);
    expect(result.envelope.deliveryEmail).toBe("reader@example.com");
    expect(result.envelope.contentSource).toEqual(source);
    expect(parseInlineShareUrl(result.shareUrl).key32).toHaveLength(32);
    expect(shareEnvelopeV2Schema.parse(result.envelope).version).toBe(2);
  });

  it("stores only the fixed HTML artifact discriminator in encrypted prefix metadata", async () => {
    const result = await createAddressedShareLink({
      matcher: { kind: "emailDomain", value: "example.com" },
      source,
      scope,
      policy: { policyCid: "policy-cid", policyBytes: "cG9saWN5" },
      actions: ["read", "list"],
      resource: { kind: "prefix", path: "docs" },
      shareId: "artifact-share",
      expiresAt: "2026-07-30T00:00:00.000Z",
      filename: "4 files",
      mediaType: "application/x-tinycloud-folder",
      byteLength: 1024,
      artifact: "html",
      encrypted: true,
      format: "inline",
      uploadEnvelope: async () => undefined,
    });
    expect(result.envelope.metadata).toMatchObject({ artifact: "html" });
    expect(JSON.stringify(result.envelope.metadata)).not.toContain("index.html");
  });

  it("rejects plaintext metadata that could expose delivery or content details", async () => {
    await expect(createAddressedShareLink({
      matcher: { kind: "emailDomain", value: "example.com" },
      deliveryEmail: "reader@example.com",
      source,
      scope,
      policy: { policyCid: "policy-cid", policyBytes: "cG9saWN5" },
      actions: ["read"],
      resource: { kind: "exact", path: source.path },
      shareId: "share-2",
      expiresAt: "2026-07-30T00:00:00.000Z",
      filename: "",
      mediaType: "application/octet-stream",
      byteLength: 0,
      encrypted: false,
      format: "inline",
      uploadEnvelope: async () => undefined,
    })).rejects.toThrow(/policy-digest|delivery/i);
  });

  it("creates an acknowledged policy-only plaintext link without content metadata", async () => {
    const result = await createAddressedShareLink({
      matcher: { kind: "policyDigest", value: "A".repeat(43) },
      source,
      scope,
      policy: { policyCid: "policy-cid", policyBytes: "cG9saWN5" },
      actions: ["read"],
      resource: { kind: "exact", path: source.path },
      shareId: "share-plaintext",
      expiresAt: "2026-07-30T00:00:00.000Z",
      filename: "",
      mediaType: "application/octet-stream",
      byteLength: 0,
      encrypted: false,
      format: "inline",
      uploadEnvelope: async () => { throw new Error("policy-only links never upload"); },
    });
    expect(result.envelope.recipientMatcher).toEqual({ kind: "policyDigest", value: "A".repeat(43) });
    expect(result.envelope.metadata).toEqual({});
    expect(result.envelope.content).toBeUndefined();
  });

  it("preserves exact-email local-part case while normalizing only DNS", () => {
    expect(normalizeExactEmail("Alice+Notes@MAILINATOR.COM")).toBe("Alice+Notes@mailinator.com");
    expect(() => normalizeExactEmail(" alice@mailinator.com")).toThrow();
  });
});
