import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { didKeyFromEd25519PublicKey, toBase64Url } from "@tinycloud/share-envelope";
import { validateSharePublicConfig } from "../src/email-share/config.js";
import { validateTrustBundle } from "../src/host/trust-bundle.js";
import { createShareHostFromEnv } from "../src/host/share-adapter.js";

function bundle(environment: "production" | "test" = "test"): Record<string, unknown> {
  const privateKey = new Uint8Array(32).fill(9);
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    version: 1,
    environment,
    public: {
      shareOrigin: "https://share.tinycloud.xyz",
      registryOrigin: "https://registry.tinycloud.xyz",
      nodeOrigin: environment === "test" ? "https://node.example" : "https://node.tinycloud.xyz",
      credentialsOrigin: "https://witness.credentials.org",
      nodeAudience: environment === "test" ? "did:web:node.example" : "did:web:node.tinycloud.xyz",
      issuerDid: "did:web:issuer.credentials.org",
      issuerVct: "opencredentials.email/v1",
      nodeInvitationKid: environment === "test" ? "did:web:node.example#invitation-key-1" : "did:web:node.tinycloud.xyz#invitation-key-1",
      nodeInvitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)),
      issuerPublicKey: toBase64Url(new Uint8Array(32).fill(4)),
    },
    sender: { senderDid: didKeyFromEd25519PublicKey(publicKey), senderPublicKey: toBase64Url(publicKey), senderPrivateKey: toBase64Url(privateKey) },
  };
}

describe("production trust and host boundaries", () => {
  it("rejects a byte-for-byte sender public/private mismatch", () => {
    const value = bundle();
    (value.sender as Record<string, unknown>).senderPublicKey = toBase64Url(new Uint8Array(32).fill(8));
    expect(() => validateTrustBundle(value, true)).toThrow(/key binding is inconsistent/);
  });

  it("rejects fixture and loopback identities in production bundles", () => {
    const value = bundle("production");
    const publicValue = value.public as Record<string, unknown>;
    publicValue.nodeOrigin = "https://node.example";
    publicValue.nodeAudience = "did:web:node.example";
    publicValue.nodeInvitationKid = "did:web:node.example#invitation-key-1";
    expect(() => validateTrustBundle(value)).toThrow(/placeholder or loopback/);
  });

  it("rejects a committed public config containing a fixture node", () => {
    const value = bundle("test").public as Record<string, unknown>;
    expect(() => validateSharePublicConfig({ version: "tinycloud.share-email-claim/config-v1", ...value })).toThrow(/placeholder or loopback/);
  });

  it("never includes the server-only sender key in the capability response", async () => {
    const value = bundle();
    const publicValue = value.public as Record<string, unknown>;
    const sender = value.sender as Record<string, unknown>;
    const scope = { senderDid: sender.senderDid, senderPrivateKey: sender.senderPrivateKey, targetOrigin: publicValue.nodeOrigin, nodeAudience: publicValue.nodeAudience, trustedNode: { targetOrigin: publicValue.nodeOrigin, nodeAudience: publicValue.nodeAudience, invitationKid: publicValue.nodeInvitationKid, invitationPublicKey: publicValue.nodeInvitationPublicKey, keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", documentName: "doc.md", senderTrust: "verified" };
    const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_CAPABILITY_JSON: JSON.stringify({ scope, source: { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" } }), SHARE_SESSION_SECRET: "fixture-session" });
    const response = await host.handler(new Request("http://127.0.0.1/api/share/capability", { headers: { origin: "https://share.tinycloud.xyz" } }));
    const body = await response.json() as Record<string, unknown>;
    expect(JSON.stringify(body)).not.toContain("senderPrivateKey");
    expect(JSON.stringify(body)).not.toContain("privateKey");
  });
});
