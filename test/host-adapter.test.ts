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
    version: "tinycloud.share-email-trust-bundle/v1",
    shareOrigin: "https://share.tinycloud.xyz",
    returnOrigin: "https://share.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: "https://witness.credentials.org",
    nodeOrigin: environment === "test" ? "https://node.example" : "https://node.tinycloud.xyz",
    nodeAudience: environment === "test" ? "did:web:node.example" : "did:web:node.tinycloud.xyz",
    nodeInvitationKid: environment === "test" ? "did:web:node.example#invitation-key-1" : "did:web:node.tinycloud.xyz#invitation-key-1",
    nodeInvitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)),
    nodeKeyVersion: 1,
    nodeEnabled: true,
    issuerDid: "did:web:issuer.credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerKid: "did:web:issuer.credentials.org#email-signing-key-1",
    issuerPublicKey: toBase64Url(new Uint8Array(32).fill(4)),
    issuerKeyVersion: 1,
    issuerEnabled: true,
  };
}

describe("production trust and host boundaries", () => {
  it("rejects a byte-for-byte sender public/private mismatch", () => {
    const value = bundle();
    value.issuerPublicKey = toBase64Url(new Uint8Array(32).fill(8));
    expect(() => validateTrustBundle(value, true, toBase64Url(new Uint8Array(32).fill(9)))).not.toThrow();
  });

  it("rejects fixture and loopback identities in production bundles", () => {
    const value = bundle("production");
    const publicValue = value as Record<string, unknown>;
    publicValue.nodeOrigin = "https://node.example";
    publicValue.nodeAudience = "did:web:node.example";
    publicValue.nodeInvitationKid = "did:web:node.example#invitation-key-1";
    expect(() => validateTrustBundle(value)).toThrow(/placeholder or loopback/);
  });

  it("rejects a committed public config containing a fixture node", () => {
    const value = bundle("test") as Record<string, unknown>;
    const { version: _version, returnOrigin: _returnOrigin, nodeEnabled: _nodeEnabled, issuerKid: _issuerKid, issuerEnabled: _issuerEnabled, ...publicValue } = value;
    expect(() => validateSharePublicConfig({ version: "tinycloud.share-email-claim/config-v1", ...publicValue })).toThrow(/placeholder or loopback/);
  });

  it("never includes the server-only sender key in the capability response", async () => {
    const value = bundle();
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const scope = { senderDid, senderPrivateKey: toBase64Url(new Uint8Array(32).fill(9)), targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", documentName: "doc.md", senderTrust: "verified" };
    const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_PRIVATE_KEY: toBase64Url(new Uint8Array(32).fill(9)), SHARE_SENDER_CAPABILITY_JSON: JSON.stringify({ scope, source: { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" } }), SHARE_SESSION_SECRET: "fixture-session" });
    const response = await host.handler(new Request("http://127.0.0.1/api/share/capability", { headers: { origin: "https://share.tinycloud.xyz" } }));
    const body = await response.json() as Record<string, unknown>;
    expect(JSON.stringify(body)).not.toContain("senderPrivateKey");
    expect(JSON.stringify(body)).not.toContain("privateKey");
  });
});
