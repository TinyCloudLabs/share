import { describe, expect, it } from "vitest";
import { randomBytes, scryptSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";
import { didKeyFromEd25519PublicKey, toBase64Url } from "@tinycloud/share-envelope";
import { validateSharePublicConfig } from "../src/email-share/config.js";
import { validateTrustBundle } from "../src/host/trust-bundle.js";
import { createShareHostFromEnv, TransactionalBindingStore } from "../src/host/share-adapter.js";

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
    const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_PRIVATE_KEY: toBase64Url(new Uint8Array(32).fill(9)), SHARE_SENDER_CAPABILITY_JSON: JSON.stringify({ scope, source: { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" } }) });
    const response = await host.handler(new Request("http://127.0.0.1/api/share/capability", { headers: { origin: "https://share.tinycloud.xyz" } }));
    const body = await response.json() as Record<string, unknown>;
    expect(JSON.stringify(body)).not.toContain("senderPrivateKey");
    expect(JSON.stringify(body)).not.toContain("privateKey");
  });

  it("accepts the fixture session cookie when a same-origin GET omits Origin", async () => {
    const value = bundle();
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const scope = { senderDid, senderPrivateKey: toBase64Url(new Uint8Array(32).fill(9)), targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", documentName: "doc.md", senderTrust: "verified" };
    const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_PRIVATE_KEY: toBase64Url(new Uint8Array(32).fill(9)), SHARE_SENDER_CAPABILITY_JSON: JSON.stringify({ scope, source: { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" } }) });
    const response = await host.handler(new Request("http://share.tinycloud.xyz/api/share/capability"));
    expect(response.status).toBe(200);
  });

  it("authenticates a user, issues an opaque secure session, and never accepts the configured secret as a cookie", async () => {
    const value = bundle("production");
    const senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9));
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const source = { kind: "kv", space: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", path: "documents/doc.md", action: "tinycloud.kv/get" };
    const scope = { userId: "sender-1", recipientEmail: "recipient@example.com", senderDid, targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: source.space, documentName: "doc.md", senderTrust: "verified", expiresAt: "2026-07-21T00:00:00.000Z" };
    const salt = randomBytes(16); const digest = scryptSync("correct horse", salt, 32, { N: 16_384, r: 8, p: 1 });
    const root = await mkdtemp(`${tmpdir()}/share-auth-`); const storePath = `${root}/bindings.ndjson`;
    try {
      const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey, SHARE_SENDER_CAPABILITY_JSON: JSON.stringify({ scope, source }), SHARE_BINDING_STORE_PATH: storePath, SHARE_AUTH_USERS_JSON: JSON.stringify([{ userId: "sender-1", username: "alice", passwordHash: `scrypt$16384$8$1$${salt.toString("base64url")}$${digest.toString("base64url")}` }]) });
      const login = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/login", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify({ username: "alice", password: "correct horse" }) }));
      expect(login.status).toBe(200);
      const setCookie = login.headers.get("set-cookie") ?? "";
      expect(setCookie).toContain("Secure"); expect(setCookie).toContain("HttpOnly"); expect(setCookie).toContain("SameSite=Lax"); expect(setCookie).toContain("Path=/"); expect(setCookie).toContain("Max-Age=1800"); expect(setCookie).not.toContain("correct horse");
      const cookieValue = setCookie.split(";", 1)[0]!; expect(cookieValue).not.toContain("SHARE_SESSION_SECRET");
      const capabilityResponse = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capability", { headers: { origin: "https://share.tinycloud.xyz", cookie: cookieValue } }));
      expect(capabilityResponse.status).toBe(200); expect((await capabilityResponse.json()).scope.userId).toBe("sender-1");
      const configuredSecret = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capability", { headers: { origin: "https://share.tinycloud.xyz", cookie: "share_session=fixture-session" } }));
      expect(configuredSecret.status).toBe(401);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("serializes concurrent durable binding writes, survives restart, and fails closed on corruption", async () => {
    const root = await mkdtemp(`${tmpdir()}/share-bindings-`); const path = `${root}/bindings.ndjson`;
    try {
      const first = new TransactionalBindingStore(path); const second = new TransactionalBindingStore(path);
      await Promise.all(Array.from({ length: 20 }, (_, index) => (index % 2 === 0 ? first : second).put(`cid-${index}`, { index })));
      const restarted = new TransactionalBindingStore(path);
      expect((await Promise.all(Array.from({ length: 20 }, (_, index) => restarted.get(`cid-${index}`)))).filter(Boolean)).toHaveLength(20);
      await writeFile(path, "{corrupt\n", "utf8");
      await expect(restarted.get("cid-1")).rejects.toThrow(/corrupt|invalid/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
