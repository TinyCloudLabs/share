import { describe, expect, it, vi } from "vitest";
import { createHash, randomBytes, scryptSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";
import { privateKeyToAccount } from "viem/accounts";
import { didKeyFromEd25519PublicKey, toBase64Url } from "@tinycloud/share-envelope";
import { trustedNodeFromConfig, validateSharePublicConfig } from "../src/email-share/config.js";
import { validateTrustBundle } from "../src/host/trust-bundle.js";
import { createShareHostFromEnv, TransactionalBindingStore } from "../src/host/share-adapter.js";
import { resolveShareUpstreams, upstreamForPath } from "../src/host/upstream.js";

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

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function sourceDigest(source: Record<string, unknown>): string {
  return createHash("sha256").update(stable(source), "utf8").digest("base64url");
}

function authorizationSigningBinding(message: Record<string, unknown>, policy: Record<string, unknown>): Record<string, unknown> {
  return {
    ...message,
    expiresAt: message.shareExpiresAt,
    policyDigest: policy.policyDigest,
    policyAuthorityCid: policy.policyAuthorityCid,
    policyAuthorityBytes: policy.policyAuthorityBytes,
    policyEnforcementCid: policy.policyEnforcementCid,
    policyEnforcementBytes: policy.policyEnforcementBytes,
  };
}

function authorizationMessage(value: Record<string, unknown>): Record<string, unknown> {
  const message: Record<string, unknown> = { ...value, jti: "A".repeat(22), reportAbuseToken: "B".repeat(22) };
  const body = { shareCid: message.shareCid, shareId: message.shareId, policyCid: message.policyCid, delegationCid: message.delegationCid, authorityMaterialHandle: message.authorityMaterialHandle, authorityMaterialDigest: message.authorityMaterialDigest, recipientEmail: message.recipientEmail, targetOrigin: message.targetOrigin, nodeAudience: message.nodeAudience, action: message.action, resource: message.resource };
  return { ...message, requestBodyDigest: sourceDigest(body) };
}

function capability(scope: Record<string, any>, source: Record<string, unknown>, overrides: { readonly email?: string; readonly expiresAt?: string } = {}): string {
  const email = overrides.email ?? scope.recipientEmail ?? "recipient@example.com";
  const expiresAt = overrides.expiresAt ?? scope.expiresAt ?? scope.expiryMax ?? "2026-07-21T00:00:00.000Z";
  return JSON.stringify({ scope, source, policy: {
    action: source.action, authorityMaterialDigest: scope.authorityMaterialDigest, contentSourceDigest: sourceDigest(source), delegationCid: scope.delegationCid,
    expiresAt, policyAuthorityBytes: "AQ", policyAuthorityCid: "authority-cid", policyBytes: "eyJ0eXBlIjoiVGlueUNsb3VkU2hhcmVQb2xpY3kifQ", policyDigest: "policy-digest", policyEnforcementBytes: "Ag", policyEnforcementCid: "enforcement-cid", policyCid: "policy-cid", recipientEmail: email, resource: source.path, source,
    target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
  } });
}

async function openKeySignIn(host: ReturnType<typeof createShareHostFromEnv>, account: ReturnType<typeof privateKeyToAccount>) {
  const nonceResponse = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey/nonce", { headers: { origin: "https://share.tinycloud.xyz" } }));
  const { nonce } = await nonceResponse.json() as { nonce: string };
  const issuedAt = new Date().toISOString();
  const message = ["share.tinycloud.xyz wants you to sign in with your Ethereum account:", account.address, "", "Sign in to TinyCloud Share.", "", "URI: https://share.tinycloud.xyz", "Version: 1", `Nonce: ${nonce}`, `Issued At: ${issuedAt}`].join("\n");
  const signature = await account.signMessage({ message });
  const body = { address: account.address, signature, message, nonce, issuedAt };
  const response = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify(body) }));
  return { body, response, cookie: response.headers.get("set-cookie")?.split(";", 1)[0] };
}

describe("production trust and host boundaries", () => {
  it("derives every sensitive upstream from the authoritative trust tuple when overrides are omitted", () => {
    const value = validateTrustBundle(bundle("production"), false);
    expect(resolveShareUpstreams(value, {})).toEqual({ node: value.public.nodeOrigin, credentials: value.public.credentialsOrigin, registry: value.public.registryOrigin });
    expect(upstreamForPath(value, "/share/v1/read", {})).toEqual({ service: "node", origin: value.public.nodeOrigin });
    expect(upstreamForPath(value, "/v1/share-email/claims/redeem", {})).toEqual({ service: "credentials", origin: value.public.credentialsOrigin });
    expect(upstreamForPath(value, "/registry/blobs", {})).toEqual({ service: "registry", origin: value.public.registryOrigin });
  });

  it.each([
    ["omitted hermetic flag", JSON.stringify({ node: { origin: "https://node.tinycloud.xyz", transportOrigin: "http://127.0.0.1:8000" }, credentials: { origin: "https://witness.credentials.org", transportOrigin: "http://127.0.0.1:8001" }, registry: { origin: "https://registry.tinycloud.xyz", transportOrigin: "http://127.0.0.1:8002" } }), {}],
    ["malformed JSON", "{", { SHARE_HERMETIC_COMPOSITION: "true" }],
    ["loopback placeholder", JSON.stringify({ node: { origin: "https://node.tinycloud.xyz", transportOrigin: "http://localhost:8000" }, credentials: { origin: "https://witness.credentials.org", transportOrigin: "http://127.0.0.1:8001" }, registry: { origin: "https://registry.tinycloud.xyz", transportOrigin: "http://127.0.0.1:8002" } }), { SHARE_HERMETIC_COMPOSITION: "true" }],
    ["bundle-inconsistent origin", JSON.stringify({ node: { origin: "https://node.other.example", transportOrigin: "http://127.0.0.1:8000" }, credentials: { origin: "https://witness.credentials.org", transportOrigin: "http://127.0.0.1:8001" }, registry: { origin: "https://registry.tinycloud.xyz", transportOrigin: "http://127.0.0.1:8002" } }), { SHARE_HERMETIC_COMPOSITION: "true" }],
  ])("rejects %s hermetic upstream composition", (_label, raw, env) => {
    const value = validateTrustBundle(bundle("production"), false);
    expect(() => resolveShareUpstreams(value, { ...env, SHARE_HERMETIC_UPSTREAMS_JSON: raw })).toThrow();
  });

  it("rejects legacy transport overrides even when they point at a valid loopback", () => {
    const value = validateTrustBundle(bundle("production"), false);
    expect(() => resolveShareUpstreams(value, { SHARE_NODE_TRANSPORT_ORIGIN: "http://127.0.0.1:8000" })).toThrow(/legacy/);
  });

  it("accepts only exact trust-bound hermetic routes", () => {
    const value = validateTrustBundle(bundle("production"), false);
    const env = { SHARE_HERMETIC_COMPOSITION: "true", SHARE_HERMETIC_UPSTREAMS_JSON: JSON.stringify({ node: { origin: value.public.nodeOrigin, transportOrigin: "http://127.0.0.1:8000" }, credentials: { origin: value.public.credentialsOrigin, transportOrigin: "http://127.0.0.1:8001" }, registry: { origin: value.public.registryOrigin, transportOrigin: "http://127.0.0.1:8002" } }) };
    expect(resolveShareUpstreams(value, env)).toEqual({ node: "http://127.0.0.1:8000", credentials: "http://127.0.0.1:8001", registry: "http://127.0.0.1:8002" });
  });

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
    const { version: _version, returnOrigin: _returnOrigin, issuerKid: _issuerKid, ...publicValue } = value;
    expect(() => validateSharePublicConfig({ version: "tinycloud.share-email-claim/config-v1", ...publicValue })).toThrow(/placeholder or loopback/);
  });

  it("never includes the server-only sender key in the capability response", async () => {
    const value = bundle();
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const scope = { userId: "fixture", senderDid, senderPrivateKey: toBase64Url(new Uint8Array(32).fill(9)), targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", documentName: "doc.md", senderTrust: "verified" };
    const source = { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" };
    const host = createShareHostFromEnv({ SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_PRIVATE_KEY: toBase64Url(new Uint8Array(32).fill(9)), SHARE_SENDER_CAPABILITY_JSON: capability(scope, source) });
    const response = await host.handler(new Request("http://127.0.0.1/api/share/capability", { headers: { origin: "https://share.tinycloud.xyz" } }));
    const body = await response.json() as Record<string, unknown>;
    expect(JSON.stringify(body)).not.toContain("senderPrivateKey");
    expect(JSON.stringify(body)).not.toContain("privateKey");
  });

  it("accepts the fixture session cookie when a same-origin GET omits Origin", async () => {
    const value = bundle();
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const scope = { userId: "fixture", senderDid, senderPrivateKey: toBase64Url(new Uint8Array(32).fill(9)), targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", documentName: "doc.md", senderTrust: "verified" };
    const source = { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" };
    const host = createShareHostFromEnv({ SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_PRIVATE_KEY: toBase64Url(new Uint8Array(32).fill(9)), SHARE_SENDER_CAPABILITY_JSON: capability(scope, source) });
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
      const host = createShareHostFromEnv({ SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey, SHARE_SENDER_CAPABILITY_JSON: capability(scope, source), SHARE_BINDING_STORE_PATH: storePath, SHARE_AUTH_USERS_JSON: JSON.stringify([{ userId: "sender-1", username: "alice", passwordHash: `scrypt$16384$8$1$${salt.toString("base64url")}$${digest.toString("base64url")}` }]) });
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

  it("runs the complete OpenKey nonce, proof, callback, session, and logout flow in default auth-only mode", async () => {
    const value = bundle("production");
    value.nodeEnabled = false;
    const account = privateKeyToAccount(`0x${"21".repeat(32)}`);
    const host = createShareHostFromEnv({
      SHARE_TRUST_BUNDLE: JSON.stringify(value),
      SHARE_SENDER_PRIVATE_KEY: "stale-invalid-secret",
      SHARE_SENDER_CAPABILITY_JSON: "{stale-invalid-capability",
      SHARE_BINDING_STORE_PATH: "/missing/stale/bindings.ndjson",
    });
    expect(host.readiness).toEqual({ authReady: true, senderReady: false });
    const publicConfig = validateSharePublicConfig(host.publicConfig);
    expect(publicConfig.nodeEnabled).toBe(false);
    expect(trustedNodeFromConfig(publicConfig).enabled).toBe(false);
    expect((await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey/nonce", { headers: { origin: "https://evil.example" } }))).status).toBe(403);

    const invalidNonce = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey/nonce", { headers: { origin: "https://share.tinycloud.xyz" } }));
    const { nonce } = await invalidNonce.json() as { nonce: string };
    const issuedAt = new Date().toISOString();
    const invalidMessage = ["share.tinycloud.xyz wants you to sign in with your Ethereum account:", account.address, "", "Sign in to TinyCloud Share.", "", "URI: https://share.tinycloud.xyz", "Version: 1", `Nonce: ${nonce}`, `Issued At: ${issuedAt}`].join("\n");
    const invalid = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify({ address: account.address, signature: `0x${"00".repeat(65)}`, message: invalidMessage, nonce, issuedAt }) }));
    expect(invalid.status).toBe(401);

    const ceremony = await openKeySignIn(host, account);
    expect(ceremony.response.status).toBe(200);
    expect(await ceremony.response.json()).toEqual({ status: "authenticated", address: account.address.toLowerCase() });
    expect(ceremony.cookie).toMatch(/^share_session=[A-Za-z0-9_-]{43}$/);
    const sessionHeaders = { origin: "https://share.tinycloud.xyz", cookie: ceremony.cookie! };
    const listed = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: sessionHeaders }));
    expect(listed.status).toBe(200);
    expect(await listed.json()).toEqual({ capabilities: [] });
    expect((await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: { ...sessionHeaders, origin: "https://evil.example" } }))).status).toBe(401);
    expect((await host.handler(new Request("https://share.tinycloud.xyz/api/share/capability", { headers: sessionHeaders }))).status).toBe(503);
    expect((await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify(ceremony.body) }))).status).toBe(401);
    expect((await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/logout", { method: "POST", headers: sessionHeaders }))).status).toBe(200);
    expect((await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: sessionHeaders }))).status).toBe(401);
  });

  it("authorizes bounded encrypted registry writes with the OpenKey session while sender routes stay disabled", async () => {
    const value = bundle("production");
    value.nodeEnabled = false;
    const host = createShareHostFromEnv({
      SHARE_TRUST_BUNDLE: JSON.stringify(value),
    });
    const endpoint =
      "https://share.tinycloud.xyz/api/share/link-only/registry/blobs";
    const deleteAfter = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const upload = (body: Uint8Array, cookie?: string, contentType = "application/vnd.ipld.raw") =>
      host.handler(
        new Request(endpoint, {
          method: "POST",
          headers: {
            origin: "https://share.tinycloud.xyz",
            "content-type": contentType,
            "if-none-match": "*",
            "x-delete-after": deleteAfter,
            ...(cookie === undefined ? {} : { cookie }),
          },
          body: body.slice().buffer as ArrayBuffer,
        }),
      );

    expect((await upload(new Uint8Array([1]))).status).toBe(401);
    expect(
      (
        await host.handler(
          new Request("https://share.tinycloud.xyz/registry/blobs", {
            method: "POST",
            headers: {
              "content-type": "application/vnd.ipld.raw",
              "if-none-match": "*",
              "x-delete-after": deleteAfter,
            },
            body: new Uint8Array([1]),
          }),
        )
      ).status,
    ).toBe(401);

    const account = privateKeyToAccount(`0x${"41".repeat(32)}`);
    const ceremony = await openKeySignIn(host, account);
    const cookie = ceremony.cookie!;
    const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          cid: `bafkrei${"a".repeat(52)}`,
          deleteAfter: "2026-07-30T00:00:00.000Z",
        }),
        {
          status: 201,
          headers: { "content-type": "application/json" },
        },
      ),
    );
    const accepted = await upload(new Uint8Array([1, 2, 3]), cookie);
    expect(accepted.status).toBe(201);
    expect(upstream).toHaveBeenCalledOnce();
    const [target, init] = upstream.mock.calls[0]!;
    expect(String(target)).toBe("https://registry.tinycloud.xyz/blobs");
    const forwarded = new Headers(init?.headers);
    expect(forwarded.get("cookie")).toBeNull();
    expect(forwarded.get("origin")).toBe("https://registry.tinycloud.xyz");
    expect(forwarded.get("if-none-match")).toBe("*");

    upstream.mockClear();
    expect((await upload(new Uint8Array(64 * 1024 + 1), cookie)).status).toBe(413);
    expect(upstream).not.toHaveBeenCalled();
    expect(
      (await upload(new Uint8Array([1]), cookie, "application/json")).status,
    ).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
    expect(host.readiness).toEqual({ authReady: true, senderReady: false });
    expect(
      (
        await host.handler(
          new Request(
            "https://share.tinycloud.xyz/share/v1/invitations/authorize",
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: "{}",
            },
          ),
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await host.handler(
          new Request("https://share.tinycloud.xyz/api/share/sign", {
            method: "POST",
            headers: {
              origin: "https://share.tinycloud.xyz",
              "content-type": "application/json",
              cookie,
            },
            body: "{}",
          }),
        )
      ).status,
    ).toBe(503);
  });

  it("rejects sender enablement when the trusted node is disabled", () => {
    const value = bundle();
    value.nodeEnabled = false;
    expect(() => createShareHostFromEnv({
      SHARE_SENDER_ENABLED: "true",
      SHARE_TRUST_BUNDLE: JSON.stringify(value),
      SHARE_TRUST_BUNDLE_ALLOW_TEST: "true",
      SHARE_SENDER_PRIVATE_KEY: toBase64Url(new Uint8Array(32).fill(9)),
      SHARE_SENDER_CAPABILITY_JSON: "{}",
    })).toThrow(/enabled trusted node/);
  });

  it("isolates capability listing and selection between two verified wallets", async () => {
    const value = bundle("production");
    const senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9));
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const alice = privateKeyToAccount(`0x${"31".repeat(32)}`);
    const bob = privateKeyToAccount(`0x${"32".repeat(32)}`);
    const common = {
      senderDid,
      targetOrigin: "https://node.tinycloud.xyz",
      nodeAudience: "did:web:node.tinycloud.xyz",
      trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true },
      delegation: "delegation",
      delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
      authorityMaterialHandle: "amh_kv_001",
      authorityMaterialDigest: "A".repeat(43),
      senderTrust: "verified",
      expiresAt: "2026-07-24T00:00:00.000Z",
    };
    const aliceScope = { ...common, policyOwnerDid: `did:pkh:eip155:1:${alice.address}`, spaceId: `did:pkh:eip155:1:${alice.address}`, documentName: "alice.md" };
    const bobScope = { ...common, policyOwnerDid: `did:pkh:eip155:1:${bob.address}`, spaceId: `did:pkh:eip155:1:${bob.address}`, documentName: "bob.md" };
    const aliceSource = { kind: "kv", space: aliceScope.spaceId, path: "documents/alice.md", action: "tinycloud.kv/get" };
    const bobSource = { kind: "kv", space: bobScope.spaceId, path: "documents/bob.md", action: "tinycloud.kv/get" };
    const root = await mkdtemp(`${tmpdir()}/share-wallet-isolation-`);
    try {
      const host = createShareHostFromEnv({
        SHARE_SENDER_ENABLED: "true",
        SHARE_TRUST_BUNDLE: JSON.stringify(value),
        SHARE_SENDER_PRIVATE_KEY: senderPrivateKey,
        SHARE_SENDER_CAPABILITIES_JSON: JSON.stringify([capability(aliceScope, aliceSource), capability(bobScope, bobSource)]),
        SHARE_BINDING_STORE_PATH: `${root}/bindings.ndjson`,
      });
      const aliceSession = await openKeySignIn(host, alice);
      const bobSession = await openKeySignIn(host, bob);
      expect(aliceSession.response.status).toBe(200);
      expect(bobSession.response.status).toBe(200);

      const inspect = async (cookie: string) => {
        const headers = { origin: "https://share.tinycloud.xyz", cookie };
        const listedResponse = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers }));
        const listed = await listedResponse.json() as { capabilities: Array<{ capabilityId: string; source: Record<string, unknown> }> };
        const selectedResponse = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capability", { headers }));
        return { headers, listed, selected: await selectedResponse.json() as { source: Record<string, unknown> } };
      };
      const aliceView = await inspect(aliceSession.cookie!);
      const bobView = await inspect(bobSession.cookie!);
      expect(aliceView.listed.capabilities.map((entry) => entry.source.path)).toEqual(["documents/alice.md"]);
      expect(aliceView.selected.source.path).toBe("documents/alice.md");
      expect(JSON.stringify(aliceView)).not.toContain("documents/bob.md");
      expect(bobView.listed.capabilities.map((entry) => entry.source.path)).toEqual(["documents/bob.md"]);
      expect(bobView.selected.source.path).toBe("documents/bob.md");
      expect(JSON.stringify(bobView)).not.toContain("documents/alice.md");

      const bobCapabilityId = bobView.listed.capabilities[0]!.capabilityId;
      const crossWalletSelection = await host.handler(new Request("https://share.tinycloud.xyz/api/share/sign", {
        method: "POST",
        headers: { ...aliceView.headers, "content-type": "application/json", "idempotency-key": "A".repeat(22) },
        body: JSON.stringify({ capabilityId: bobCapabilityId, purpose: "inviteAuthorization", message: "{}", binding: {} }),
      }));
      expect(crossWalletSelection.status).toBe(400);
      expect(JSON.stringify(await crossWalletSelection.json())).not.toContain("bob.md");
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("authenticates an OpenKey proof only when its address owns the policy capability", async () => {
    const value = bundle("production");
    const senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9));
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const account = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const source = { kind: "kv", space: `did:pkh:eip155:1:${account.address}`, path: "documents/doc.md", action: "tinycloud.kv/get" };
    const scope = { userId: "openkey-sender", senderDid, targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: `did:pkh:eip155:1:${account.address}`, delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: source.space, documentName: "doc.md", senderTrust: "verified", expiresAt: "2026-07-23T00:00:00.000Z" };
    const root = await mkdtemp(`${tmpdir()}/share-openkey-`); const storePath = `${root}/bindings.ndjson`;
    try {
      const host = createShareHostFromEnv({ SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey, SHARE_SENDER_CAPABILITY_JSON: capability(scope, source, { expiresAt: scope.expiresAt }), SHARE_BINDING_STORE_PATH: storePath });
      const nonceResponse = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/openkey/nonce", { headers: { origin: "https://share.tinycloud.xyz" } }));
      expect(nonceResponse.status).toBe(200);
      const { nonce } = await nonceResponse.json() as { nonce: string };
      const issuedAt = new Date().toISOString();
      const message = ["share.tinycloud.xyz wants you to sign in with your Ethereum account:", account.address, "", "Sign in to TinyCloud Share.", "", "URI: https://share.tinycloud.xyz", "Version: 1", `Nonce: ${nonce}`, `Issued At: ${issuedAt}`].join("\n");
      const signature = await account.signMessage({ message });
      const request = () => new Request("https://share.tinycloud.xyz/api/share/auth/openkey", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify({ address: account.address, signature, message, nonce, issuedAt }) });
      const authenticated = await host.handler(request());
      expect(authenticated.status).toBe(200);
      const cookie = authenticated.headers.get("set-cookie")!.split(";", 1)[0]!;
      const listed = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: { origin: "https://share.tinycloud.xyz", cookie } }));
      expect(listed.status).toBe(200);
      expect(((await listed.json()) as { capabilities: unknown[] }).capabilities).toHaveLength(1);
      expect((await host.handler(request())).status).toBe(401);
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

  it("probes the exact binding journal and persists a successful write/read", async () => {
    const root = await mkdtemp(`${tmpdir()}/share-binding-probe-`);
    try {
      const missingParent = new TransactionalBindingStore(`${root}/missing/bindings.ndjson`);
      expect(missingParent.writable).toBe(false);

      const readOnly = `${root}/read-only`;
      await mkdir(readOnly);
      await chmod(readOnly, 0o500);
      const permissionDenied = new TransactionalBindingStore(`${readOnly}/bindings.ndjson`);
      if (process.platform !== "win32" && process.getuid?.() !== 0) expect(permissionDenied.writable).toBe(false);
      await chmod(readOnly, 0o700);

      const path = `${root}/usable/bindings.ndjson`;
      await mkdir(`${root}/usable`);
      const store = new TransactionalBindingStore(path);
      expect(store.writable).toBe(true);
      expect(await store.get("cid")).toBeUndefined();
      await store.put("cid", { value: "persisted" });
      expect(await store.get("cid")).toEqual({ value: "persisted" });
      expect(await new TransactionalBindingStore(path).get("cid")).toEqual({ value: "persisted" });
    } finally {
      await chmod(`${root}/read-only`, 0o700).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  });

  it("parses sender enablement strictly and fails startup for incomplete or unusable enabled material", async () => {
    const value = bundle("production");
    const senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9));
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const scope = { policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", senderDid, targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", documentName: "doc.md", senderTrust: "verified", expiresAt: "2026-07-24T00:00:00.000Z" };
    const source = { kind: "kv", space: scope.spaceId, path: "documents/doc.md", action: "tinycloud.kv/get" };
    const common = { SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey, SHARE_SENDER_CAPABILITY_JSON: capability(scope, source) };
    expect(() => createShareHostFromEnv({ ...common, SHARE_SENDER_ENABLED: "yes" })).toThrow(/exactly true or false/);
    expect(() => createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_ENABLED: "true" })).toThrow(/private key|capability/);
    expect(() => createShareHostFromEnv({ ...common, SHARE_SENDER_ENABLED: "true" })).toThrow(/binding store/);
    expect(() => createShareHostFromEnv({ ...common, SHARE_SENDER_ENABLED: "true", SHARE_BINDING_STORE_PATH: "/missing/share-parent/bindings.ndjson" })).toThrow(/not writable/);

    const root = await mkdtemp(`${tmpdir()}/share-sender-enabled-`);
    try {
      const enabled = createShareHostFromEnv({ ...common, SHARE_SENDER_ENABLED: "true", SHARE_BINDING_STORE_PATH: `${root}/bindings.ndjson` });
      expect(enabled.readiness).toEqual({ authReady: true, senderReady: true });
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("selects the authenticated capability named by signing and binding requests", async () => {
    const value = bundle("production");
    const senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9));
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const baseScope = { userId: "sender-1", recipientEmail: "recipient@example.com", senderDid, targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", documentName: "doc.md", senderTrust: "verified", expiresAt: "2026-07-21T00:00:00.000Z" };
    const firstSource = { kind: "kv", space: baseScope.spaceId, path: "documents/first.md", action: "tinycloud.kv/get" };
    const secondSource = { kind: "kv", space: baseScope.spaceId, path: "documents/second.md", action: "tinycloud.kv/get" };
    const salt = randomBytes(16); const digest = scryptSync("correct horse", salt, 32, { N: 16_384, r: 8, p: 1 });
    const root = await mkdtemp(`${tmpdir()}/share-capabilities-`); const storePath = `${root}/bindings.ndjson`;
    try {
      const host = createShareHostFromEnv({ SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey, SHARE_SENDER_CAPABILITIES_JSON: JSON.stringify([capability(baseScope, firstSource), capability({ ...baseScope, documentName: "second.md" }, secondSource)]), SHARE_BINDING_STORE_PATH: storePath, SHARE_AUTH_USERS_JSON: JSON.stringify([{ userId: "sender-1", username: "alice", passwordHash: `scrypt$16384$8$1$${salt.toString("base64url")}$${digest.toString("base64url")}` }]) });
      const login = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/login", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify({ username: "alice", password: "correct horse" }) }));
      const cookie = login.headers.get("set-cookie")!.split(";", 1)[0]!;
      const listed = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: { origin: "https://share.tinycloud.xyz", cookie } }));
      const capabilities = await listed.json() as { capabilities: Array<{ capabilityId: string; scope: Record<string, unknown>; source: Record<string, unknown>; policy: Record<string, unknown> }> };
      const selected = capabilities.capabilities.find((candidate) => candidate.source.path === "documents/second.md")!;
      const source = selected.source;
      const message = authorizationMessage({ shareCid: `bafkrei${"a".repeat(52)}`, shareId: "share-2", senderDid, targetOrigin: baseScope.targetOrigin, nodeAudience: baseScope.nodeAudience, returnOrigin: "https://share.tinycloud.xyz", policyCid: selected.policy.policyCid, delegationCid: baseScope.delegationCid, authorityMaterialHandle: baseScope.authorityMaterialHandle, authorityMaterialDigest: baseScope.authorityMaterialDigest, documentName: "second.md", senderTrust: "verified", recipientEmail: baseScope.recipientEmail, action: source.action, resource: source.path, contentSource: source, contentSourceDigest: sourceDigest(source), shareExpiresAt: baseScope.expiresAt });
      const signed = await host.handler(new Request("https://share.tinycloud.xyz/api/share/sign", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", cookie, "content-type": "application/json", "idempotency-key": "A".repeat(22) }, body: JSON.stringify({ capabilityId: selected.capabilityId, purpose: "inviteAuthorization", message: JSON.stringify(message), binding: authorizationSigningBinding(message, selected.policy) }) }));
      expect(signed.status).toBe(200);
      const cid = `bafkrei${"a".repeat(52)}`;
      const selectedPolicy = ((await (await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: { origin: "https://share.tinycloud.xyz", cookie } }))).json()) as any).capabilities.find((candidate: any) => candidate.capabilityId === selected.capabilityId).policy;
      const put = await host.handler(new Request("https://share.tinycloud.xyz/api/share/bindings", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", cookie, "content-type": "application/json" }, body: JSON.stringify({ shareCid: cid, capabilityId: selected.capabilityId, binding: { shareCid: cid, shareId: "share-2", recipientEmail: baseScope.recipientEmail, expiry: selectedPolicy.expiresAt, policyCid: selectedPolicy.policyCid, policyDigest: selectedPolicy.policyDigest, policyBytes: selectedPolicy.policyBytes, delegationCid: baseScope.delegationCid, authorityMaterialHandle: baseScope.authorityMaterialHandle, authorityMaterialDigest: baseScope.authorityMaterialDigest, policyAuthorityCid: selectedPolicy.policyAuthorityCid, policyAuthorityBytes: selectedPolicy.policyAuthorityBytes, policyEnforcementCid: selectedPolicy.policyEnforcementCid, policyEnforcementBytes: selectedPolicy.policyEnforcementBytes, contentSource: source, contentSourceDigest: sourceDigest(source), action: source.action, resource: source.path, target: { origin: baseScope.targetOrigin, nodeAudience: baseScope.nodeAudience, spaceId: baseScope.spaceId }, returnOrigin: "https://share.tinycloud.xyz" } }) }));
      expect(put.status).toBe(201);
      const stored = await host.handler(new Request(`https://share.tinycloud.xyz/.well-known/tinycloud-share/bindings/${cid}`, { method: "GET" }));
      expect(stored.status).toBe(200);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("keeps recipient and expiry selectable while binding both to the authenticated resource", async () => {
    const value = bundle("production");
    const senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9));
    const senderDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
    const source = { kind: "kv", space: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", path: "documents/selected.md", action: "tinycloud.kv/get" };
    const scope = { userId: "sender-1", senderDid, targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", trustedNode: { targetOrigin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", invitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true }, policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111", delegation: "delegation", delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43), spaceId: source.space, documentName: "selected.md", senderTrust: "verified", expiryMin: "2026-07-20T05:00:00.000Z", expiryMax: "2026-07-21T00:00:00.000Z" };
    const salt = randomBytes(16); const digest = scryptSync("correct horse", salt, 32, { N: 16_384, r: 8, p: 1 });
    const root = await mkdtemp(`${tmpdir()}/share-selectable-`); const storePath = `${root}/bindings.ndjson`;
    try {
      const host = createShareHostFromEnv({ SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(value), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey, SHARE_SENDER_CAPABILITIES_JSON: JSON.stringify([capability(scope, source, { email: "Alice+Notes@example.com", expiresAt: "2026-07-20T12:00:00.000Z" })]), SHARE_BINDING_STORE_PATH: storePath, SHARE_AUTH_USERS_JSON: JSON.stringify([{ userId: "sender-1", username: "alice", passwordHash: `scrypt$16384$8$1$${salt.toString("base64url")}$${digest.toString("base64url")}` }]) });
      const login = await host.handler(new Request("https://share.tinycloud.xyz/api/share/auth/login", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", "content-type": "application/json" }, body: JSON.stringify({ username: "alice", password: "correct horse" }) }));
      const cookie = login.headers.get("set-cookie")!.split(";", 1)[0]!;
      const listed = await host.handler(new Request("https://share.tinycloud.xyz/api/share/capabilities", { headers: { origin: "https://share.tinycloud.xyz", cookie } }));
      const listedBody = await listed.json() as { capabilities: Array<{ capabilityId: string; policy: Record<string, unknown> }> }; const capabilityId = listedBody.capabilities[0]!.capabilityId; const selectedPolicy = listedBody.capabilities[0]!.policy;
      const message = authorizationMessage({ shareCid: `bafkrei${"a".repeat(52)}`, shareId: "share-selectable", senderDid, targetOrigin: scope.targetOrigin, nodeAudience: scope.nodeAudience, returnOrigin: "https://share.tinycloud.xyz", policyCid: selectedPolicy.policyCid, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest, documentName: scope.documentName, senderTrust: scope.senderTrust, recipientEmail: "Alice+Notes@example.com", contentSource: source, contentSourceDigest: sourceDigest(source), action: source.action, resource: source.path, shareExpiresAt: "2026-07-20T12:00:00.000Z" });
      const valid = await host.handler(new Request("https://share.tinycloud.xyz/api/share/sign", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", cookie, "content-type": "application/json", "idempotency-key": "B".repeat(22) }, body: JSON.stringify({ capabilityId, purpose: "inviteAuthorization", message: JSON.stringify(message), binding: authorizationSigningBinding(message, selectedPolicy) }) }));
      expect(valid.status).toBe(200);
      const wrongExpiry = { ...message, shareExpiresAt: "2026-07-22T12:00:00.000Z" };
      const rejected = await host.handler(new Request("https://share.tinycloud.xyz/api/share/sign", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", cookie, "content-type": "application/json", "idempotency-key": "C".repeat(22) }, body: JSON.stringify({ capabilityId, purpose: "inviteAuthorization", message: JSON.stringify(wrongExpiry), binding: authorizationSigningBinding(wrongExpiry, selectedPolicy) }) }));
      expect(rejected.status).toBe(400);
      const substitutedPolicy = { ...selectedPolicy, policyDigest: "C".repeat(43) };
      const substituted = await host.handler(new Request("https://share.tinycloud.xyz/api/share/sign", { method: "POST", headers: { origin: "https://share.tinycloud.xyz", cookie, "content-type": "application/json", "idempotency-key": "D".repeat(22) }, body: JSON.stringify({ capabilityId, purpose: "inviteAuthorization", message: JSON.stringify(message), binding: authorizationSigningBinding(message, substitutedPolicy) }) }));
      expect(substituted.status).toBe(400);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
