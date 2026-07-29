import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";
import { privateKeyToAccount } from "viem/accounts";
import { createShareHostFromEnv } from "../src/host/share-adapter.js";
import { derivedSenderIdentitySource, loadSenderRootSeed, staticSenderIdentitySource } from "../src/host/sender-identity.js";

/**
 * TC-348. `SHARE_SENDER_ENABLED=true` was unbootable in every legal production
 * composition, because sender authority was only ever expressible through the
 * static variables the production entrypoint and deploy validator forbid.
 * These tests pin the replacement: authority admitted per verified OpenKey
 * session, signed with a key derived for that exact wallet, fail-closed.
 *
 * Every composition here is production-shaped: `SHARE_TRUST_BUNDLE_ALLOW_TEST`,
 * `SHARE_SENDER_PRIVATE_KEY`, `SHARE_SENDER_CAPABILITY_JSON`, and
 * `SHARE_SENDER_CAPABILITIES_JSON` are absent throughout, so `testMode` is
 * false and every session comes from a real SIWE signature.
 */

const SHARE_ORIGIN = "https://share.tinycloud.xyz";
const NODE_ORIGIN = "https://node.tinycloud.xyz";
const NODE_AUDIENCE = "did:web:node.tinycloud.xyz";

function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}`;
}
function sourceDigest(source: Record<string, unknown>): string { return createHash("sha256").update(stable(source), "utf8").digest("base64url"); }

function productionBundle(): Record<string, unknown> {
  return {
    version: "tinycloud.share-email-trust-bundle/v1",
    shareOrigin: SHARE_ORIGIN,
    returnOrigin: SHARE_ORIGIN,
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: "https://witness.credentials.org",
    nodeOrigin: NODE_ORIGIN,
    nodeAudience: NODE_AUDIENCE,
    nodeInvitationKid: `${NODE_AUDIENCE}#invitation-key-1`,
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

/**
 * A production-shaped host: real trust bundle, durable binding store, and a
 * sender root seed created inside the persistent volume. No test-authority or
 * static sender variable is set anywhere.
 */
async function productionHost(overrides: Record<string, string | undefined> = {}): Promise<{ host: ReturnType<typeof createShareHostFromEnv>; root: string; dispose: () => Promise<void> }> {
  const root = await mkdtemp(`${tmpdir()}/share-sender-authority-`);
  const host = createShareHostFromEnv({
    SHARE_SENDER_ENABLED: "true",
    SHARE_TRUST_BUNDLE: JSON.stringify(productionBundle()),
    SHARE_BINDING_STORE_ROOT: root,
    SHARE_BINDING_STORE_PATH: `${root}/bindings.ndjson`,
    SHARE_SENDER_ROOT_KEY_PATH: `${root}/sender-root.key`,
    // Only relocates the persistent volume for a local production-shaped run;
    // it does not enable test authority, test mode, or any static sender path.
    SHARE_HERMETIC_COMPOSITION: "true",
    ...overrides,
  });
  return { host, root, dispose: () => rm(root, { recursive: true, force: true }) };
}

type Host = ReturnType<typeof createShareHostFromEnv>;

async function signIn(host: Host, account: ReturnType<typeof privateKeyToAccount>): Promise<string> {
  const nonceResponse = await host.handler(new Request(`${SHARE_ORIGIN}/api/share/auth/openkey/nonce`, { headers: { origin: SHARE_ORIGIN } }));
  const { nonce } = await nonceResponse.json() as { nonce: string };
  const issuedAt = new Date().toISOString();
  const message = [`share.tinycloud.xyz wants you to sign in with your Ethereum account:`, account.address, "", "Sign in to TinyCloud Share.", "", `URI: ${SHARE_ORIGIN}`, "Version: 1", `Nonce: ${nonce}`, `Issued At: ${issuedAt}`].join("\n");
  const signature = await account.signMessage({ message });
  const response = await host.handler(new Request(`${SHARE_ORIGIN}/api/share/auth/openkey`, { method: "POST", headers: { origin: SHARE_ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ address: account.address, signature, message, nonce, issuedAt }) }));
  expect(response.status).toBe(200);
  return response.headers.get("set-cookie")!.split(";", 1)[0]!;
}

async function senderIdentity(host: Host, cookie: string): Promise<{ senderDid: string; senderPublicKey: string }> {
  const response = await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sender-identity`, { headers: { origin: SHARE_ORIGIN, cookie } }));
  expect(response.status).toBe(200);
  return await response.json() as { senderDid: string; senderPublicKey: string };
}

const SOURCE = { kind: "kv", space: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222", path: "documents/doc.md", action: "tinycloud.kv/get" };
const EXPIRES_AT = "2026-12-21T00:00:00.000Z";

function descriptor(senderDid: string, policyOwnerDid: string, source: Record<string, unknown> = SOURCE): Record<string, unknown> {
  const scope = {
    recipientEmail: "recipient@example.com",
    senderDid,
    targetOrigin: NODE_ORIGIN,
    nodeAudience: NODE_AUDIENCE,
    trustedNode: { targetOrigin: NODE_ORIGIN, nodeAudience: NODE_AUDIENCE, invitationKid: `${NODE_AUDIENCE}#invitation-key-1`, invitationPublicKey: toBase64Url(new Uint8Array(32).fill(3)), keyVersion: 1, enabled: true },
    policyOwnerDid,
    delegation: "delegation",
    delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4",
    authorityMaterialHandle: "amh_kv_001",
    authorityMaterialDigest: "A".repeat(43),
    spaceId: source.space,
    documentName: "doc.md",
    senderTrust: "verified",
    expiresAt: EXPIRES_AT,
  };
  return {
    scope,
    source,
    policy: {
      action: source.action, authorityMaterialDigest: scope.authorityMaterialDigest, contentSourceDigest: sourceDigest(source), delegationCid: scope.delegationCid,
      expiresAt: EXPIRES_AT, policyAuthorityBytes: "AQ", policyAuthorityCid: "authority-cid", policyBytes: "eyJ0eXBlIjoiVGlueUNsb3VkU2hhcmVQb2xpY3kifQ", policyDigest: "policy-digest",
      policyEnforcementBytes: "Ag", policyEnforcementCid: "enforcement-cid", policyCid: "policy-cid", recipientEmail: "recipient@example.com", resource: source.path, source,
      target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
    },
  };
}

function enroll(host: Host, cookie: string, capability: Record<string, unknown>): Promise<Response> {
  return host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { method: "POST", headers: { origin: SHARE_ORIGIN, cookie, "content-type": "application/json" }, body: JSON.stringify({ capability }) }));
}

function invitationMessage(senderDid: string, policy: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const base = {
    shareCid: `bafkrei${"a".repeat(52)}`, shareId: "share-1", senderDid, targetOrigin: NODE_ORIGIN, nodeAudience: NODE_AUDIENCE, returnOrigin: SHARE_ORIGIN,
    policyCid: policy.policyCid, delegationCid: "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4", authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43),
    documentName: "doc.md", senderTrust: "verified", recipientEmail: "recipient@example.com", action: source.action, resource: source.path,
    contentSource: source, contentSourceDigest: sourceDigest(source), shareExpiresAt: EXPIRES_AT, jti: "A".repeat(22), reportAbuseToken: "B".repeat(22),
  };
  const body = { shareCid: base.shareCid, shareId: base.shareId, policyCid: base.policyCid, delegationCid: base.delegationCid, authorityMaterialHandle: base.authorityMaterialHandle, authorityMaterialDigest: base.authorityMaterialDigest, recipientEmail: base.recipientEmail, targetOrigin: base.targetOrigin, nodeAudience: base.nodeAudience, action: base.action, resource: base.resource };
  return { ...base, requestBodyDigest: sourceDigest(body) };
}

function signingBinding(message: Record<string, unknown>, policy: Record<string, unknown>): Record<string, unknown> {
  return { ...message, expiresAt: message.shareExpiresAt, policyDigest: policy.policyDigest, policyAuthorityCid: policy.policyAuthorityCid, policyAuthorityBytes: policy.policyAuthorityBytes, policyEnforcementCid: policy.policyEnforcementCid, policyEnforcementBytes: policy.policyEnforcementBytes };
}

function sign(host: Host, cookie: string, capabilityId: string, message: Record<string, unknown>, policy: Record<string, unknown>, idempotencyKey = "A".repeat(22)): Promise<Response> {
  return host.handler(new Request(`${SHARE_ORIGIN}/api/share/sign`, { method: "POST", headers: { origin: SHARE_ORIGIN, cookie, "content-type": "application/json", "idempotency-key": idempotencyKey }, body: JSON.stringify({ capabilityId, purpose: "inviteAuthorization", message: JSON.stringify(message), binding: signingBinding(message, policy) }) }));
}

const ALICE = privateKeyToAccount(`0x${"31".repeat(32)}`);
const BOB = privateKeyToAccount(`0x${"52".repeat(32)}`);

afterEach(() => { vi.restoreAllMocks(); });

describe("wallet-rooted sender authority (TC-348)", () => {
  it("boots SHARE_SENDER_ENABLED=true in a production-shaped composition with no test-mode variables", async () => {
    const { host, dispose } = await productionHost();
    try {
      expect(host.readiness).toEqual({ authReady: true, senderReady: true });
      const readiness = await host.handler(new Request(`${SHARE_ORIGIN}/health/readiness`));
      expect(readiness.status).toBe(200);
      expect(await readiness.json()).toEqual({ authReady: true, senderReady: true });
      expect(host.publicConfig).not.toHaveProperty("environment");
    } finally { await dispose(); }
  });

  it("keeps the forbidden static sender variables rejected while sender authority is enabled", async () => {
    const root = await mkdtemp(`${tmpdir()}/share-sender-static-`);
    try {
      const base = {
        SHARE_SENDER_ENABLED: "true", SHARE_TRUST_BUNDLE: JSON.stringify(productionBundle()), SHARE_BINDING_STORE_ROOT: root,
        SHARE_BINDING_STORE_PATH: `${root}/bindings.ndjson`, SHARE_SENDER_ROOT_KEY_PATH: `${root}/sender-root.key`, SHARE_HERMETIC_COMPOSITION: "true",
      };
      for (const name of ["SHARE_SENDER_PRIVATE_KEY", "SHARE_SENDER_CAPABILITY_JSON", "SHARE_SENDER_CAPABILITIES_JSON"]) {
        expect(() => createShareHostFromEnv({ ...base, [name]: "anything" })).toThrow(/static sender authority variables are forbidden/);
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("creates the sender root seed once, 0600, inside the persistent volume and reuses it across restarts", async () => {
    const root = await mkdtemp(`${tmpdir()}/share-sender-seed-`);
    try {
      const path = `${root}/sender-root.key`;
      const first = loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: path }, "production");
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      expect(toBase64Url(loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: path }, "production"))).toBe(toBase64Url(first));
      // There is no inline environment variant: a sender secret must never be
      // expressible in deployment configuration.
      expect(() => loadSenderRootSeed({}, "test")).toThrow(/persistent sender root key path is required/);
      expect(() => loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: "relative/sender.key" }, "production")).toThrow(/must be an absolute path/);
      expect(() => loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: `${root}/../escape.key` }, "production")).toThrow(/traversal-free/);

      // Confined to the verified persistent root and never colliding with the
      // binding journal or the lock its stale-lock reaper unlinks.
      expect(() => loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: `${tmpdir()}/elsewhere.key` }, "production", { root })).toThrow(/descendant of the configured persistent Share volume/);
      for (const reservedPath of [`${root}/bindings.ndjson`, `${root}/bindings.ndjson.lock`, `${root}/registry-upload.key`]) {
        expect(() => loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: reservedPath }, "production", { root, reserved: [`${root}/bindings.ndjson`, `${root}/registry-upload.key`] })).toThrow(/must not collide/);
      }

      // A symlinked seed is refused rather than followed.
      const linked = `${root}/linked.key`;
      await symlink(path, linked);
      expect(() => loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: linked }, "production", { root })).toThrow(/symlink/);

      // Group- or world-readable key material is refused.
      const loose = `${root}/loose.key`;
      await writeFile(loose, toBase64Url(new Uint8Array(32).fill(5)), { encoding: "utf8", mode: 0o644 });
      await chmod(loose, 0o644);
      expect(() => loadSenderRootSeed({ SHARE_SENDER_ROOT_KEY_PATH: loose }, "production", { root })).toThrow(/group- or world-accessible/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("derives a distinct stable sender identity per principal and never exposes the private half", async () => {
    const { host, dispose } = await productionHost();
    try {
      const aliceCookie = await signIn(host, ALICE);
      const bobCookie = await signIn(host, BOB);
      const alice = await senderIdentity(host, aliceCookie);
      const bob = await senderIdentity(host, bobCookie);
      expect(alice.senderDid).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
      expect(alice.senderDid).not.toBe(bob.senderDid);
      // Stable within a wallet: a second session for the same wallet resolves
      // the same sender identity, which is what the node's boot-time authority
      // material requires.
      expect((await senderIdentity(host, await signIn(host, ALICE))).senderDid).toBe(alice.senderDid);
      const raw = await (await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sender-identity`, { headers: { origin: SHARE_ORIGIN, cookie: aliceCookie } }))).text();
      expect(raw.toLowerCase()).not.toContain("privatekey");
      expect(Object.keys(JSON.parse(raw) as Record<string, unknown>).sort()).toEqual(["alg", "senderDid", "senderPublicKey"]);
    } finally { await dispose(); }
  });

  it("admits a session capability and signs it with that session's wallet-rooted key", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookie = await signIn(host, ALICE);
      const identity = await senderIdentity(host, cookie);
      const owner = `did:pkh:eip155:1:${ALICE.address.toLowerCase()}`;

      const admitted = await enroll(host, cookie, descriptor(identity.senderDid, owner));
      expect(admitted.status).toBe(201);
      const { capabilityId } = await admitted.json() as { capabilityId: string };

      const listed = await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN, cookie } }));
      const body = await listed.json() as { capabilities: Array<{ capabilityId: string; policy: Record<string, unknown>; source: Record<string, unknown> }> };
      expect(body.capabilities).toHaveLength(1);
      const selected = body.capabilities[0]!;
      expect(selected.capabilityId).toBe(capabilityId);

      const message = invitationMessage(identity.senderDid, selected.policy, selected.source);
      const signed = await sign(host, cookie, capabilityId, message, selected.policy);
      expect(signed.status).toBe(200);
      const result = await signed.json() as { signerDid: string; signature: string };
      expect(result.signerDid).toBe(identity.senderDid);

      // The signature verifies under the session's derived public key, not a
      // server-configured static key.
      const domain = new TextEncoder().encode("xyz.tinycloud.share/invite-authorization/v1\0");
      const bytes = new TextEncoder().encode(JSON.stringify(message));
      const preimage = new Uint8Array(domain.length + bytes.length); preimage.set(domain); preimage.set(bytes, domain.length);
      expect(ed25519.verify(fromBase64Url(result.signature), preimage, fromBase64Url(identity.senderPublicKey))).toBe(true);
    } finally { await dispose(); }
  });

  it("fails closed with no session", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookie = await signIn(host, ALICE);
      const identity = await senderIdentity(host, cookie);
      const owner = `did:pkh:eip155:1:${ALICE.address.toLowerCase()}`;
      const capability = descriptor(identity.senderDid, owner);

      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sender-identity`, { headers: { origin: SHARE_ORIGIN } }))).status).toBe(401);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { method: "POST", headers: { origin: SHARE_ORIGIN, "content-type": "application/json" }, body: JSON.stringify({ capability }) }))).status).toBe(401);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN } }))).status).toBe(401);
      expect((await sign(host, "share_session=forged", "any", invitationMessage(identity.senderDid, capability.policy as Record<string, unknown>, SOURCE), capability.policy as Record<string, unknown>)).status).toBe(401);
      // A wrong browser origin is not a session either, even with a real cookie.
      expect((await enroll(host, cookie, capability)).status).toBe(201);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { method: "POST", headers: { origin: "https://evil.example", cookie, "content-type": "application/json" }, body: JSON.stringify({ capability }) }))).status).toBe(401);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sender-identity`, { headers: { origin: "https://evil.example", cookie } }))).status).toBe(401);
      // Readiness is public and must not leak any sender identity.
      expect(await (await host.handler(new Request(`${SHARE_ORIGIN}/health/readiness`))).text()).not.toContain("did:key:");
    } finally { await dispose(); }
  });

  it("fails closed for an expired session", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookie = await signIn(host, ALICE);
      const identity = await senderIdentity(host, cookie);
      const owner = `did:pkh:eip155:1:${ALICE.address.toLowerCase()}`;
      const admitted = await enroll(host, cookie, descriptor(identity.senderDid, owner));
      expect(admitted.status).toBe(201);
      const { capabilityId } = await admitted.json() as { capabilityId: string };

      const realNow = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(realNow + 1_800_001);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sender-identity`, { headers: { origin: SHARE_ORIGIN, cookie } }))).status).toBe(401);
      expect((await enroll(host, cookie, descriptor(identity.senderDid, owner))).status).toBe(401);
      const policy = (descriptor(identity.senderDid, owner).policy as Record<string, unknown>);
      expect((await sign(host, cookie, capabilityId, invitationMessage(identity.senderDid, policy, SOURCE), policy)).status).toBe(401);
    } finally { await dispose(); }
  });

  it("fails closed when the capability names another wallet as its policy owner", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookie = await signIn(host, ALICE);
      const identity = await senderIdentity(host, cookie);
      const foreignOwner = `did:pkh:eip155:1:${BOB.address.toLowerCase()}`;
      const rejected = await enroll(host, cookie, descriptor(identity.senderDid, foreignOwner));
      expect(rejected.status).toBe(400);
      expect(await rejected.json()).toEqual({ error: { code: "capability_unavailable" } });
      // Ownership is the complete DID: the same address on another EIP-155
      // chain is a different principal, not a match.
      expect((await enroll(host, cookie, descriptor(identity.senderDid, `did:pkh:eip155:137:${ALICE.address.toLowerCase()}`))).status).toBe(400);
      // A malformed owner DID is not silently treated as unowned either.
      expect((await enroll(host, cookie, descriptor(identity.senderDid, "did:pkh:eip155:1:not-an-address"))).status).toBe(400);
      expect((await (await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN, cookie } }))).json() as { capabilities: unknown[] }).capabilities).toEqual([]);
    } finally { await dispose(); }
  });

  it("fails closed for a capability bound to another session's sender identity", async () => {
    const { host, dispose } = await productionHost();
    try {
      const aliceCookie = await signIn(host, ALICE);
      const bobCookie = await signIn(host, BOB);
      const bob = await senderIdentity(host, bobCookie);
      const aliceOwner = `did:pkh:eip155:1:${ALICE.address.toLowerCase()}`;
      // Alice presents authority minted for Bob's sender key.
      expect((await enroll(host, aliceCookie, descriptor(bob.senderDid, aliceOwner))).status).toBe(400);

      // And Bob's own admitted capability is not selectable from Alice's session.
      const bobOwner = `did:pkh:eip155:1:${BOB.address.toLowerCase()}`;
      const admitted = await enroll(host, bobCookie, descriptor(bob.senderDid, bobOwner));
      expect(admitted.status).toBe(201);
      const { capabilityId } = await admitted.json() as { capabilityId: string };
      const policy = descriptor(bob.senderDid, bobOwner).policy as Record<string, unknown>;
      expect((await sign(host, aliceCookie, capabilityId, invitationMessage(bob.senderDid, policy, SOURCE), policy)).status).toBe(400);
    } finally { await dispose(); }
  });

  it("fails closed for a tampered capability", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookie = await signIn(host, ALICE);
      const identity = await senderIdentity(host, cookie);
      const owner = `did:pkh:eip155:1:${ALICE.address.toLowerCase()}`;
      const base = descriptor(identity.senderDid, owner);
      const tamper = (mutate: (value: Record<string, any>) => void): Record<string, unknown> => {
        const copy = JSON.parse(JSON.stringify(base)) as Record<string, any>;
        mutate(copy);
        return copy;
      };

      const cases: Record<string, Record<string, unknown>> = {
        // A sender DID the host does not hold the key for.
        forgedSender: tamper((value) => { value.scope.senderDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; }),
        // A node the trust bundle does not name.
        foreignNode: tamper((value) => { value.scope.targetOrigin = "https://node.evil.example"; }),
        foreignAudience: tamper((value) => { value.scope.nodeAudience = "did:web:node.evil.example"; }),
        // A node invitation key the trust bundle does not name.
        forgedEnrollment: tamper((value) => { value.scope.trustedNode.invitationPublicKey = toBase64Url(new Uint8Array(32).fill(7)); }),
        // Policy no longer bound to the capability it travels with.
        detachedPolicyRecipient: tamper((value) => { value.policy.recipientEmail = "attacker@example.com"; }),
        detachedPolicyResource: tamper((value) => { value.policy.resource = "documents/other.md"; }),
        detachedPolicyDelegation: tamper((value) => { value.policy.delegationCid = "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl5"; }),
        detachedPolicyAuthority: tamper((value) => { value.policy.authorityMaterialDigest = "B".repeat(43); }),
        // Expiry outside the capability bounds.
        widenedExpiry: tamper((value) => { value.policy.expiresAt = "2027-12-21T00:00:00.000Z"; }),
        // An attempt to smuggle signing material in through the descriptor.
        smuggledKey: tamper((value) => { value.scope.senderPrivateKey = toBase64Url(new Uint8Array(32).fill(9)); value.scope.signingCapability = { capabilityId: "forged", publicKey: toBase64Url(new Uint8Array(32).fill(9)) }; }),
      };
      for (const [name, capability] of Object.entries(cases)) {
        const response = await enroll(host, cookie, capability);
        if (name === "smuggledKey") {
          // Accepted as a descriptor, but the smuggled material is discarded:
          // the host re-derives the signing key from the session.
          expect(response.status).toBe(201);
          const stored = await response.json() as { capabilityId: string; senderDid: string; scope: Record<string, unknown> };
          expect(stored.senderDid).toBe(identity.senderDid);
          expect((stored.scope.signingCapability as Record<string, unknown>).publicKey).toBe(identity.senderPublicKey);
          expect((stored.scope.signingCapability as Record<string, unknown>).capabilityId).not.toBe("forged");
          expect(JSON.stringify(stored).toLowerCase()).not.toContain("privatekey");
          continue;
        }
        expect(response.status, `${name} was admitted`).toBe(400);
      }

      // A tampered request body shape is rejected before any parsing.
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { method: "POST", headers: { origin: SHARE_ORIGIN, cookie, "content-type": "application/json" }, body: JSON.stringify({ capability: base, extra: 1 }) }))).status).toBe(400);
    } finally { await dispose(); }
  });

  it("reports a missing session capability per request instead of degrading readiness", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookie = await signIn(host, ALICE);
      expect(host.readiness.senderReady).toBe(true);
      const selected = await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capability`, { headers: { origin: SHARE_ORIGIN, cookie } }));
      expect(selected.status).toBe(409);
      expect(await selected.json()).toEqual({ error: { code: "sender_capability_required" } });
      const listed = await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN, cookie } }));
      expect(await listed.json()).toEqual({ capabilities: [] });
    } finally { await dispose(); }
  });

  it("fails closed with 503 for every sender operation when the sender path is disabled", async () => {
    const root = await mkdtemp(`${tmpdir()}/share-sender-off-`);
    try {
      const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE: JSON.stringify(productionBundle()), SHARE_BINDING_STORE_ROOT: root, SHARE_BINDING_STORE_PATH: `${root}/bindings.ndjson`, SHARE_HERMETIC_COMPOSITION: "true" });
      expect(host.readiness).toEqual({ authReady: true, senderReady: false });
      const cookie = await signIn(host, ALICE);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sender-identity`, { headers: { origin: SHARE_ORIGIN, cookie } }))).status).toBe(503);
      expect((await enroll(host, cookie, descriptor("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", `did:pkh:eip155:1:${ALICE.address.toLowerCase()}`))).status).toBe(503);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/sign`, { method: "POST", headers: { origin: SHARE_ORIGIN, cookie, "content-type": "application/json", "idempotency-key": "A".repeat(22) }, body: "{}" }))).status).toBe(503);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("binds derived identities to the seed and rejects malformed identity inputs", () => {
    const seed = new Uint8Array(32).fill(1);
    const source = derivedSenderIdentitySource(seed);
    const other = derivedSenderIdentitySource(new Uint8Array(32).fill(2));
    const principal = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    expect(source.forPrincipal(principal).did).toBe(source.forPrincipal(principal).did);
    expect(source.forPrincipal(principal).did).not.toBe(other.forPrincipal(principal).did);
    expect(ed25519.getPublicKey(source.forPrincipal(principal).privateKey)).toEqual(fromBase64Url(source.forPrincipal(principal).publicKey));
    expect(() => source.forPrincipal("")).toThrow(/principal is invalid/);
    expect(() => derivedSenderIdentitySource(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => staticSenderIdentitySource("not-a-key")).toThrow(/invalid/);
    // Legacy SHARE_AUTH_USERS_JSON ids are arbitrary operator strings: anything
    // the host authenticates must also derive an identity.
    for (const legacy of ["alice@example.com", "sender-1", "Ops Team #2", "did:pkh:eip155:1:0x1111111111111111111111111111111111111111"]) {
      expect(source.forPrincipal(legacy).did).toMatch(/^did:key:z/);
    }
    expect(source.forPrincipal("alice@example.com").did).not.toBe(source.forPrincipal("alice@example.org").did);
    expect(() => source.forPrincipal("a".repeat(257))).toThrow(/principal is invalid/);
    expect(() => source.forPrincipal(`bad${String.fromCharCode(10)}principal`)).toThrow(/principal is invalid/);
  });

  it("bounds live sessions per principal without ever refusing to authenticate", async () => {
    const { host, dispose } = await productionHost();
    try {
      const cookies: string[] = [];
      for (let index = 0; index < 10; index += 1) cookies.push(await signIn(host, ALICE));
      // The newest sessions stay usable and no sign-in was refused.
      for (const cookie of cookies.slice(-8)) {
        expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN, cookie } }))).status).toBe(200);
      }
      // The oldest were evicted rather than kept forever.
      for (const cookie of cookies.slice(0, 2)) {
        expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN, cookie } }))).status).toBe(401);
      }
      // One wallet's churn does not evict another wallet's session.
      const bobCookie = await signIn(host, BOB);
      for (let index = 0; index < 10; index += 1) await signIn(host, ALICE);
      expect((await host.handler(new Request(`${SHARE_ORIGIN}/api/share/capabilities`, { headers: { origin: SHARE_ORIGIN, cookie: bobCookie } }))).status).toBe(200);
    } finally { await dispose(); }
  });
});
