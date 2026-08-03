import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalize, didKeyFromEd25519PublicKey, shareEnvelopeV3Schema, signCompactUcanAuthorization, toBase64Url, verifyCompactUcanAuthorization, type UnifiedPolicyCapability } from "@tinycloud/share-envelope";
import { ShareRecipientClient } from "@tinycloud/share-sdk";
import { claimUnifiedDelegation, createSiblingRoots, createUnifiedPolicy, invokeUnifiedDelegation, rejectV3Downgrade, requestAttestedEnforcerBinding, signV3Envelope } from "../src/share/unified-delegation.js";

const ownerKey = new Uint8Array(32).fill(7);
const shareKey = new Uint8Array(32).fill(8);
const ownerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(ownerKey));
const source = {
  shareId: "share-405",
  kvResource: "tinycloud://space-405/kv/shares/share-405/document.txt",
  selector: "exact" as const,
  encryptionNetwork: "urn:tinycloud:encryption:network-405",
  encryptedSymmetricKeyDigestHex: "a".repeat(64),
  keyVersion: 1,
  mode: "mutable" as const,
};
const capabilities: UnifiedPolicyCapability[] = [
  { kind: "kv" as const, resource: source.kvResource, selector: source.selector, actions: ["tinycloud.kv/get", "tinycloud.kv/metadata"] },
  { kind: "encryption" as const, resource: source.encryptionNetwork, action: "tinycloud.encryption/decrypt" as const },
];

async function policyFixture() {
  return createUnifiedPolicy({
    policyId: "",
    ownerDid,
    createdAt: "2026-07-31T12:00:00.000Z",
    expiresAt: "2026-08-01T12:00:00.000Z",
    contentSource: source,
    capabilityCeiling: capabilities,
    sign: async (bytes) => ed25519.sign(bytes, ownerKey),
  });
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const canonicalHash = (value: unknown): string => hex(sha256(new TextEncoder().encode(canonicalize(value))));
async function aesEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt"]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, cryptoKey, plaintext as BufferSource));
  return Uint8Array.from([...nonce, ...encrypted]);
}

describe("TC-405 unified delegation", () => {
  it("verifies the node-signed enforcer binding before owner roots are created", async () => {
    const nodeKey = new Uint8Array(32).fill(10);
    const nodeDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeKey));
    const bindingDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize({ enforcerDid: nodeDid, nodeAudience: nodeDid }))));
    const unsigned = { schema: "xyz.tinycloud.policy/attested-enforcer/v2", enforcerDid: nodeDid, nodeAudience: nodeDid, attestationBindingDigestHex: Buffer.from(bindingDigest).toString("hex"), issuedAt: "2026-07-31T12:00:00.000Z", expiresAt: "2026-07-31T12:05:00.000Z" };
    const signature = ed25519.sign(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0${canonicalize(unsigned)}`))), nodeKey);
    const binding = { ...unsigned, signature: { suite: "Ed25519", signerDid: nodeDid, value: Buffer.from(signature).toString("base64url") } };
    await expect(requestAttestedEnforcerBinding({ nodeOrigin: "https://node.example.com", rootExpiresAt: "2026-08-01T00:00:00.000Z", fetchFn: async () => Response.json(binding) })).resolves.toEqual(binding);
    await expect(requestAttestedEnforcerBinding({ nodeOrigin: "https://node.example.com", rootExpiresAt: "2026-08-01T00:00:00.000Z", fetchFn: async () => Response.json({ ...binding, attestationBindingDigestHex: "b".repeat(64) }) })).rejects.toThrow("digest");
  });

  it("creates two role-bound roots and a strict signed v3 envelope", async () => {
    const vector = JSON.parse(readFileSync(resolve("test/fixtures/tc-405-compact-authorization.json"), "utf8")) as any;
    const policy = {
      policy: vector.policy.value,
      bytes: Uint8Array.from(Buffer.from(vector.policy.bytesUtf8Hex, "hex")),
      policyDigestHex: vector.policy.policyDigestHex,
      policyCid: vector.policy.policyCid,
    };
    const vectorSource = vector.policy.value.contentSource;
    const vectorExpiry = new Date(vector.policy.value.expiresAt);
    const roots = await createSiblingRoots({
      factory: {
        createOwnerRoot: async (input) => ({
          cid: vector[input.role === "policy-authority" ? "policyRoot" : "enforcementRoot"].cid,
          delegationHeader: { Authorization: vector[input.role === "policy-authority" ? "policyRoot" : "enforcementRoot"].authorization },
          delegateDID: input.audienceDid,
          spaceId: "applications",
          path: "shares/share-405/document.txt",
          actions: ["tinycloud.kv/get"],
          expiry: input.expiresAt,
        }),
      },
      ownerDid: vector.principals.ownerDid,
      policy: policy.policy,
      policyCid: policy.policyCid,
      policyDigestHex: policy.policyDigestHex,
      contentSourceDigestHex: vector.projections.contentSourceDigestHex,
      nativeProjectionHashHex: vector.projections.nativeProjectionHashHex,
      enforcerDid: vector.principals.enforcerDid,
      nodeAudience: vector.principals.nodeDid,
      expiresAt: vectorExpiry,
    });
    const envelope = await signV3Envelope({
      unsigned: {
        version: 3,
        shareId: vectorSource.shareId,
        recipientMatcher: { kind: "exactEmail", value: "recipient@example.com" },
        actions: ["read"],
        resource: { kind: "exact", path: "shares/share-405/document.txt" },
        target: { origin: "https://node.example.com", nodeAudience: vector.principals.nodeDid, spaceId: "applications" },
        policy: policy.policy,
        policyCid: policy.policyCid,
        policyRoot: roots.policyRoot,
        enforcementRoot: roots.enforcementRoot,
        attestedEnforcerBinding: { schema: "xyz.tinycloud.policy/attested-enforcer/v2", enforcerDid: vector.principals.nodeDid, nodeAudience: vector.principals.nodeDid, attestationBindingDigestHex: "a".repeat(64), issuedAt: vector.policy.value.createdAt, expiresAt: vector.policy.value.expiresAt, signature: { suite: "Ed25519", signerDid: vector.principals.nodeDid, value: "A".repeat(86) } },
        contentSource: vectorSource,
        contentSourceDigestHex: vector.projections.contentSourceDigestHex,
        encryptionNetwork: vectorSource.encryptionNetwork,
        expiry: vector.policy.value.expiresAt,
        display: { filename: "document.txt" },
        encrypted: true,
        metadata: { mediaType: "text/plain", byteLength: 4, filename: "document.txt" },
      },
      signerDid: didKeyFromEd25519PublicKey(ed25519.getPublicKey(shareKey)),
      sign: async (bytes) => ed25519.sign(bytes, shareKey),
    });
    expect(shareEnvelopeV3Schema.parse(envelope)).toEqual(envelope);
    expect(() => shareEnvelopeV3Schema.parse({
      ...envelope,
      contentSource: { ...envelope.contentSource, keyVersion: 2 },
    })).toThrow();
    expect(roots.policyRoot.role).toBe("policy-authority");
    expect(roots.enforcementRoot.role).toBe("policy-enforcement");
    expect(() => shareEnvelopeV3Schema.parse({ ...envelope, downgrade: true })).toThrow();
    expect(() => rejectV3Downgrade({ version: 2 })).toThrow();
  });

  it("claims through v3 ceremony then imports and invokes through ordinary SDK routes", async () => {
    const vector = JSON.parse(readFileSync(resolve("test/fixtures/tc-405-compact-authorization.json"), "utf8")) as any;
    const calls: Array<{ url: string; authorization?: string }> = [];
    const authorization = vector.s0.authorization;
    const fetchFn: typeof fetch = async (input, init) => {
      const url = String(input);
      const authorizationHeader = new Headers(init?.headers).get("Authorization");
      calls.push(authorizationHeader === null ? { url } : { url, authorization: authorizationHeader });
      if (url.endsWith("/share/v3/policy/challenges")) return Response.json({ challengeId: "challenge-405", nonce: "nonce-405", policyCid: vector.policy.policyCid, recipientDid: vector.principals.recipientDid, expiresAt: "2026-08-01T12:00:00.000Z" });
      if (url.endsWith("/share/v3/policy/delegations")) return Response.json({ sessionCid: vector.s0.cid, authorization, admitted: true });
      if (url.endsWith("/delegate")) return Response.json({ activated: [vector.s0.cid] });
      if (url.endsWith("/invoke")) return new Response("ok", { status: 200 });
      return new Response("not found", { status: 404 });
    };
    const delegation = await claimUnifiedDelegation({
      nodeOrigin: "https://node.example.com",
      recipientDid: vector.principals.recipientDid,
      policyCid: vector.policy.policyCid,
      policyRootCid: vector.policyRoot.cid,
      enforcementRootCid: vector.enforcementRoot.cid,
      requestedCapabilities: vector.policy.value.capabilityCeiling,
      claim: { challenge: "challenge-405" },
      presentation: { ceremony: "specialized" },
      fetchFn,
    });
    expect(delegation.delegationHeader.Authorization).toBe(authorization);
    const recipientKey = new Uint8Array(32).fill(9);
    const invocationNow = verifyCompactUcanAuthorization(authorization).payload.nbf + 1;
    await invokeUnifiedDelegation({ nodeOrigin: "https://node.example.com", sessionAuthorization: authorization, sessionCid: vector.s0.cid, recipientDid: vector.principals.recipientDid, nodeAudience: vector.principals.nodeDid, resource: vector.policy.value.contentSource.kvResource, action: "tinycloud.kv/get", caveat: { type: "xyz.tinycloud.resource/selector", kind: "exact", value: vector.policy.value.contentSource.kvResource }, sign: async (bytes) => ed25519.sign(bytes, recipientKey), now: invocationNow, fetchFn });
    const decryptBody = { type: "tinycloud.encryption.decrypt/v1", targetNode: vector.principals.nodeDid, networkId: vector.policy.value.contentSource.encryptionNetwork, alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), receiverPublicKey: "receiver", receiverPublicKeyHash: "b".repeat(64) };
    await invokeUnifiedDelegation({ nodeOrigin: "https://node.example.com", sessionAuthorization: authorization, sessionCid: vector.s0.cid, recipientDid: vector.principals.recipientDid, nodeAudience: vector.principals.nodeDid, resource: vector.policy.value.contentSource.encryptionNetwork, action: "tinycloud.encryption/decrypt", request: decryptBody, sign: async (bytes) => ed25519.sign(bytes, recipientKey), now: invocationNow, fetchFn });
    expect(calls.map((call) => call.url)).toEqual([
      "https://node.example.com/share/v3/policy/challenges",
      "https://node.example.com/share/v3/policy/delegations",
      "https://node.example.com/delegate",
      "https://node.example.com/invoke",
      "https://node.example.com/invoke",
    ]);
    expect(calls.at(-1)?.authorization).not.toBe(authorization);
    expect(calls.at(-1)?.authorization?.split(".")).toHaveLength(3);
    expect(canonicalize({ version: 3 })).toBe('{"version":3}');
  });

  it("verifies a signed decrypt response and opens v3 content locally", async () => {
    const recipientKey = new Uint8Array(32).fill(9);
    const nodeKey = new Uint8Array(32).fill(8);
    const recipientDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(recipientKey));
    const nodeDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(nodeKey));
    const networkId = "urn:tinycloud:encryption:did:key:zOwner:default";
    const encryptedSymmetricKey = "network-wrapped-key";
    const encryptedSymmetricKeyHash = canonicalHash(encryptedSymmetricKey);
    const now = Math.floor(Date.now() / 1000);
    const session = await signCompactUcanAuthorization({ issuerDid: nodeDid, audienceDid: recipientDid, attenuation: { [networkId]: { "tinycloud.encryption/decrypt": [{}] } }, facts: [{ profile: "policy-session-ucan/v1", policyCid: "policy", recipientDid }], proofs: ["policy-root", "enforcement-root"], notBefore: now - 1, expiresAt: now + 59, nonce: "session", sign: async (bytes) => ed25519.sign(bytes, nodeKey) });
    const symmetricKey = new Uint8Array(32).fill(41);
    const plaintext = new TextEncoder().encode("hello");
    const ciphertext = await aesEncrypt(symmetricKey, plaintext);
    const stored = new TextEncoder().encode(canonicalize({ v: 1, networkId, alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey, encryptedSymmetricKeyHash, ciphertext: toBase64Url(ciphertext), metadata: { contentType: "text/plain" } }));
    const fetchFn: typeof fetch = async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      // Noble rejects Buffer's cross-realm subclass identity under jsdom;
      // copy into this test realm's plain Uint8Array before verification.
      const receiverPublicKey = Uint8Array.from(Buffer.from(String(body.receiverPublicKey), "base64url"));
      const ephemeralPrivate = new Uint8Array(32).fill(23);
      const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
      const shared = x25519.getSharedSecret(ephemeralPrivate, receiverPublicKey);
      const wrapped = await aesEncrypt(shared, symmetricKey);
      const invocation = verifyCompactUcanAuthorization(new Headers(init?.headers).get("Authorization")!);
      const bodyHash = canonicalHash(body);
      const unsigned = { type: "tinycloud.encryption.decrypt-result/v1", targetNode: nodeDid, networkId, invocationCid: invocation.cid, encryptedSymmetricKeyHash, receiverPublicKeyHash: body.receiverPublicKeyHash, wrappedKey: toBase64Url(Uint8Array.from([...ephemeralPublic, ...wrapped])), alg: "x25519-aes256gcm/v1", keyVersion: 1, requestHash: hex(sha256(new TextEncoder().encode(`${invocation.cid}${bodyHash}`))), nodeId: nodeDid };
      return Response.json({ ...unsigned, nodeSignature: toBase64Url(ed25519.sign(new TextEncoder().encode(canonicalize(unsigned)), nodeKey)) });
    };
    const envelope = { version: 3, target: { nodeAudience: nodeDid }, encryptionNetwork: networkId, contentSource: { keyVersion: 1, encryptedSymmetricKeyDigestHex: encryptedSymmetricKeyHash }, metadata: { mediaType: "text/plain" } } as any;
    const client = new ShareRecipientClient({ nodeOrigin: "https://node.example.com", envelope, shareCid: "share", holderDid: recipientDid, trustedNode: {} as any, fetchFn, buildPresentation: async () => ({}) });
    Object.assign(client as any, { session: { sessionId: session.cid }, v3Authorization: session.authorization, nativeSigner: async (bytes: Uint8Array) => ed25519.sign(bytes, recipientKey) });
    const opened = await client.decryptV3Content(stored);
    expect(new TextDecoder().decode(opened.bytes)).toBe("hello");
    expect(opened.mediaType).toBe("text/plain");
    expect(new TextDecoder().decode(await client.encryptV3Content(new TextEncoder().encode("edited"), "text/plain"))).not.toContain("edited");
  });
});
