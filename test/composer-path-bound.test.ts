// @vitest-environment jsdom
// TC-2242: an email share's recipient may decrypt exactly one key, `share/<shareId>` on the owner's network,
// never the whole network. The composer encrypts under that path, registers the source with the path and
// the digest of the raw wrapped-key bytes, and the recipient capability is that leaf.
import { sha256 } from "@noble/hashes/sha256";
import { getAddress } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { signCompactUcanRootAuthorization } from "@tinycloud/sdk-core";
import { canonicalize, toBase64Url } from "@tinycloud/share-envelope";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import { mountShareComposer } from "../src/share/composer.js";
import { ISSUER_DID, mockLinks, SHARE_ORIGIN, signWithIssuer } from "./fixtures/link-material.js";

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example", credentialsOrigin: "https://witness.example" }),
}));

const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;
const NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:1:${ADDRESS}:default`;
// Discovery answers with the node's own spelling of the network: the owner's address, checksummed. Key resources need it.
const CANONICAL_NETWORK = `urn:tinycloud:encryption:did:pkh:eip155:1:${getAddress(ADDRESS)}:default`;
const NODE_DID = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";
const hex = (bytes: Uint8Array): string => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

// The wrapped key the fake network returns. Its bytes are not text and not the 32 bytes of a hash, and the
// envelope's own `encryptedSymmetricKeyHash` is a different value, so only a digest of the DECODED bytes matches.
const WRAPPED_BYTES = Uint8Array.from({ length: 61 }, (_, index) => (index * 7 + 3) % 256);
const WRAPPED_BASE64 = btoa(String.fromCharCode(...WRAPPED_BYTES));
const ENVELOPE_CANONICAL_HASH = hex(sha256(new TextEncoder().encode(canonicalize(WRAPPED_BASE64))));

interface Registered {
  policy?: { contentSource: Record<string, unknown>; capabilityCeiling: { kind: string; resource: string; action?: string }[] };
  encryptCalls: { network: string; options: { keyPath?: string } | undefined }[];
  stored: Uint8Array[];
}

/** An owner session with the SDK's named-key client, recording what the composer encrypts and registers. */
function owner(seen: Registered): ShareTinyCloud {
  return {
    spaceId: SPACE,
    credentialHolderDid: ISSUER_DID,
    activeNodeIdentity: async () => ({ origin: "https://node.example.invalid", nodeDid: NODE_DID }),
    publishActiveNodeLocation: async () => undefined,
    signSessionBytes: signWithIssuer,
    // The named-key client the SDK helper drives: a v2 envelope wrapped to the share key's public key. It has no createKey: publishing never creates the key.
    keys: {
      encrypt: async (keyPath: string, _plaintext: Uint8Array, encryptOptions: { networkId: string; metadata?: Record<string, string> }) => {
        seen.encryptCalls.push({ network: encryptOptions.networkId, options: { keyPath } });
        return {
          v: 2, networkId: encryptOptions.networkId, keyPath, alg: "x25519-aes256gcm/v1", keyVersion: 1,
          encryptedSymmetricKey: WRAPPED_BASE64, encryptedSymmetricKeyHash: ENVELOPE_CANONICAL_HASH, ciphertext: btoa("c".repeat(48)),
          ...(encryptOptions.metadata === undefined ? {} : { metadata: encryptOptions.metadata }),
        };
      },
    },
    kvForSpace: () => ({ put: async (_path: string, bytes: Uint8Array) => { seen.stored.push(bytes); return { ok: true }; } }),
    createUnifiedOwnerRoot: async (input: { audienceDid: string; role: string; policyId: string; policyCid: string; nodeAudience: string; notBefore: Date; expiresAt: Date; capabilities: { kind: string; resource: string; selector: string }[] }) => {
      const kv = input.capabilities.find((capability) => capability.kind === "kv")!;
      const root = await signCompactUcanRootAuthorization({
        issuerDid: ISSUER_DID, audienceDid: input.audienceDid,
        attenuation: { [kv.resource]: { "tinycloud.kv/get": [{ type: "xyz.tinycloud.resource/selector", kind: kv.selector, value: kv.resource }] } },
        facts: [{ role: input.role, policyId: input.policyId, policyCid: input.policyCid, ownerDid: ISSUER_DID, nodeAudience: input.nodeAudience }],
        notBefore: Math.floor(input.notBefore.getTime() / 1000), expiresAt: Math.floor(input.expiresAt.getTime() / 1000),
        nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), sign: signWithIssuer,
      });
      return { cid: root.cid, delegationHeader: { Authorization: root.authorization }, delegateDID: input.audienceDid, spaceId: SPACE, path: "", actions: [], expiry: input.expiresAt };
    },
    registerPolicy: async (registration: { policyCid: string; policy: NonNullable<Registered["policy"]>; policyRoot: { cid: string }; enforcementRoot: { cid: string }; enforcerDid: string; expectedNodeAudience: string }) => {
      seen.policy = registration.policy;
      return {
        policyCid: registration.policyCid, policyRootCid: registration.policyRoot.cid, enforcementRootCid: registration.enforcementRoot.cid,
        attestedEnforcerBinding: {
          schema: "xyz.tinycloud.policy/attested-enforcer/v2", enforcerDid: registration.enforcerDid, nodeAudience: registration.expectedNodeAudience, attestationBindingDigestHex: "c".repeat(64),
          issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 40 * 86_400_000).toISOString(), signature: { suite: "Ed25519", signerDid: registration.expectedNodeAudience, value: toBase64Url(new Uint8Array(64).fill(7)) },
        },
      };
    },
    authorizeShareDeliveryV3: async (input: { shareUrl: string }) => ({ request: { returnLink: input.shareUrl } }),
  } as unknown as ShareTinyCloud;
}

afterEach(() => {
  document.body.replaceChildren();
});

/** Sends one email share of one small file through the real composer and returns once its result is shown. */
async function publishEmailShare(tinycloud: ShareTinyCloud): Promise<HTMLElement> {
  const links = mockLinks(() => Date.now());
  const root = document.createElement("div");
  document.body.append(root);
  mountShareComposer(root, {
    openKeyAddress: ADDRESS, origin: SHARE_ORIGIN, onBack: () => undefined, session: {} as OpenKeyShareSession,
    tinycloud, fetchFn: links.fetchFn, copyText: async () => undefined, persistShare: async () => undefined,
  });
  const choice = root.querySelector<HTMLInputElement>("input[name=recipient][value=exactEmail]")!;
  choice.checked = true;
  choice.dispatchEvent(new Event("change", { bubbles: true }));
  const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
  value.value = "reader@example.com";
  value.dispatchEvent(new Event("input", { bubbles: true }));
  const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
  Object.defineProperty(file, "files", { configurable: true, value: [new File(["notes"], "notes.txt", { type: "text/plain" })] });
  file.dispatchEvent(new Event("change", { bubbles: true }));
  root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  // A refused share ends the wait with the composer's own words, not with a timeout.
  await vi.waitFor(() => {
    const failure = root.querySelector<HTMLElement>('.composer-status[data-state^="error"]');
    if (failure !== null) throw new Error(`the composer refused: ${failure.textContent ?? ""}`);
    expect(root.querySelector(".result-title")).not.toBeNull();
  }, { timeout: 10_000 });
  return root;
}

describe("an email share is bound to its own key path", () => {
  it("registers the source with share/<shareId> and the digest of the raw wrapped-key bytes", async () => {
    const seen: Registered = { encryptCalls: [], stored: [] };
    await publishEmailShare(owner(seen));
    const source = seen.policy!.contentSource;
    expect(source.shareId).toMatch(/^[0-9a-f-]{36}$/);
    expect(source.encryptionNetwork).toBe(CANONICAL_NETWORK);
    expect(source.encryptionKeyPath).toBe(`share/${source.shareId as string}`);
    // SHA-256 of the decoded bytes (not of the base64 text, and not the envelope's canonical-JSON hash).
    expect(source.encryptedSymmetricKeyDigestHex).toBe(hex(sha256(WRAPPED_BYTES)));
    expect(source.encryptedSymmetricKeyDigestHex).not.toBe(ENVELOPE_CANONICAL_HASH);
    expect(source.encryptedSymmetricKeyDigestHex).not.toBe(hex(sha256(new TextEncoder().encode(WRAPPED_BASE64))));
  });

  it("encrypts under that same path, so the stored envelope carries it", async () => {
    const seen: Registered = { encryptCalls: [], stored: [] };
    await publishEmailShare(owner(seen));
    expect(seen.encryptCalls).toHaveLength(1);
    // The key resource is spelled with the checksummed owner; the lower-cased network is not one.
    expect(seen.encryptCalls[0]!.network).toBe(CANONICAL_NETWORK);
    const keyPath = `share/${seen.policy!.contentSource.shareId as string}`;
    expect(seen.encryptCalls[0]!.options?.keyPath).toBe(keyPath);
    const envelope = JSON.parse(new TextDecoder().decode(seen.stored[0]!)) as { v: number; keyPath?: string; networkId: string };
    expect(envelope.keyPath).toBe(keyPath);
    // The recipient SDK reads a record that carries a key path as version 2 (share-sdk 1.4.1-beta.3).
    expect(envelope.v).toBe(2);
  });

  it("grants the recipient decrypt on exactly that leaf and never on the bare network", async () => {
    const seen: Registered = { encryptCalls: [], stored: [] };
    await publishEmailShare(owner(seen));
    const decrypts = seen.policy!.capabilityCeiling.filter((capability) => capability.kind === "encryption");
    expect(decrypts).toEqual([{ kind: "encryption", resource: `${CANONICAL_NETWORK}/share/${seen.policy!.contentSource.shareId as string}`, action: "tinycloud.encryption/decrypt" }]);
    expect(seen.policy!.capabilityCeiling.some((capability) => capability.resource === CANONICAL_NETWORK || capability.resource === NETWORK)).toBe(false);
  });
});
