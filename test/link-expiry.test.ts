// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { signCompactUcanRootAuthorization } from "@tinycloud/sdk-core";
import { toBase64Url } from "@tinycloud/share-envelope";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import { mountShareComposer } from "../src/share/composer.js";
import { publishLink } from "../src/short-links/publish.js";
import { API_ORIGIN, ISSUER_DID, mockLinks, SHARE_ORIGIN, sealedMaterial, signWithIssuer } from "./fixtures/link-material.js";

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example", credentialsOrigin: "https://witness.example" }),
}));

// A whole second, so the cases below add the milliseconds explicitly.
const WHOLE_SECOND = Date.UTC(2026, 9, 26, 12, 25, 24);
const FRACTIONS = [671, 999, 0, 1, 500];
const isoSeconds = (ms: number): string => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

afterEach(() => {
  vi.useRealTimers();
  document.body.replaceChildren();
});

describe("the stored link's expiry against the share's expiry", () => {
  for (const fraction of FRACTIONS) {
    it(`is a whole second and never later than the share's, with the clock at .${String(fraction).padStart(3, "0")}`, async () => {
      const now = WHOLE_SECOND + fraction;
      const links = mockLinks(() => now);
      // The share's own expiry, whole seconds, as the SDK registers it.
      const shareExpiry = isoSeconds(now + 3_600_000);
      await publishLink({
        material: await sealedMaterial(), expiresAt: shareExpiry, signer: { issuerDid: ISSUER_DID, sign: signWithIssuer },
        shareOrigin: SHARE_ORIGIN, apiOrigin: API_ORIGIN, fetchFn: links.fetchFn, now: () => now,
      });
      const [stored] = [...links.api.state.records.values()];
      expect(stored).toBeDefined();
      expect(Date.parse(stored!.expiresAt)).toBeLessThanOrEqual(Date.parse(shareExpiry));
      expect(Date.parse(stored!.expiresAt) % 1000).toBe(0);
      expect(stored!.expiresAt).toMatch(/:\d\d\.000Z$/);
    });

    it(`stays within a share expiry that carries milliseconds (.${String(fraction).padStart(3, "0")})`, async () => {
      const now = WHOLE_SECOND + 5;
      const links = mockLinks(() => now);
      const shareExpiry = new Date(WHOLE_SECOND + 3_600_000 + fraction).toISOString();
      await publishLink({
        material: await sealedMaterial(), expiresAt: shareExpiry, signer: { issuerDid: ISSUER_DID, sign: signWithIssuer },
        shareOrigin: SHARE_ORIGIN, apiOrigin: API_ORIGIN, fetchFn: links.fetchFn, now: () => now,
      });
      const [stored] = [...links.api.state.records.values()];
      expect(Date.parse(stored!.expiresAt)).toBeLessThanOrEqual(Date.parse(shareExpiry));
      expect(Date.parse(stored!.expiresAt) % 1000).toBe(0);
    });
  }
});

const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;
const NODE_DID = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";

/** The owner's session is a fake with real local signing; the SDK's publisher and the composer are the real code. */
function owner(registered: { policyExpiresAt?: string | undefined }): ShareTinyCloud {
  return {
    spaceId: SPACE,
    credentialHolderDid: ISSUER_DID,
    activeNodeIdentity: async () => ({ origin: "https://node.example.invalid", nodeDid: NODE_DID }),
    publishActiveNodeLocation: async () => undefined,
    signSessionBytes: signWithIssuer,
    encryption: { encryptToNetwork: async (network: string) => ({ ok: true, data: { v: 1, networkId: network, alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AAAA", nonce: "AAAA" } }) },
    kvForSpace: () => ({ put: async () => ({ ok: true }) }),
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
    registerPolicy: async (registration: { policyCid: string; policy: { expiresAt?: string }; policyRoot: { cid: string }; enforcementRoot: { cid: string }; enforcerDid: string; expectedNodeAudience: string }) => {
      registered.policyExpiresAt = registration.policy.expiresAt;
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

describe("the composer's link against the policy the node registered", () => {
  for (const fraction of [671, 999, 0]) {
    it(`never outlives the registered share expiry, with the clock at .${String(fraction).padStart(3, "0")}`, async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(WHOLE_SECOND + fraction);
      const links = mockLinks(() => Date.now());
      const registered: { policyExpiresAt?: string | undefined } = {};
      const root = document.createElement("div");
      document.body.append(root);
      mountShareComposer(root, {
        openKeyAddress: ADDRESS, origin: SHARE_ORIGIN, onBack: () => undefined, session: {} as OpenKeyShareSession,
        tinycloud: owner(registered), fetchFn: links.fetchFn, copyText: async () => undefined, persistShare: async () => undefined,
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
      await vi.waitFor(() => expect(root.querySelector(".result-title")).not.toBeNull(), { timeout: 10_000 });

      const [stored] = [...links.api.state.records.values()];
      expect(stored).toBeDefined();
      expect(registered.policyExpiresAt).toMatch(/:\d\d(?:\.\d+)?Z$/);
      expect(Date.parse(stored!.expiresAt)).toBeLessThanOrEqual(Date.parse(registered.policyExpiresAt!));
      expect(Date.parse(stored!.expiresAt) % 1000).toBe(0);
    });
  }
});
