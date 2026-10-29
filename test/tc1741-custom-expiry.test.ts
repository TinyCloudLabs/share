import { afterEach, describe, expect, it, vi } from "vitest";
import { signCompactUcanRootAuthorization } from "@tinycloud/sdk-core";
import { toBase64Url } from "@tinycloud/share-envelope";
import { expiryFromLocalDateTime } from "../src/share/composer-model.js";
import { endShareComposer, mountShareComposer, type ShareComposerOptions } from "../src/share/composer.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import { resolveLink } from "../src/short-links/resolve.js";
import { API_ORIGIN, ISSUER_DID, SHARE_ORIGIN, signWithIssuer } from "./fixtures/link-material.js";

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example.invalid", credentialsOrigin: "https://witness.example.invalid" }),
}));

const NOW = Date.parse("2030-01-01T12:00:00.671Z");
const LOCAL = "2032-06-15T14:45:37";
const EXPECTED = new Date(2032, 5, 15, 14, 45, 37).toISOString();
const SPACE = "tinycloud:pkh:eip155:1:0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b:applications";
const NODE_DID = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";

afterEach(() => {
  endShareComposer();
  document.body.replaceChildren();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function mount(options: Partial<ShareComposerOptions> = {}): HTMLElement {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  const root = document.createElement("div"); document.body.append(root);
  mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: SHARE_ORIGIN, onBack: () => undefined, now: () => NOW, ...options });
  const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
  Object.defineProperty(file, "files", { value: [new File(["custom expiry"], "expiry.txt", { type: "text/plain" })] });
  file.dispatchEvent(new Event("change", { bubbles: true }));
  return root;
}

function choose(root: HTMLElement, value: string): void {
  const radio = root.querySelector<HTMLInputElement>(`input[name=expiry][value="${value}"]`);
  expect(radio, `expiry option ${value}`).not.toBeNull();
  radio!.click();
}

function custom(root: HTMLElement, value: string): HTMLInputElement {
  choose(root, "custom");
  const input = root.querySelector<HTMLInputElement>('input[type="datetime-local"]')!;
  expect(input.labels?.[0]?.textContent).toMatch(/date.*time/i);
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  return input;
}

function submit(root: HTMLElement): void {
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

describe("custom expiry selection", () => {
  it("interprets wall time locally and retains dates years beyond the presets", () => {
    expect(expiryFromLocalDateTime(LOCAL, NOW)).toBe(EXPECTED);
    expect(expiryFromLocalDateTime("2099-12-31T23:59", NOW)).toBe(new Date(2099, 11, 31, 23, 59).toISOString());
  });

  it("accepts a leap day and rejects a local time skipped by daylight saving", () => {
    expect(expiryFromLocalDateTime("2032-02-29T12:00", NOW)).toBe(new Date(2032, 1, 29, 12).toISOString());
    const skipped = new Date(2032, 2, 14, 2, 30);
    if (skipped.getHours() !== 2) {
      expect(() => expiryFromLocalDateTime("2032-03-14T02:30", NOW)).toThrow("Choose when the link should expire.");
    } else {
      expect(expiryFromLocalDateTime("2032-03-14T02:30", NOW)).toBe(skipped.toISOString());
    }
  });

  it.each(["", "invalid", "2032-02-30T12:00", "2032-13-01T12:00", "2032-06-15T24:00", "2029-12-31T23:59", "2032-06-15T14:45Z"])("rejects invalid or elapsed local time %s", (value) => {
    expect(() => expiryFromLocalDateTime(value, NOW)).toThrow("Choose when the link should expire.");
  });

  it("rejects a selected second that is already underway", () => {
    expect(() => expiryFromLocalDateTime(LOCAL, Date.parse(EXPECTED) + 1)).toThrow("Choose when the link should expire.");
  });

  it.each(["", "2029-12-31T23:59", "2032-02-30T12:00"])("blocks publication and labels invalid custom time %s, then recovers to a preset", async (value) => {
    const createShare = vi.fn(async () => ({ url: `${SHARE_ORIGIN}/viewer#tc1=synthetic`, cid: "synthetic" }));
    const root = mount({ createShare });
    const input = custom(root, value);
    submit(root);
    expect(createShare).not.toHaveBeenCalled();
    expect(input.getAttribute("aria-invalid")).toBe("true");
    const error = document.getElementById(input.getAttribute("aria-errormessage")!);
    expect(error?.textContent).toMatch(/future.*date.*time/i);
    expect(error?.hidden).toBe(false);
    expect(document.activeElement).toBe(input);
    choose(root, "24h");
    submit(root);
    await vi.waitFor(() => expect(root.querySelector(".result-title")).not.toBeNull());
    expect(input.disabled).toBe(true);
  });

  it.each([["24h", 1], ["7d", 7], ["30d", 30]] as const)("restores %s after Custom and publishes whole-second preset time", async (preset, days) => {
    let expiry = "";
    const root = mount({ createShare: async ({ model }) => { expiry = model.expiresAt; return { url: `${SHARE_ORIGIN}/viewer#tc1=synthetic`, cid: "synthetic" }; } });
    const input = custom(root, LOCAL);
    choose(root, preset);
    submit(root);
    await vi.waitFor(() => expect(root.querySelector(".result-title")).not.toBeNull());
    expect(Date.parse(expiry)).toBe(Math.floor((NOW + days * 86_400_000) / 1000) * 1000);
    expect(input.closest("label")!.hidden).toBe(true);
  });

  it("retains an entered time across preset changes and revalidates as time passes", () => {
    let now = NOW;
    const createShare = vi.fn();
    const root = mount({ now: () => now, createShare });
    const input = custom(root, LOCAL);
    choose(root, "7d");
    choose(root, "custom");
    expect(expiryFromLocalDateTime(input.value, NOW)).toBe(EXPECTED);
    now = Date.parse(EXPECTED) + 1;
    submit(root);
    expect(createShare).not.toHaveBeenCalled();
    expect(input.getAttribute("aria-invalid")).toBe("true");
  });
});

describe("custom expiry through the production composers", () => {
  it("publishes a years-ahead bearer selection through native sharing and saves its actual expiry", async () => {
    const generate = vi.fn(async () => ({ ok: true as const, data: { token: "synthetic", delegation: { cid: "bafy-native" }, expiresAt: new Date(EXPECTED) } }));
    const persistShare = vi.fn(async () => undefined);
    const root = mount({
      tinycloud: {
        spaceId: SPACE, activeNodeIdentity: async () => ({ origin: "https://node.example.invalid", nodeDid: NODE_DID }),
        kvForSpace: () => ({ put: async () => ({ ok: true }) }),
        sharing: { generate, decodeLink: () => ({ spaceId: SPACE, path: "synthetic" }) },
      } as unknown as ShareTinyCloud,
      persistShare,
    });
    custom(root, LOCAL);
    submit(root);
    await vi.waitFor(() => expect(root.querySelector(".result-title")).not.toBeNull());
    expect(generate).toHaveBeenCalledWith(expect.objectContaining({ expiry: new Date(EXPECTED) }));
    expect(persistShare).toHaveBeenCalledWith(expect.objectContaining({ share: expect.objectContaining({ record: expect.objectContaining({ expiresAt: EXPECTED }) }) }));
  });

  it.each([30.5, 730])("preserves a %s-day choice through the addressed authority decision", async (days) => {
    const future = new Date(Math.floor((NOW + days * 86_400_000) / 1000) * 1000);
    const expected = future.toISOString();
    const local = new Date(future.getTime() - future.getTimezoneOffset() * 60_000).toISOString().slice(0, 19);
    const requested: string[] = [];
    let policyExpiry: string | undefined;
    const fetchFn = vi.fn(async () => { throw new Error("no external request expected"); });
    const owner: ShareTinyCloud = {
      spaceId: SPACE, credentialHolderDid: ISSUER_DID,
      activeNodeIdentity: async () => ({ origin: "https://node.example.invalid", nodeDid: NODE_DID }),
      publishActiveNodeLocation: async () => undefined, signSessionBytes: signWithIssuer,
      encryption: { encryptToNetwork: async (network: string) => ({ ok: true, data: { v: 1, networkId: network, alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AAAA", nonce: "AAAA" } }) },
      kvForSpace: () => ({ put: async () => ({ ok: true }) }),
      createUnifiedOwnerRoot: async (input: { audienceDid: string; role: string; policyId: string; policyCid: string; nodeAudience: string; notBefore: Date; expiresAt: Date; capabilities: { kind: string; resource: string; selector: string }[] }) => {
        requested.push(input.expiresAt.toISOString());
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
        policyExpiry = registration.policy.expiresAt;
        return {
          policyCid: registration.policyCid, policyRootCid: registration.policyRoot.cid, enforcementRootCid: registration.enforcementRoot.cid,
          attestedEnforcerBinding: { schema: "xyz.tinycloud.policy/attested-enforcer/v2", enforcerDid: registration.enforcerDid, nodeAudience: registration.expectedNodeAudience, attestationBindingDigestHex: "c".repeat(64), issuedAt: new Date(NOW).toISOString(), expiresAt: new Date(NOW + 40 * 86_400_000).toISOString(), signature: { suite: "Ed25519", signerDid: registration.expectedNodeAudience, value: toBase64Url(new Uint8Array(64).fill(7)) } },
        };
      },
    } as unknown as ShareTinyCloud;
    let url = "";
    const root = mount({ tinycloud: owner, session: {} as OpenKeyShareSession, fetchFn, persistShare: async ({ share }) => { url = share.url; } });
    root.querySelector<HTMLInputElement>('input[name=recipient][value=exactEmail]')!.click();
    const recipient = root.querySelector<HTMLInputElement>('input[name=recipient-value]')!;
    recipient.value = "reader@example.com"; recipient.dispatchEvent(new Event("input", { bubbles: true }));
    custom(root, local);
    submit(root);
    if (days === 730) {
      await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).toBe("error-invalid"));
      expect(requested).toEqual([expected]);
      expect(policyExpiry).toBeUndefined();
      expect(url).toBe("");
      expect(root.querySelector(".result-title")).toBeNull();
      expect(fetchFn).not.toHaveBeenCalled();
      return;
    }
    await vi.waitFor(() => expect(root.querySelector(".result-title"), root.querySelector(".composer-status")?.textContent ?? "").not.toBeNull(), { timeout: 3_000 });
    expect(requested).toEqual([expected, expected]);
    expect(Date.parse(policyExpiry!)).toBe(Date.parse(expected));
    expect(url).toMatch(/\/s\/full#/);
    const resolved = await resolveLink(url, { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn });
    expect(Date.parse(resolved.header.expiresAt)).toBe(Date.parse(expected));
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
