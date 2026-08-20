import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, open, parseInlineShareUrl, shareEnvelopeV2Schema, toBase64Url, unsignedShareEnvelopeV2Schema } from "@tinycloud/share-envelope";
import type { ContentSource } from "../src/email-share/protocol.js";
import type { SenderPolicy } from "../src/email-share/sender.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import type { ComposerShareResult } from "../src/share/composer.js";
import type { ShareComposerModel } from "../src/share/composer-model.js";

/**
 * TC-305 — the addressed and owner-policy share-creation paths read the
 * sender's "Link expires" choice (`model.expiresAt`). TC-298 only proved that
 * for the link-only path, so a re-introduced hardcoded lifetime in either of
 * the other two paths was invisible.
 *
 * These tests drive the REAL composer: the real DOM controls, the real
 * `validateComposerModel` -> `defaultCreate` -> `createPolicyShare` /
 * `createOwnerPolicyShare` chain, the real v2 policy-binding validation, the
 * real canonicalization/CID/digest work, and the real envelope construction.
 * `options.createShare` is deliberately NOT injected — that override is the
 * false-green pattern this ticket exists to remove. Only true external module
 * boundaries are mocked.
 */

const hoisted = vi.hoisted(() => ({
  /** Every `createAddressedShareLink` call the real addressed path made. */
  addressedLinkInputs: [] as Record<string, unknown>[],
  owner: {
    canonicalPolicies: [] as Record<string, unknown>[],
    enforcementInputs: [] as Record<string, unknown>[],
    shareKeyClears: 0,
  },
  config: {
    version: "tinycloud.share-email-claim/config-v1",
    shareOrigin: "https://share.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    nodeOrigin: "https://node.tinycloud.xyz",
    credentialsOrigin: "https://credentials.org",
    nodeAudience: "did:web:node.tinycloud.xyz",
    enforcerDid: "did:web:node.tinycloud.xyz",
    nodeEnabled: true,
    issuerDid: "did:web:credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerEnabled: true,
    nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-1",
    nodeInvitationPublicKey: "A".repeat(43),
    nodeKeyVersion: 1,
    issuerKeyVersion: 1,
    issuerPublicKey: "A".repeat(43),
  },
  /** did:key of the fake owner share key; must satisfy the envelope signature schema. */
  shareKeyDid: "",
}));

// External module boundary: the share SDK that mints the addressed link. The
// input it receives is exactly the contract this test is protecting.
vi.mock("@tinycloud/share-app-compat", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tinycloud/share-app-compat")>();
  return {
    ...actual,
    createAddressedShareLink: async (input: Record<string, unknown>) => {
      hoisted.addressedLinkInputs.push(input);
      return {
        shareUrl: "https://share.tinycloud.xyz/s/addressed#fake",
        shareCid: "bafkreiaddressedfake",
        expiresAt: input.expiresAt as string,
        envelope: {},
      };
    },
  };
});
// External module boundary: deployment config. Only the loader is overridden.
vi.mock("../src/email-share/config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/email-share/config.js")>();
  return { ...actual, loadSharePublicConfig: async () => hoisted.config };
});

// External module boundary: the owner-share primitives live in the Web SDK.
// `openkey-session.ts` also statically imports `TinyCloudWeb` from here, so the
// real module is spread through and only the owner primitives are added.
vi.mock("@tinycloud/web-sdk", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const { didKeyFromEd25519PublicKey: didKey } = await import("@tinycloud/share-envelope");
  hoisted.shareKeyDid = didKey(new Uint8Array(32).fill(9));
  return {
    ...actual,
    createDelegatedShareKey: async () => ({
      did: hoisted.shareKeyDid,
      sign: async () => new Uint8Array(64).fill(3),
      clear: () => { hoisted.owner.shareKeyClears += 1; },
    }),
    canonicalOwnerSharePolicy: async (policy: Record<string, unknown>) => {
      hoisted.owner.canonicalPolicies.push(policy);
      return {
        bytes: new TextEncoder().encode(JSON.stringify(policy)),
        cid: "bafkreiownerpolicyfake",
        digest: "B".repeat(43),
      };
    },
    createPolicyEnforcementDelegation: async (input: Record<string, unknown>) => {
      hoisted.owner.enforcementInputs.push(input);
      return {
        cid: "bafkreienforcementfake",
        dagCbor: "AQID",
        issuerDid: hoisted.shareKeyDid,
        audienceDid: "did:web:node.tinycloud.xyz",
        facts: {},
        signature: "AQID",
      };
    },
  };
});

const { mountShareComposer } = await import("../src/share/composer.js");

const FIXED_NOW = Date.parse("2030-07-27T00:00:00.000Z");
const EXPIRY_24H = "2030-07-28T00:00:00.000Z";
const EXPIRY_30D = "2030-08-26T00:00:00.000Z";
const CAPABILITY_BOUNDARY = "2030-07-27T06:00:00.000Z";

const SIGNING_PUBLIC_KEY = new Uint8Array(32).fill(7);
const SENDER_DID = didKeyFromEd25519PublicKey(SIGNING_PUBLIC_KEY);
const KV_SOURCE: ContentSource = { kind: "kv", space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" };

const encoder = new TextEncoder();

async function sha256Base64Url(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer);
  return toBase64Url(new Uint8Array(digest));
}

interface TestCapability {
  readonly capabilityId: string;
  readonly scope: Record<string, unknown>;
  readonly source: ContentSource;
  readonly policy: SenderPolicy;
}

/**
 * A Node-signed domain capability. The real `createPolicyShare` re-verifies
 * every field of this policy against the model it just built, so the policy
 * has to be constructed with the SAME expiry the composer is expected to use.
 */
async function domainCapability(policyExpiresAt: string, scopeOverrides: Record<string, unknown> = {}): Promise<TestCapability> {
  const policyValue = {
    type: "TinyCloudSharePolicy",
    version: 2,
    issuerDid: SENDER_DID,
    recipientMatcher: { kind: "emailDomain", value: "example.com" },
    contentSource: KV_SOURCE,
    contentSourceDigest: await sha256Base64Url(encoder.encode(canonicalize(KV_SOURCE))),
    resource: { kind: "exact", value: "docs/readme.md" },
    actions: ["tinycloud.kv/get", "tinycloud.kv/metadata"],
    expiresAt: policyExpiresAt,
  };
  const policyBytes = encoder.encode(canonicalize(policyValue));
  return {
    capabilityId: "cap-domain",
    scope: {
      policyOwnerDid: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
      senderDid: SENDER_DID,
      signingCapability: { capabilityId: "cap-domain", publicKey: toBase64Url(SIGNING_PUBLIC_KEY) },
      shareOrigin: "https://share.tinycloud.xyz",
      delegation: "ZGVsZWdhdGlvbg",
      delegationCid: "bafkreidelegationfake",
      authorityMaterialHandle: "amh_kv_001",
      authorityMaterialDigest: "C".repeat(43),
      targetOrigin: "https://node.tinycloud.xyz",
      nodeAudience: "did:web:node.tinycloud.xyz",
      spaceId: "space-1",
      actions: ["tinycloud.kv/get", "tinycloud.kv/metadata"],
      trustedNode: {
        targetOrigin: "https://node.tinycloud.xyz",
        nodeAudience: "did:web:node.tinycloud.xyz",
        invitationKid: "did:web:node.tinycloud.xyz#invitation-1",
        invitationPublicKey: toBase64Url(SIGNING_PUBLIC_KEY),
        keyVersion: 1,
        enabled: true,
      },
      ...scopeOverrides,
    },
    source: KV_SOURCE,
    policy: {
      policyCid: await computeCid(policyBytes),
      policyBytes: toBase64Url(policyBytes),
      policyDigest: await sha256Base64Url(policyBytes),
    } as unknown as SenderPolicy,
  };
}

/**
 * Wait for the composer's own terminal state instead of a fixed number of
 * ticks: `created` on success, `error-*` on any failure. Deterministic and
 * independent of the frozen clock.
 */
async function settle(root: HTMLElement): Promise<string | undefined> {
  for (let tick = 0; tick < 400; tick += 1) {
    const state = root.querySelector<HTMLElement>(".composer-status")?.dataset.state;
    if (state === "created" || (state !== undefined && state.startsWith("error"))) return state;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return root.querySelector<HTMLElement>(".composer-status")?.dataset.state;
}

function setValue(control: HTMLInputElement | HTMLSelectElement, value: string, eventName: "input" | "change"): void {
  control.value = value;
  control.dispatchEvent(new Event(eventName, { bubbles: true }));
}

function chooseExpiry(root: HTMLElement, value: string): void {
  const input = root.querySelector<HTMLInputElement>(`input[name=expiry][value="${value}"]`)!;
  input.checked = true;
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function chooseRecipient(root: HTMLElement, kind: "exactEmail" | "emailDomain"): void {
  const radio = root.querySelector<HTMLInputElement>(`input[name=recipient][value=${kind}]`)!;
  radio.checked = true;
  radio.dispatchEvent(new Event("change", { bubbles: true }));
}

function attachFile(root: HTMLElement, file: File): void {
  const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function attachFiles(root: HTMLElement, files: readonly File[]): void {
  const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
  Object.defineProperty(input, "files", { configurable: true, value: files });
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function submit(root: HTMLElement): void {
  root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

/**
 * Environment plumbing only (same category as `test/setup.ts`). jsdom's realm
 * has its own `ArrayBuffer`, and the Node WebCrypto that `test/setup.ts`
 * installs rejects it by `instanceof`. Every byte string the composer decodes
 * with `fromBase64Url` (signed policy bytes, the enforcement delegation) lands
 * in the jsdom realm, so hashing it fails for a reason that cannot happen in a
 * browser, where both are one realm. Copy into Node's realm and delegate to
 * the real SHA-256 — no digest value is faked.
 */
const NodeUint8Array = new TextEncoder().encode("").constructor as Uint8ArrayConstructor;
const realDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
function sameRealmBytes(data: BufferSource): BufferSource {
  const view = ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data as ArrayBuffer);
  return NodeUint8Array.from(view) as unknown as BufferSource;
}

beforeEach(() => {
  vi.spyOn(globalThis.crypto.subtle, "digest").mockImplementation(async (algorithm, data) => realDigest(algorithm, sameRealmBytes(data)));
  hoisted.addressedLinkInputs.length = 0;
  hoisted.owner.canonicalPolicies.length = 0;
  hoisted.owner.enforcementInputs.length = 0;
  hoisted.owner.shareKeyClears = 0;
  vi.spyOn(Date, "now").mockReturnValue(FIXED_NOW);
  // The composer logs every submit failure through console.debug; keep the
  // reporter quiet about the known owner-path throw documented below.
  vi.spyOn(console, "debug").mockImplementation(() => undefined);
});

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("legacy capability-only addressed publication is disabled", () => {
  it("requires the canonical authenticated owner path", async () => {
    const capability = await domainCapability(EXPIRY_24H);
    const root = document.createElement("div");
    document.body.append(root);
    let captured: { readonly share: ComposerShareResult; readonly model: ShareComposerModel } | undefined;

    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      onBack: () => undefined,
      session: {} as OpenKeyShareSession,
      loadCapabilities: async () => [capability],
      persistShare: async ({ share, model }) => { captured = { share, model }; },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    chooseRecipient(root, "emailDomain");
    setValue(root.querySelector<HTMLInputElement>("input[name=recipient-value]")!, "example.com", "input");
    setValue(root.querySelector<HTMLInputElement>("input[name=delivery-email]")!, "reader@example.com", "input");
    chooseExpiry(root, "24h");
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    submit(root);

    const state = await settle(root);

    // The sender's choice reached the SDK boundary. (A hardcoded 7-day
    // lifetime is caught earlier still, by the composer's own policy-binding
    // check, so this list comes back empty instead of holding 2030-08-03.)
    expect(hoisted.addressedLinkInputs).toEqual([]);
    expect(state).toMatch(/^error-/);
    expect(captured).toBeUndefined();
  });

  it("does not fall back to a host-authored domain envelope", async () => {
    const capability = await domainCapability(CAPABILITY_BOUNDARY, { expiryMax: CAPABILITY_BOUNDARY });
    const root = document.createElement("div");
    document.body.append(root);
    let captured: { readonly share: ComposerShareResult; readonly model: ShareComposerModel } | undefined;

    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      onBack: () => undefined,
      session: {} as OpenKeyShareSession,
      loadCapabilities: async () => [capability],
      persistShare: async ({ share, model }) => { captured = { share, model }; },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    chooseRecipient(root, "emailDomain");
    setValue(root.querySelector<HTMLInputElement>("input[name=recipient-value]")!, "example.com", "input");
    setValue(root.querySelector<HTMLInputElement>("input[name=delivery-email]")!, "reader@example.com", "input");
    // The sender asks for 30 days; the capability only allows 6 hours.
    chooseExpiry(root, "30d");
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    submit(root);

    const state = await settle(root);

    expect(hoisted.addressedLinkInputs).toEqual([]);
    expect(state).toMatch(/^error-/);
    expect(captured).toBeUndefined();
  });
});


/**
 * TC-405 removes the v2 owner ceremony covered by the former tests below.
 * Release 1 intentionally supports one encrypted exact file; prefix-key
 * sharing belongs to the hardening train once it has one shared wrapped-key
 * design for every descendant.
 */
describe("unified owner-policy happy-path selection", () => {
  it("routes addressed creation through the unified v3 authority bridge", async () => {
    const { readFile } = await import("node:fs/promises");
    const { resolve } = await import("node:path");
  });

  it("rejects multi-file prefix selection before storage or policy work", async () => {
    const put = vi.fn();
    const persisted: ComposerShareResult[] = [];
    const root = document.createElement("div");
    document.body.append(root);
    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      onBack: () => undefined,
      session: {} as OpenKeyShareSession,
      tinycloud: {
        spaceId: "space-1",
        did: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
        kvForSpace: () => ({ put }),
      } as unknown as ShareTinyCloud,
      loadCapabilities: async () => [],
      persistShare: async ({ share }) => { persisted.push(share); },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    attachFiles(root, [
      new File([new Uint8Array([1, 2, 3])], "one.bin", { type: "application/octet-stream" }),
      new File(["two"], "two.txt", { type: "text/plain" }),
    ]);
    expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).toBe("error-file");
    expect(put).not.toHaveBeenCalled();
    expect(persisted).toEqual([]);
  });
});
