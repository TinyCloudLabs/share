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
vi.mock("@tinycloud/share-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tinycloud/share-sdk")>();
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

describe("addressed share creation honors the sender's expiry choice", () => {
  it("carries the selected 24-hour expiry through the real createPolicyShare path", async () => {
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
    setValue(root.querySelector<HTMLSelectElement>("select[name=expiry]")!, "24h", "change");
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    submit(root);

    const state = await settle(root);

    // The sender's choice reached the SDK boundary. (A hardcoded 7-day
    // lifetime is caught earlier still, by the composer's own policy-binding
    // check, so this list comes back empty instead of holding 2030-08-03.)
    expect(hoisted.addressedLinkInputs.map((input) => input.expiresAt)).toEqual([EXPIRY_24H]);
    expect(state).toBe("created");
    expect(captured).toBeDefined();
    // The model and the persisted share agree with it.
    expect(captured!.model.expiresAt).toBe(EXPIRY_24H);
    expect(captured!.share.expiresAt).toBe(EXPIRY_24H);
  });

  it("clamps the addressed expiry to the signed capability boundary", async () => {
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
    setValue(root.querySelector<HTMLSelectElement>("select[name=expiry]")!, "30d", "change");
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    submit(root);

    const state = await settle(root);

    expect(hoisted.addressedLinkInputs.map((input) => input.expiresAt)).toEqual([CAPABILITY_BOUNDARY]);
    expect(state).toBe("created");
    expect(captured).toBeDefined();
    // The sender's own choice is still what the model recorded; only the
    // capability boundary shortened the link.
    expect(captured!.model.expiresAt).toBe(EXPIRY_30D);
    expect(captured!.share.expiresAt).toBe(CAPABILITY_BOUNDARY);
  });
});

/**
 * The bug this comment used to describe is fixed (TC-338).
 * `createOwnerPolicyShare` validated the not-yet-signed envelope with
 * `shareEnvelopeV2Schema`, which requires `signature`, so the parse always
 * threw `ZodError: signature Required` right after the enforcement delegation
 * was minted — before the envelope, the share URL, or the return value existed.
 * The unsigned envelope is now checked with `unsignedShareEnvelopeV2Schema` and
 * the signed one with `shareEnvelopeV2Schema`.
 *
 * So this test now runs the owner ceremony to completion and pins the expiry
 * everywhere it is bound: the owner delegation, the canonical owner policy, the
 * policy-enforcement delegation, AND (as the old comment asked for) the emitted
 * envelope plus the returned/persisted share. Reintroducing the parse bug stops
 * the flow before `persistShare`, so the envelope assertions below fail.
 */
describe("owner-policy share creation honors the sender's expiry choice", () => {
  it("binds the selected 24-hour expiry into the owner delegation, policy, and enforcement delegation", async () => {
    const ownerDelegationInputs: Record<string, unknown>[] = [];
    const registrations: Record<string, unknown>[] = [];
    const tinycloud = {
      spaceId: "space-1",
      did: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
      createOwnerDelegation: async (input: Record<string, unknown>) => {
        ownerDelegationInputs.push(input);
        return { delegationCid: "bafkreiownerdelegationfake", signedDagCbor: new Uint8Array([1, 2, 3]) };
      },
      registerOwnerSharePolicy: async (input: Record<string, unknown>) => {
        registrations.push(input);
        return { registration: { registrationCid: "bafkreiregistrationfake" } };
      },
      kvForSpace: () => ({ put: async () => ({ ok: true }) }),
    } as unknown as ShareTinyCloud;

    const root = document.createElement("div");
    document.body.append(root);
    const persisted: { readonly share: ComposerShareResult; readonly model: ShareComposerModel }[] = [];

    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      onBack: () => undefined,
      session: {} as OpenKeyShareSession,
      tinycloud,
      loadCapabilities: async () => [],
      persistShare: async ({ share, model }) => { persisted.push({ share, model }); },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    chooseRecipient(root, "exactEmail");
    setValue(root.querySelector<HTMLInputElement>("input[name=recipient-value]")!, "reader@example.com", "input");
    setValue(root.querySelector<HTMLSelectElement>("select[name=expiry]")!, "24h", "change");
    // A self-contained link keeps the registry (and its fetch) out of the test.
    setValue(root.querySelector<HTMLSelectElement>("select[name=format]")!, "inline", "change");
    attachFile(root, new File([new Uint8Array([1, 2, 3, 4])], "notes.txt", { type: "text/plain" }));
    submit(root);

    // The real path ran to (at least) the enforcement delegation and then
    // settled one way or the other; see the block comment above.
    await settle(root);

    // The owner delegation is minted for exactly the chosen lifetime...
    expect(ownerDelegationInputs).toHaveLength(1);
    expect(ownerDelegationInputs[0]!.expiresAt).toEqual(new Date(EXPIRY_24H));
    // ...the canonical owner policy carries it...
    expect(hoisted.owner.canonicalPolicies).toHaveLength(1);
    expect(hoisted.owner.canonicalPolicies[0]!.expiresAt).toBe(EXPIRY_24H);
    // ...and so does the policy-enforcement delegation.
    expect(hoisted.owner.enforcementInputs).toHaveLength(1);
    expect(hoisted.owner.enforcementInputs[0]!.expiresAt).toBe(EXPIRY_24H);
    // A hardcoded 7-day lifetime would land here.
    expect(hoisted.owner.canonicalPolicies[0]!.expiresAt).not.toBe("2030-08-03T00:00:00.000Z");
    expect(ownerDelegationInputs[0]!.expiresAt).not.toEqual(new Date("2030-08-03T00:00:00.000Z"));

    // The chosen expiry is the one the whole owner ceremony was built around,
    // and the ceremony really ran against the injected owner client.
    expect(hoisted.owner.canonicalPolicies[0]!.ownerDelegationCid).toBe("bafkreiownerdelegationfake");
    expect(registrations).toHaveLength(1);
    expect(hoisted.owner.shareKeyClears).toBe(1);
    // TC-338: the ceremony now reaches the end. Before the schema fix the
    // envelope parse threw and `persistShare` was never called, so this was a
    // vacuous loop over an empty array.
    expect(persisted).toHaveLength(1);
    for (const entry of persisted) {
      expect(entry.model.expiresAt).toBe(EXPIRY_24H);
      expect(entry.share.expiresAt).toBe(EXPIRY_24H);
    }

    // And the envelope the sender's browser actually emitted is a SIGNED v2
    // envelope that the schema recipients parse accepts — the property the
    // broken `shareEnvelopeV2Schema.parse(unsigned)` claimed to check but
    // could never reach.
    const inline = parseInlineShareUrl(persisted[0]!.share.url, { expectedOrigin: "https://share.tinycloud.xyz" });
    expect(inline.key32).toBeDefined();
    const envelope = JSON.parse(new TextDecoder().decode(await open(inline.ciphertext, inline.key32!))) as Record<string, unknown>;

    const parsed = shareEnvelopeV2Schema.parse(envelope);
    expect(parsed.expiry).toBe(EXPIRY_24H);
    expect(parsed.signature.signerDid).toBe(hoisted.shareKeyDid);
    expect(parsed.signature.algorithm).toBe("Ed25519");
    // The signature covers exactly the unsigned envelope, so stripping it must
    // leave something the unsigned schema accepts. That is the pair of parses
    // the fixed code performs, checked against the bytes that actually shipped.
    const { signature: _signature, ...withoutSignature } = envelope;
    expect(unsignedShareEnvelopeV2Schema.safeParse(withoutSignature).success).toBe(true);
  });
});
