import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fromBase64Url } from "@tinycloud/share-envelope";
import { OWNER_TINYCLOUD_DELIVERY_METHODS, mountShareComposer } from "../src/share/composer.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

/**
 * TC-343.
 *
 * `authorizeShareDelivery` requires `nodeProof` and `credentialsAudience` —
 * the enrolled Node receipt key it verifies the detached EdDSA proof with, and
 * the OpenCredentials witness the delivery is scoped to. The composer passed
 * neither. Nothing caught it because the call site cast the method to
 * `(input: Record<string, string>) => Promise<Record<string, unknown>>`, which
 * erased both required fields from the compiler's view, and because it read
 * the method off the session and called it detached, losing `this`.
 *
 * So this file asserts the ARGUMENTS, not just that a call happened. It
 * deliberately does NOT mock `@tinycloud/web-sdk`: the owner ceremony runs
 * against the real `createDelegatedShareKey` (WebCrypto Ed25519, async since
 * 2.10.0), `canonicalOwnerSharePolicy`, and `createPolicyEnforcementDelegation`
 * from the pinned package, so a signature drift in any of them stops this test
 * rather than reaching a browser. Only the deployment config and the TinyCloud
 * session — the two real external boundaries — are stubbed.
 */

const CONFIG = {
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
};

vi.mock("../src/email-share/config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/email-share/config.js")>();
  return { ...actual, loadSharePublicConfig: async () => CONFIG };
});

const RECIPIENT = "reader@example.com";

interface DeliveryCall {
  readonly input: Record<string, unknown>;
  readonly receiver: unknown;
}

function ownerSession(calls: DeliveryCall[], omitAuthorize = false): ShareTinyCloud {
  const session = {
    spaceId: "space-1",
    did: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
    createOwnerDelegation: async (input: Record<string, unknown>) => ({ delegationCid: "bafkreiownerdelegationfake", signedDagCbor: new Uint8Array([1, 2, 3]), permissions: input.permissions }),
    registerOwnerSharePolicy: async (input: Record<string, unknown>) => ({
      registration: {
        registrationCid: "bafkreiregistrationfake",
        ownerDelegationCid: (input.ownerDelegation as { delegationCid: string }).delegationCid,
        ownerDid: session.did,
        shareKeyDid: "did:key:z6Mkfixture",
        enforcerDid: CONFIG.enforcerDid,
      },
      proof: {},
    }),
    kvForSpace: () => ({ put: async () => ({ ok: true }) }),
    // Not an arrow: `this` is only bound when the composer calls this as a
    // method on the session, which is the second half of the TC-343 defect.
    authorizeShareDelivery(this: unknown, input: Record<string, unknown>) {
      calls.push({ input, receiver: this });
      return Promise.resolve({ authorization: { jti: "delivery-jti" }, proof: { alg: "EdDSA", kid: CONFIG.nodeInvitationKid, signature: "AQID" } });
    },
  } as Record<string, unknown>;
  if (omitAuthorize) delete session.authorizeShareDelivery;
  return session as unknown as ShareTinyCloud;
}

async function createOwnerShare(root: HTMLElement, tinycloud: ShareTinyCloud, notified: Record<string, unknown>[]): Promise<string | undefined> {
  mountShareComposer(root, {
    openKeyAddress: "0x1234567890abcdef",
    origin: "https://share.tinycloud.xyz",
    onBack: () => undefined,
    session: {} as OpenKeyShareSession,
    tinycloud,
    loadCapabilities: async () => [],
    notify: async (input) => { notified.push(input as unknown as Record<string, unknown>); },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));

  const recipient = root.querySelector<HTMLInputElement>("input[value=exactEmail]")!;
  recipient.checked = true; recipient.dispatchEvent(new Event("change", { bubbles: true }));
  const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
  value.value = RECIPIENT; value.dispatchEvent(new Event("input", { bubbles: true }));
  // A self-contained link keeps the registry (and its fetch) out of the test.
  const format = root.querySelector<HTMLSelectElement>("select[name=format]")!;
  format.value = "inline"; format.dispatchEvent(new Event("change", { bubbles: true }));
  const delivery = root.querySelector<HTMLInputElement>("input[name=delivery-email]")!;
  delivery.value = RECIPIENT; delivery.dispatchEvent(new Event("input", { bubbles: true }));
  const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
  Object.defineProperty(file, "files", { configurable: true, value: [new File([new Uint8Array([1, 2, 3, 4])], "notes.txt", { type: "text/plain" })] });
  file.dispatchEvent(new Event("change", { bubbles: true }));
  root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

  for (let tick = 0; tick < 400; tick += 1) {
    const state = root.querySelector<HTMLElement>(".composer-status")?.dataset.state;
    if (state === "created" || (state !== undefined && state.startsWith("error"))) return state;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return root.querySelector<HTMLElement>(".composer-status")?.dataset.state;
}

/**
 * Environment plumbing only, lifted verbatim from `composer-expiry.test.ts`.
 * jsdom's realm has its own `ArrayBuffer` and the Node WebCrypto that
 * `test/setup.ts` installs rejects it by `instanceof`, so every byte string the
 * composer decodes with `fromBase64Url` fails to hash for a reason that cannot
 * happen in a browser, where both are one realm. Copy into Node's realm and
 * delegate to the real SHA-256 — no digest value is faked.
 */
const NodeUint8Array = new TextEncoder().encode("").constructor as Uint8ArrayConstructor;
const realDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
function sameRealmBytes(data: BufferSource): BufferSource {
  const view = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data as ArrayBuffer);
  return NodeUint8Array.from(view) as unknown as BufferSource;
}

describe("the owner-share delivery authorization carries the trust bundle the SDK requires", () => {
  beforeEach(() => { vi.spyOn(globalThis.crypto.subtle, "digest").mockImplementation(async (algorithm, data) => realDigest(algorithm, sameRealmBytes(data))); });
  afterEach(() => { vi.restoreAllMocks(); document.body.replaceChildren(); });

  it("passes nodeProof and credentialsAudience, and calls the method on the session", async () => {
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const calls: DeliveryCall[] = [];
    const notified: Record<string, unknown>[] = [];
    const tinycloud = ownerSession(calls);

    const root = document.createElement("div");
    document.body.append(root);
    const state = await createOwnerShare(root, tinycloud, notified);
    const failures = debug.mock.calls.filter((call) => String(call[0]).includes("sender request failed")).map((call) => String((call[1] as Error | undefined)?.message ?? call[1]));
    // The real ceremony ran to completion; a missing SDK export or session
    // method lands here by name instead of failing an assertion below.
    expect(failures).toEqual([]);
    expect(state).toBe("created");

    root.querySelector<HTMLButtonElement>(".confirm-notification")!.click();
    for (let tick = 0; tick < 200 && notified.length === 0; tick += 1) await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toHaveLength(1);
    const { input, receiver } = calls[0]!;

    // The two fields TC-343 omitted. `nodeProof` is the enrolled receipt key
    // the SDK verifies the Node's detached proof with; without it the SDK
    // throws inside the call and no email is ever authorized.
    expect(input.nodeProof).toEqual({ kid: CONFIG.nodeInvitationKid, publicKey: fromBase64Url(CONFIG.nodeInvitationPublicKey) });
    expect((input.nodeProof as { publicKey: Uint8Array }).publicKey).toBeInstanceOf(Uint8Array);
    // Deliberately the credentials origin, not the node audience and not the
    // share origin: the SDK rejects an authorization that conflates them.
    expect(input.credentialsAudience).toBe(CONFIG.credentialsOrigin);
    expect(input.credentialsAudience).not.toBe(CONFIG.nodeAudience);
    expect(input.credentialsAudience).not.toBe(CONFIG.shareOrigin);

    // Detaching the method (`const authorize = tinycloud.authorizeShareDelivery`)
    // loses `this`, which the SDK implementation reads.
    expect(receiver).toBe(tinycloud);

    // Every field the SDK's `authorizeShareDelivery` declares, none undefined.
    expect(Object.keys(input).sort()).toEqual([
      "credentialsAudience", "delegationCid", "documentName", "enforcementDelegationCid", "envelopeCid",
      "expiresAt", "idempotencyKey", "nodeProof", "policyCid", "recipientEmail", "registrationCid", "resourcePath",
      "shareCid", "shareId", "shareUrl",
    ]);
    for (const [name, field] of Object.entries(input)) expect(field, name).toBeDefined();
    expect(input.recipientEmail).toBe(RECIPIENT);
    expect(input.registrationCid).toBe("bafkreiregistrationfake");
    expect(input.delegationCid).toBe("bafkreiownerdelegationfake");
    expect(input.idempotencyKey).toMatch(/^tinycloud-share:[A-Za-z0-9_-]+:[A-Za-z0-9_-]{43}$/);
    // The delivery window is capped well below the share's own expiry.
    expect(Date.parse(input.expiresAt as string)).toBeLessThanOrEqual(Date.now() + 5 * 60 * 1000);

    // And the Node-signed receipt reaches the notifier that posts it.
    expect(notified).toHaveLength(1);
    expect((notified[0]!.deliveryAuthorization as Record<string, unknown>).proof).toBeDefined();
    const deliveryCopy = root.querySelector<HTMLElement>(".notification-status")?.textContent ?? "";
    expect(deliveryCopy).toBe("Invitation requested.");
    expect(deliveryCopy).not.toMatch(/sent|delivered/i);
  });

  it("still produces a working link when the session cannot authorize delivery", async () => {
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const calls: DeliveryCall[] = [];
    const notified: Record<string, unknown>[] = [];

    const root = document.createElement("div");
    document.body.append(root);
    // An SDK without `authorizeShareDelivery` must not cost the sender the
    // link: delivery is a post-link action, so the guard belongs at the send.
    const state = await createOwnerShare(root, ownerSession(calls, true), notified);
    expect(state).toBe("created");
    expect(OWNER_TINYCLOUD_DELIVERY_METHODS).toEqual(["authorizeShareDelivery"]);

    root.querySelector<HTMLButtonElement>(".confirm-notification")!.click();
    for (let tick = 0; tick < 200; tick += 1) await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toHaveLength(0);
    expect(notified).toHaveLength(0);
    expect(root.querySelector<HTMLElement>(".notification-status")?.textContent).toContain("The link above still works");
    debug.mockRestore();
  });
});
