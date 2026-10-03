// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

// The owner-share path runs for real; only the SDK publish call, the public
// config, and the OpenCredentials request are replaced.
const state = vi.hoisted(() => ({
  published: [] as Record<string, unknown>[],
  failOnce: new Set<string>(),
  delivered: [] as string[],
}));
vi.mock("@tinycloud/share-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tinycloud/share-sdk")>()),
  publishAddressedShare: vi.fn(async (options: Record<string, unknown> & { readonly onDeliveryMaterial: (material: unknown) => void }) => {
    state.published.push(options);
    options.onDeliveryMaterial({ envelope: { version: 3 }, sealedEnvelope: "sealed", envelopeKey: "key", shareCid: "bafy-share" });
    return { url: "https://share.tinycloud.xyz/s/inline#v=2&p=opaque", link: { cid: "bafy-share" }, metadata: { expiresAt: "2030-01-01T00:00:00Z" } };
  }),
  historyRecordForPublishedShare: vi.fn(() => ({ id: "record" })),
}));
vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example", credentialsOrigin: "https://witness.example" }),
}));
vi.mock("../src/share/delivery.js", () => ({
  requestAddressedDelivery: vi.fn(async (input: { readonly deliveryAuthorization: { readonly request: { readonly recipient: string } } }) => {
    const recipient = input.deliveryAuthorization.request.recipient;
    if (state.failOnce.delete(recipient)) throw new Error("credential invitation unavailable (503)");
    state.delivered.push(recipient);
  }),
}));

const { mountShareComposer } = await import("../src/share/composer.js");

type DeliveryInput = { readonly recipientEmail: string; readonly idempotencyKey: string; readonly expiresAt: string };

function owner() {
  const authorizeShareDeliveryV3 = vi.fn(async (input: DeliveryInput) => ({ request: { recipient: input.recipientEmail }, admission: {}, proof: {} }));
  const tinycloud = {
    spaceId: "tinycloud:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678:applications",
    credentialHolderDid: "did:key:z6MkOwnerSession",
    activeNodeIdentity: async () => ({ origin: "https://node.example", nodeDid: "did:key:z6MkOwnerNode" }),
    publishActiveNodeLocation: async () => undefined,
    encryption: { encryptToNetwork: async () => ({ ok: true, data: { v: 1, networkId: "urn:tinycloud:encryption:owner:default", alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AA" } }) },
    kvForSpace: () => ({ put: async () => ({ ok: true }) }),
    signSessionBytes: async () => new Uint8Array(64),
    createUnifiedOwnerRoot: vi.fn(),
    registerPolicy: vi.fn(),
    authorizeShareDeliveryV3,
  } as unknown as ShareTinyCloud;
  const root = document.createElement("div");
  document.body.append(root);
  mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", onBack: () => undefined, session: {} as OpenKeyShareSession, tinycloud });
  return { root, authorizeShareDeliveryV3 };
}

async function create(root: HTMLElement, kind: "exactEmail" | "emailDomain", recipient: string, delivery?: string): Promise<HTMLButtonElement> {
  const choice = root.querySelector<HTMLInputElement>(`input[name=recipient][value=${kind}]`)!;
  choice.checked = true;
  choice.dispatchEvent(new Event("change", { bubbles: true }));
  const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
  value.value = recipient;
  value.dispatchEvent(new Event("input", { bubbles: true }));
  if (delivery !== undefined) {
    const field = root.querySelector<HTMLTextAreaElement | HTMLInputElement>(kind === "emailDomain" ? "textarea[name=delivery-emails]" : "input[name=delivery-email]")!;
    field.value = delivery;
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }
  const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
  Object.defineProperty(file, "files", { configurable: true, value: [new File(["notes"], "notes.txt", { type: "text/plain" })] });
  file.dispatchEvent(new Event("change", { bubbles: true }));
  root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(root.querySelector(".confirm-notification")).not.toBeNull());
  return root.querySelector<HTMLButtonElement>(".confirm-notification")!;
}

describe("TC-530 owner delivery", () => {
  afterEach(() => {
    vi.clearAllMocks();
    state.published.length = 0;
    state.delivered.length = 0;
    state.failOnce.clear();
    document.body.replaceChildren();
  });

  it("emails a domain link to each canonical address and retries only what failed, with the same signed request", async () => {
    const { root, authorizeShareDeliveryV3 } = owner();
    const confirm = await create(root, "emailDomain", "example.com", "Alice@example.com, bob@example.com\ncarol@example.com");
    // The domain envelope is not pinned to one mailbox.
    expect(state.published[0]).toMatchObject({ target: { kind: "emailDomain", domain: "example.com" } });
    expect(state.published[0]).not.toHaveProperty("deliveryEmail");
    expect(confirm.textContent).toBe("Notify 3 recipients");

    state.failOnce.add("bob@example.com");
    confirm.click();
    const status = () => root.querySelector(".notification-status")?.textContent;
    await vi.waitFor(() => expect(status()).toBe("Sent 2 of 3. The link above still works; try again to send the rest."));
    const first = authorizeShareDeliveryV3.mock.calls.map(([input]) => input);
    expect(first.map((input) => input.recipientEmail)).toEqual(["alice@example.com", "bob@example.com", "carol@example.com"]);
    for (const input of first) expect(input.idempotencyKey).toMatch(new RegExp(`^tinycloud-share:[0-9a-f-]{36}:${input.recipientEmail.replace(".", "\\.")}$`));
    expect(state.delivered).toEqual(["alice@example.com", "carol@example.com"]);

    confirm.click();
    await vi.waitFor(() => expect(status()).toBe("Invitations requested."));
    const retry = authorizeShareDeliveryV3.mock.calls.slice(first.length).map(([input]) => input);
    // Only bob is asked again, with the identical request, so the Node returns
    // the same receipt and OpenCredentials deduplicates it.
    expect(retry).toHaveLength(1);
    expect(retry[0]).toMatchObject({ recipientEmail: "bob@example.com", idempotencyKey: first[1]!.idempotencyKey, expiresAt: first[1]!.expiresAt });
    expect(state.delivered).toEqual(["alice@example.com", "carol@example.com", "bob@example.com"]);
  });

  it("keeps the exact-email address as typed and its original retry key", async () => {
    const { root, authorizeShareDeliveryV3 } = owner();
    const confirm = await create(root, "exactEmail", "John.Smith@Example.com");
    expect(state.published[0]).toMatchObject({ deliveryEmail: "John.Smith@example.com" });
    expect(confirm.textContent).toBe("Notify recipient");
    confirm.click();
    await vi.waitFor(() => expect(root.querySelector(".notification-status")?.textContent).toBe("Invitation requested."));
    const [input] = authorizeShareDeliveryV3.mock.calls[0]!;
    expect(input.recipientEmail).toBe("John.Smith@example.com");
    expect(input.idempotencyKey).toMatch(/^tinycloud-share:[0-9a-f-]{36}$/);
  });
});
