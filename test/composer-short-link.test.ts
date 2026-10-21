// @vitest-environment jsdom
import vectorsJson from "./fixtures/shortlink-vectors.json";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as SdkModule from "@tinycloud/share-sdk";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import { mountShareComposer } from "../src/share/composer.js";

// The composer runs for real. Only the SDK publish call, the public config and
// the network are replaced: the SDK returns the canonical inline link from a
// shortlink vector, and `fetchFn` answers the short-link service.
const DAY_MS = 24 * 60 * 60 * 1000;
const NOTICE = "Short link unavailable: this link is long. Try again later for a shorter one.";
const vector = (vectorsJson as Record<string, string>[])[0]!;

const state = vi.hoisted(() => ({
  published: [] as Record<string, unknown>[],
  expiresAt: "",
  inline: "",
  cid: "",
  sealed: "",
}));

vi.mock("@tinycloud/share-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof SdkModule>()),
  publishAddressedShare: vi.fn(async (options: Record<string, unknown> & { readonly onDeliveryMaterial: (material: unknown) => void }) => {
    state.published.push(options);
    options.onDeliveryMaterial({ envelope: { version: 3 }, sealedEnvelope: state.sealed, envelopeKey: "key", shareCid: state.cid });
    return { url: state.inline, link: { cid: state.cid }, metadata: { expiresAt: state.expiresAt } };
  }),
  historyRecordForPublishedShare: vi.fn(() => ({ id: "record" })),
}));
vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example", credentialsOrigin: "https://witness.example" }),
}));


interface Call { readonly url: string; readonly init: RequestInit }

/** Routes the short-link service: POST answers `create`, DELETE answers `remove`. */
function shortLinkService(create: () => Response, remove: () => Response = () => new Response(null, { status: 204 })) {
  const calls: Call[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    calls.push({ url: String(url), init });
    return init.method === "DELETE" ? remove() : create();
  }) as typeof fetch;
  return { fetchFn, calls };
}

const created = (cid: string = vector.cid!) => () => new Response(JSON.stringify({ id: vector.id, cid, deleteToken: "delete-token-1" }), { status: 201 });

function mount(fetchFn: typeof fetch) {
  const records: { path: string; body: unknown }[] = [];
  const put = vi.fn(async (path: string, value: Uint8Array) => {
    if (path.endsWith("/short-link.json")) records.push({ path, body: JSON.parse(new TextDecoder().decode(value)) });
    return { ok: true };
  });
  const copyText = vi.fn(async (_value: string) => undefined);
  const tinycloud = {
    spaceId: "tinycloud:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678:applications",
    credentialHolderDid: "did:key:z6MkOwnerSession",
    activeNodeIdentity: async () => ({ origin: "https://node.example", nodeDid: "did:key:z6MkOwnerNode" }),
    publishActiveNodeLocation: async () => undefined,
    encryption: { encryptToNetwork: async () => ({ ok: true, data: { v: 1, networkId: "urn:tinycloud:encryption:owner:default", alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AA" } }) },
    kvForSpace: () => ({ put }),
    signSessionBytes: async () => new Uint8Array(64),
    createUnifiedOwnerRoot: vi.fn(),
    registerPolicy: vi.fn(),
  } as unknown as ShareTinyCloud;
  const root = document.createElement("div");
  document.body.append(root);
  mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", onBack: () => undefined, session: {} as OpenKeyShareSession, tinycloud, fetchFn, copyText });
  return { root, records, copyText };
}

async function submit(root: HTMLElement): Promise<void> {
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
  await vi.waitFor(() => expect(root.querySelector(".result-title")).not.toBeNull());
}

function clickCopy(root: HTMLElement): void {
  const copy = [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Copy link");
  copy!.click();
}

beforeEach(() => {
  state.published.length = 0;
  state.inline = vector.inline!;
  state.cid = vector.cid!;
  state.sealed = vector.ciphertextB64Url!;
  state.expiresAt = new Date(Date.now() + 7 * DAY_MS).toISOString();
});

afterEach(() => {
  vi.clearAllMocks();
  document.body.replaceChildren();
});

describe("composer short link for an addressed share", () => {
  it("copies, shows, and stores the short link, and posts only the sealed bytes and expiry", async () => {
    const { fetchFn, calls } = shortLinkService(created());
    const { root, records, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);

    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());
    expect(copyText).toHaveBeenCalledWith(vector.short);
    expect(root.textContent).not.toContain("#v=2");
    expect(root.querySelector(".result-notice")).toBeNull();

    const post = calls.find((call) => call.init.method === "POST")!;
    expect(JSON.parse(String(post.init.body))).toEqual({ ciphertext: vector.ciphertextB64Url, expiresAt: state.expiresAt });
    expect(String(post.init.body)).not.toContain(vector.k!);

    const shareId = state.published[0]!.shareId as string;
    expect(records).toEqual([{ path: `xyz.tinycloud.share/shares/${shareId}/short-link.json`, body: { id: vector.id, deleteToken: "delete-token-1" } }]);
  });

  it("falls back to the inline link with the visible notice when the service is unavailable", async () => {
    const { fetchFn } = shortLinkService(() => new Response(null, { status: 503, headers: { "Retry-After": "3600" } }));
    const { root, records, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);

    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());
    expect(copyText).toHaveBeenCalledWith(vector.inline);
    expect(root.querySelector(".result-notice")?.textContent).toBe(NOTICE);
    expect(records).toHaveLength(0);
  });

  it("refuses a short link whose CID differs from the share, deletes it, and keeps the inline link", async () => {
    const { fetchFn, calls } = shortLinkService(created("bafkreiotherothercidvalueforthistestonly0000000000000000000000"));
    const { root, records, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);

    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());
    expect(copyText).toHaveBeenCalledWith(vector.inline);
    expect(root.querySelector(".result-notice")?.textContent).toBe(NOTICE);
    expect(records).toHaveLength(0);
    const remove = calls.find((call) => call.init.method === "DELETE")!;
    expect(remove.url).toBe(`/api/share-links/${vector.id}`);
    expect(new Headers(remove.init.headers).get("authorization")).toBe("Bearer delete-token-1");
  });

  it("keeps the share and the inline link when the expiry is past the 400-day service limit", async () => {
    state.expiresAt = new Date(Date.now() + 401 * DAY_MS).toISOString();
    const { fetchFn, calls } = shortLinkService(created());
    const { root, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);

    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());
    expect(copyText).toHaveBeenCalledWith(vector.inline);
    expect(root.querySelector(".result-notice")?.textContent).toBe(NOTICE);
    expect(calls).toHaveLength(0);
  });
});
