// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as SdkModule from "@tinycloud/share-sdk";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import { mountShareComposer } from "../src/share/composer.js";
import { parseLink } from "../src/short-links/codec.js";
import { resolveLink } from "../src/short-links/resolve.js";
import { FULL_LINK_NO_EMAIL, LINK_LONG_LIFE_NOTICE, SHARE_TOO_LARGE_FOR_LINK, SHORT_LINK_UNAVAILABLE_NOTICE } from "../src/short-links/strings.js";
import { API_ORIGIN, ISSUER_DID, mockLinks, SHARE_ORIGIN, signWithIssuer } from "./fixtures/link-material.js";

// The composer runs for real, with real signing and the mock links API. Only the SDK publish call,
// the public config and the owner's TinyCloud are replaced.
const DAY_MS = 24 * 60 * 60 * 1000;

const state = vi.hoisted(() => ({
  published: [] as Record<string, unknown>[],
  expiresAt: "",
  material: undefined as undefined | { sealedEnvelope: string; envelopeKey: string; shareCid: string },
  /** Extra plaintext bytes in the sealed envelope, to make it larger. */
  pad: 0,
  registrations: 0,
}));

vi.mock("@tinycloud/share-sdk", async (importOriginal) => {
  const sdk = await importOriginal<typeof SdkModule>();
  return {
    ...sdk,
    // The SDK's size check, answered by the size the test sets: over the limit when `pad` is set.
    assertAddressedShareFits: vi.fn(async () => { if (state.pad > 0) throw new sdk.SharePublishError("max-bytes-exceeded", sdk.ADDRESSED_SHARE_TOO_LARGE_MESSAGE); }),
    publishAddressedShare: vi.fn(async (options: Record<string, unknown> & { readonly contentSource: unknown; readonly onDeliveryMaterial: (material: unknown) => void }) => {
      state.published.push(options);
      // vi.mock factories run before static imports exist, so this module is loaded here.
      const { sealedMaterial } = await import("./fixtures/link-material.js");
      state.material = await sealedMaterial({ version: 3, signature: { signerDid: "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S", algorithm: "Ed25519", value: "TEST ONLY" }, pad: "x".repeat(state.pad) });
      options.onDeliveryMaterial({ envelope: { version: 3 }, ...state.material });
      return { url: "unused", link: { cid: state.material.shareCid }, metadata: { expiresAt: state.expiresAt } };
    }),
    historyRecordForPublishedShare: vi.fn(() => ({ id: "record" })),
  };
});
vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example", credentialsOrigin: "https://witness.example" }),
}));

interface Call { readonly url: string; readonly init: RequestInit }

/** Wraps a fetch so a test can see every request and answer the links API its own way. */
function spy(inner: typeof fetch, override?: (url: string, init: RequestInit) => Response | undefined) {
  const calls: Call[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, init });
    const answer = url.startsWith(API_ORIGIN) ? override?.(url, init) : undefined;
    if (answer !== undefined) return answer;
    if (url.startsWith(API_ORIGIN)) return inner(input, init);
    return new Response(null, { status: 200 });
  }) as typeof fetch;
  return { fetchFn, calls };
}

function mount(fetchFn: typeof fetch) {
  const puts: string[] = [];
  const put = vi.fn(async (path: string) => { puts.push(path); return { ok: true }; });
  const copyText = vi.fn(async (_value: string) => undefined);
  const authorize = vi.fn(async (input: { readonly shareUrl: string }) => ({ request: { returnLink: input.shareUrl } }));
  const saved: { link?: string }[] = [];
  const encryptToNetwork = vi.fn(async () => ({ ok: true, data: { v: 1, networkId: "urn:tinycloud:encryption:owner:default", alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AAAA", nonce: "AAAA" } }));
  const registerPolicy = vi.fn();
  const publishActiveNodeLocation = vi.fn(async () => undefined);
  const tinycloud = {
    spaceId: "tinycloud:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678:applications",
    credentialHolderDid: ISSUER_DID,
    activeNodeIdentity: async () => ({ origin: "https://node.example", nodeDid: "did:key:z6MkOwnerNode" }),
    publishActiveNodeLocation,
    encryption: { encryptToNetwork },
    kvForSpace: () => ({ put }),
    signSessionBytes: signWithIssuer,
    createUnifiedOwnerRoot: vi.fn(),
    registerPolicy,
    authorizeShareDeliveryV3: authorize,
  } as unknown as ShareTinyCloud;
  const root = document.createElement("div");
  document.body.append(root);
  mountShareComposer(root, {
    openKeyAddress: "0x1234567890abcdef", origin: SHARE_ORIGIN, onBack: () => undefined, session: {} as OpenKeyShareSession, tinycloud, fetchFn, copyText,
    persistShare: async ({ share }) => { saved.push(share.record as { link?: string }); },
  });
  return { root, puts, copyText, authorize, saved, encryptToNetwork, registerPolicy, put, publishActiveNodeLocation };
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
  [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Copy link")!.click();
}

beforeEach(() => {
  state.published.length = 0;
  state.pad = 0;
  state.expiresAt = new Date(Date.now() + 7 * DAY_MS).toISOString();
});

afterEach(() => {
  vi.clearAllMocks();
  document.body.replaceChildren();
});

describe("composer link for an addressed share", () => {
  it("creates a short link through the API with an issuer-signed header, and the key never reaches the API", async () => {
    const links = mockLinks();
    const { fetchFn, calls } = spy(links.fetchFn);
    const { root, copyText, saved, puts, put, publishActiveNodeLocation } = mount(fetchFn);

    await submit(root);
    clickCopy(root);
    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());
    // The registry write happens once, after the size check and before the upload.
    expect(publishActiveNodeLocation).toHaveBeenCalledTimes(1);
    expect(publishActiveNodeLocation.mock.invocationCallOrder[0]!).toBeLessThan(put.mock.invocationCallOrder[0]!);

    const link = copyText.mock.calls[0]![0];
    const parsed = parseLink(link, [SHARE_ORIGIN]);
    expect(parsed.ok && parsed.link.form === "short" && parsed.link.pathType === "share").toBe(true);
    expect(link).toContain(`#v=4&k=${state.material!.envelopeKey}&c=${state.material!.shareCid}`);
    expect(root.querySelector(".result-notice")).toBeNull();
    // History keeps the link text; nothing is written for a delete token.
    expect(saved[0]!.link).toBe(link);
    expect(puts.some((path) => path.endsWith("/.short-link.json"))).toBe(false);

    const post = calls.find((call) => call.init.method === "POST" && call.url === `${API_ORIGIN}/v1/links`)!;
    const body = String(post.init.body);
    expect(Object.keys(JSON.parse(body)).sort()).toEqual(["body", "header", "signature"]);
    expect(body).not.toContain(state.material!.envelopeKey);
    expect(post.init.credentials).toBe("omit");
    expect(post.init.redirect).toBe("error");
    // The stored record opens in the viewer's reader.
    const resolved = await resolveLink(link, { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn: links.fetchFn });
    expect(resolved.header.issuer).toBe(ISSUER_DID);
  });

  it.each([
    ["is unavailable (503)", 503],
    ["rate limits the sender (429)", 429],
    ["answers a server error (500)", 500],
  ])("falls back to the full link with the visible notice when the service %s", async (_name, status) => {
    const { fetchFn } = spy(mockLinks().fetchFn, () => new Response(JSON.stringify({ error: "x" }), { status }));
    const { root, copyText, saved } = mount(fetchFn);

    await submit(root);
    clickCopy(root);
    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());

    const link = copyText.mock.calls[0]![0];
    expect(link.startsWith(`${SHARE_ORIGIN}/s/full#v=4&k=`)).toBe(true);
    expect(root.querySelector(".result-notice")?.textContent).toBe(SHORT_LINK_UNAVAILABLE_NOTICE);
    expect(saved[0]!.link).toBe(link);
    // The full link opens through the same reader, with no API call.
    const resolved = await resolveLink(link, { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn: (async () => { throw new Error("no request expected"); }) as unknown as typeof fetch });
    expect(resolved.type).toBe("share");
  });

  it("falls back to the full link when the service cannot be reached", async () => {
    const { fetchFn } = spy((async () => { throw new TypeError("offline"); }) as unknown as typeof fetch);
    const { root, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);
    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());

    expect(copyText.mock.calls[0]![0].startsWith(`${SHARE_ORIGIN}/s/full#v=4`)).toBe(true);
    expect(root.querySelector(".result-notice")?.textContent).toBe(SHORT_LINK_UNAVAILABLE_NOTICE);
  });

  it("gives a share longer than 30 days the full link and the warning, without calling the API", async () => {
    state.expiresAt = new Date(Date.now() + 31 * DAY_MS).toISOString();
    const { fetchFn, calls } = spy(mockLinks().fetchFn);
    const { root, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);
    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());

    expect(copyText.mock.calls[0]![0].startsWith(`${SHARE_ORIGIN}/s/full#v=4`)).toBe(true);
    expect(root.querySelector(".result-notice")?.textContent).toBe(LINK_LONG_LIFE_NOTICE);
    expect(LINK_LONG_LIFE_NOTICE).toContain("https://tinycloud.xyz/delegations?from=link-expiry");
    expect(calls.some((call) => call.url.startsWith(API_ORIGIN))).toBe(false);
  });
});

describe("composer link and Notify", () => {
  it("sends the short link to the node and the witness on Notify", async () => {
    const { fetchFn, calls } = spy(mockLinks().fetchFn);
    const { root, authorize, copyText } = mount(fetchFn);

    await submit(root);
    clickCopy(root);
    await vi.waitFor(() => expect(copyText).toHaveBeenCalled());
    const link = copyText.mock.calls[0]![0];
    const confirm = await vi.waitFor(() => {
      const button = root.querySelector<HTMLButtonElement>(".confirm-notification");
      expect(button).not.toBeNull();
      return button!;
    });
    confirm.click();

    const witnessUrl = "https://witness.example/v1/credential-invitations";
    await vi.waitFor(() => expect(calls.some((call) => call.url === witnessUrl)).toBe(true));
    expect(authorize).toHaveBeenCalledWith(expect.objectContaining({ shareUrl: link }));
    // The delivery input carries the short link and the origin it may be on; the sealed material is not part of it.
    const delivery = authorize.mock.calls[0]![0] as Record<string, unknown>;
    expect(delivery.trustedOrigins).toEqual([SHARE_ORIGIN]);
    for (const field of ["sealedEnvelope", "envelopeKey", "shareCid"]) expect(delivery).not.toHaveProperty(field);
    expect(JSON.parse(String(calls.find((call) => call.url === witnessUrl)!.init.body)).request.returnLink).toBe(link);
  });

  it("does not email a full link, and says so", async () => {
    const { fetchFn, calls } = spy(mockLinks().fetchFn, () => new Response(null, { status: 503 }));
    const { root, authorize } = mount(fetchFn);

    await submit(root);
    const confirm = await vi.waitFor(() => {
      const button = root.querySelector<HTMLButtonElement>(".confirm-notification");
      expect(button).not.toBeNull();
      return button!;
    });
    confirm.click();

    await vi.waitFor(() => expect(root.textContent).toContain(FULL_LINK_NO_EMAIL));
    expect(authorize).not.toHaveBeenCalled();
    expect(calls.some((call) => call.url.startsWith("https://witness.example"))).toBe(false);
  });
});

describe("composer opened by Send the link again", () => {
  const open = (prefill: NonNullable<Parameters<typeof mountShareComposer>[1]["prefill"]>) => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: SHARE_ORIGIN, onBack: () => undefined, session: {} as OpenKeyShareSession, tinycloud: {} as unknown as ShareTinyCloud, prefill });
    return root;
  };

  it("fills in the recipient, the expiry and the mailbox, and asks for the file again", () => {
    const root = open({ recipient: { kind: "exactEmail", value: "person@example.invalid" }, deliveryEmails: [], expiry: "30d", filename: "report.md" });
    expect(root.querySelector<HTMLInputElement>("input[name=recipient]:checked")?.value).toBe("exactEmail");
    expect(root.querySelector<HTMLInputElement>("input[name=recipient-value]")?.value).toBe("person@example.invalid");
    expect(root.querySelector<HTMLInputElement>("input[name=delivery-email]")?.value).toBe("person@example.invalid");
    expect(root.querySelector<HTMLInputElement>("input[name=expiry]:checked")?.value).toBe("30d");
    expect(root.querySelector(".send-again-hint")?.textContent).toBe("Attach report.md again to send the link again.");
    // Nothing is chosen for the sender: no file is attached.
    expect(root.querySelector<HTMLInputElement>("input[type=file]")?.files?.length ?? 0).toBe(0);
  });

  it("fills in a domain and the addresses it was emailed to", () => {
    const root = open({ recipient: { kind: "emailDomain", value: "example.invalid" }, deliveryEmails: ["a@example.invalid", "b@example.invalid"], expiry: "24h" });
    expect(root.querySelector<HTMLInputElement>("input[name=recipient]:checked")?.value).toBe("emailDomain");
    expect(root.querySelector<HTMLTextAreaElement>("textarea[name=delivery-emails]")?.value).toBe("a@example.invalid, b@example.invalid");
    expect(root.querySelector(".send-again-hint")?.textContent).toBe("Attach the file again to send the link again.");
  });

  it("is the plain composer when nothing was passed", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: SHARE_ORIGIN, onBack: () => undefined, session: {} as OpenKeyShareSession, tinycloud: {} as unknown as ShareTinyCloud });
    expect(root.querySelector(".send-again-hint")).toBeNull();
    expect(root.querySelector<HTMLInputElement>("input[name=recipient]:checked")?.value).toBe("bearer");
  });
});

describe("a share too large for any link", () => {
  it("is refused before anything is uploaded or registered, with no request to any service, and shows the message", async () => {
    state.pad = 70_000;
    const { fetchFn, calls } = spy(mockLinks().fetchFn);
    const { root, put, puts, encryptToNetwork, registerPolicy, saved, authorize, publishActiveNodeLocation } = mount(fetchFn);

    root.querySelector<HTMLInputElement>("input[name=recipient][value=exactEmail]")!.click();
    const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
    value.value = "reader@example.com";
    value.dispatchEvent(new Event("input", { bubbles: true }));
    const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(file, "files", { configurable: true, value: [new File(["notes"], "notes.txt", { type: "text/plain" })] });
    file.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).toBe("error-invalid"));
    expect(root.querySelector(".composer-status")?.textContent).toContain(SHARE_TOO_LARGE_FOR_LINK);
    expect(SHARE_TOO_LARGE_FOR_LINK).toBe("This share is too large to send as a link, so nothing was shared. Use a shorter path or fewer folders.");
    // Nothing written: no registry write, no encryption request, no upload, no registration, no history, no link, no delivery.
    expect(publishActiveNodeLocation).not.toHaveBeenCalled();
    expect(encryptToNetwork).not.toHaveBeenCalled();
    expect(put).not.toHaveBeenCalled();
    expect(puts).toEqual([]);
    expect(registerPolicy).not.toHaveBeenCalled();
    expect(saved).toEqual([]);
    expect(authorize).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    // No link of any form is offered.
    expect(root.querySelector(".result-title")).toBeNull();
  });
});
