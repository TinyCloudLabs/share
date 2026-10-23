// @vitest-environment jsdom
// @vitest-environment-options {"url":"http://127.0.0.1:4173/viewer"}
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKey, seal, toBase64Url } from "@tinycloud/share-envelope";
import { createLink } from "../src/short-links/client.js";
import { buildShortLink } from "../src/short-links/codec.js";
import { publishLink } from "../src/short-links/publish.js";
import { buildHeader, HEADER_DOMAIN, signObject } from "../src/short-links/record.js";
import { OPEN_CONFIRM_BUTTON, OPEN_CONFIRM_TITLE } from "../src/short-links/strings.js";
import { API_ORIGIN, ISSUER_DID, mockLinks, SHARE_ORIGIN, signWithIssuer, sealedMaterial } from "./fixtures/link-material.js";

// main.ts runs for real, with the real capture, confirm click, link reader and views. Only the
// config, the SDK receive path and the presentation are replaced.
const state = vi.hoisted(() => ({
  received: [] as string[],
  presented: [] as unknown[],
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({
    version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz", credentialsOrigin: "https://credentials.example", accountlessReceiverEnabled: false,
  }),
}));
vi.mock("../src/viewer/resolve.js", () => ({
  presentationEnvelope: () => ({}),
  resolveShare: async (href: string) => { state.received.push(href); return { state: "ok", envelope: {}, senderVerified: true, contentBytes: new Uint8Array(0) }; },
}));
vi.mock("../src/viewer/present.js", () => ({ presentShare: async (_root: HTMLElement, result: unknown) => { state.presented.push(result); } }));
vi.mock("../src/viewer/save-copy.js", () => ({ createSaveToTinyCloud: () => async () => ({ path: "x" }) }));

const OTHER_KEY = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
const OTHER_CID = "bafkreie3nxr36mwl2jprkro4mr42bdkcvvvrwbvbxur2qe6iq4mxhvdrfq";
const viewerText = (): string => document.querySelector("#viewer")?.textContent ?? "";

async function shareLink(links: ReturnType<typeof mockLinks>, plaintext?: Record<string, unknown>): Promise<string> {
  const material = await sealedMaterial(plaintext);
  const published = await publishLink({
    material, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), signer: { issuerDid: ISSUER_DID, sign: signWithIssuer },
    shareOrigin: SHARE_ORIGIN, apiOrigin: API_ORIGIN, fetchFn: links.fetchFn,
  });
  expect(published.form).toBe("short");
  return published.url;
}

async function courierLink(links: ReturnType<typeof mockLinks>, plaintext: Record<string, unknown>): Promise<string> {
  const key = generateKey();
  const sealed = await seal(new TextEncoder().encode(JSON.stringify(plaintext)), key);
  const header = await buildHeader({ type: "courier", issuer: ISSUER_DID, audience: API_ORIGIN, issuedAt: new Date(), expiresAt: new Date(Date.now() + 3_600_000), body: sealed.blob });
  const signature = await signObject(HEADER_DOMAIN, header, signWithIssuer);
  const created = await createLink({ header, signature, body: sealed.blob }, { apiOrigin: API_ORIGIN, fetchFn: links.fetchFn });
  return buildShortLink({ origin: SHARE_ORIGIN, type: "courier", id: created.id, key: toBase64Url(key), cid: header.bodyCid });
}

/** Opens `link` in a fresh viewer page, with the page's fetch routed to `links`. Returns the requests the viewer made. */
async function openViewer(link: string, links: ReturnType<typeof mockLinks>) {
  vi.resetModules();
  document.body.innerHTML = '<div id="viewer"></div>';
  state.received.length = 0;
  state.presented.length = 0;
  const url = new URL(link);
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const viewerFetch = links.api.fetchFor(API_ORIGIN);
  vi.stubGlobal("fetch", (async (input: RequestInfo | URL, init?: RequestInit) => { requests.push({ url: String(input), init }); return viewerFetch(input, init); }) as typeof fetch);
  await import("../src/main.js");
  return requests;
}

const clickOpen = async (): Promise<void> => {
  await vi.waitFor(() => expect(document.querySelector<HTMLButtonElement>(".link-confirm-action")).not.toBeNull());
  document.querySelector<HTMLButtonElement>(".link-confirm-action")!.click();
};

// The hermetic build maps the local page origin onto the Share origin, as the other viewer tests do.
beforeEach(() => { vi.unstubAllGlobals(); vi.stubEnv("VITE_SHARE_VIEWER_HERMETIC", "true"); });

describe("the viewer opens a v=4 link only after a click", () => {
  it("shows the confirm screen first and makes no request, then reads the link once on the click", async () => {
    const links = mockLinks();
    const link = await shareLink(links);
    links.api.received.length = 0;
    const requests = await openViewer(link, links);

    await vi.waitFor(() => expect(viewerText()).toContain(OPEN_CONFIRM_TITLE));
    expect(document.querySelector(".link-confirm-action")?.textContent).toBe(OPEN_CONFIRM_BUTTON);
    expect(requests).toEqual([]);
    // The fragment is already off the address bar.
    expect(window.location.hash).toBe("");

    await clickOpen();
    await vi.waitFor(() => expect(state.presented).toHaveLength(1));
    expect(requests).toHaveLength(1);
    const [{ url, init }] = requests as [{ url: string; init: RequestInit }];
    const id = new URL(link).pathname.split("/")[2]!;
    expect(url).toBe(`${API_ORIGIN}/v1/links/${id}`);
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("omit");
    expect(init.referrerPolicy).toBe("no-referrer");
    // The key and the link's CID are in no request.
    const key = new URLSearchParams(new URL(link).hash.slice(1)).get("k")!;
    expect(JSON.stringify(requests)).not.toContain(key);
    expect(JSON.stringify(requests)).not.toContain("#");
    // The verified bytes reach the existing receive path.
    expect(state.received).toHaveLength(1);
    expect(state.received[0]).not.toBe(link);
  });

  it("opens a full link without any API request", async () => {
    const links = mockLinks();
    const material = await sealedMaterial();
    const full = await publishLink({
      material, expiresAt: new Date(Date.now() + 40 * 86_400_000).toISOString(), signer: { issuerDid: ISSUER_DID, sign: signWithIssuer },
      shareOrigin: SHARE_ORIGIN, apiOrigin: API_ORIGIN, fetchFn: links.fetchFn,
    });
    expect(full.form).toBe("full");
    const requests = await openViewer(full.url, links);
    await clickOpen();
    await vi.waitFor(() => expect(state.presented).toHaveLength(1));
    expect(requests).toEqual([]);
  });
});

describe("every refusal shows the same not-found screen", () => {
  type Tamper = (link: string, links: ReturnType<typeof mockLinks>) => Promise<string> | string;
  const swap = (link: string, name: "k" | "c", value: string): string => {
    const url = new URL(link);
    const parts = new URLSearchParams(url.hash.slice(1));
    parts.set(name, value);
    return `${url.origin}${url.pathname}#${parts.toString()}`;
  };
  const cases: [string, Tamper][] = [
    ["the wrong key", (link) => swap(link, "k", OTHER_KEY)],
    ["a CID that is not the record's", (link) => swap(link, "c", OTHER_CID)],
    ["a truncated link", (link) => link.slice(0, link.length - 12)],
    ["a deleted link", (link, links) => { links.api.state.records.clear(); return link; }],
    ["an expired link", (link, links) => { for (const [id, record] of links.api.state.records) links.api.state.records.set(id, { ...record, expiresAt: new Date(Date.now() - 1000).toISOString() }); return link; }],
    ["a body over the size limit", (link, links) => {
      for (const [id, record] of links.api.state.records) links.api.state.records.set(id, { ...record, body: new Uint8Array(65_537) });
      return link;
    }],
    ["a removed link version", (link) => link.replace("#v=4", "#v=3")],
    ["an issuer that is not the envelope signer", async (_link, links) => shareLink(links, { version: 3, signature: { signerDid: "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK", algorithm: "Ed25519", value: "x" } })],
    ["a login link on the share origin", (link) => link.replace("/s/", "/l/")],
  ];

  it("renders identical text for each", async () => {
    const screens = new Map<string, string>();
    for (const [name, tamper] of cases) {
      const links = mockLinks();
      const original = await shareLink(links);
      const link = await tamper(original, links);
      await openViewer(link, links);
      // The /l/ path is not a viewer route at all: it never reaches the reader and shows the link-needed screen.
      if (name === "a login link on the share origin") {
        await vi.waitFor(() => expect(viewerText()).toContain("Open the original link again"));
        continue;
      }
      await clickOpen();
      await vi.waitFor(() => expect(viewerText()).toContain("This share isn't available"));
      screens.set(name, document.querySelector("#viewer")!.innerHTML);
      expect(state.received).toEqual([]);
    }
    expect(new Set(screens.values()).size).toBe(1);
    expect(screens.size).toBe(cases.length - 1);
  });
});

describe("an invitation link at /c/", () => {
  it("is read the same way and shown through the placeholder view", async () => {
    const links = mockLinks();
    const link = await courierLink(links, { issuer: ISSUER_DID, note: "hello" });
    expect(new URL(link).pathname.startsWith("/c/")).toBe(true);
    await openViewer(link, links);
    await clickOpen();
    await vi.waitFor(() => expect(document.querySelector(".courier-record")).not.toBeNull());
    expect(document.querySelector(".courier-record-name")?.textContent).toBe("note");
    expect(document.querySelector(".courier-record-value")?.textContent).toBe("hello");
    expect(state.received).toEqual([]);
  });

  it("repeats: a second visit reads the same record", async () => {
    const links = mockLinks();
    const link = await courierLink(links, { issuer: ISSUER_DID, note: "hello" });
    for (let visit = 0; visit < 2; visit += 1) {
      await openViewer(link, links);
      await clickOpen();
      await vi.waitFor(() => expect(document.querySelector(".courier-record")).not.toBeNull());
    }
  });

  it("is not found when its record is a share (type and path must agree)", async () => {
    const links = mockLinks();
    const asShare = await shareLink(links);
    await openViewer(asShare.replace("/s/", "/c/"), links);
    await clickOpen();
    await vi.waitFor(() => expect(viewerText()).toContain("This share isn't available"));
  });

  it("is not found when the invitation's sealed issuer is not its header issuer", async () => {
    const links = mockLinks();
    const link = await courierLink(links, { issuer: "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK", note: "x" });
    await openViewer(link, links);
    await clickOpen();
    await vi.waitFor(() => expect(viewerText()).toContain("This share isn't available"));
  });
});

describe("a lookup that cannot complete", () => {
  it("shows the temporary-unavailable screen, and Try again reads without asking for the click again", async () => {
    const links = mockLinks();
    const link = await shareLink(links);
    await openViewer(link, links);
    const failing = vi.fn(async () => new Response(null, { status: 503 }));
    vi.stubGlobal("fetch", failing);
    await clickOpen();
    await vi.waitFor(() => expect(viewerText()).toContain("TinyCloud is temporarily unavailable"));
    vi.stubGlobal("fetch", links.api.fetchFor(API_ORIGIN));
    document.querySelector<HTMLButtonElement>(".viewer-state-action")!.click();
    await vi.waitFor(() => expect(state.presented).toHaveLength(1));
    expect(document.querySelector(".link-confirm-action")).toBeNull();
  });
});
