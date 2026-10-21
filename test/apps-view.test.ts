import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CatalogEntry } from "../src/apps/catalog.ts";
import { runnerHref } from "../src/apps/install-plan.ts";
import { mountApps } from "../src/apps/view.ts";

const HOSTILE = "<img src=x onerror=\"window.__pwned=1\"><script>window.__pwned=1</script>";
const digest = "a".repeat(64);

async function sha256(text: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** A fetch result whose bytes come from node's realm: jsdom's ArrayBuffer is rejected by webcrypto on Node 20. */
const reply = (text: string) => ({ ok: true, arrayBuffer: async () => Buffer.from(text) });

async function entryFor(manifestText: string, overrides: Partial<CatalogEntry> = {}): Promise<CatalogEntry> {
  return {
    app_id: `t.app.${Math.random().toString(36).slice(2)}`,
    name: HOSTILE,
    description: HOSTILE,
    publisher: { name: HOSTILE },
    source: { repo: "javascript:alert(1)", tag: HOSTILE, commit: "c".repeat(40) },
    manifest: { path: "manifest.json", sha256: await sha256(manifestText) },
    bundle: { root: `/apps/b/${digest}/`, files: [{ path: "manifest.json", sha256: "d".repeat(64), size: 1 }], digest },
    knowledge: null,
    ...overrides,
  };
}

/** A bundle that includes app.jsx, as the catalog lists for an app that has code. */
const WITH_CODE: Partial<CatalogEntry> = {
  bundle: { root: `/apps/b/${digest}/`, files: [{ path: "app.jsx", sha256: "e".repeat(64), size: 1 }, { path: "manifest.json", sha256: "d".repeat(64), size: 1 }], digest },
};

const settle = async (): Promise<void> => { await vi.waitFor(() => expect(document.querySelector("#sheet [aria-busy]")).toBeNull()); };

let list: HTMLElement;
let sheet: HTMLDialogElement;
beforeEach(() => {
  document.body.innerHTML = "<ul id=list></ul><dialog id=sheet></dialog>";
  list = document.querySelector<HTMLElement>("#list") as HTMLElement;
  sheet = document.querySelector<HTMLDialogElement>("#sheet") as HTMLDialogElement;
  // jsdom has no modal dialog support.
  sheet.showModal = () => { sheet.setAttribute("open", ""); };
  sheet.close = () => { sheet.removeAttribute("open"); sheet.dispatchEvent(new Event("close")); };
  Reflect.deleteProperty(window, "__pwned");
});
afterEach(() => { vi.unstubAllGlobals(); });

describe("apps page rendering", () => {
  it("renders catalog and manifest text as text, never as markup or a script URL", async () => {
    const manifest = JSON.stringify({
      app_id: "t.app", name: "T", defaults: false,
      permissions: [{ service: "tinycloud.kv", path: "x/", actions: ["get", "put"], description: HOSTILE }],
      secrets: { [HOSTILE]: { description: HOSTILE } },
    });
    vi.stubGlobal("fetch", vi.fn(async () => reply(manifest)));
    mountApps(list, sheet, [await entryFor(manifest)]);
    list.querySelector<HTMLButtonElement>("button:not([disabled])")?.click();
    await settle();

    expect(sheet.querySelector("[role=alert]")).toBeNull(); // the manifest loaded, so the lists below are really its text
    expect(sheet.querySelectorAll(".apps-access__text").length).toBeGreaterThan(2);
    expect([...sheet.querySelectorAll(".apps-access code")].some((node) => node.textContent === HOSTILE)).toBe(true);
    expect(sheet.hasAttribute("open")).toBe(true);
    for (const root of [list, sheet]) {
      expect(root.querySelectorAll("img, script, iframe, svg")).toHaveLength(0);
    }
    expect(sheet.textContent).toContain(HOSTILE);
    expect(list.querySelector("h2")?.textContent).toBe(HOSTILE);
    // The hostile source URL is shown as text, never a link: the only link is the runner's Open link.
    expect([...sheet.querySelectorAll("a")].every((link) => link.getAttribute("href")?.startsWith("/apps/run#") === true)).toBe(true);
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
  });

  it("shows nothing of a manifest whose bytes differ from the catalog's sha256", async () => {
    const pinned = JSON.stringify({ app_id: "t.app", name: "T", permissions: [] });
    const served = JSON.stringify({ app_id: "t.app", name: "T", permissions: [{ service: "tinycloud.kv", path: "x", actions: ["put"], description: "Tampered grant." }] });
    vi.stubGlobal("fetch", vi.fn(async () => reply(served)));
    mountApps(list, sheet, [await entryFor(pinned, { name: "Plain", description: "Plain app." })]);
    list.querySelector<HTMLButtonElement>("button:not([disabled])")?.click();
    await settle();

    expect(sheet.querySelector("[role=alert]")?.textContent).toContain("doesn't match the catalog");
    expect(sheet.textContent).not.toContain("Tampered grant.");
    expect(sheet.querySelector(".apps-access")).toBeNull();
  });

  it("refuses to fetch from a bundle root outside /apps/b/<digest>/", async () => {
    const manifest = JSON.stringify({ app_id: "t.app", name: "T" });
    const fetchSpy = vi.fn(async () => reply(manifest));
    vi.stubGlobal("fetch", fetchSpy);
    const entry = await entryFor(manifest, { name: "Plain", description: "Plain app.", bundle: { root: "https://evil.example/", files: [], digest } });
    mountApps(list, sheet, [entry]);
    list.querySelector<HTMLButtonElement>("button:not([disabled])")?.click();
    await settle();

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(sheet.querySelector("[role=alert]")?.textContent).toContain("Couldn't load");
  });

  it("makes Open the card's primary action, Details secondary, and offers no Install button anywhere", async () => {
    const manifest = JSON.stringify({ app_id: "t.app", name: "T", defaults: false });
    vi.stubGlobal("fetch", vi.fn(async () => reply(manifest)));
    const entry = await entryFor(manifest, { name: "Plain", description: "Plain app.", ...WITH_CODE });
    mountApps(list, sheet, [entry]);
    const installButtons = (root: ParentNode): HTMLButtonElement[] => [...root.querySelectorAll("button")].filter((button) => button.textContent === "Install");
    const openLink = list.querySelector<HTMLAnchorElement>(`a[href="${runnerHref(entry.app_id)}"]`);
    expect(openLink?.textContent).toBe("Open");
    expect(openLink?.getAttribute("aria-label")).toBe("Open Plain");
    expect(installButtons(list)).toEqual([]);
    const details = [...list.querySelectorAll("button")].find((button) => button.textContent === "Details");
    expect(details).toBeDefined();
    details?.click();
    await settle();
    expect(sheet.querySelector<HTMLAnchorElement>(`a[href="${runnerHref(entry.app_id)}"]`)).not.toBeNull();
    expect(installButtons(sheet)).toEqual([]);
  });

  it("a disabled entry's card shows Open as a disabled button with no runner link, and says why", async () => {
    const manifest = JSON.stringify({ app_id: "t.app", name: "T", defaults: false });
    vi.stubGlobal("fetch", vi.fn(async () => reply(manifest)));
    const entry = await entryFor(manifest, { name: "Plain", description: "Plain app.", disabled: true, disabledReason: "Paused for maintenance." });
    mountApps(list, sheet, [entry]);
    const open = [...list.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Open");
    expect(open?.disabled).toBe(true);
    expect(list.querySelector(`a[href="${runnerHref(entry.app_id)}"]`)).toBeNull();
    expect(list.textContent).toContain("Paused for maintenance.");
  });

  it("an entry the catalog lists without its code shows Open disabled with the reason, on the card and in its sheet", async () => {
    const manifest = JSON.stringify({ app_id: "t.app", name: "T", defaults: false });
    vi.stubGlobal("fetch", vi.fn(async () => reply(manifest)));
    const entry = await entryFor(manifest, { name: "Plain", description: "Plain app." });
    mountApps(list, sheet, [entry]);
    expect(list.querySelector<HTMLButtonElement>("button[aria-label='Open Plain']")?.disabled).toBe(true);
    expect(list.querySelector(`a[href="${runnerHref(entry.app_id)}"]`)).toBeNull();
    expect(list.textContent).toContain("The catalog lists no code for this app, so it can't be opened.");
    list.querySelector<HTMLButtonElement>("button[aria-label='Details for Plain']")!.click();
    await settle();
    expect(sheet.querySelector<HTMLButtonElement>("footer button[aria-label='Open Plain']")?.disabled).toBe(true);
    expect(sheet.querySelector(`a[href="${runnerHref(entry.app_id)}"]`)).toBeNull();
  });
});
