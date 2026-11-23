import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { type AppData, createCapabilityBridge } from "../src/apps/bridge.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { type SaveWith, createFileOffers } from "../src/apps/file-offer.ts";
import type { SaveFile } from "../src/apps/save-file.ts";
import { type ManifestSdk, makeAuthorizer } from "../src/apps/grants.ts";
import type { RunPorts, RunSession, RuntimeSession } from "../src/apps/run.ts";
import { mountRunner } from "../src/apps/run-view.ts";
import type { CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import type { JsxManifest } from "../src/artifact/jsx-runtime/files.ts";
import { storedFiles } from "./stored-fixtures.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const HEALTH = "xyz.tinycloud.sample.healthlog";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH) as CatalogEntry;
const sdk: ManifestSdk = sdkCore;

const text = (value: string): Uint8Array => new TextEncoder().encode(value);
const read = (file: SaveFile): string => new TextDecoder().decode(file.bytes);

describe("the offer the runner shows the owner", () => {
  let host: HTMLElement;
  let saved: SaveFile[];
  let announced: string[];
  const make = (save: SaveWith) => {
    const offers = createFileOffers({ view: window, appName: () => "Contacts", announce: (line) => { announced.push(line); }, save });
    host.append(offers.region, offers.actions);
    return offers;
  };
  const file = (name = "people.vcf", body = "BEGIN:VCARD\r\nEND:VCARD\r\n", type = "text/vcard"): SaveFile => ({ name, type, bytes: text(body) });
  const click = (label: string): void => {
    [...host.querySelectorAll("button")].find((button) => button.textContent === label)!.click();
  };
  beforeEach(() => { document.body.innerHTML = "<main></main>"; host = document.querySelector("main") as HTMLElement; saved = []; announced = []; });

  it("says who offers what, shows Save and Dismiss, and saves nothing until Save is clicked", () => {
    const offers = make(async (f) => { saved.push(f); return "started"; });
    expect(host.querySelector(".run-offer-region")?.getAttribute("role")).toBe("status");
    expect(host.querySelector("button")).toBeNull();
    expect(offers.offer(file())).toBe(true);
    expect(host.querySelector(".run-offer-text")?.textContent).toBe("Contacts offers a file to save: people.vcf (contact card (vCard), 24 bytes). Nothing is saved unless you choose Save.");
    expect([...host.querySelectorAll("button")].map((button) => button.textContent)).toEqual(["Save", "Dismiss"]);
    expect(saved).toEqual([]);
  });

  it("saves exactly the offered bytes once, then clears the offer and says so", async () => {
    const offers = make(async (f) => { saved.push(f); return "started"; });
    offers.offer(file("a.csv", "x,y\n1,2\n", "text/csv"));
    click("Save");
    click("Save");
    await vi.waitFor(() => expect(host.querySelector("button")).toBeNull());
    expect(saved.map((f) => [f.name, f.type, read(f)])).toEqual([["a.csv", "text/csv", "x,y\n1,2\n"]]);
    expect(host.querySelector(".run-offer-text")).toBeNull();
    expect(announced).toEqual(["Started the download of a.csv. Your browser decides where it goes."]);
    expect(offers.offer(file("b.txt", "b", "text/plain"))).toBe(true);
  });

  it("says Saved when the owner picked the place themselves", async () => {
    const offers = make(async () => "saved");
    offers.offer(file());
    click("Save");
    await vi.waitFor(() => expect(announced).toEqual(["Saved people.vcf."]));
  });

  it("refuses a second offer while one waits, and takes one again after Dismiss", () => {
    const offers = make(async (f) => { saved.push(f); return "started"; });
    expect(offers.offer(file("one.txt", "1", "text/plain"))).toBe(true);
    expect(offers.offer(file("two.txt", "2", "text/plain"))).toBe(false);
    expect(host.querySelector(".run-offer-text")?.textContent).toContain("one.txt");
    click("Dismiss");
    expect(host.querySelector("button")).toBeNull();
    expect(saved).toEqual([]);
    expect(offers.offer(file("two.txt", "2", "text/plain"))).toBe(true);
  });

  it("keeps the offer when the owner closes the save dialog, and when saving fails", async () => {
    let outcome: "cancelled" | "boom" = "cancelled";
    const offers = make(async () => { if (outcome === "boom") throw new Error("disk full"); return "cancelled"; });
    offers.offer(file());
    click("Save");
    await vi.waitFor(() => expect((host.querySelector("button") as HTMLButtonElement).disabled).toBe(false));
    expect(host.querySelector(".run-offer-text")).not.toBeNull();
    expect(announced).toEqual([]);
    outcome = "boom";
    click("Save");
    await vi.waitFor(() => expect(announced).toEqual(["Couldn't save people.vcf. Choose Save to try again or Dismiss."]));
    expect([...host.querySelectorAll("button")].every((button) => !button.disabled)).toBe(true);
  });

  it("drops the offer and its bytes when the app stops, even while a save is open", async () => {
    let finish: () => void = () => undefined;
    const offers = make(() => new Promise((resolve) => { finish = () => resolve("started"); }));
    offers.offer(file());
    click("Save");
    offers.clear();
    finish();
    await Promise.resolve();
    await Promise.resolve();
    expect(host.querySelector("button")).toBeNull();
    expect(announced).toEqual([]);
  });

  it("shows the app's file name as text, never as markup", () => {
    const offers = make(async () => "started");
    offers.offer(file("&lt;img src=x&gt; &amp;.txt", "x", "text/plain"));
    expect(host.querySelector("img")).toBeNull();
    expect(host.querySelector(".run-offer-text")?.textContent).toContain("&lt;img src=x&gt; &amp;.txt");
  });
});

describe("file.save on the bridge", () => {
  const replies: Array<{ id: string; result: CapResult }> = [];
  const noData = new Proxy({}, { get: () => async () => { throw new Error("data port must not be touched"); } }) as AppData;
  const manifest = sdkCore.validateManifest(JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")));
  let offered: SaveFile[];
  let counter = 0;
  const build = (accept = true, withPort = true) => {
    replies.length = 0;
    offered = [];
    const files = { offer: (f: SaveFile) => { if (accept) offered.push(f); return accept; } };
    return createCapabilityBridge({ appId: HEALTH, authorize: makeAuthorizer(manifest, sdk), data: noData, reply: (id, result) => { replies.push({ id, result }); }, ...(withPort ? { files } : {}) });
  };
  const call = async (bridge: ReturnType<typeof build>, args: unknown, type = "cap/file.save"): Promise<CapResult> => {
    const id = String((counter += 1));
    bridge.handle({ type, body: { id, args } });
    await vi.waitFor(() => { if (!replies.some((reply) => reply.id === id)) throw new Error("no reply"); });
    return replies.find((reply) => reply.id === id)!.result;
  };

  it("offers a valid file to the runner and answers ok, needing no grant and touching no data", async () => {
    const bridge = build();
    expect(await call(bridge, { name: "meals.csv", body: "a,b\n1,2\n" })).toEqual({ ok: true });
    expect(offered).toHaveLength(1);
    expect(offered[0]).toMatchObject({ name: "meals.csv", type: "text/csv" });
    expect(read(offered[0]!)).toBe("a,b\n1,2\n");
  });

  it("answers BUSY while the runner holds an earlier offer", async () => {
    const result = await call(build(false), { name: "meals.csv", body: "x" });
    expect(result).toMatchObject({ ok: false, error: { code: "BUSY" } });
  });

  it.each([
    [{ name: "../meals.csv", body: "x" }],
    [{ name: "page.html", body: "<script>1</script>" }],
    [{ name: "a.txt", type: "text/html", body: "x" }],
    [{ name: "a.txt", body: "" }],
    [{ name: "a.txt", body: 5 }],
    [{ name: "a.txt", body: "x", path: "/etc" }],
    [{ body: "x" }],
  ])("refuses %j with BAD_REQUEST and offers nothing", async (args) => {
    const bridge = build();
    expect(await call(bridge, args)).toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
    expect(offered).toEqual([]);
  });

  it("refuses a file larger than the bridge limit", async () => {
    const bridge = build();
    expect(await call(bridge, { name: "big.txt", body: new Uint8Array(1_000_001) })).toMatchObject({ ok: false, error: { code: "TOO_LARGE" } });
    expect(offered).toEqual([]);
  });

  it("takes a file just under the limit", async () => {
    const bridge = build();
    expect(await call(bridge, { name: "big.txt", body: new Uint8Array(999_000).fill(97) })).toEqual({ ok: true });
    expect(offered[0]!.bytes.byteLength).toBe(999_000);
  });

  it("answers NOT_CONNECTED once the session is over, and offers nothing after the app stops", async () => {
    replies.length = 0;
    offered = [];
    const files = { offer: (f: SaveFile) => { offered.push(f); return true; } };
    const bridge = createCapabilityBridge({ appId: HEALTH, authorize: makeAuthorizer(manifest, sdk), data: noData, reply: (id, result) => { replies.push({ id, result }); }, files, isLive: () => false });
    expect(await call(bridge, { name: "a.txt", body: "x" })).toMatchObject({ ok: false, error: { code: "NOT_CONNECTED" } });
    const stopped = build();
    const id = "9001";
    stopped.handle({ type: "cap/file.save", body: { id, args: { name: "a.txt", body: "x" } } });
    stopped.close();
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(offered).toEqual([]);
  });

  it("is an unknown call where the runner gave the bridge no place to show it", async () => {
    expect(await call(build(true, false), { name: "a.txt", body: "x" })).toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
  });
});

// ---- the whole runner page, with an app in its frame

const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
const moduleText = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
const frameManifest: JsxManifest = {
  version: 1,
  files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind", "tinycloud-app"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(moduleText(id)), bytes: moduleText(id).length, provides: id === "tinycloud-app" ? ["@tinycloud/app"] : id === "react" ? ["react", "react/jsx-runtime", "react/jsx-dev-runtime"] : id === "react-dom" ? ["react-dom", "react-dom/client"] : id === "runtime" ? ["@tc/runtime"] : ["@tailwindcss/browser"] }])),
};
const frameFetch = (async (url: string) => new Response(moduleText(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;
const bundleFile = (path: string): Uint8Array => new Uint8Array(readFileSync(join("public", entry.bundle.root, path)));
const nodeBuffer = (bytes: Uint8Array): ArrayBuffer => { const copy = Buffer.from(bytes); return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength) as ArrayBuffer; };

describe("the runner page when an app offers a file", () => {
  let root: HTMLElement;
  let ended = 0;
  const data = new Proxy({}, { get: () => async () => { throw new Error("data port must not be touched"); } }) as AppData;
  const ports = (): RunPorts => ({
    hasPersistedSession: async () => false,
    sdk: async () => sdkCore,
    prepare: async (candidate) => {
      const manifest = JSON.parse(readFileSync(join("public", candidate.bundle.root, candidate.manifest.path), "utf8")) as unknown;
      return { bundle: { files: [], manifest }, manifest: { ok: true, manifest } };
    },
    loadCatalogManifest: async (candidate) => ({ ok: true, manifest: JSON.parse(readFileSync(join("public", candidate.bundle.root, candidate.manifest.path), "utf8")) }),
    async signIn(candidate, _plan, hooks): Promise<RunSession> {
      hooks.approval(false);
      const runtime: RuntimeSession = { data, expiresAt: Date.now() + 3_600_000, end: async () => { ended += 1; }, detach: async () => undefined };
      return { files: storedFiles(candidate, undefined), authorize: async () => undefined, put: async () => "created" as const, runtime };
    },
  });
  const nonceOf = (iframe: HTMLIFrameElement): string => new URL(iframe.src).hash.slice(1);
  const fromFrame = (iframe: HTMLIFrameElement, message: Record<string, unknown>): void => {
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, nonce: nonceOf(iframe), ...message } }));
  };
  const button = (label: string): HTMLButtonElement | undefined => [...root.querySelectorAll("button")].find((node) => node.textContent === label);
  let saved: SaveFile[];

  async function run(): Promise<{ iframe: HTMLIFrameElement; results: () => Array<{ id: string; result: CapResult }> }> {
    mountRunner(root, { appId: HEALTH, ports: ports(), frame: { manifest: frameManifest, fetch: frameFetch }, saveFile: async (f) => { saved.push(f); return "started"; } });
    await vi.waitFor(() => expect(root.querySelector("iframe")).toBeTruthy());
    const iframe = root.querySelector("iframe") as HTMLIFrameElement;
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    fromFrame(iframe, { type: "bridge-ready" });
    fromFrame(iframe, { type: "ready" });
    post.mockClear();
    return { iframe, results: () => post.mock.calls.map(([message]) => message as { id: string; result: CapResult }) };
  }

  beforeEach(() => {
    saved = [];
    ended = 0;
    document.body.innerHTML = '<main><div id="runner"></div></main>';
    root = document.querySelector<HTMLElement>("#runner") as HTMLElement;
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:test", revokeObjectURL: () => undefined }));
    vi.stubGlobal("fetch", vi.fn(async (url: string) => ({ ok: true, arrayBuffer: async () => nodeBuffer(bundleFile(String(url).slice(entry.bundle.root.length))) })));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("shows the offer in the runner's bar, outside the frame, and saves only on the owner's click", async () => {
    const { iframe, results } = await run();
    fromFrame(iframe, { type: "cap/file.save", body: { id: "1", args: { name: "meals.csv", body: "a,b\n1,2\n" } } });
    await vi.waitFor(() => expect(results().map((message) => message.result)).toEqual([{ ok: true }]));
    const region = root.querySelector(".run-bar .run-offer-region");
    expect(region?.textContent).toBe("Health Log offers a file to save: meals.csv (spreadsheet text (CSV), 8 bytes). Nothing is saved unless you choose Save.");
    expect(root.querySelector("iframe")?.closest(".run-bar")).toBeNull();
    expect(saved).toEqual([]);
    // A second offer waits its turn: the app is told BUSY and the first stays.
    fromFrame(iframe, { type: "cap/file.save", body: { id: "2", args: { name: "again.txt", body: "x" } } });
    await vi.waitFor(() => expect(results()).toHaveLength(2));
    expect(results()[1]!.result).toMatchObject({ ok: false, error: { code: "BUSY" } });
    expect(region?.textContent).toContain("meals.csv");
    button("Save")!.click();
    await vi.waitFor(() => expect(saved).toHaveLength(1));
    expect(read(saved[0]!)).toBe("a,b\n1,2\n");
    await vi.waitFor(() => expect(root.querySelector(".run-bar .run-status")?.textContent).toBe("Started the download of meals.csv. Your browser decides where it goes."));
    expect(root.querySelector(".run-offer-text")).toBeNull();
  });

  it("drops a waiting offer when the owner signs out of the app", async () => {
    const { iframe, results } = await run();
    fromFrame(iframe, { type: "cap/file.save", body: { id: "1", args: { name: "meals.csv", body: "x" } } });
    await vi.waitFor(() => expect(results()).toHaveLength(1));
    expect(root.querySelector(".run-offer-text")).not.toBeNull();
    button("Sign out of this app")!.click();
    await vi.waitFor(() => expect(ended).toBe(1));
    expect(root.querySelector(".run-offer-text")).toBeNull();
    expect(button("Save")).toBeUndefined();
    expect(saved).toEqual([]);
  });

  it("lists, in 'What this app can do', that an app may offer a file and that nothing is saved without Save", async () => {
    await run();
    const list = [...root.querySelectorAll(".run-details")].find((node) => node.querySelector("summary")?.textContent === "What this app can do");
    expect(list?.textContent).toContain("It can offer you a file to save, such as an export. Nothing is saved unless you choose Save.");
  });
});
