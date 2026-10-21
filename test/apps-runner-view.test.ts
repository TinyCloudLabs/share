import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AppData } from "../src/apps/bridge.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { RunError, type ReadSession, type RunPorts, type RuntimeSession } from "../src/apps/run.ts";
import { CAUTION } from "../src/apps/limits.ts";
import { failureScreen, mountRunner, progressText, provenanceDetailText, provenanceText } from "../src/apps/run-view.ts";
import { RUNNER_APP_ID, readerManifest, readerScope } from "../src/apps/run-session.ts";
import { type StoredOverrides, storedFiles } from "./stored-fixtures.ts";
import { ManifestRejectedError, assertManifestInScope, MANIFEST_CHECK_ADDRESS } from "../src/share/manifest-policy.ts";
import { APPS_HREF } from "../src/apps/run-view.ts";
import type { JsxManifest } from "../src/artifact/jsx-runtime/files.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES_ID = "xyz.tinycloud.sample.recipes";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH) as CatalogEntry;
const bundleFile = (path: string): Uint8Array => new Uint8Array(readFileSync(join("public", entry.bundle.root, path)));
const nodeBuffer = (bytes: Uint8Array): ArrayBuffer => { const copy = Buffer.from(bytes); return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength) as ArrayBuffer; };

const sha = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");
const moduleText = (id: string): string => `__TC_DEFINE__(["${id}"],function(){});`;
const frameManifest: JsxManifest = {
  version: 1,
  files: Object.fromEntries(["react", "react-dom", "runtime", "tailwind", "tinycloud-app"].map((id) => [id, { id, url: `/assets/jsx-runtime/${id}.js`, sha256: sha(moduleText(id)), bytes: moduleText(id).length, provides: id === "tinycloud-app" ? ["@tinycloud/app"] : [id] }])),
};
const frameFetch = (async (url: string) => new Response(moduleText(/jsx-runtime\/(.+)\.js$/.exec(url)![1]!), { status: 200 })) as unknown as typeof fetch;

interface Fake {
  ports: RunPorts;
  reads: number;
  runtimes: number;
  ended: { read: boolean[]; runtime: number };
  calls: string[];
  release(): void;
}

function fakePorts(overrides: { stored?: StoredOverrides; readError?: RunError; runtimeError?: RunError; expiresIn?: number; hold?: boolean; catalog?: readonly CatalogEntry[] } = {}): Fake {
  const fake: Fake = { reads: 0, runtimes: 0, ended: { read: [], runtime: 0 }, calls: [], release: () => undefined, ports: undefined as unknown as RunPorts };
  const data: AppData = {
    kvGet: async (path) => { fake.calls.push(`kv.get ${path}`); return { ok: true, data: { bytes: new TextEncoder().encode("hi"), contentType: "text/plain" } }; },
    kvPut: async () => ({ ok: true, data: undefined }),
    kvList: async () => ({ ok: true, data: { keys: [], truncated: false } }),
    kvDelete: async () => ({ ok: true, data: undefined }),
    sqlQuery: async (db, text) => { fake.calls.push(`sql.query ${db} ${text}`); return { ok: true, data: { columns: ["n"], rows: [[1]], rowCount: 1 } }; },
    sqlExecute: async () => ({ ok: true, data: { changes: 1, lastInsertRowId: 1 } }),
  };
  const gate = new Promise<void>((resolve) => { fake.release = resolve; });
  fake.ports = {
    ...(overrides.catalog === undefined ? {} : { catalog: overrides.catalog }),
    sdk: async () => sdkCore,
    prepare: async (candidate) => {
      const manifest = JSON.parse(readFileSync(join("public", candidate.bundle.root, candidate.manifest.path), "utf8")) as unknown;
      return { bundle: { files: [], manifest }, manifest: { ok: true, manifest } };
    },
    async readStored(_entry, hooks): Promise<ReadSession> {
      fake.reads += 1;
      hooks.approval(true);
      if (overrides.hold === true) await gate;
      hooks.approval(false);
      if (overrides.readError !== undefined) throw overrides.readError;
      const files = storedFiles(entry, overrides.stored);
      return { files, put: async () => "created" as const, end: async ({ keepOpenKey }) => { fake.ended.read.push(keepOpenKey); } };
    },
    async openRuntime(): Promise<RuntimeSession> {
      fake.runtimes += 1;
      if (overrides.runtimeError !== undefined) throw overrides.runtimeError;
      return { data, expiresAt: Date.now() + (overrides.expiresIn ?? 3_600_000), end: async () => { fake.ended.runtime += 1; } };
    },
  };
  return fake;
}

let root: HTMLElement;
beforeEach(() => {
  document.body.innerHTML = '<main><div id="runner"></div></main>';
  root = document.querySelector<HTMLElement>("#runner") as HTMLElement;
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:test", revokeObjectURL: () => undefined }));
  vi.stubGlobal("fetch", vi.fn(async (url: string) => ({ ok: true, arrayBuffer: async () => nodeBuffer(bundleFile(String(url).slice(entry.bundle.root.length))) })));
});
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

const status = (): string => root.querySelector(".run-status-region")?.textContent ?? "";
const button = (label: string): HTMLButtonElement | undefined => [...root.querySelectorAll("button")].find((node) => node.textContent === label);
const frame = (): HTMLIFrameElement => root.querySelector("iframe") as HTMLIFrameElement;
const nonceOf = (iframe: HTMLIFrameElement): string => new URL(iframe.src).hash.slice(1);
const fromFrame = (iframe: HTMLIFrameElement, data: Record<string, unknown>): void => {
  window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { v: 1, nonce: nonceOf(iframe), ...data } }));
};

async function open(fake: Fake, id: string | null = HEALTH): Promise<ReturnType<typeof mountRunner>> {
  const runner = mountRunner(root, { appId: id, ports: fake.ports, frame: { manifest: frameManifest, fetch: frameFetch } });
  if (id === HEALTH) await vi.waitFor(() => { if (button("Continue") === undefined) throw new Error("start screen"); });
  return runner;
}

describe("the runner page before anything is signed", () => {
  it("says which app it is, where it came from and that it is sandboxed, outside the frame", async () => {
    const fake = fakePorts();
    await open(fake);
    expect(root.querySelector(".run-title")?.textContent).toBe("Health Log");
    const provenance = root.querySelector(".run-provenance")?.textContent ?? "";
    expect(provenance).toBe(provenanceText(entry));
    const whence = [...root.querySelectorAll<HTMLDetailsElement>(".run-bar details")].find((d) => d.querySelector("summary")?.textContent === "Where it comes from");
    const detail = whence?.querySelector("p")?.textContent ?? "";
    expect(detail).toBe(provenanceDetailText(entry));
    expect(detail).toContain(`${entry.source.commit.slice(0, 7)}`);
    expect(detail).toContain(entry.bundle.digest.slice(0, 12));
    expect(detail).toContain("It runs in a sandbox");
    expect(detail).not.toMatch(/no network/i);
    expect(root.querySelector(".run-bar .run-caution")).toBeNull();
    expect(root.querySelector("iframe")).toBeNull();
    expect([...root.querySelectorAll(".run-details")].find((d) => d.querySelector("summary")?.textContent === "What this app can do")?.textContent).toContain("What this app can do");
    expect(root.textContent).toContain("It can change");
    expect(root.textContent).toContain("This app can change or delete its own tables.");
    expect(root.textContent).not.toMatch(/Sample app|throwaway/i);
    expect(root.querySelector("a[href='/apps/']")?.textContent).toBe("Open another app");
    expect((button("Sign out of this app") as HTMLButtonElement).disabled).toBe(true);
    // Nothing was signed or read until Continue.
    expect(fake.reads).toBe(0);
  });

  it.each([null, "", "no/slash", "../x", "x y", "com.example.nothing", "<img src=x onerror=1>"])("an address of %j opens nothing and links to the apps page", async (id) => {
    const fake = fakePorts();
    mountRunner(root, { appId: id, ports: fake.ports });
    expect(root.querySelector(".run-screen__title")?.textContent).toBe("We don't know this app");
    expect(root.querySelector(`a[href='${APPS_HREF}']`)).not.toBeNull();
    expect(root.querySelector("button")?.textContent).toBe("Sign out of this app");
    expect(fake.reads).toBe(0);
    expect(root.querySelector("img, script")).toBeNull();
  });
});

describe("opening an app", () => {
  it("reads, verifies, starts and runs the person's copy in a frame, with the status in a live region", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"], shouldAdvanceTime: true });
    const fake = fakePorts({ hold: true });
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(status()).toContain("Approve in the OpenKey window (1 of 2)"));
    expect(root.querySelector(".run-status-region")?.getAttribute("role")).toBe("status");
    fake.release();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    expect(fake.ended.read).toEqual([]);
    expect(fake.runtimes).toBe(1);
    const iframe = frame();
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("title")).toBe("Health Log (installed app)");
    expect(iframe.className).toBe("run-frame");
    // The frame starts and reports ready.
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    fromFrame(iframe, { type: "bridge-ready" });
    const render = post.mock.calls[0]![0] as { source: string; modules: Record<string, string> };
    expect(render.source).toBe(new TextDecoder().decode(bundleFile("app.jsx")));
    expect(Object.keys(render.modules)).toContain("tinycloud-app");
    fromFrame(iframe, { type: "ready" });
    await vi.waitFor(() => expect(status()).toContain("Health Log is running"));
    expect((button("Sign out of this app") as HTMLButtonElement).disabled).toBe(false);
    // The permission lists now come from the person's own manifest.
    expect([...root.querySelectorAll(".run-details")].find((d) => d.querySelector("summary")?.textContent === "What this app can do")?.textContent).toContain("healthlog");
  });

  it("answers an app's cap/* request through the bridge, under the manifest, and refuses the rest", async () => {
    const fake = fakePorts();
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    const iframe = frame();
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    fromFrame(iframe, { type: "bridge-ready" });
    fromFrame(iframe, { type: "ready" });
    post.mockClear();
    fromFrame(iframe, { type: "cap/sql.query", body: { id: "1", args: { db: "healthlog", sql: "SELECT 1 AS n", params: [] } } });
    fromFrame(iframe, { type: "cap/kv.get", body: { id: "2", args: { key: "secrets/x" } } });
    fromFrame(iframe, { type: "cap/sql.query", body: { id: "3", args: { db: "healthlog", sql: "DROP TABLE meal", params: [] } } });
    await vi.waitFor(() => expect(post.mock.calls.length).toBe(3));
    const answers = post.mock.calls.map(([message]) => message as { type: string; id: string; nonce: string; result: { ok: boolean; error?: { code: string } } });
    expect(answers.every((message) => message.type === "cap/result" && message.nonce === nonceOf(iframe))).toBe(true);
    const byId = Object.fromEntries(answers.map((message) => [message.id, message.result]));
    expect(byId["1"]).toEqual({ ok: true, columns: ["n"], rows: [[1]], rowCount: 1 });
    expect(byId["2"]?.error?.code).toBe("PERMISSION_DENIED");
    expect(byId["3"]?.error?.code).toBe("BAD_REQUEST");
    expect(fake.calls).toEqual([`sql.query ${HEALTH}/healthlog SELECT 1 AS n`]);
  });

  it("a cap/* message from anything but its own frame is not answered", async () => {
    const fake = fakePorts();
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    const iframe = frame();
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    const body = { v: 1, type: "cap/sql.query", nonce: nonceOf(iframe), body: { id: "1", args: { db: "healthlog", sql: "SELECT 1", params: [] } } };
    window.dispatchEvent(new MessageEvent("message", { source: window, origin: "null", data: body }));
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "https://evil.example", data: body }));
    window.dispatchEvent(new MessageEvent("message", { source: iframe.contentWindow, origin: "null", data: { ...body, nonce: "0".repeat(32) } }));
    window.dispatchEvent(new MessageEvent("message", { source: null, origin: "null", data: body }));
    await Promise.resolve();
    expect(post).not.toHaveBeenCalled();
    expect(fake.calls).toEqual([]);
  });

  it("Sign out of this app removes the frame, ends the session and offers to open it again", async () => {
    const fake = fakePorts();
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    const iframe = frame();
    const post = vi.spyOn(iframe.contentWindow!, "postMessage");
    fromFrame(iframe, { type: "bridge-ready" });
    fromFrame(iframe, { type: "ready" });
    await vi.waitFor(() => expect(status()).toContain("is running"));
    button("Sign out of this app")!.click();
    expect(root.querySelector("iframe")).toBeNull();
    expect(fake.ended.runtime).toBe(1);
    expect(root.querySelector(".run-screen__title")?.textContent).toBe("Signed out of this app");
    expect((button("Sign out of this app") as HTMLButtonElement).disabled).toBe(true);
    // A call from the closed frame is not answered.
    post.mockClear();
    fromFrame(iframe, { type: "cap/kv.get", body: { id: "9", args: { key: "prefs/a" } } });
    expect(post).not.toHaveBeenCalled();
    expect(button("Open Health Log again")).toBeTruthy();
  });

  it("the session ends at its time: the frame goes away, calls are refused and the page says so", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"], shouldAdvanceTime: true });
    const fake = fakePorts({ expiresIn: 5_000 });
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    const iframe = frame();
    fromFrame(iframe, { type: "bridge-ready" });
    fromFrame(iframe, { type: "ready" });
    await vi.advanceTimersByTimeAsync(5_001);
    expect(root.querySelector("iframe")).toBeNull();
    expect(root.querySelector(".run-screen__title")?.textContent).toBe("Your session expired");
    expect(root.textContent).toContain("Your session expired: open the app again.");
    expect(fake.ended.runtime).toBe(1);
    expect(button("Open Health Log again")).toBeTruthy();
  });

  it("a page that stops after it started says so and keeps Sign out available", async () => {
    const fake = fakePorts();
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    const iframe = frame();
    fromFrame(iframe, { type: "bridge-ready" });
    fromFrame(iframe, { type: "ready" });
    await vi.waitFor(() => expect(status()).toContain("is running"));
    fromFrame(iframe, { type: "error", phase: "runtime", message: "boom" });
    await vi.waitFor(() => expect(status()).toContain("stopped"));
    expect((button("Sign out of this app") as HTMLButtonElement).disabled).toBe(false);
  });

  it("destroying the page (another app's address) ends the session and removes the frame", async () => {
    const fake = fakePorts();
    const runner = await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    runner.destroy();
    expect(root.querySelector("iframe")).toBeNull();
    expect(fake.ended.runtime).toBe(1);
  });

  it("destroying the page while the read approval is pending aborts the open: the read session is ended and no runtime session starts", async () => {
    const fake = fakePorts({ hold: true });
    const runner = await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(fake.reads).toBe(1));
    runner.destroy();
    fake.release();
    await vi.waitFor(() => expect(fake.ended.read).toEqual([false]));
    expect(fake.runtimes).toBe(0);
    expect(root.querySelector("iframe")).toBeNull();
  });
});

describe("opening an app that cannot run", () => {
  const stored = (manifest: unknown): Parameters<typeof fakePorts>[0] => ({ stored: { files: { "manifest.json": new TextEncoder().encode(JSON.stringify(manifest)) } } });
  interface TestManifest { name: string; permissions: { service: string; path: string; actions: string[] }[]; [key: string]: unknown }
  const original = (): TestManifest => JSON.parse(new TextDecoder().decode(bundleFile("manifest.json"))) as TestManifest;

  it("refuses a manifest that was widened, before anything more is signed, and says what differs", async () => {
    const manifest = original();
    manifest.permissions.push({ service: "tinycloud.kv", path: "photos/", actions: ["get", "put"] });
    const fake = fakePorts(stored(manifest));
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe("This app asks for more than it did when you installed it"));
    expect(root.querySelector(".run-screen")?.getAttribute("role")).toBe("alert");
    expect(root.querySelector(".run-screen__detail")?.textContent).toMatch(/^First difference: /);
    expect(fake.runtimes).toBe(0);
    expect(root.querySelector("iframe")).toBeNull();
    // Repair restores manifest.json from the catalog, so it is offered here too: to the same address, as the first action.
    const repair = [...root.querySelectorAll("a")].find((link) => link.textContent === "Repair");
    expect(repair?.getAttribute("href")).toBe(`${APPS_HREF}#repair=${encodeURIComponent(HEALTH)}`);
    expect(root.querySelector(".run-screen")?.textContent).toMatch(/Repair replaces the app's code files, manifest\.json included, with the catalog's\. Your data is untouched\./);
    expect(root.querySelector(".run-screen")?.textContent).not.toMatch(/Restore manifest\.json from the catalog/);
  });

  it("shows a hostile name from the saved manifest as text only", async () => {
    const hostile = "<img src=x onerror=\"window.__pwned=1\"><script>window.__pwned=1</script>";
    const manifest = original();
    manifest.name = hostile;
    const fake = fakePorts(stored(manifest));
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    expect(root.querySelector(".run-title")?.textContent).toBe(hostile.slice(0, 80));
    expect(root.querySelectorAll("img, script, svg")).toHaveLength(0);
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
  });

  it.each([
    ["cancelled", "Sign-in cancelled"],
    ["timeout", "OpenKey didn't answer in time"],
    ["busy", "Another OpenKey request is waiting"],
    ["wrong-account", "That approval came from a different account"],
    ["failed", "We couldn't open this app"],
  ] as const)("a %s sign-in leaves a plain screen with a way back and starts nothing", async (reason, title) => {
    const fake = fakePorts({ readError: new RunError(reason) });
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe(title));
    expect(button("Open Health Log again")).toBeTruthy();
    expect(root.querySelector("iframe")).toBeNull();
    expect(fake.runtimes).toBe(0);
  });

  it("a second-approval failure ends the read session too", async () => {
    const fake = fakePorts({ runtimeError: new RunError("cancelled") });
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe("Sign-in cancelled"));
    expect(fake.ended.read).toEqual([false]);
  });
});

describe("copy and the sign-in manifests", () => {
  it("every failure has a screen with a title and plain lines", () => {
    for (const reason of ["unknown-app", "damaged", "not-listed", "catalog-unavailable", "widened", "unsupported", "cancelled", "timeout", "busy", "wrong-account", "failed"] as const) {
      const screen = failureScreen(reason, "X");
      expect(screen.title.length).toBeGreaterThan(5);
      expect(screen.lines.join(" ")).not.toMatch(/undefined|\[object/);
    }
    expect(progressText({ phase: "starting", approval: true }, "X")).toContain("(2 of 2)");
  });

  it("the read sign-in asks for get, list and put under <app_id>/app/ and put under <app_id>/knowledge/, in the applications space, under the runner's own identity, inside its scope", () => {
    const manifest = readerManifest(HEALTH, "Health Log");
    expect(manifest.app_id).toBe(RUNNER_APP_ID);
    expect(manifest.app_id).not.toBe("xyz.tinycloud.share");
    expect(() => assertManifestInScope(sdkCore.validateManifest(manifest), readerScope(HEALTH), MANIFEST_CHECK_ADDRESS)).not.toThrow();
    // The helper would refuse the same manifest widened: another app's folder, a delete, the default tier.
    const widen = (change: Partial<sdkCore.Manifest>): unknown => { try { assertManifestInScope({ ...sdkCore.validateManifest(manifest), ...change }, readerScope(HEALTH), MANIFEST_CHECK_ADDRESS); return "accepted"; } catch (error) { return error instanceof ManifestRejectedError ? error.code : error; } };
    expect(widen({ permissions: [{ service: "tinycloud.kv", path: `${RECIPES_ID}/app/`, actions: ["get"], skipPrefix: true }] })).toBe("path-not-allowed");
    expect(widen({ permissions: [{ service: "tinycloud.kv", path: `${HEALTH}/app/`, actions: ["get", "delete"], skipPrefix: true }] })).toBe("action-not-allowed");
    expect(widen({ defaults: true })).not.toBe("accepted");
    const composed = sdkCore.composeManifestRequest([sdkCore.validateManifest(manifest)], { includeAccountRegistryPermissions: true });
    expect(composed.delegationTargets).toEqual([]);
    expect(composed.resources.filter((resource) => resource.service === "tinycloud.kv" && resource.space === "applications")).toEqual([
      expect.objectContaining({ path: `${HEALTH}/app/`, actions: ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"] }),
      expect.objectContaining({ path: `${HEALTH}/knowledge/`, actions: ["tinycloud.kv/put"] }),
    ]);
  });
});

describe("the pin, the kill switch, Repair and pagehide", () => {
  const tampered = (): Parameters<typeof fakePorts>[0] => ({ stored: { files: { "app.jsx": new TextEncoder().encode('fetch("https://x.example");') } } });

  it("a saved app.jsx that is not the pinned file opens nothing: no runtime session, no frame, Repair offered", async () => {
    const fake = fakePorts(tampered());
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe("This app's code doesn't match the pinned version"));
    expect(root.querySelector(".run-screen")?.textContent).toContain("Repair replaces the app's code files with the pinned version.");
    expect(root.querySelector(".run-screen")?.textContent).toContain("Your data is untouched.");
    expect(root.querySelector(".run-screen")?.getAttribute("role")).toBe("alert");
    expect(root.querySelector(".run-screen__detail")?.textContent).toBe("app.jsx differs from the pinned version");
    expect(root.querySelector(`a[href='/apps/#repair=${HEALTH}']`)?.textContent).toBe("Repair");
    expect(root.querySelector("iframe")).toBeNull();
    expect(fake.runtimes).toBe(0);
    expect(fake.ended.read).toEqual([false]);
  });

  it("an extra or missing code file does the same", async () => {
    for (const stored of [{ files: { "extra.js": new TextEncoder().encode("1") } }, { remove: ["schema.sql"] }] as const) {
      const fake = fakePorts({ stored });
      document.body.innerHTML = '<main><div id="runner"></div></main>';
      root = document.querySelector<HTMLElement>("#runner") as HTMLElement;
      await open(fake);
      button("Continue")!.click();
      await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe("This app's code doesn't match the pinned version"));
      expect(fake.runtimes).toBe(0);
    }
  });

  it("an installed version that has left the catalog gets the honest message and an Uninstall link, not a Repair", async () => {
    const other = { ...entry, bundle: { ...entry.bundle, digest: "f".repeat(64) } };
    const fake = fakePorts({ catalog: [entry] });
    // The install recorded a digest the catalog no longer lists.
    const original = fake.ports.readStored;
    fake.ports.readStored = async (candidate, hooks) => {
      const session = await original(candidate, hooks);
      const files = { entries: new Map(session.files.entries) };
      files.entries.set("install.json", new TextEncoder().encode(JSON.stringify({ source: entry.source, digest: other.bundle.digest, installed_at: "2026-10-20T10:00:00.000Z" })));
      return { files, put: session.put, end: session.end };
    };
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe("This version of the app isn't in the catalog any more"));
    expect(root.querySelector("a[href*='repair']")).toBeNull();
    const uninstall = root.querySelector<HTMLAnchorElement>(`a[href='/apps/#uninstall=${encodeURIComponent(HEALTH)}']`);
    expect(uninstall?.textContent).toBe("Uninstall");
    expect(root.querySelector(".run-screen")?.textContent ?? "").not.toContain("tinycloud kv");
    expect(fake.runtimes).toBe(0);
  });

  it("a disabled catalog entry opens nothing and calls nothing: the kill switch", async () => {
    const off = { ...entry, disabled: true as const, disabledReason: "A problem was found in this app." };
    const fake = fakePorts({ catalog: [off] });
    mountRunner(root, { appId: HEALTH, ports: fake.ports });
    await vi.waitFor(() => expect(root.querySelector(".run-screen__title")?.textContent).toBe("This app is temporarily unavailable"));
    expect(root.querySelector(".run-screen")?.textContent).toContain("A problem was found in this app.");
    expect(button("Continue")).toBeUndefined();
    expect(fake.reads).toBe(0);
    expect(fake.runtimes).toBe(0);
  });

  it("a disabled entry is refused by the flow itself before the SDK loads or any sign-in", async () => {
    const off = { ...entry, disabled: true as const, disabledReason: "Off." };
    const fake = fakePorts({ catalog: [off] });
    const sdk = vi.spyOn(fake.ports, "sdk");
    const { openApp } = await import("../src/apps/run.ts");
    await expect(openApp(HEALTH, fake.ports, () => undefined)).rejects.toMatchObject({ reason: "unavailable", detail: "Off." });
    expect(sdk).not.toHaveBeenCalled();
    expect(fake.reads).toBe(0);
  });

  it("pagehide ends the session, removes the frame, and a restored page says so", async () => {
    const fake = fakePorts();
    await open(fake);
    button("Continue")!.click();
    await vi.waitFor(() => expect(frame()).toBeTruthy());
    fromFrame(frame(), { type: "bridge-ready" });
    fromFrame(frame(), { type: "ready" });
    await vi.waitFor(() => expect(status()).toContain("is running"));
    window.dispatchEvent(new Event("pagehide"));
    expect(root.querySelector("iframe")).toBeNull();
    expect(fake.ended.runtime).toBe(1);
    expect(root.querySelector(".run-screen__title")?.textContent).toBe("Signed out of this app");
  });

  it("the page does not claim there is no network access, and says what to do", async () => {
    const fake = fakePorts();
    await open(fake);
    expect(root.textContent).not.toMatch(/no network|can't send your data/i);
    expect(root.textContent).toContain(CAUTION);
    expect(root.textContent).toContain("Known limits:");
  });
});
