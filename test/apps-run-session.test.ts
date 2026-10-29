import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PortableDelegation } from "@tinycloud/web-sdk";
import type { Manifest } from "@tinycloud/sdk-core";
import type { ScopedPrefix } from "../src/share/manifest-policy.ts";
import * as sdkCore from "@tinycloud/sdk-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
type WebSdkModule = typeof import("@tinycloud/web-sdk");

import { catalog } from "../src/apps/catalog.ts";
import { RUNTIME_SESSION_MS, openManifest, openScope } from "../src/apps/grants.ts";
import { type PreparedApp, type RunPorts, installRecordPlan, openApp } from "../src/apps/run.ts";
import { MAX_STORED_BYTES, MAX_STORED_FILES, type ReaderFetch, createRunPorts, putCreateOnly, readSavedFiles, runnerAppName, runnerSessionPrefix } from "../src/apps/run-session.ts";
import { isSignInLabel } from "../src/share/sign-in-label.ts";
import { type StoredOverrides, bundleBytes, storedFiles } from "./stored-fixtures.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const SIBLING = "xyz.tinycloud.sample.healthlog2";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH)!;
const previousEntry = catalog.apps.find((candidate) => candidate.app_id === HEALTH && candidate.bundle.digest.startsWith("dc3ec19f"))!;
const appFiles = entry.bundle.files.filter((file) => !file.path.startsWith("knowledge/"));

interface SignInCall { options: Record<string, unknown>; guard: (wait: () => Promise<unknown>) => Promise<unknown>; fake: FakeSignIn }
interface FakeSignIn {
  tinycloud: {
    kvForSpace: () => unknown;
    space: (name: string) => { id: string; kv: unknown };
    sqlForSpace: () => unknown;
    signOut: ReturnType<typeof vi.fn>;
    hasPermissions: ReturnType<typeof vi.fn>;
    requestPermissions: ReturnType<typeof vi.fn>;
    getRuntimePermissionDelegations: ReturnType<typeof vi.fn>;
    useRuntimeDelegation: ReturnType<typeof vi.fn>;
    address: ReturnType<typeof vi.fn>;
  };
  session: { address: string; openkey: object };
  spaces: Record<string, string>;
  sessionExpiresAt: number;
  preparePermissionRequest: ReturnType<typeof vi.fn>;
  detach: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
}

const calls: SignInCall[] = [];
/** Every key the sign-in's kv writes were asked for, in order. */
const puts: string[] = [];
let kvFiles: Map<string, Uint8Array>;
/** When set, the listing answers this instead of the keys in `kvFiles`. */
let kvListResult: { ok: boolean; data?: { keys: string[]; truncated?: boolean }; error?: { code: string; message?: string; meta?: { status?: unknown } } } | undefined;
let signInBehaviour: (call: number, options: Record<string, unknown>) => Promise<void> | void;
/** The node's status for a signed read URL that has bytes (200 by default). */
let fetchStatus: number;
let savedSessionExists: boolean;
let savedGrantManifest: Manifest | undefined;
let stepUpPrompts: number;
let acceptStepUp: boolean;
const stepUpEvents: string[] = [];
const stepUpRequests: Array<Array<{ service: string; space: string; path: string; actions: string[] }>> = [];
const stepUpDelegation: PortableDelegation = {
  cid: "bafy-step-up",
  delegateDID: "did:key:z6Mkhp7CE4S8DUWvC6D5RXNNu3bA6PJyfd",
  spaceId: "applications",
  path: `${HEALTH}/settings/`,
  actions: ["tinycloud.kv/get", "tinycloud.kv/put"],
  expiry: new Date(Date.now() + RUNTIME_SESSION_MS),
  delegationHeader: { Authorization: "Bearer step-up" },
  ownerAddress: "0x0000000000000000000000000000000000000000",
  chainId: 1,
};

vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => ({ shareOrigin: "https://share.example" }) }));
vi.mock("@tinycloud/web-sdk", async () => {
  const actual = await vi.importActual<WebSdkModule>("@tinycloud/web-sdk");
  return {
    ...actual,
    BrowserSessionStorage: class {
      activeAddress(): string | undefined {
        return savedSessionExists ? "0x0" : undefined;
      }
    },
  };
});
vi.mock("../src/share/openkey-session.js", () => ({
  takeWalletApprovalFailure: () => undefined,
  signInWithManifest: async (options: Record<string, unknown>) => {
    const kv = {
      list: async () => kvListResult ?? { ok: true, data: { keys: [...kvFiles.keys()] } },
      put: async (key: string, value: Uint8Array, write: { ifNoneMatch?: string }) => {
        puts.push(key);
        if (write.ifNoneMatch === "*" && kvFiles.has(key)) return { ok: false, error: { code: "KV_PRECONDITION_FAILED" } };
        kvFiles.set(key, value);
        return { ok: true };
      },
      createSignedReadUrl: async (key: string) => (kvFiles.has(key) ? { ok: true, data: { url: `https://node.example/signed/${encodeURIComponent(key)}` } } : { ok: false, error: { code: "KV_NOT_FOUND" } }),
    };
    const runtimeGrants: PortableDelegation[] = [];
    const fake: FakeSignIn = {
      tinycloud: {
        kvForSpace: () => kv,
        space: (name) => ({ id: name, kv }),
        sqlForSpace: () => ({ db: () => ({}) }),
        signOut: vi.fn(async () => undefined),
        hasPermissions: vi.fn((permissions: Array<{ service: string; space: string; path: string; actions: string[] }>) => {
          const saved = savedGrantManifest === undefined ? [] : sdkCore.resolveManifest(savedGrantManifest).resources;
          const runtime = runtimeGrants.map((grant) => ({ service: "tinycloud.kv", space: grant.spaceId, path: grant.path, actions: grant.actions }));
          const grants = [...saved, ...runtime];
          return permissions.every((requested) => requested.actions.every((action) => grants.some((grant) =>
            grant.service === requested.service && grant.space === requested.space && grant.actions.includes(action) &&
            (grant.path === requested.path || (grant.path.endsWith("/") && requested.path.startsWith(grant.path))),
          )));
        }),
        requestPermissions: vi.fn(async (permissions: Array<{ service: string; space: string; path: string; actions: string[] }>) => {
          stepUpPrompts += 1;
          stepUpRequests.push(permissions.map((permission) => ({ ...permission, actions: [...permission.actions] })));
          stepUpEvents.push("dialog");
          const hooks = Reflect.get(fake.tinycloud, "_testHooks");
          const showModal = typeof hooks === "object" && hooks !== null ? Reflect.get(hooks, "showModal") : undefined;
          if (typeof showModal === "function") {
            const result = showModal({ appName: "Health Log", additional: permissions });
            if (acceptStepUp) document.querySelector<HTMLButtonElement>("[data-permission-allow]")?.click();
            else document.querySelector<HTMLButtonElement>("dialog button:not([data-permission-allow])")?.click();
            const decision = await result as { approved: boolean };
            if (!decision.approved) return { approved: false };
          }
          runtimeGrants.push(stepUpDelegation);
          return { approved: true, delegations: [stepUpDelegation] };
        }),
        address: vi.fn(() => "0x0000000000000000000000000000000000000000"),
        getRuntimePermissionDelegations: vi.fn(() => runtimeGrants),
        useRuntimeDelegation: vi.fn(async (delegation: PortableDelegation) => { runtimeGrants.push(delegation); }),
      },
      preparePermissionRequest: vi.fn(async () => { stepUpEvents.push("openkey"); }),
      session: { address: "0x0000000000000000000000000000000000000000", openkey: {} },
      spaces: {},
      sessionExpiresAt: Date.now() + RUNTIME_SESSION_MS,
      detach: vi.fn(async () => undefined),
      dispose: vi.fn(async () => undefined),
    };
    const guard = options["guardApproval"] as SignInCall["guard"];
    calls.push({ options, guard, fake });
    if (!savedSessionExists && options["manifest"] !== undefined) savedGrantManifest = sdkCore.validateManifest(options["manifest"]);
    await signInBehaviour(calls.length, options);
    if (options["persistSession"] === true) savedSessionExists = true;
    return fake;
  },
}));

const manifestJson = (): unknown => JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")) as unknown;
const catalogManifest = (): Manifest => sdkCore.validateManifest(manifestJson());
const manifestFor = (candidate: typeof entry): Manifest => sdkCore.validateManifest(JSON.parse(readFileSync(join("public", candidate.bundle.root, candidate.manifest.path), "utf8")));

function seedSaved(overrides: StoredOverrides = {}): void {
  kvFiles = new Map();
  kvListResult = undefined;
  for (const [path, bytes] of storedFiles(entry, overrides).entries) kvFiles.set(`${HEALTH}/app/${path}`, bytes);
}

/** The real ports, with the catalog bundle and saved install record served from memory. */
function ports(overrides: Partial<RunPorts> = {}): RunPorts {
  return {
    ...createRunPorts(),
    prepare: async (): Promise<PreparedApp> => ({
      bundle: { files: entry.bundle.files.map((file) => ({ ...file, bytes: bundleBytes(entry, file.path) })), manifest: manifestJson() },
      manifest: { ok: true, manifest: manifestJson() },
    }),
    ...overrides,
  };
}

const open = (run: RunPorts = ports(), signal?: AbortSignal) => openApp(HEALTH, run, () => undefined, signal);

beforeEach(() => {
  calls.length = 0;
  puts.length = 0;
  signInBehaviour = () => undefined;
  fetchStatus = 200;
  savedSessionExists = false;
  localStorage.clear();
  savedGrantManifest = undefined;
  stepUpPrompts = 0;
  acceptStepUp = true;
  stepUpRequests.length = 0;
  stepUpEvents.length = 0;
  seedSaved();
  vi.stubGlobal("fetch", async (url: string) => {
    const key = decodeURIComponent(String(url).slice("https://node.example/signed/".length));
    const value = kvFiles.get(key);
    return value === undefined || fetchStatus !== 200 ? new Response("no", { status: fetchStatus === 200 ? 404 : fetchStatus }) : new Response(value.slice().buffer);
  });
});
afterEach(() => { localStorage.clear(); vi.unstubAllGlobals(); });


describe("readSavedFiles: bounded, never silently cut", () => {
  const prefix = "a/app/";
  /** A node holding `values`; `streams` makes a value arrive as many chunks (never held whole), and every fetch and cancel is recorded. */
  function node(keys: string[], values: Record<string, Uint8Array | { chunks: number; chunkBytes: number }>, options: { truncated?: boolean; declared?: Record<string, string> } = {}): { kv: Parameters<typeof readSavedFiles>[0]; fetcher: ReaderFetch; fetched: string[]; inits: Array<{ credentials: string; redirect: string }>; pulled: Record<string, number>; cancelled: string[] } {
    const fetched: string[] = [];
    const cancelled: string[] = [];
    const pulled: Record<string, number> = {};
    const inits: Array<{ credentials: string; redirect: string }> = [];
    return {
      fetched,
      inits,
      cancelled,
      pulled,
      kv: {
        list: async () => ({ ok: true, data: { keys, truncated: options.truncated === true } }),
        createSignedReadUrl: async (key) => (key in values ? { ok: true, data: { url: key } } : { ok: false, error: { code: "KV_NOT_FOUND" } }),
      },
      fetcher: async (url, init) => {
        fetched.push(url);
        inits.push({ credentials: init.credentials, redirect: init.redirect });
        const value = values[url];
        if (value === undefined) return new Response("no", { status: 404 });
        if (value instanceof Uint8Array) return new Response(value.slice().buffer);
        let index = 0;
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) { if (index >= value.chunks) { controller.close(); return; } index += 1; pulled[url] = index; controller.enqueue(new Uint8Array(value.chunkBytes)); },
          cancel() { cancelled.push(url); },
        });
        return new Response(stream, { headers: options.declared?.[url] === undefined ? {} : { "content-length": options.declared[url]! } });
      },
    };
  }

  it("keys files by their path under the prefix and ignores keys outside it", async () => {
    const fake = node([`${prefix}x.jsx`, `${prefix}sub/y.sql`, "other/z", prefix], { [`${prefix}x.jsx`]: new Uint8Array([1]), [`${prefix}sub/y.sql`]: new Uint8Array([2, 3]) });
    const result = await readSavedFiles(fake.kv, prefix, fake.fetcher);
    expect([...result.entries.entries()].map(([path, bytes]) => [path, [...bytes]])).toEqual([["x.jsx", [1]], ["sub/y.sql", [2, 3]]]);
    expect(result.incomplete).toBe(false);
    expect(fake.fetched).toEqual([`${prefix}x.jsx`, `${prefix}sub/y.sql`]);
    // A signed URL is a bearer link: no cookies go with it and no redirect is followed to somewhere else.
    expect(fake.inits).toEqual([{ credentials: "omit", redirect: "error" }, { credentials: "omit", redirect: "error" }]);
  });

  it("is incomplete when the listing is truncated, has too many files, or a listed file vanished", async () => {
    const one = node([`${prefix}x`], { [`${prefix}x`]: new Uint8Array(1) }, { truncated: true });
    expect((await readSavedFiles(one.kv, prefix, one.fetcher)).incomplete).toBe(true);
    const many = Array.from({ length: MAX_STORED_FILES + 1 }, (_, index) => `${prefix}f${index}`);
    const lots = node(many, Object.fromEntries(many.map((key) => [key, new Uint8Array(1)])));
    expect((await readSavedFiles(lots.kv, prefix, lots.fetcher)).incomplete).toBe(true);
    const gone = node([`${prefix}gone`], {});
    expect((await readSavedFiles(gone.kv, prefix, gone.fetcher)).incomplete).toBe(true);
    const goneAfterUrl = node([`${prefix}late`], { [`${prefix}late`]: new Uint8Array(1) });
    goneAfterUrl.fetcher = async () => new Response("no", { status: 404 });
    expect((await readSavedFiles(goneAfterUrl.kv, prefix, goneAfterUrl.fetcher)).incomplete).toBe(true);
  });

  it("stops reading a huge file at the cap: the stream is cancelled after a few chunks, the rest of a 1 GB file is never pulled", async () => {
    const chunkBytes = 1024 * 1024;
    const gigabyte = { chunks: 1024, chunkBytes };
    const fake = node([`${prefix}a.jsx`, `${prefix}huge`, `${prefix}z.js`], { [`${prefix}a.jsx`]: new Uint8Array([1]), [`${prefix}huge`]: gigabyte, [`${prefix}z.js`]: new Uint8Array([3]) });
    const result = await readSavedFiles(fake.kv, prefix, fake.fetcher);
    expect(result.incomplete).toBe(true);
    expect(fake.cancelled).toEqual([`${prefix}huge`]);
    // The cap is 8 MB of 1 MB chunks: the stream was pulled a handful of times, nowhere near its 1024 chunks, and the next file was not fetched.
    expect(fake.pulled[`${prefix}huge`]!).toBeLessThanOrEqual(Math.ceil(MAX_STORED_BYTES / chunkBytes) + 2);
    expect(fake.fetched).toEqual([`${prefix}a.jsx`, `${prefix}huge`]);
  });

  it("refuses a file whose declared length would pass the cap without reading any of it", async () => {
    const fake = node([`${prefix}big`], { [`${prefix}big`]: { chunks: 4, chunkBytes: 4 } }, { declared: { [`${prefix}big`]: String(MAX_STORED_BYTES + 1) } });
    const result = await readSavedFiles(fake.kv, prefix, fake.fetcher);
    expect(result.incomplete).toBe(true);
    // A stream starts with one eager pull; a declared length over the cap is refused before anything is read from it.
    expect(fake.pulled[`${prefix}big`] ?? 0).toBeLessThanOrEqual(1);
  });

  it("files that fit one by one but not together stop at the file that crosses the cap, and the bytes counted are the bytes received", async () => {
    const half = Math.floor(MAX_STORED_BYTES / 2) + 1;
    const fake = node([`${prefix}p`, `${prefix}q`, `${prefix}r`], { [`${prefix}p`]: new Uint8Array(half), [`${prefix}q`]: new Uint8Array(half), [`${prefix}r`]: new Uint8Array(1) });
    const result = await readSavedFiles(fake.kv, prefix, fake.fetcher);
    expect(result.incomplete).toBe(true);
    expect([...result.entries.keys()]).toEqual(["p"]);
    expect(fake.fetched).toEqual([`${prefix}p`, `${prefix}q`]);
  });

  it("a download that fails or answers an error is a failure, not a smaller set", async () => {
    const failing = node([`${prefix}x`], { [`${prefix}x`]: new Uint8Array(1) });
    await expect(readSavedFiles(failing.kv, prefix, async () => { throw new TypeError("network down"); })).rejects.toMatchObject({ reason: "failed" });
    await expect(readSavedFiles(failing.kv, prefix, async () => new Response("boom", { status: 500 }))).rejects.toMatchObject({ reason: "failed" });
    const listFails: Parameters<typeof readSavedFiles>[0] = { list: async () => ({ ok: false, error: { code: "KV_ERROR" } }), createSignedReadUrl: async () => ({ ok: false, error: { code: "x" } }) };
    await expect(readSavedFiles(listFails, prefix, failing.fetcher)).rejects.toMatchObject({ reason: "failed" });
  });
});

describe("opening an installed app", () => {
  it("a repeat open signs in once, reads the saved copy, and writes no app file", async () => {
    const app = await open();
    expect(calls).toHaveLength(1);
    expect(puts.filter((key) => key.startsWith(`${HEALTH}/app/`))).toEqual([]);
    expect(app.session.expiresAt).toBeGreaterThan(Date.now());
  });

  it("a fresh install signs in once and saves every app file and the install record", async () => {
    kvFiles = new Map();
    await open();
    expect(calls).toHaveLength(1);
    for (const file of appFiles) expect(kvFiles.get(`${HEALTH}/app/${file.path}`)).toEqual(bundleBytes(entry, file.path));
    expect(kvFiles.has(`${HEALTH}/app/install.json`)).toBe(true);
  });

  it("a partial install resumes under the same single sign-in: only the missing record is written", async () => {
    seedSaved({ remove: ["install.json"] });
    const appJsx = kvFiles.get(`${HEALTH}/app/app.jsx`);
    await open();
    expect(calls).toHaveLength(1);
    expect(puts.filter((key) => key.startsWith(`${HEALTH}/app/`))).toEqual([`${HEALTH}/app/install.json`]);
    expect(kvFiles.get(`${HEALTH}/app/app.jsx`)).toBe(appJsx);
  });

  it("a file that appears after the listing is never overwritten: the open fails and the saved bytes stand", async () => {
    const junk = new Uint8Array([0]);
    kvFiles = new Map(appFiles.map((file) => [`${HEALTH}/app/${file.path}`, junk]));
    kvListResult = { ok: true, data: { keys: [] } };
    await expect(open()).rejects.toMatchObject({ reason: "failed" });
    expect(calls).toHaveLength(1);
    expect(puts).toHaveLength(1);
    expect([...kvFiles.values()].every((value) => value === junk)).toBe(true);
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("a kill-switched app is refused before any sign-in", async () => {
    const prepare = vi.fn(ports().prepare);
    await expect(open(ports({ catalog: [{ ...entry, disabled: true, disabledReason: "Paused for maintenance" }], prepare }))).rejects.toMatchObject({ reason: "unavailable" });
    expect(prepare).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("a failed download of the catalog copy is refused before any sign-in", async () => {
    await expect(open(ports({ prepare: async () => { throw new Error("offline"); } }))).rejects.toMatchObject({ reason: "failed" });
    expect(calls).toHaveLength(0);
  });

  it("cancelled before the sign-in: nothing is signed or written", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(open(ports(), controller.signal)).rejects.toMatchObject({ reason: "cancelled" });
    expect(calls).toHaveLength(0);
    expect(puts).toEqual([]);
  });

  it("cancelled while OpenKey is asking: the sign-in is ended and nothing is saved", async () => {
    seedSaved({ remove: ["install.json"] });
    const controller = new AbortController();
    signInBehaviour = () => { controller.abort(); };
    await expect(open(ports(), controller.signal)).rejects.toMatchObject({ reason: "cancelled" });
    expect(calls).toHaveLength(1);
    expect(puts).toEqual([]);
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("preserves the underlying error when OpenKey sign-in fails", async () => {
    signInBehaviour = () => { throw new Error("widget rejected the sign request"); };
    await expect(open()).rejects.toMatchObject({ reason: "failed", detail: "widget rejected the sign request" });
    expect(calls).toHaveLength(1);
    expect(puts).toEqual([]);
  });

  it("does not create spaces during a covered reopen", async () => {
    savedSessionExists = true;
    savedGrantManifest = openManifest(manifestFor(entry));
    await open();
    const { options } = calls[0]!;
    expect(options["hostSpaces"]).toBeUndefined();
    expect(options["autoCreateSpace"]).toBe(false);
    expect(options["includeAccountRegistryPermissions"]).toBe(false);
  });
  it("refuses a missing applications space without creating or hosting one", async () => {
    kvListResult = { ok: false, error: { code: "SPACE_NOT_FOUND", message: "404 - Space not found", meta: { status: 404 } } };

    await expect(open()).rejects.toMatchObject({ reason: "failed", detail: expect.stringContaining("SPACE_NOT_FOUND") });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.options["autoCreateSpace"]).toBe(false);
    expect(calls[0]!.options["includeAccountRegistryPermissions"]).toBe(false);
    expect(calls[0]!.options["hostSpaces"]).toBeUndefined();
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
    expect(puts).toEqual([]);
  });

  it("a listing that fails ends the sign-in and fails", async () => {
    kvListResult = { ok: false, error: { code: "KV_ERROR" } };
    await expect(open()).rejects.toMatchObject({ reason: "failed" });
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("a download that answers an error ends the sign-in and fails", async () => {
    fetchStatus = 500;
    await expect(open()).rejects.toMatchObject({ reason: "failed" });
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });
  it("passes app-scoped restore configuration and checks version grants on the returned client", async () => {
    kvFiles = new Map();
    const runPorts = ports();
    const first = await open(runPorts);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.options["persistSession"]).toBe(true);
    expect(calls[0]!.options["restoreBeforeOpenKey"]).toBe(true);
    expect(calls[0]!.options["sessionPrefix"]).toBe(await runnerSessionPrefix(HEALTH));
    expect(calls[0]!.fake.tinycloud.requestPermissions).not.toHaveBeenCalled();
    expect(calls[0]!.options["autoCreateSpace"]).toBe(false);
    await first.session.detach();

    await open(runPorts);
    expect(calls).toHaveLength(2);
    expect(calls[1]!.options["manifest"]).toEqual(installRecordPlan(entry).manifest);
    expect(calls[1]!.options["restoreBeforeOpenKey"]).toBe(true);
    expect(calls[1]!.options["autoCreateSpace"]).toBe(false);
    expect(calls[1]!.fake.tinycloud.requestPermissions).not.toHaveBeenCalled();
    expect(calls.slice(1).every((call) => call.options["sessionPrefix"] === calls[0]!.options["sessionPrefix"])).toBe(true);
  });
  it("requests only the uncovered version permission and restores its runtime grant on reopen", async () => {
    savedSessionExists = true;
    savedGrantManifest = openManifest(manifestFor(previousEntry));

    await open();

    const previous = sdkCore.resolveManifest(openManifest(manifestFor(previousEntry))).resources;
    const current = sdkCore.resolveManifest(openManifest(manifestFor(entry))).resources;
    const added = current.filter((resource) => resource.path.includes("settings/") && !previous.some((grant) =>
      grant.service === resource.service && grant.space === resource.space &&
      grant.path === resource.path && resource.actions.every((action) => grant.actions.includes(action)),
    )).map((resource) => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] }));
    expect(stepUpPrompts).toBe(1);
    expect(stepUpRequests).toEqual([added]);
    expect(stepUpEvents).toEqual(["dialog", "openkey"]);

    await open();

    expect(calls[1]!.fake.tinycloud.useRuntimeDelegation).toHaveBeenCalledTimes(1);
    expect(stepUpRequests).toEqual([added]);
    expect(stepUpPrompts).toBe(1);
    expect(stepUpEvents).toEqual(["dialog", "openkey"]);
  });
  it("does not open OpenKey or clear the saved session when added-permission approval is cancelled", async () => {
    savedSessionExists = true;
    savedGrantManifest = openManifest(manifestFor(previousEntry));
    acceptStepUp = false;

    await expect(open()).rejects.toMatchObject({ reason: "cancelled" });

    expect(stepUpEvents).toEqual(["dialog"]);
    expect(calls[0]!.fake.dispose).not.toHaveBeenCalled();
    expect(calls[0]!.fake.detach).toHaveBeenCalledTimes(1);
    expect(savedSessionExists).toBe(true);
  });

  it("the sign-in asks for exactly the union for this app, for one hour, under the reader's name", async () => {
    await open();
    const catalogManifest = sdkCore.validateManifest(manifestJson());
    const { options } = calls[0]!;
    expect(options["manifest"]).toEqual(openManifest(catalogManifest));
    expect(options["allowedActions"]).toEqual(openScope(catalogManifest, sdkCore).allowedActions);
    expect(options["allowedPathPrefixes"]).toEqual(openScope(catalogManifest, sdkCore).allowedPathPrefixes);
    expect(options["expiry"]).toBe(RUNTIME_SESSION_MS);
    expect(options["hostSpaces"]).toBeUndefined();
    expect(options["autoCreateSpace"]).toBe(false);
    expect(options["includeAccountRegistryPermissions"]).toBe(false);
    expect(options["appName"]).toBe(runnerAppName("TinyCloud Share: ", entry.name));
  });
  it("lets the approvals of the sign-in itself through, one at a time", async () => {
    let inside: Promise<unknown> | undefined;
    signInBehaviour = (_n, options) => { inside = (options["guardApproval"] as SignInCall["guard"])(async () => "signed"); };
    await open();
    await expect(inside).resolves.toBe("signed");
  });

  it("refuses every signature request once the sign-in is done", async () => {
    await open();
    const wait = vi.fn(async () => "signed");
    await expect(calls[0]!.guard(wait)).rejects.toThrow("runner-signing-closed");
    expect(wait).not.toHaveBeenCalled();
  });

  it("ending the app's session disposes OpenKey's connection once", async () => {
    const app = await open();
    await app.session.end();
    await app.session.end();
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });
  it("ends the app's runtime at the sign-in's own expiry, not a fresh hour from the open", async () => {
    const app = await open();
    expect(app.session.expiresAt).toBe(calls[0]!.fake.sessionExpiresAt - 60_000);
  });

  it("detaching for a page unload keeps the sign-in: OpenKey is closed without a sign-out", async () => {
    const app = await open();
    await app.session.detach();
    await app.session.detach();
    expect(calls[0]!.fake.detach).toHaveBeenCalledTimes(1);
    expect(calls[0]!.fake.dispose).not.toHaveBeenCalled();
    expect(calls[0]!.fake.tinycloud.signOut).not.toHaveBeenCalled();
  });

});

describe("runnerAppName", () => {
  it("uses the catalog's name when the sign-in accepts it as a label, and a fixed one when it does not", () => {
    expect(runnerAppName("TinyCloud Share: ", "Health Log")).toBe("TinyCloud Share: Health Log");
    expect(runnerAppName("TinyCloud Share: ", "evil.example/login")).toBe("TinyCloud Share: Tiny app");
    expect(runnerAppName("TinyCloud Share: ", "\u202eevil")).toBe("TinyCloud Share: Tiny app");
    expect([...runnerAppName("TinyCloud Share: open ", "x".repeat(200))].length).toBeLessThanOrEqual(64);
  });
});

describe("runnerSessionPrefix", () => {
  it("gives every app id its own label-valid storage prefix, so one app's saved session is never another's", async () => {
    const a = await runnerSessionPrefix(HEALTH);
    const b = await runnerSessionPrefix("xyz.tinycloud.sample.recipes");
    expect(isSignInLabel(a)).toBe(true);
    expect(a).not.toBe(b);
    expect(a.startsWith("tinycloud-share-runner-")).toBe(true);
    // Same app id always hashes to the same prefix: a reload must find the session it saved.
    expect(await runnerSessionPrefix(HEALTH)).toBe(a);
  });
});

describe("the one sign-in's request, per app id", () => {
  it("asks for get, list and create-only put on the app's folder, and create-only put on its notes, and nothing else under the app's id", () => {
    const manifest = openManifest(catalogManifest());
    const own = (manifest.permissions ?? []).filter((permission) => (permission.path ?? "").startsWith(`${HEALTH}/`));
    expect(own.map((permission) => ({ path: permission.path, actions: permission.actions }))).toEqual([
      { path: `${HEALTH}/app/`, actions: ["get", "list", "put"] },
      { path: `${HEALTH}/knowledge/`, actions: ["put"] },
    ]);
    expect(manifest.expiry).toBe("1h");
    expect(manifest.includePublicSpace).toBe(false);
  });

  const prefixOf = (entryPath: ScopedPrefix): string => (typeof entryPath === "string" ? entryPath : entryPath.prefix);

  it("a sibling app id gets only its own two folders in the request and in the upper bound", () => {
    const sibling = { ...catalogManifest(), app_id: SIBLING };
    const folders = (openManifest(sibling).permissions ?? []).map((permission) => permission.path ?? "").filter((path) => path.startsWith(`${SIBLING}/`));
    expect(folders).toEqual([`${SIBLING}/app/`, `${SIBLING}/knowledge/`]);
    const prefixes = (openScope(sibling, sdkCore).allowedPathPrefixes ?? []).map(prefixOf);
    expect([...new Set(prefixes.filter((prefix) => prefix === `${SIBLING}/app/` || prefix === `${SIBLING}/knowledge/`))]).toEqual([`${SIBLING}/app/`, `${SIBLING}/knowledge/`]);
    expect(prefixes).not.toContain(`${HEALTH}/app/`);
    // The fixture's own grants already cover the sibling's folders, so only "no prefix belongs to another id" pins the bound to the app id.
    expect(prefixes.filter((prefix) => !prefix.startsWith(`${SIBLING}/`))).toEqual([]);
  });

  it("the upper bound names the app's two folders and grants get, list and put", () => {
    const scope = openScope(catalogManifest(), sdkCore);
    const folders = [...new Set((scope.allowedPathPrefixes ?? []).map(prefixOf).filter((prefix) => prefix === `${HEALTH}/app/` || prefix === `${HEALTH}/knowledge/`))];
    expect(folders).toEqual([`${HEALTH}/app/`, `${HEALTH}/knowledge/`]);
    expect(scope.allowedActions).toEqual(expect.arrayContaining(["get", "list", "put"]));
  });
});

describe("putCreateOnly", () => {
  it("writes with ifNoneMatch '*', reports a created key as created and an existing key as exists", async () => {
    const put = vi.fn(async (_key: string, _value: Uint8Array, _options: unknown) => ({ ok: true as const }));
    await expect(putCreateOnly({ put }, "k", new Uint8Array([1]), "text/plain")).resolves.toBe("created");
    expect(put).toHaveBeenCalledWith("k", expect.any(Uint8Array), { contentType: "text/plain", ifNoneMatch: "*" });
    const taken = vi.fn(async (_key: string, _value: Uint8Array, _options: unknown) => ({ ok: false as const, error: { code: "KV_PRECONDITION_FAILED" } }));
    await expect(putCreateOnly({ put: taken }, "k", new Uint8Array(), "text/plain")).resolves.toBe("exists");
  });

  it("any other write error is a failed open, never a silent skip", async () => {
    const put = vi.fn(async (_key: string, _value: Uint8Array, _options: unknown) => ({ ok: false as const, error: { code: "KV_ERROR" } }));
    await expect(putCreateOnly({ put }, "k", new Uint8Array(), "text/plain")).rejects.toMatchObject({ reason: "failed" });
  });
});
