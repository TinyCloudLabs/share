import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE } from "../src/apps/install-plan.ts";
import { RUNTIME_SESSION_MS } from "../src/apps/grants.ts";
import { RunError, type ReadSession, type RunHooks } from "../src/apps/run.ts";
import { MAX_STORED_BYTES, MAX_STORED_FILES, RUNNER_APP_ID, type ReaderFetch, createRunPorts, putCreateOnly, readSavedFiles, readerManifest, readerScope, runnerAppName } from "../src/apps/run-session.ts";
import { type RunnableApp, verifyStoredApp } from "../src/apps/stored-app.ts";
import { storedFiles } from "./stored-fixtures.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH)!;

interface SignInCall { options: Record<string, unknown>; guard: (wait: () => Promise<unknown>) => Promise<unknown>; fake: FakeSignIn }
interface FakeSignIn {
  tinycloud: { kvForSpace: () => unknown; sqlForSpace: () => unknown; signOut: ReturnType<typeof vi.fn> };
  session: { address: string; openkey: object };
  spaces: Record<string, string>;
  dispose: ReturnType<typeof vi.fn>;
}

const calls: SignInCall[] = [];
let kvFiles: Map<string, Uint8Array>;
let kvListResult: { ok: boolean; data?: { keys: string[]; truncated?: boolean }; error?: { code: string } };
let signInBehaviour: (call: number, options: Record<string, unknown>) => Promise<void> | void;
let spaces: Record<string, string>;

vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => ({ shareOrigin: "https://share.example" }) }));
vi.mock("../src/share/openkey-session.js", () => ({
  takeWalletApprovalFailure: () => undefined,
  signInWithManifest: async (options: Record<string, unknown>) => {
    const fake: FakeSignIn = {
      tinycloud: {
        kvForSpace: () => ({
          list: async () => kvListResult,
          createSignedReadUrl: async (key: string) => (kvFiles.has(key) ? { ok: true, data: { url: `https://node.example/signed/${encodeURIComponent(key)}` } } : { ok: false, error: { code: "KV_NOT_FOUND" } }),
        }),
        sqlForSpace: () => ({ db: () => ({}) }),
        signOut: vi.fn(async () => undefined),
      },
      session: { address: "0x0", openkey: {} },
      spaces,
      dispose: vi.fn(async () => undefined),
    };
    const guard = options["guardApproval"] as SignInCall["guard"];
    calls.push({ options, guard, fake });
    await signInBehaviour(calls.length, options);
    return fake;
  },
}));

const hooks: RunHooks = { approval: () => undefined };
const manifestJson = (): unknown => JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")) as unknown;

async function runnable(): Promise<RunnableApp> {
  const result = await verifyStoredApp(HEALTH, storedFiles(entry), { catalog: catalog.apps, loadCatalogManifest: async () => ({ ok: true, manifest: manifestJson() }), sdk: sdkCore });
  if (!result.ok) throw new Error(`fixture: ${result.failure.reason}`);
  return result.app;
}

function seedSaved(): void {
  kvFiles = new Map();
  const stored = storedFiles(entry);
  for (const [path, bytes] of stored.entries) kvFiles.set(`${HEALTH}/app/${path}`, bytes);
  kvListResult = { ok: true, data: { keys: [...kvFiles.keys()] } };
}

beforeEach(() => {
  calls.length = 0;
  spaces = { [INSTALL_SPACE]: "space-id" };
  signInBehaviour = () => undefined;
  seedSaved();
});

/** The node's signed read URLs, served from `kvFiles` (a test sets `fetchStatus` to make the node answer something else). */
let fetchStatus: number;
beforeEach(() => {
  fetchStatus = 200;
  vi.stubGlobal("fetch", async (url: string) => {
    const key = decodeURIComponent(String(url).slice("https://node.example/signed/".length));
    const value = kvFiles.get(key);
    return value === undefined || fetchStatus !== 200 ? new Response("no", { status: fetchStatus === 200 ? 404 : fetchStatus }) : new Response(value.slice().buffer);
  });
});
afterEach(() => { vi.unstubAllGlobals(); });

describe("reading the saved app (sign-in 1)", () => {
  it("asks the shared sign-in for a get and a list on the one app's folder, under the runner's identity, 15 minutes, with a label that is allowed", async () => {
    const read = await createRunPorts().readStored(entry, hooks);
    expect(calls).toHaveLength(1);
    const { options } = calls[0]!;
    expect(options["manifest"]).toEqual(readerManifest(HEALTH, entry.name));
    expect((options["manifest"] as { app_id: string }).app_id).toBe(RUNNER_APP_ID);
    expect(options["allowedActions"]).toEqual(readerScope(HEALTH).allowedActions);
    expect(options["allowedPathPrefixes"]).toEqual(readerScope(HEALTH).allowedPathPrefixes);
    expect(options["hostSpaces"]).toEqual([INSTALL_SPACE]);
    expect(options["expiry"]).toBe(INSTALL_EXPIRY_MS);
    expect(options["appName"]).toBe(runnerAppName("TinyCloud Share: open ", entry.name));
    expect([...read.files.entries.keys()].sort()).toEqual([...storedFiles(entry).entries.keys()].sort());
    expect(read.files.incomplete).toBe(false);
  });

  it("signs nothing more once it has signed in: a later signature request is refused", async () => {
    await createRunPorts().readStored(entry, hooks);
    const wait = vi.fn(async () => "signed");
    await expect(calls[0]!.guard(wait)).rejects.toThrow("runner-signing-closed");
    expect(wait).not.toHaveBeenCalled();
  });

  it("lets the approvals of the sign-in itself through, one at a time", async () => {
    let inside: Promise<unknown> | undefined;
    signInBehaviour = (_n, options) => { inside = (options["guardApproval"] as SignInCall["guard"])(async () => "signed"); };
    await createRunPorts().readStored(entry, hooks);
    await expect(inside).resolves.toBe("signed");
  });

  it("disposes the sign-in when the files cannot be read, and says it failed", async () => {
    kvListResult = { ok: false, error: { code: "KV_ERROR" } };
    await expect(createRunPorts().readStored(entry, hooks)).rejects.toMatchObject({ reason: "failed" });
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
    seedSaved();
    fetchStatus = 500;
    calls.length = 0;
    await expect(createRunPorts().readStored(entry, hooks)).rejects.toBeInstanceOf(RunError);
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("disposes the sign-in when the applications space is not hosted", async () => {
    spaces = {};
    await expect(createRunPorts().readStored(entry, hooks)).rejects.toMatchObject({ reason: "failed" });
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("ending the read session keeps OpenKey connected for the next sign-in, or closes everything", async () => {
    const keep = await createRunPorts().readStored(entry, hooks);
    await keep.end({ keepOpenKey: true });
    await keep.end({ keepOpenKey: true });
    expect(calls[0]!.fake.tinycloud.signOut).toHaveBeenCalledTimes(1);
    expect(calls[0]!.fake.dispose).not.toHaveBeenCalled();
    calls.length = 0;
    const close = await createRunPorts().readStored(entry, hooks);
    await close.end({ keepOpenKey: false });
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });
});

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

describe("starting the app (sign-in 2)", () => {
  async function started(): Promise<{ app: RunnableApp; read: ReadSession; runtime: Awaited<ReturnType<ReturnType<typeof createRunPorts>["openRuntime"]>> }> {
    const ports = createRunPorts();
    const app = await runnable();
    const read = await ports.readStored(entry, hooks);
    const runtime = await ports.openRuntime(app, read, hooks);
    return { app, read, runtime };
  }

  it("signs exactly the checked manifest, inside the catalog-derived scope, for one hour, on the reader's OpenKey connection", async () => {
    const { app, runtime } = await started();
    expect(calls).toHaveLength(2);
    const { options } = calls[1]!;
    expect(options["manifest"]).toBe(app.signing);
    expect(options["allowedActions"]).toEqual(app.scope.allowedActions);
    expect(options["allowedPathPrefixes"]).toEqual(app.scope.allowedPathPrefixes);
    expect(options["expiry"]).toBe(RUNTIME_SESSION_MS);
    expect(options["appName"]).toBe(runnerAppName("TinyCloud Share: ", entry.name));
    expect(options["session"]).toBe(calls[0]!.fake.session);
    // The reader's client was signed out first; OpenKey itself stays connected for this one.
    expect(calls[0]!.fake.tinycloud.signOut).toHaveBeenCalledTimes(1);
    expect(calls[0]!.fake.dispose).not.toHaveBeenCalled();
    expect(runtime.expiresAt).toBeGreaterThan(Date.now() + RUNTIME_SESSION_MS - 120_000);
    expect(runtime.expiresAt).toBeLessThan(Date.now() + RUNTIME_SESSION_MS);
  });

  it("refuses every signature request after the runtime sign-in: the page's substitute for a signer-less client", async () => {
    await started();
    const wait = vi.fn(async () => "signed");
    await expect(calls[1]!.guard(wait)).rejects.toThrow("runner-signing-closed");
    expect(wait).not.toHaveBeenCalled();
  });

  it("ending the runtime session disposes the app's session AND the reader's OpenKey connection, once", async () => {
    const { runtime } = await started();
    await runtime.end();
    await runtime.end();
    expect(calls[1]!.fake.dispose).toHaveBeenCalledTimes(1);
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("a failed runtime sign-in disposes the reader's OpenKey connection and reports the failure", async () => {
    const ports = createRunPorts();
    const app = await runnable();
    const read = await ports.readStored(entry, hooks);
    signInBehaviour = (call) => { if (call === 2) throw new Error("approval closed"); };
    await expect(ports.openRuntime(app, read, hooks)).rejects.toMatchObject({ reason: "failed" });
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
  });

  it("a missing applications space disposes both sign-ins", async () => {
    const ports = createRunPorts();
    const app = await runnable();
    const read = await ports.readStored(entry, hooks);
    spaces = {};
    await expect(ports.openRuntime(app, read, hooks)).rejects.toMatchObject({ reason: "failed" });
    expect(calls[1]!.fake.dispose).toHaveBeenCalledTimes(1);
    expect(calls[0]!.fake.dispose).toHaveBeenCalledTimes(1);
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

describe("read scope and create-only writes", () => {
  it("the read sign-in holds get, list and put on the app's folder, and put alone on its notes", () => {
    const permissions = readerManifest(HEALTH, entry.name).permissions ?? [];
    expect(permissions.map((permission) => ({ path: permission.path, actions: permission.actions }))).toEqual([
      { path: `${HEALTH}/app/`, actions: ["get", "list", "put"] },
      { path: `${HEALTH}/knowledge/`, actions: ["put"] },
    ]);
  });

  it("the read scope allows only those two folders in the applications space, with get, list and put", () => {
    expect(readerScope(HEALTH)).toEqual({
      allowedSpaces: [INSTALL_SPACE],
      allowedServices: ["kv"],
      allowedActions: ["get", "list", "put"],
      allowedPathPrefixes: [
        { space: INSTALL_SPACE, prefix: `${HEALTH}/app/` },
        { space: INSTALL_SPACE, prefix: `${HEALTH}/knowledge/` },
      ],
    });
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
