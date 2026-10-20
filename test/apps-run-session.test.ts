import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE } from "../src/apps/install-plan.ts";
import { RUNTIME_SESSION_MS } from "../src/apps/grants.ts";
import { RunError, type ReadSession, type RunHooks } from "../src/apps/run.ts";
import { MAX_STORED_BYTES, MAX_STORED_FILES, RUNNER_APP_ID, createRunPorts, readSavedFiles, readerManifest, readerScope, runnerAppName } from "../src/apps/run-session.ts";
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
          get: async (key: string) => (kvFiles.has(key) ? { ok: true, data: { data: kvFiles.get(key) } } : { ok: false, error: { code: "KV_NOT_FOUND" } }),
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
    kvFiles.set(`${HEALTH}/app/app.jsx`, "not bytes" as unknown as Uint8Array);
    // A string is read as UTF-8 text; a value that is neither is refused.
    kvFiles.set(`${HEALTH}/app/schema.sql`, 5 as unknown as Uint8Array);
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
  const kvOver = (keys: string[], values: Record<string, Uint8Array>, truncated = false): Parameters<typeof readSavedFiles>[0] => ({
    list: async () => ({ ok: true, data: { keys, truncated } }),
    get: async (key) => (values[key] === undefined ? { ok: false, error: { code: "KV_NOT_FOUND" } } : { ok: true, data: { data: values[key] } }),
  });
  const prefix = "a/app/";

  it("keys files by their path under the prefix and ignores keys outside it", async () => {
    const result = await readSavedFiles(kvOver([`${prefix}x.jsx`, `${prefix}sub/y.sql`, "other/z", prefix], { [`${prefix}x.jsx`]: new Uint8Array([1]), [`${prefix}sub/y.sql`]: new Uint8Array([2]) }), prefix);
    expect([...result.entries.keys()]).toEqual(["x.jsx", "sub/y.sql"]);
    expect(result.incomplete).toBe(false);
  });

  it("is incomplete when the listing is truncated, has too many files, or too many bytes, or a listed file vanished", async () => {
    expect((await readSavedFiles(kvOver([`${prefix}x`], { [`${prefix}x`]: new Uint8Array(1) }, true), prefix)).incomplete).toBe(true);
    const many = Array.from({ length: MAX_STORED_FILES + 1 }, (_, index) => `${prefix}f${index}`);
    expect((await readSavedFiles(kvOver(many, Object.fromEntries(many.map((key) => [key, new Uint8Array(1)]))), prefix)).incomplete).toBe(true);
    const big = new Uint8Array(MAX_STORED_BYTES + 1);
    expect((await readSavedFiles(kvOver([`${prefix}big`], { [`${prefix}big`]: big }), prefix)).incomplete).toBe(true);
    expect((await readSavedFiles(kvOver([`${prefix}gone`], {}), prefix)).incomplete).toBe(true);
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
    expect(runnerAppName("TinyCloud Share: ", "Health Log (sample)")).toBe("TinyCloud Share: Health Log (sample)");
    expect(runnerAppName("TinyCloud Share: ", "evil.example/login")).toBe("TinyCloud Share: Tiny app");
    expect(runnerAppName("TinyCloud Share: ", "\u202eevil")).toBe("TinyCloud Share: Tiny app");
    expect([...runnerAppName("TinyCloud Share: open ", "x".repeat(200))].length).toBeLessThanOrEqual(64);
  });
});
