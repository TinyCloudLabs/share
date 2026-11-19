import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Manifest } from "@tinycloud/sdk-core";
import * as sdkCore from "@tinycloud/sdk-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { INSTALL_SPACE } from "../src/apps/install-plan.ts";
import { RUNTIME_SESSION_MS } from "../src/apps/grants.ts";
import { type PreparedApp, type RunPorts, openApp } from "../src/apps/run.ts";
import { createRunPorts } from "../src/apps/run-session.ts";
import { bundleBytes, storedFiles } from "./stored-fixtures.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const SIBLING = "xyz.tinycloud.sample.healthlog2";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH)!;
const appFiles = entry.bundle.files.filter((file) => !file.path.startsWith("knowledge/"));

interface SignInCall { options: Record<string, unknown>; guard: (wait: () => Promise<unknown>) => Promise<unknown>; fake: FakeSignIn }
interface FakeSignIn {
  tinycloud: { kvForSpace: () => unknown; sqlForSpace: () => unknown; signOut: ReturnType<typeof vi.fn> };
  session: { address: string; openkey: object };
  spaces: Record<string, string>;
  sessionExpiresAt: number;
  detach: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
}

const calls: SignInCall[] = [];
/** Every key the sign-in's kv writes were asked for, in order. */
const puts: string[] = [];
let kvFiles: Map<string, Uint8Array>;
/** When set, the listing answers this instead of the keys in `kvFiles`. */
let kvListResult: { ok: boolean; data?: { keys: string[]; truncated?: boolean }; error?: { code: string } } | undefined;
let signInBehaviour: (call: number, options: Record<string, unknown>) => Promise<void> | void;
let spaces: Record<string, string>;
/** The node's status for a signed read URL that has bytes (200 by default). */
let fetchStatus: number;

vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => ({ shareOrigin: "https://share.example" }) }));
vi.mock("../src/share/openkey-session.js", () => ({
  takeWalletApprovalFailure: () => undefined,
  signInWithManifest: async (options: Record<string, unknown>) => {
    const fake: FakeSignIn = {
      tinycloud: {
        kvForSpace: () => ({
          list: async () => kvListResult ?? { ok: true, data: { keys: [...kvFiles.keys()] } },
          put: async (key: string, value: Uint8Array, write: { ifNoneMatch?: string }) => {
            puts.push(key);
            if (write.ifNoneMatch === "*" && kvFiles.has(key)) return { ok: false, error: { code: "KV_PRECONDITION_FAILED" } };
            kvFiles.set(key, value);
            return { ok: true };
          },
          createSignedReadUrl: async (key: string) => (kvFiles.has(key) ? { ok: true, data: { url: `https://node.example/signed/${encodeURIComponent(key)}` } } : { ok: false, error: { code: "KV_NOT_FOUND" } }),
        }),
        sqlForSpace: () => ({ db: () => ({}) }),
        signOut: vi.fn(async () => undefined),
      },
      session: { address: "0x0", openkey: {} },
      spaces,
      sessionExpiresAt: Date.now() + RUNTIME_SESSION_MS,
      detach: vi.fn(async () => undefined),
      dispose: vi.fn(async () => undefined),
    };
    const guard = options["guardApproval"] as SignInCall["guard"];
    calls.push({ options, guard, fake });
    await signInBehaviour(calls.length, options);
    return fake;
  },
}));

const manifestJson = (): unknown => JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")) as unknown;
const catalogManifest = (): Manifest => sdkCore.validateManifest(manifestJson());

function seedSaved(): void {
  kvFiles = new Map();
  kvListResult = undefined;
  for (const [path, bytes] of storedFiles(entry, {}).entries) kvFiles.set(`${HEALTH}/app/${path}`, bytes);
}

/** The real ports, with the catalog bundle read from `public/` in place of the network. */
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
  spaces = { [INSTALL_SPACE]: "space-id" };
  signInBehaviour = () => undefined;
  fetchStatus = 200;
  seedSaved();
  vi.stubGlobal("fetch", async (url: string) => {
    const key = decodeURIComponent(String(url).slice("https://node.example/signed/".length));
    const value = kvFiles.get(key);
    return value === undefined || fetchStatus !== 200 ? new Response("no", { status: fetchStatus === 200 ? 404 : fetchStatus }) : new Response(value.slice().buffer);
  });
});
afterEach(() => { vi.unstubAllGlobals(); });

// TC-2285. A brand-new account's first open spends minutes in OpenKey's own login or sign-up window, which is a connect, not a
// signed revocation. The 60 s approval window belongs to a revocation signature; connecting waits as long as the OpenKey SDK itself does.
// TC-2416. The runner's own signatures (its first authorization) wait the same five minutes; revocation keeps 60 s (see openkey-session / sender-owner-revoke tests).
const SIXTY_SECONDS = 60_000;
const NINETY_SECONDS = 90_000;
const FIVE_MINUTES = 300_000;
const answersAfter = (ms: number): Promise<string> => new Promise((resolve) => { setTimeout(() => resolve("answered"), ms); });
/** The SDK and the sign-in helper load on demand, so the sign-in starts a little after the open does. */
const signInStarted = (): Promise<void> => vi.waitFor(() => { if (calls.length === 0) throw new Error("the sign-in has not started"); }, { timeout: 4_000, interval: 5 });
type Info = { kind: "connect" } | { kind: "sign" };
const guardOf = (options: Record<string, unknown>): ((wait: () => Promise<unknown>, info?: Info) => Promise<unknown>) => options["guardApproval"] as (wait: () => Promise<unknown>, info?: Info) => Promise<unknown>;

describe("the approval window a first sign-in waits for", () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] }); });
  afterEach(() => { vi.useRealTimers(); });

  it("lets OpenKey's connect take 90 s (a first login or sign-up) and the open succeeds", async () => {
    let connecting: Promise<unknown> | undefined;
    signInBehaviour = (_n, options) => { connecting = guardOf(options)(() => answersAfter(NINETY_SECONDS), { kind: "connect" }); return connecting.then(() => undefined); };
    const outcome = open().then((app) => ({ app }), (error: unknown) => ({ error }));
    await signInStarted();
    await vi.advanceTimersByTimeAsync(NINETY_SECONDS);
    const result = await outcome;
    if ("error" in result) throw result.error;
    await expect(connecting).resolves.toBe("answered");
  });

  it("still gives up on a connect that never answers, at the OpenKey SDK's own five minutes", async () => {
    signInBehaviour = (_n, options) => guardOf(options)(() => answersAfter(FIVE_MINUTES * 2), { kind: "connect" }).then(() => undefined);
    const outcome = open().then(() => "opened", (error: unknown) => error);
    await signInStarted();
    await vi.advanceTimersByTimeAsync(FIVE_MINUTES - 1_000);
    // Still waiting a second before the window ends (the sign-in began a few milliseconds into the clock).
    let settled = false;
    void outcome.then(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await outcome).toMatchObject({ reason: "timeout" });
  });

  it("lets an app-run signature take longer than 60 s (a first authorization) and the open succeeds", async () => {
    let signing: Promise<unknown> | undefined;
    signInBehaviour = (_n, options) => { signing = guardOf(options)(() => answersAfter(SIXTY_SECONDS + 1_000), { kind: "sign" }); return signing.then(() => undefined); };
    const outcome = open().then((app) => ({ app }), (error: unknown) => ({ error }));
    await signInStarted();
    await vi.advanceTimersByTimeAsync(SIXTY_SECONDS + 1_000);
    const result = await outcome;
    if ("error" in result) throw result.error;
    await expect(signing).resolves.toBe("answered");
  });

  it("treats a wait with no kind as a signature, with the same window", async () => {
    let signing: Promise<unknown> | undefined;
    signInBehaviour = (_n, options) => { signing = guardOf(options)(() => answersAfter(SIXTY_SECONDS + 1_000)); return signing.then(() => undefined); };
    const outcome = open().then((app) => ({ app }), (error: unknown) => ({ error }));
    await signInStarted();
    await vi.advanceTimersByTimeAsync(SIXTY_SECONDS + 1_000);
    const result = await outcome;
    if ("error" in result) throw result.error;
    await expect(signing).resolves.toBe("answered");
  });

  it("still gives up on an app-run signature that never answers, at five minutes", async () => {
    signInBehaviour = (_n, options) => guardOf(options)(() => answersAfter(FIVE_MINUTES * 2), { kind: "sign" }).then(() => undefined);
    const outcome = open().then(() => "opened", (error: unknown) => error);
    await signInStarted();
    await vi.advanceTimersByTimeAsync(FIVE_MINUTES - 1_000);
    let settled = false;
    void outcome.then(() => { settled = true; });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await outcome).toMatchObject({ reason: "timeout" });
  });
});
