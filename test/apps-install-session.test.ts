// @vitest-environment jsdom
import { parseExpiry } from "@tinycloud/sdk-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { INSTALL_EXPIRY, INSTALL_EXPIRY_MS, INSTALL_SESSION_LABEL, APP_NAME_FALLBACK, installAppName, installerManifest, installerScope } from "../src/apps/install-plan.ts";
import { createInstallPorts } from "../src/apps/install-session.ts";
import { InstallError, type InstallSession } from "../src/apps/install.ts";
import { MANIFEST_CHECK_ADDRESS, assertManifestInScope } from "../src/share/manifest-policy.ts";
import { isSignInLabel } from "../src/share/sign-in-label.ts";
import { catalog } from "../src/apps/catalog.ts";
import { resetRevokeFlights } from "../src/share/revoke-flight.ts";

type KvResult = { ok: true } | { ok: false; error: { code: string } };
type ComposeFn = (manifests: unknown, options: unknown) => { resources: unknown[]; delegationTargets: unknown[] };

const state = vi.hoisted(() => ({
  signIn: vi.fn(),
  taken: undefined as undefined | (() => string | undefined),
  compose: undefined as undefined | ((...args: unknown[]) => unknown),
}));

// The shared sign-in is S6's and has its own tests; here it is a recorder, so what THIS module asks of it can be read.
vi.mock("../src/share/openkey-session.js", () => ({
  takeWalletApprovalFailure: () => state.taken?.(),
  signInWithManifest: (options: unknown) => state.signIn(options),
}));
vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz" }) }));
// The real SDK, except that a test can change what `composeManifestRequest` returns (a different SDK version).
vi.mock("@tinycloud/sdk-core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tinycloud/sdk-core")>();
  return { ...actual, composeManifestRequest: (...args: unknown[]) => (state.compose ?? actual.composeManifestRequest as (...a: unknown[]) => unknown)(...args) };
});

const APP = "xyz.tinycloud.sample.healthlog";
const manifest = installerManifest({ app_id: APP, name: "Health Log (sample)", description: "d" });
const hooks = { approval: vi.fn() };

/** A signed-in client whose key-value service answers like a node: a taken key is a precondition failure. */
function fakeClient(options: { taken?: readonly string[]; failWith?: string; listedAfter?: number; spaces?: Record<string, string> } = {}) {
  const taken = new Set(options.taken ?? []);
  const puts: { key: string; value: Uint8Array; options: Record<string, unknown> }[] = [];
  let reads = 0;
  const registered: unknown[] = [];
  const dispose = vi.fn(async () => undefined);
  const signedIn = {
    tinycloud: {
      kvForSpace: (spaceId: string) => ({
        put: async (key: string, value: Uint8Array, putOptions: Record<string, unknown>): Promise<KvResult> => {
          puts.push({ key, value, options: { ...putOptions, spaceId } });
          if (options.failWith !== undefined) return { ok: false, error: { code: options.failWith } };
          // Create-only is the CLIENT's request: without `ifNoneMatch` the node overwrites.
          if (putOptions.ifNoneMatch === "*" && taken.has(key)) return { ok: false, error: { code: "KV_PRECONDITION_FAILED" } };
          taken.add(key);
          return { ok: true };
        },
      }),
      account: {
        applications: {
          get: async () => { reads += 1; return { ok: options.listedAfter !== undefined && reads > options.listedAfter }; },
          register: async (installer: unknown) => { registered.push(installer); return { ok: true }; },
        },
      },
    },
    session: {},
    spaces: options.spaces ?? { applications: "space:applications", account: "space:account" },
    dispose,
  };
  return { signedIn, puts, dispose, registered, reads: () => reads };
}

async function openSession(client: ReturnType<typeof fakeClient>): Promise<InstallSession> {
  state.signIn.mockResolvedValue(client.signedIn);
  return createInstallPorts().openSession(manifest, hooks);
}

beforeEach(() => {
  resetRevokeFlights();
  state.signIn.mockReset();
  state.taken = undefined;
  state.compose = undefined;
  hooks.approval.mockReset();
});

describe("what the install port asks of the shared sign-in", () => {
  it("states the installer's scope, a short session, the hosted space and the registry wait, with a manifest that is inside the scope", async () => {
    const client = fakeClient();
    await openSession(client);
    expect(state.signIn).toHaveBeenCalledTimes(1);
    const options = state.signIn.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(options.expiry).toBe(INSTALL_EXPIRY_MS);
    expect(options).toMatchObject({ ...installerScope(APP), hostSpaces: ["applications"], waitForAccountRegistrySync: true, sessionPrefix: "tinycloud-share-install" });
    expect(options.manifest).toEqual(manifest);
    expect(() => assertManifestInScope(options.manifest as typeof manifest, installerScope(APP), MANIFEST_CHECK_ADDRESS)).not.toThrow();
    // Never a way around the scope.
    expect(options).not.toHaveProperty("unsafeAllowBroadManifest");
    expect(typeof options.guardApproval).toBe("function");
  });

  it("the session length, the manifest's expiry and the sheet's wording come from one constant", () => {
    expect(parseExpiry(INSTALL_EXPIRY)).toBe(INSTALL_EXPIRY_MS);
    expect(manifest.expiry).toBe(INSTALL_EXPIRY);
    expect(INSTALL_SESSION_LABEL).toBe(`${INSTALL_EXPIRY_MS / 60_000} minutes`);
    // An install only copies files: a long-lived installer session is a policy change, not a tweak.
    expect(INSTALL_EXPIRY_MS).toBeLessThanOrEqual(15 * 60 * 1000);
  });

  it("names the window for OpenKey within what the helper accepts, as display text only", () => {
    expect(installAppName("Health Log (sample)")).toBe("TinyCloud Share: install Health Log (sample)");
    // A long catalog name is cut to the helper's 64 characters and still accepted.
    const long = installAppName("Very long name ".repeat(20).trim());
    expect([...long].length).toBeLessThanOrEqual(64);
    expect(isSignInLabel(long)).toBe(true);
    // The catalog's name is used only if the helper would accept it as a name; otherwise a fixed one stands in.
    for (const bad of ["Node.js Notes", "Zero\u200bWidth", "see https://evil.example", "mail me@evil.example", "www.evil.example", "", "   ", "a\u202eb", "<b>x</b>\u200b"]) {
      const name = installAppName(bad);
      expect(name, JSON.stringify(bad)).toBe(`TinyCloud Share: install ${APP_NAME_FALLBACK}`);
      expect(isSignInLabel(name)).toBe(true);
    }
    expect(APP_NAME_FALLBACK).toBe("Tiny app");
    // Every name in the committed catalog works as it is.
    for (const app of catalog.apps) expect(isSignInLabel(installAppName(app.name)), app.name).toBe(true);
  });

  it.each([["Node.js Notes"], ["Zero\u200bWidth Notes"]])("a catalog name the helper would refuse (%j) falls back to the fixed name and the install still goes ahead", async (name) => {
    const client = fakeClient();
    state.signIn.mockResolvedValue(client.signedIn);
    await createInstallPorts().openSession(installerManifest({ app_id: APP, name, description: "d" }), hooks);
    expect(state.signIn).toHaveBeenCalledTimes(1);
    const options = state.signIn.mock.calls[0]?.[0] as { appName: string; manifest: { name: string } };
    expect(options.appName).toBe("TinyCloud Share: install Tiny app");
    expect(isSignInLabel(options.appName)).toBe(true);
    // The app is still identified by its id and manifest, not by the window's name.
    expect(options.manifest.name).toBe(name);
});
});

describe("create-only writes through the real port", () => {
  it("every put carries ifNoneMatch '*' and goes to the applications space the helper hosted", async () => {
    const client = fakeClient();
    const session = await openSession(client);
    for (const key of [`${APP}/app/app.jsx`, `${APP}/knowledge/index.md`, `${APP}/app/install.json`]) expect(await session.put(key, new Uint8Array([1]), "text/plain")).toBe("created");
    expect(client.puts.map((put) => put.key)).toEqual([`${APP}/app/app.jsx`, `${APP}/knowledge/index.md`, `${APP}/app/install.json`]);
    for (const put of client.puts) expect(put.options).toMatchObject({ ifNoneMatch: "*", spaceId: "space:applications" });
  });

  it("a taken key keeps the user's file (the node answers a precondition failure and the value is untouched)", async () => {
    const client = fakeClient({ taken: [`${APP}/knowledge/app.md`] });
    const session = await openSession(client);
    expect(await session.put(`${APP}/knowledge/app.md`, new Uint8Array([9]), "text/markdown")).toBe("exists");
    expect(await session.put(`${APP}/knowledge/other.md`, new Uint8Array([9]), "text/markdown")).toBe("created");
  });

  it("only a precondition failure means 'exists'; every other node error is a failed write", async () => {
    for (const code of ["KV_WRITE_FAILED", "AUTH_UNAUTHORIZED", "NETWORK_ERROR", "STORAGE_FULL", ""]) {
      const session = await openSession(fakeClient({ failWith: code }));
      await expect(session.put(`${APP}/app/app.jsx`, new Uint8Array([1]), "text/plain"), code).rejects.toThrow(`install-write-failed:${code}`);
    }
  });
});

describe("the sheet is the SDK's request, checked before OpenKey opens", () => {
  const real = async (): Promise<ComposeFn> => (await vi.importActual<typeof import("@tinycloud/sdk-core")>("@tinycloud/sdk-core")).composeManifestRequest as unknown as ComposeFn;
  const withCompose = async (change: (composed: ReturnType<ComposeFn>) => ReturnType<ComposeFn>): Promise<void> => {
    const compose = await real();
    state.compose = (manifests, options) => change(compose(manifests, options));
  };

  it("passes an unchanged request", async () => {
    await withCompose((composed) => composed);
    await openSession(fakeClient());
    expect(state.signIn).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["an extra capability", (composed: ReturnType<ComposeFn>) => ({ ...composed, resources: [...composed.resources, { service: "tinycloud.kv", space: "applications", path: "", actions: ["tinycloud.kv/del"] }] })],
    ["a wider action on a listed folder", (composed: ReturnType<ComposeFn>) => ({ ...composed, resources: composed.resources.map((resource) => ((resource as { path: string }).path === `${APP}/app/` ? { ...(resource as object), actions: ["tinycloud.kv/put", "tinycloud.kv/del"] } : resource)) })],
    ["a missing capability", (composed: ReturnType<ComposeFn>) => ({ ...composed, resources: composed.resources.slice(1) })],
    ["a delegation target", (composed: ReturnType<ComposeFn>) => ({ ...composed, delegationTargets: [{ did: "did:key:zExample", permissions: [] }] })],
  ])("stops before OpenKey opens for %s", async (_label, change) => {
    await withCompose(change);
    await expect(createInstallPorts().openSession(manifest, hooks)).rejects.toThrow(/install-request-/);
    expect(state.signIn).not.toHaveBeenCalled();
  });
});

describe("the session is disposed", () => {
  it("when the space was not hosted: the install fails and the session is closed", async () => {
    const client = fakeClient({ spaces: { account: "space:account" } });
    state.signIn.mockResolvedValue(client.signedIn);
    await expect(createInstallPorts().openSession(manifest, hooks)).rejects.toBeInstanceOf(InstallError);
    expect(client.dispose).toHaveBeenCalledTimes(1);
  });

  it("the port's dispose closes the helper's session (runInstall calls it on success, on a failed write and on a refusal)", async () => {
    const client = fakeClient();
    const session = await openSession(client);
    await session.dispose();
    expect(client.dispose).toHaveBeenCalledTimes(1);
  });

  it("a sign-in that rejects becomes a typed failure from what the approval said, and no session is left to use", async () => {
    // The helper hands out the client as soon as it exists, so a later failure can still be read from it.
    state.signIn.mockImplementation(async (options: { onClient: (client: object) => void }) => { options.onClient({}); throw new Error("[object Object]"); });
    state.taken = () => "cancelled";
    await expect(createInstallPorts().openSession(manifest, hooks)).rejects.toMatchObject({ name: "InstallError", reason: "cancelled" });
    state.taken = () => undefined;
    await expect(createInstallPorts().openSession(manifest, hooks)).rejects.toMatchObject({ reason: "failed" });
  });
});

describe("confirming the apps list", () => {
  it("reads once when the helper's sync already recorded the app, and registers nothing", async () => {
    const client = fakeClient({ listedAfter: 0 });
    const session = await openSession(client);
    expect(await session.confirmListed(manifest)).toBe(true);
    expect(client.reads()).toBe(1);
    expect(client.registered).toEqual([]);
  });

  it("registers once when the list lacks the app, then looks a bounded number of times and says false", async () => {
    vi.useFakeTimers();
    try {
      const client = fakeClient({ listedAfter: 1000 });
      const session = await openSession(client);
      const confirmed = session.confirmListed(manifest);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(await confirmed).toBe(false);
      expect(client.registered).toEqual([manifest]);
      expect(client.reads()).toBeLessThanOrEqual(7);
    } finally {
      vi.useRealTimers();
    }
  });
});
