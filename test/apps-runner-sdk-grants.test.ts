// @vitest-environment node
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import * as sdkCore from "@tinycloud/sdk-core";
import { BrowserSessionStorage, TinyCloudWeb, type PermissionEntry, type PortableDelegation } from "@tinycloud/web-sdk";
import { NodeWasmBindings } from "@tinycloud/node-sdk";
import { catalog } from "../src/apps/catalog.ts";
import { openManifest, openScope } from "../src/apps/grants.ts";
import { INSTALL_SPACE } from "../src/apps/install-plan.ts";
import type { RunHooks, SignInPlan } from "../src/apps/run.ts";
import { createRunPorts, runnerSessionPrefix } from "../src/apps/run-session.ts";

const OWNER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const HEALTH = "xyz.tinycloud.sample.healthlog";
const entryV1 = catalog.apps.find((candidate) => candidate.app_id === HEALTH && candidate.bundle.digest.startsWith("dc3ec19f"))!;
const entryV2 = catalog.apps.find((candidate) => candidate.app_id === HEALTH && candidate.bundle.digest !== entryV1.bundle.digest)!;

const testState = vi.hoisted(() => ({
  nodeOrigin: "",
  modalPrompts: 0,
  signCalls: 0,
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({
    version: "tinycloud.share/config-v2",
    shareOrigin: "https://share.tinycloud.xyz",
    senderBootstrapNodeOrigin: testState.nodeOrigin,
    registryOrigin: `${testState.nodeOrigin}/registry`,
    credentialsOrigin: `${testState.nodeOrigin}/credentials`,
    accountlessReceiverEnabled: false,
  }),
}));

vi.mock("@openkey/sdk", () => {
  const decodeHex = (hex: string): string => {
    const digits = hex.startsWith("0x") ? hex.slice(2) : hex;
    return Buffer.from(digits, "hex").toString("utf8");
  };
  return {
    OpenKey: class {
      disconnect(): void {}
      async connect() {
        return { address: OWNER.address, keyId: "key-1", keyType: "MANAGED" };
      }
      async signMessage(input: { message: string }) {
        testState.signCalls += 1;
        return { address: OWNER.address, signature: await OWNER.signMessage({ message: input.message }) };
      }
    },
    OpenKeyProvider: class {
      async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
        if (args.method === "eth_accounts" || args.method === "eth_requestAccounts") return [OWNER.address];
        if (args.method === "eth_chainId") return "0x1";
        if (args.method === "personal_sign") {
          testState.signCalls += 1;
          const raw = String(args.params?.[0] ?? "");
          const message = raw.startsWith("0x") ? decodeHex(raw) : raw;
          return OWNER.signMessage({ message });
        }
        throw new Error(`unexpected provider method: ${args.method}`);
      }
    },
  };
});

vi.mock("../src/apps/permission-dialog.ts", () => ({
  showRuntimePermissionDialog: async () => {
    testState.modalPrompts += 1;
    return { approved: true };
  },
}));

function makeMemoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() { return map.size; },
    clear() { map.clear(); },
    getItem(key: string) { return map.get(key) ?? null; },
    key(index: number) { return [...map.keys()][index] ?? null; },
    removeItem(key: string) { map.delete(key); },
    setItem(key: string, value: string) { map.set(key, value); },
  };
}

/** Minimal sign-in plan covering only reading the stored app bundle, not the app's runtime kv/sql data grants. */
function bundleReadPlan(entry: typeof entryV1): SignInPlan {
  const appPrefix = `${entry.app_id}/app/`;
  return {
    manifest: {
      manifest_version: 1,
      app_id: entry.app_id,
      name: entry.name,
      space: INSTALL_SPACE,
      prefix: "",
      defaults: false,
      includePublicSpace: false,
      permissions: [{ service: "tinycloud.kv", space: INSTALL_SPACE, path: appPrefix, actions: ["get", "list"], skipPrefix: true }],
    },
    scope: {
      allowedSpaces: [INSTALL_SPACE],
      allowedServices: ["kv"],
      allowedActions: ["get", "list"],
      allowedPathPrefixes: [{ space: INSTALL_SPACE, prefix: appPrefix }],
    },
  };
}

function appOpenPlan(entry: typeof entryV1): SignInPlan {
  const raw = JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")) as unknown;
  const manifest = sdkCore.validateManifest(raw);
  return {
    manifest: openManifest(manifest),
    scope: openScope(manifest, sdkCore),
  };
}

function runtimeKvSqlPermissionsOf(manifest: sdkCore.Manifest, appId: string): PermissionEntry[] {
  const appPrefix = `${appId}/app/`;
  return sdkCore.resolveManifest(manifest).resources
    .filter((resource) =>
      resource.space === INSTALL_SPACE
      && (resource.service === "tinycloud.kv" || resource.service === "tinycloud.sql")
      && !resource.path.startsWith(appPrefix),
    )
    .map((resource) => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] }));
}

const hooks: RunHooks = { approval: () => undefined };

describe("apps runner disables Web SDK grant keeping so updated bundles never inherit old kv/sql grants", () => {
  let server: Server;
  let storage: Storage;
  const createdClients: TinyCloudWeb[] = [];
  let restoreSpy: { mockRestore(): void } | undefined;

  beforeEach(async () => {
    testState.modalPrompts = 0;
    testState.signCalls = 0;
    createdClients.length = 0;
    storage = makeMemoryStorage();
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true });
    Object.defineProperty(globalThis, "window", { value: { location: { origin: "https://share.tinycloud.xyz", host: "share.tinycloud.xyz" }, localStorage: storage, crypto: globalThis.crypto }, configurable: true });

    const protocol = new NodeWasmBindings().protocolVersion();
    server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      request.resume();
      if (url.pathname === "/info") {
        response.setHeader("content-type", "application/json").end(JSON.stringify({
          protocol,
          version: "0.0.0-test",
          nodeId: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
          features: [],
        }));
        return;
      }
      if (url.pathname.startsWith("/registry/")) {
        response.statusCode = 404;
        response.setHeader("content-type", "application/json").end('{"error":"location record not found"}');
        return;
      }
      if (request.method === "POST" && (url.pathname === "/delegate" || url.pathname.endsWith("/delegate"))) {
        response.setHeader("content-type", "application/json").end(JSON.stringify({ cid: "bafy-test", activated: [], skipped: [] }));
        return;
      }
      if (url.pathname === "/invoke" || url.pathname.endsWith("/invoke")) {
        response.setHeader("content-type", "application/json").end(JSON.stringify([]));
        return;
      }
      response.setHeader("content-type", "application/json").end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    testState.nodeOrigin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    // Track every real TinyCloudWeb instance created by the runner (restoreBeforeOpenKey always calls restoreSession).
    const origRestore = TinyCloudWeb.prototype.restoreSession;
    restoreSpy = vi.spyOn(TinyCloudWeb.prototype, "restoreSession").mockImplementation(function (this: TinyCloudWeb, ...args) {
      if (!createdClients.includes(this)) createdClients.push(this);
      return origRestore.apply(this, args);
    });
  });

  afterEach(async () => {
    restoreSpy?.mockRestore();
    restoreSpy = undefined;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("does not inherit kv/sql grants after reload when the app has a different bundle digest, and asks again", async () => {
    const ports = createRunPorts();
    const sessionPrefix = await runnerSessionPrefix(entryV1.app_id);
    const planV1 = appOpenPlan(entryV1);
    const planV2 = appOpenPlan(entryV2);
    const kvSqlV1 = runtimeKvSqlPermissionsOf(planV1.manifest, entryV1.app_id);
    const kvSqlV2 = runtimeKvSqlPermissionsOf(planV2.manifest, entryV2.app_id);
    expect(kvSqlV2.some((entry) => entry.service === "tinycloud.kv")).toBe(true);
    expect(kvSqlV2.some((entry) => entry.service === "tinycloud.sql")).toBe(true);

    // 1. First open: grant kv/sql for V1 via the real runner + real TinyCloudWeb.
    const first = await ports.signIn(entryV1, bundleReadPlan(entryV1), hooks);
    await first.authorize(entryV1, planV1, sdkCore);
    expect(testState.modalPrompts).toBe(1);
    expect(createdClients).toHaveLength(1);
    const firstClient = createdClients[0]!;
    expect(firstClient.hasPermissions(kvSqlV1)).toBe(true);

    // The SDK's own kept-grants store must be empty immediately after requestPermissions.
    const sdkStore = new BrowserSessionStorage({ keyPrefix: sessionPrefix });
    expect(await sdkStore.loadRuntimeGrants(OWNER.address)).toEqual([]);

    await first.runtime.detach();

    // 2. Reload (new TinyCloudWeb on the same localStorage) with a DIFFERENT bundle digest (V2).
    const reloaded = await ports.signIn(entryV2, bundleReadPlan(entryV2), hooks);
    expect(createdClients).toHaveLength(2);
    const reloadedClient = createdClients[1]!;
    expect(reloadedClient).not.toBe(firstClient);
    expect(reloadedClient.sessionRestoreStatus).toBe("restored");

    // Wait for any SDK restored-grants background work; kv/sql must NOT be held.
    await reloadedClient.permissionsReady();
    expect(reloadedClient.hasPermissions(kvSqlV2)).toBe(false);

    // Runner must ask again for V2 (different digest).
    await reloaded.authorize(entryV2, planV2, sdkCore);
    expect(testState.modalPrompts).toBe(2);
    expect(reloadedClient.hasPermissions(kvSqlV2)).toBe(true);
    expect(await sdkStore.loadRuntimeGrants(OWNER.address)).toEqual([]);
  }, 30_000);

  it("clears pre-existing SDK-kept grants before restore on load so a new digest still asks again", async () => {
    const ports = createRunPorts();
    const sessionPrefix = await runnerSessionPrefix(entryV1.app_id);
    const planV1 = appOpenPlan(entryV1);
    const planV2 = appOpenPlan(entryV2);
    const kvSqlV1 = runtimeKvSqlPermissionsOf(planV1.manifest, entryV1.app_id);
    const kvSqlV2 = runtimeKvSqlPermissionsOf(planV2.manifest, entryV2.app_id);

    // 1. Grant V1 via runner, capture its real signed delegations, then simulate a pre-fix/crashed
    //    tab having left those delegations inside the SDK's own BrowserSessionStorage grants entry.
    const first = await ports.signIn(entryV1, bundleReadPlan(entryV1), hooks);
    await first.authorize(entryV1, planV1, sdkCore);
    const firstClient = createdClients[0]!;
    const delegations: readonly PortableDelegation[] = firstClient.getRuntimePermissionDelegations(kvSqlV1);
    expect(delegations.length).toBeGreaterThan(0);

    const sdkStore = new BrowserSessionStorage({ keyPrefix: sessionPrefix });
    await sdkStore.saveRuntimeGrants(OWNER.address, delegations);
    expect((await sdkStore.loadRuntimeGrants(OWNER.address)).length).toBe(delegations.length);
    await first.runtime.detach();

    // 2. Reload with V2: runner clears the SDK-kept grants BEFORE TinyCloudWeb restores.
    const reloaded = await ports.signIn(entryV2, bundleReadPlan(entryV2), hooks);
    const reloadedClient = createdClients[1]!;
    expect(reloadedClient.sessionRestoreStatus).toBe("restored");
    await reloadedClient.permissionsReady();

    expect(await sdkStore.loadRuntimeGrants(OWNER.address)).toEqual([]);
    expect(reloadedClient.hasPermissions(kvSqlV2)).toBe(false);

    await reloaded.authorize(entryV2, planV2, sdkCore);
    expect(testState.modalPrompts).toBe(2);
  }, 30_000);

  it("control case: restores kv/sql grants without asking again when reloading the same bundle digest via Share's runtime-grants store", async () => {
    const ports = createRunPorts();
    const sessionPrefix = await runnerSessionPrefix(entryV1.app_id);
    const planV1 = appOpenPlan(entryV1);
    const kvSqlV1 = runtimeKvSqlPermissionsOf(planV1.manifest, entryV1.app_id);

    // 1. Grant V1 via runner; SDK kept-grants store stays empty, Share's digest-bound store saves it.
    const first = await ports.signIn(entryV1, bundleReadPlan(entryV1), hooks);
    await first.authorize(entryV1, planV1, sdkCore);
    expect(testState.modalPrompts).toBe(1);
    const sdkStore = new BrowserSessionStorage({ keyPrefix: sessionPrefix });
    expect(await sdkStore.loadRuntimeGrants(OWNER.address)).toEqual([]);
    await first.runtime.detach();

    // 2. Reload with the SAME bundle digest (V1).
    const reloaded = await ports.signIn(entryV1, bundleReadPlan(entryV1), hooks);
    const reloadedClient = createdClients[1]!;
    expect(reloadedClient.sessionRestoreStatus).toBe("restored");

    // Before authorize, SDK alone does NOT hold kv/sql (proving SDK store is off).
    await reloadedClient.permissionsReady();
    expect(reloadedClient.hasPermissions(kvSqlV1)).toBe(false);

    // authorize restores from Share's digest-bound runtime-grants store with NO second prompt.
    await reloaded.authorize(entryV1, planV1, sdkCore);
    expect(reloadedClient.hasPermissions(kvSqlV1)).toBe(true);
    expect(testState.modalPrompts).toBe(1);
  }, 30_000);

  it("signing out after clearing kept grants via a second BrowserSessionStorage leaves only a single retired: marker", async () => {
    const ports = createRunPorts();
    const sessionPrefix = await runnerSessionPrefix(entryV1.app_id);
    const planV1 = appOpenPlan(entryV1);

    const session = await ports.signIn(entryV1, bundleReadPlan(entryV1), hooks);
    await session.authorize(entryV1, planV1, sdkCore);
    await session.runtime.end();

    const sdkStore = new BrowserSessionStorage({ keyPrefix: sessionPrefix });
    expect(sdkStore.activeAddress()).toBeUndefined();
    expect(sdkStore.exists(OWNER.address)).toBe(false);
    expect(await sdkStore.loadRuntimeGrants(OWNER.address)).toEqual([]);

    const runnerSdkKeys: string[] = [];
    for (let i = 0; i < storage.length; i += 1) {
      const key = storage.key(i);
      if (key !== null && key.startsWith(sessionPrefix) && key !== `${sessionPrefix}-runtime-grants`) {
        runnerSdkKeys.push(key);
      }
    }
    expect(runnerSdkKeys).toHaveLength(1);
    expect(runnerSdkKeys[0]).toMatch(new RegExp(`^${sessionPrefix}retired:${OWNER.address.toLowerCase()}:[^:]+$`));
  }, 30_000);

  it("propagates saveRuntimeGrants failure after requestPermissions instead of swallowing it", async () => {
    const ports = createRunPorts();
    const sessionPrefix = await runnerSessionPrefix(entryV1.app_id);
    const planV1 = appOpenPlan(entryV1);

    const session = await ports.signIn(entryV1, bundleReadPlan(entryV1), hooks);
    const origSave = BrowserSessionStorage.prototype.saveRuntimeGrants;
    const saveSpy = vi.spyOn(BrowserSessionStorage.prototype, "saveRuntimeGrants").mockImplementation(function (this: BrowserSessionStorage, address, grants) {
      if (grants.length === 0) return Promise.reject(new Error("clear-grants-failed"));
      return origSave.call(this, address, grants);
    });
    try {
      await expect(session.authorize(entryV1, planV1, sdkCore)).rejects.toThrow("clear-grants-failed");
      expect(storage.getItem(`${sessionPrefix}-runtime-grants`)).toBeNull();
    } finally {
      saveSpy.mockRestore();
    }
  }, 30_000);
});
