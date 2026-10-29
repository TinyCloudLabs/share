import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { describe, expect, it } from "vitest";

import { type BundleFetch } from "../src/apps/bundle.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { RepairError, type RepairPorts, type RepairSession, repairManifest, repairScope, repairWrites, runRepair } from "../src/apps/repair.ts";
import { installRecordKey, REGISTRY_RESOURCES } from "../src/apps/install-plan.ts";
import { parseInstallRecord } from "../src/apps/stored-app.ts";
import { ManifestRejectedError, MANIFEST_CHECK_ADDRESS, assertManifestInScope } from "../src/share/manifest-policy.ts";
import { storedFiles } from "./stored-fixtures.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH) as CatalogEntry;
const previousEntry = catalog.apps.find((candidate) => candidate.app_id === HEALTH && candidate.bundle.digest === "dc3ec19fffce8fee350944469948531659a258347538a98aacdd5544deea5014");
const nodeBuffer = (bytes: Uint8Array): ArrayBuffer => { const copy = Buffer.from(bytes); return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength) as ArrayBuffer; };

function bundleFetch(overrides: Record<string, Uint8Array> = {}, candidate: CatalogEntry = entry): { fetch: BundleFetch; urls: string[] } {
  const urls: string[] = [];
  return {
    urls,
    fetch: async (url) => {
      urls.push(url);
      const selected = catalog.apps.find((candidate) => url.startsWith(candidate.bundle.root)) ?? candidate;
      const path = url.slice(selected.bundle.root.length);
      const bytes = overrides[path] ?? new Uint8Array(readFileSync(join("public", selected.bundle.root, path)));
      return { ok: true, status: 200, arrayBuffer: async () => nodeBuffer(bytes) };
    },
  };
}

/** A node holding `store`; every call is recorded. */
function fakeNode(store: Map<string, Uint8Array>, options: { failPutAt?: number } = {}): { ports: RepairPorts; log: string[]; sessions: number; lookups: number; disposed: number; manifests: unknown[]; hooks: { approval(open: boolean): void }[] } {
  const state = { log: [] as string[], sessions: 0, lookups: 0, disposed: 0, manifests: [] as unknown[], hooks: [] as { approval(open: boolean): void }[], ports: undefined as unknown as RepairPorts };
  let puts = 0;
  state.ports = {
    async readInstallDigest(candidate): Promise<string | null> {
      state.lookups += 1;
      const record = store.get(installRecordKey(candidate.app_id));
      return record === undefined ? null : parseInstallRecord(record)?.digest ?? null;
    },
    async openSession(manifest, hooks): Promise<RepairSession> {
      state.sessions += 1;
      state.manifests.push(manifest);
      state.hooks.push(hooks);
      return {
        async put(key, bytes, contentType) {
          puts += 1;
          if (options.failPutAt === puts) throw new Error("node down");
          state.log.push(`put ${key} ${contentType}`);
          store.set(key, bytes);
        },
        async list(prefix) { state.log.push(`list ${prefix}`); return [...store.keys()].filter((key) => key.startsWith(prefix)); },
        async del(key) { state.log.push(`del ${key}`); store.delete(key); },
        dispose() { state.disposed += 1; },
      };
    },
  };
  return state;
}

/** What the person's TinyCloud holds for an installed app: code under app/, their notes, their data. */
function installedStore(candidate: CatalogEntry = entry): Map<string, Uint8Array> {
  const store = new Map<string, Uint8Array>();
  for (const [path, bytes] of storedFiles(candidate).entries) store.set(`${HEALTH}/app/${path}`, bytes);
  store.set(`${HEALTH}/knowledge/app.md`, new TextEncoder().encode("# my notes"));
  store.set(`${HEALTH}/prefs/goals.json`, new TextEncoder().encode('{"kcal":1800}'));
  return store;
}

describe("Repair puts the catalog's code files back over the saved ones", () => {
  it("overwrites a tampered app.jsx and removes a stray file, and touches nothing else", async () => {
    const store = installedStore();
    store.set(`${HEALTH}/app/app.jsx`, new TextEncoder().encode('fetch("https://x.example")'));
    store.set(`${HEALTH}/app/stray.js`, new TextEncoder().encode("1"));
    const before = new Map(store);
    const node = fakeNode(store);
    const progress: string[] = [];
    const outcome = await runRepair(entry, { ...node.ports, fetch: bundleFetch().fetch }, (step) => progress.push(step.phase));
    // The code files are the catalog's again, byte for byte (the stray is gone).
    for (const write of repairWrites(entry)) expect(store.get(write.key)).toEqual(new Uint8Array(readFileSync(join("public", entry.bundle.root, write.path))));
    expect(store.has(`${HEALTH}/app/stray.js`)).toBe(false);
    expect(outcome.removed).toEqual([`${HEALTH}/app/stray.js`]);
    // Everything that is the person's is untouched: their notes, their settings, the install record.
    for (const key of [`${HEALTH}/knowledge/app.md`, `${HEALTH}/prefs/goals.json`, `${HEALTH}/app/install.json`]) expect(store.get(key), key).toEqual(before.get(key));
    expect(progress[0]).toBe("checking-version");
    expect(progress).toContain("repairing");
    expect(node.sessions).toBe(1);
    expect(node.disposed).toBe(1);
  });
  it("repairs a retained install from its saved digest without changing its install record", async () => {
    expect(previousEntry).toBeDefined();
    if (previousEntry === undefined) return;
    const store = installedStore(previousEntry);
    const record = new Uint8Array(store.get(installRecordKey(HEALTH))!);
    store.set(`${HEALTH}/app/app.jsx`, new TextEncoder().encode("tampered old code"));
    const node = fakeNode(store);
    const fetcher = bundleFetch({}, previousEntry);
    await runRepair(entry, { ...node.ports, fetch: fetcher.fetch }, () => undefined, catalog.apps.filter((candidate) => candidate.app_id === HEALTH));

    expect(fetcher.urls.length).toBeGreaterThan(0);
    expect(fetcher.urls.every((url) => url.startsWith(previousEntry.bundle.root))).toBe(true);
    for (const write of repairWrites(previousEntry)) {
      expect(store.get(write.key)).toEqual(new Uint8Array(readFileSync(join("public", previousEntry.bundle.root, write.path))));
    }
    expect(Buffer.from(store.get(installRecordKey(HEALTH))!).equals(Buffer.from(record))).toBe(true);
    expect(node.log.filter((line) => line.startsWith("put ")).map((line) => line.split(" ")[1])).toEqual(repairWrites(previousEntry).map((write) => write.key));
    const { pinProblem } = await import("../src/apps/stored-app.ts");
    const files = new Map<string, Uint8Array>();
    for (const [key, bytes] of store) if (key.startsWith(`${HEALTH}/app/`)) files.set(key.slice(`${HEALTH}/app/`.length), bytes);
    expect(await pinProblem(previousEntry, { entries: files })).toBeUndefined();
  });

  it("writes only code files under <app_id>/app/ (never knowledge/, install.json, data), deletes only strays there, and in that order", async () => {
    const store = installedStore();
    store.set(`${HEALTH}/app/stray.js`, new TextEncoder().encode("1"));
    const node = fakeNode(store);
    await runRepair(entry, { ...node.ports, fetch: bundleFetch().fetch }, () => undefined);
    const writes = node.log.filter((line) => line.startsWith("put ")).map((line) => line.split(" ")[1]!);
    expect(writes.sort()).toEqual(repairWrites(entry).map((write) => write.key).sort());
    for (const key of writes) {
      expect(key.startsWith(`${HEALTH}/app/`), key).toBe(true);
      expect(key).not.toMatch(/\/knowledge\/|install\.json$|\/prefs\//);
    }
    const deletes = node.log.filter((line) => line.startsWith("del "));
    expect(deletes).toEqual([`del ${HEALTH}/app/stray.js`]);
    // Strays last.
    expect(node.log.findIndex((line) => line.startsWith("del "))).toBeGreaterThan(node.log.map((line) => line.startsWith("put ")).lastIndexOf(true));
    expect(node.log.filter((line) => line.startsWith("list "))).toEqual([`list ${HEALTH}/app/`]);
  });

  it("restores a widened manifest.json too (the manifest is one of the files it replaces)", async () => {
    const store = installedStore();
    store.set(`${HEALTH}/app/manifest.json`, new TextEncoder().encode('{"app_id":"x"}'));
    await runRepair(entry, { ...fakeNode(store).ports, fetch: bundleFetch().fetch }, () => undefined);
    expect(store.get(`${HEALTH}/app/manifest.json`)).toEqual(new Uint8Array(readFileSync(join("public", entry.bundle.root, "manifest.json"))));
  });

  it("a repaired app passes the runner's pin check", async () => {
    const store = installedStore();
    store.set(`${HEALTH}/app/app.jsx`, new TextEncoder().encode("evil"));
    store.set(`${HEALTH}/app/extra.js`, new TextEncoder().encode("evil"));
    await runRepair(entry, { ...fakeNode(store).ports, fetch: bundleFetch().fetch }, () => undefined);
    const { pinProblem } = await import("../src/apps/stored-app.ts");
    const entries = new Map<string, Uint8Array>();
    for (const [key, bytes] of store) if (key.startsWith(`${HEALTH}/app/`)) entries.set(key.slice(`${HEALTH}/app/`.length), bytes);
    expect(await pinProblem(entry, { entries })).toBeUndefined();
  });

  it("a tampered bundle file is refused with zero sign-ins and zero writes", async () => {
    const store = installedStore();
    const node = fakeNode(store);
    const bad = bundleFetch({ "app.jsx": new TextEncoder().encode("tampered") });
    await expect(runRepair(entry, { ...node.ports, fetch: bad.fetch }, () => undefined)).rejects.toMatchObject({ reason: "tampered" });
    expect(node.sessions).toBe(0);
    expect(node.log).toEqual([]);
  });

  it("a disabled entry is refused before anything is fetched", async () => {
    const node = fakeNode(installedStore());
    const server = bundleFetch();
    await expect(runRepair({ ...entry, disabled: true, disabledReason: "Off." }, { ...node.ports, fetch: server.fetch }, () => undefined)).rejects.toMatchObject({ reason: "disabled" });
    expect(server.urls).toEqual([]);
    expect(node.sessions).toBe(0);
  });

  it("deletes nothing outside <app_id>/app/ even if the node lists more than it was asked for", async () => {
    const store = installedStore();
    const node = fakeNode(store);
    const over: RepairPorts = {
      ...node.ports,
      openSession: async (manifest, hooks) => ({ ...(await node.ports.openSession(manifest, hooks)), list: async () => [...store.keys()] }),
    };
    await runRepair(entry, { ...over, fetch: bundleFetch().fetch }, () => undefined);
    expect(node.log.filter((line) => line.startsWith("del "))).toEqual([]);
    expect(store.has(`${HEALTH}/knowledge/app.md`)).toBe(true);
    expect(store.has(`${HEALTH}/prefs/goals.json`)).toBe(true);
  });

  it("a catalog path that would land outside app/ is never written", async () => {
    const hostile: CatalogEntry = { ...entry, bundle: { ...entry.bundle, files: [...entry.bundle.files, { path: "../knowledge/app.md", sha256: "0".repeat(64), size: 1 }] } };
    const node = fakeNode(installedStore());
    await expect(runRepair(hostile, { ...node.ports, fetch: bundleFetch().fetch }, () => undefined)).rejects.toBeInstanceOf(RepairError);
    expect(node.sessions).toBe(0);
    for (const write of repairWrites(entry)) expect(write.key.startsWith(`${HEALTH}/app/`)).toBe(true);
  });

  it("a failed write stops, says what was replaced, still disposes, and Try again finishes", async () => {
    const store = installedStore();
    store.set(`${HEALTH}/app/app.jsx`, new TextEncoder().encode("evil"));
    const node = fakeNode(store, { failPutAt: 2 });
    await expect(runRepair(entry, { ...node.ports, fetch: bundleFetch().fetch }, () => undefined)).rejects.toMatchObject({ reason: "write-failed", written: [repairWrites(entry)[0]!.key] });
    expect(node.disposed).toBe(1);
    expect(node.log.some((line) => line.startsWith("del "))).toBe(false);
    const again = fakeNode(store);
    await runRepair(entry, { ...again.ports, fetch: bundleFetch().fetch }, () => undefined);
    expect(store.get(`${HEALTH}/app/app.jsx`)).toEqual(new Uint8Array(readFileSync(join("public", entry.bundle.root, "app.jsx"))));
  });

  it("an approval that is open is reported, and a failed sign-in is the sign-in's failure", async () => {
    const node = fakeNode(installedStore());
    const states: string[] = [];
    const ports: RepairPorts = { readInstallDigest: async () => entry.bundle.digest, fetch: bundleFetch().fetch, openSession: async (manifest, hooks) => { hooks.approval(true); hooks.approval(false); return node.ports.openSession(manifest, hooks); } };
    await runRepair(entry, ports, (step) => states.push(step.phase));
    expect(states).toEqual(expect.arrayContaining(["signing-in", "approval"]));
    const refusing: RepairPorts = { readInstallDigest: async () => entry.bundle.digest, fetch: bundleFetch().fetch, openSession: async () => { throw new RepairError("cancelled"); } };
    await expect(runRepair(entry, refusing, () => undefined)).rejects.toMatchObject({ reason: "cancelled" });
  });
});

describe("what Repair asks OpenKey for", () => {
  const manifest = repairManifest({ app_id: HEALTH, name: entry.name });

  it("is put, del and list on <app_id>/app/ only, and the SDK's registry grants: nothing about knowledge, data or SQL", () => {
    const composed = sdkCore.composeManifestRequest([sdkCore.validateManifest(manifest)], { includeAccountRegistryPermissions: true });
    expect(composed.delegationTargets).toEqual([]);
    const own = composed.resources.filter((resource) => resource.space === "applications" && resource.service !== "tinycloud.capabilities");
    expect(own.map((resource) => ({ service: resource.service, path: resource.path, actions: [...resource.actions].sort() }))).toEqual([{ service: "tinycloud.kv", path: `${HEALTH}/app/`, actions: ["tinycloud.kv/del", "tinycloud.kv/list", "tinycloud.kv/put"] }]);
    const rest = composed.resources.filter((resource) => resource.space !== "applications");
    expect(rest.map((resource) => `${resource.service}|${resource.space}|${resource.path}`).sort()).toEqual(REGISTRY_RESOURCES.map((resource) => `${resource.service}|${resource.space}|${resource.path}`).sort());
    expect(manifest.expiry).toBe("15m");
  });

  it("is inside the helper's scope, which refuses the same manifest widened", () => {
    const scope = repairScope(HEALTH);
    expect(() => assertManifestInScope(sdkCore.validateManifest(manifest), scope, MANIFEST_CHECK_ADDRESS)).not.toThrow();
    const widen = (permissions: sdkCore.PermissionEntry[]): unknown => { try { assertManifestInScope({ ...sdkCore.validateManifest(manifest), permissions }, scope, MANIFEST_CHECK_ADDRESS); return "accepted"; } catch (error) { return error instanceof ManifestRejectedError ? error.code : error; } };
    expect(widen([{ service: "tinycloud.kv", path: "knowledge/", actions: ["put"] }])).toBe("path-not-allowed");
    expect(widen([{ service: "tinycloud.kv", path: "prefs/", actions: ["put", "del"] }])).toBe("path-not-allowed");
    expect(widen([{ service: "tinycloud.kv", path: "app/", actions: ["put", "get"] }])).toBe("action-not-allowed");
    expect(widen([{ service: "tinycloud.sql", path: "healthlog", actions: ["write"] }])).toBe("service-not-allowed");
  });

  it("repairWrites lists exactly the catalog's files outside knowledge/, manifest included", () => {
    const expected = entry.bundle.files.filter((file) => !file.path.startsWith("knowledge/")).map((file) => file.path).sort();
    expect(repairWrites(entry).map((write) => write.path)).toEqual(expected);
    expect(expected).toContain("manifest.json");
  });
});
