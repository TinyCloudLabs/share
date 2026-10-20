import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ACCOUNT_MANIFEST_PERMISSIONS } from "@tinycloud/bootstrap";
import { composeManifestRequest } from "@tinycloud/sdk-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { type BundleResponse, INSTALL_RECORD_PATH, bundleDigest, fetchVerifiedBundle, installPathProblem, sha256Hex } from "../src/apps/bundle.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { SAMPLE_NOTICE, SQL_CHANGE_NOTICE, consentFor } from "../src/apps/consent.ts";
import { resetInstallFlights, startInstall } from "../src/apps/install-flight.ts";
import { InstallError, type InstallPorts, type InstallSession, type PutResult, runInstall } from "../src/apps/install.ts";
import { REGISTRY_RESOURCES, expectedInstallerResources, installerAccess, installerManifest, resourceMismatch } from "../src/apps/install-plan.ts";
import { installPathProblem as buildTimePathProblem } from "../scripts/apps-catalog.mjs";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
const entryOf = (appId: string): CatalogEntry => {
  const found = catalog.apps.find((app) => app.app_id === appId);
  if (found === undefined) throw new Error(`catalog has no ${appId}`);
  return found;
};

type FetchResult = BundleResponse;

/** An ArrayBuffer from node's realm: jsdom's own is rejected by webcrypto on Node 20. */
function nodeArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = Buffer.from(bytes);
  return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength) as ArrayBuffer;
}

/** The committed bundle bytes, served the way `/apps/b/<digest>/` serves them; `overrides` replaces a file's bytes (a tampered server). */
function bundleServer(entry: CatalogEntry, overrides: Record<string, Uint8Array> = {}): { fetch: NonNullable<InstallPorts["fetch"]>; urls: string[] } {
  const urls: string[] = [];
  return {
    urls,
    fetch: async (url): Promise<FetchResult> => {
      urls.push(url);
      const path = url.slice(entry.bundle.root.length);
      const bytes = overrides[path] ?? readFileSync(join("public", url));
      return { ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(bytes) };
    },
  };
}

/** A person's TinyCloud: create-only puts into a map, the way the node answers `If-None-Match: *`. */
function fakeNode(options: { existing?: Record<string, string>; failOnPut?: number } = {}) {
  const store = new Map<string, Uint8Array>(Object.entries(options.existing ?? {}).map(([key, text]) => [key, new TextEncoder().encode(text)]));
  const calls: string[] = [];
  const sessions: { manifest: unknown; disposed: number }[] = [];
  const ports = (extra: Partial<InstallPorts> = {}): InstallPorts => ({
    ...extra,
    openSession: async (manifest, hooks) => {
      const record = { manifest, disposed: 0 };
      sessions.push(record);
      hooks.approval(true);
      hooks.approval(false);
      const session: InstallSession = {
        put: async (key, bytes): Promise<PutResult> => {
          calls.push(key);
          if (options.failOnPut !== undefined && calls.length === options.failOnPut) throw new Error("node unavailable");
          if (store.has(key)) return "exists";
          store.set(key, bytes);
          return "created";
        },
        confirmListed: async () => true,
        dispose: () => { record.disposed += 1; },
      };
      return session;
    },
  });
  return { store, calls, sessions, ports };
}

beforeEach(() => { resetInstallFlights(); });

describe("the installer's sign-in", () => {
  it.each(catalog.apps.map((app) => [app.app_id]))("asks for exactly two put-only folders plus the account registry, and nothing the app itself asks for (%s)", (appId) => {
    const manifest = installerManifest({ app_id: appId, name: "X", description: "Y" });
    const composed = composeManifestRequest([manifest], { includeAccountRegistryPermissions: true });
    expect(resourceMismatch(expectedInstallerResources(manifest), composed.resources)).toBeNull();
    expect(composed.delegationTargets).toEqual([]);
    expect(composed.includePublicSpace).toBe(false);
    // The only writes into the applications space are the two folders, and the only action there is put.
    const inApplications = composed.resources.filter((resource) => resource.space === "applications" && resource.service === "tinycloud.kv");
    expect(inApplications.map((resource) => [resource.path, resource.actions])).toEqual([
      [`${appId}/app/`, ["tinycloud.kv/put"]],
      [`${appId}/knowledge/`, ["tinycloud.kv/put"]],
    ]);
    expect(composed.resources.some((resource) => resource.actions.some((action) => action.includes("*") || action.startsWith("tinycloud.delegation/") && action !== "tinycloud.delegation/list"))).toBe(false);
    expect(composed.resources.some((resource) => resource.service === "tinycloud.sql" && resource.space === "applications")).toBe(false);
  });

  it("does not carry the app's own SQL, KV or cross-app grants into the install sign-in", async () => {
    const recipes = entryOf(RECIPES);
    const server = bundleServer(recipes);
    const node = fakeNode();
    await runInstall(recipes, node.ports({ fetch: server.fetch }), () => undefined);
    const signed = JSON.stringify(node.sessions[0]?.manifest);
    expect(signed).not.toContain("tinycloud.sql");
    expect(signed).not.toContain(HEALTH);
    expect(signed).not.toContain("secrets");
    expect(node.sessions[0]?.manifest).toMatchObject({ app_id: RECIPES, defaults: false, includePublicSpace: false, space: "applications" });
  });

  it("mirrors the SDK's account registry grants and the sheet's list is the same list", () => {
    const sdk = ACCOUNT_MANIFEST_PERMISSIONS.map((resource) => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] }));
    expect(resourceMismatch(sdk, REGISTRY_RESOURCES)).toBeNull();

    const manifest = installerManifest({ app_id: HEALTH, name: "X" });
    const { app, registry } = installerAccess(manifest);
    const shown = [...app.read, ...app.change, ...registry.read, ...registry.change];
    const labelToService: Record<string, string> = { "Key-value": "tinycloud.kv", "SQL database": "tinycloud.sql", Delegation: "tinycloud.delegation", Capabilities: "tinycloud.capabilities" };
    const sheetActions = new Map<string, Set<string>>();
    for (const item of shown) {
      const key = `${labelToService[item.service]}|${item.space ?? "applications"}|${item.target}`;
      sheetActions.set(key, new Set([...(sheetActions.get(key) ?? []), ...item.actions]));
    }
    const composed = composeManifestRequest([manifest], { includeAccountRegistryPermissions: true });
    // Same resources, same actions (a capabilities grant has no path: the sheet names its space).
    for (const resource of composed.resources) {
      const key = `${resource.service}|${resource.space}|${resource.path === "" ? resource.space : resource.path}`;
      expect([...(sheetActions.get(key) ?? [])].sort(), key).toEqual(resource.actions.map((action) => action.slice(action.lastIndexOf("/") + 1)).sort());
    }
    expect(sheetActions.size).toBe(composed.resources.length);
  });

  it("refuses to proceed if the SDK would compose something the sheet does not show", () => {
    const manifest = installerManifest({ app_id: HEALTH, name: "X" });
    const widened = { ...manifest, permissions: [...(manifest.permissions ?? []), { service: "tinycloud.kv", path: "app/", actions: ["put", "del"] }] };
    const composed = composeManifestRequest([widened], { includeAccountRegistryPermissions: true });
    expect(resourceMismatch(expectedInstallerResources(manifest), composed.resources)).toContain("unexpected");
  });
});

describe("verification before any write", () => {
  it("installs the Health Log sample: every file create-only, install.json last, one sign-in, nothing else", async () => {
    const entry = entryOf(HEALTH);
    const server = bundleServer(entry);
    const node = fakeNode();
    const outcome = await runInstall(entry, node.ports({ fetch: server.fetch, now: () => new Date("2026-10-20T08:00:00.000Z") }), () => undefined);

    expect(outcome).toMatchObject({ kind: "installed", kept: [], listed: true });
    expect(node.sessions).toHaveLength(1);
    expect(node.sessions[0]?.disposed).toBe(1);
    expect(node.calls.at(-1)).toBe(`${HEALTH}/app/install.json`);
    expect(node.calls.slice(0, -1).sort()).toEqual(entry.bundle.files.map((file) => (file.path.startsWith("knowledge/") ? `${HEALTH}/${file.path}` : `${HEALTH}/app/${file.path}`)).sort());
    expect([...node.store.keys()].every((key) => key.startsWith(`${HEALTH}/app/`) || key.startsWith(`${HEALTH}/knowledge/`))).toBe(true);
    expect(JSON.parse(new TextDecoder().decode(node.store.get(`${HEALTH}/app/install.json`)))).toEqual({
      source: { repo: entry.source.repo, tag: null, commit: entry.source.commit },
      digest: entry.bundle.digest,
      installed_at: "2026-10-20T08:00:00.000Z",
    });
    // Every fetch stayed under the entry's own root.
    expect(server.urls.length).toBe(entry.bundle.files.length);
    expect(server.urls.every((url) => url.startsWith(`/apps/b/${entry.bundle.digest}/`))).toBe(true);
  });

  it("a tampered file refuses the install: zero writes, and OpenKey is never opened", async () => {
    const entry = entryOf(HEALTH);
    const original = readFileSync(join("public", entry.bundle.root, "app.jsx"));
    const server = bundleServer(entry, { "app.jsx": new Uint8Array([...original, 10, 47, 47]) });
    const node = fakeNode();
    const progress = vi.fn();
    await expect(runInstall(entry, node.ports({ fetch: server.fetch }), progress)).rejects.toMatchObject({ name: "InstallError", reason: "tampered", written: [] });
    expect(node.sessions).toEqual([]);
    expect(node.calls).toEqual([]);
    expect(node.store.size).toBe(0);
    expect(progress).not.toHaveBeenCalledWith({ phase: "approval" });
  });

  it("a same-length substitution is caught by the hash, not the size", async () => {
    const entry = entryOf(RECIPES);
    const original = new Uint8Array(readFileSync(join("public", entry.bundle.root, "schema.sql")));
    const swapped = new Uint8Array(original);
    swapped[0] = swapped[0] === 65 ? 66 : 65;
    const node = fakeNode();
    await expect(runInstall(entry, node.ports({ fetch: bundleServer(entry, { "schema.sql": swapped }).fetch }), () => undefined)).rejects.toMatchObject({ reason: "tampered" });
    expect(node.sessions).toEqual([]);
  });

  it("an unavailable file is a refusal too, with zero writes", async () => {
    const entry = entryOf(HEALTH);
    const node = fakeNode();
    const missing: NonNullable<InstallPorts["fetch"]> = async () => ({ ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) });
    await expect(runInstall(entry, node.ports({ fetch: missing }), () => undefined)).rejects.toMatchObject({ reason: "unavailable" });
    expect(node.sessions).toEqual([]);
  });

  it("a manifest whose app_id or name differs from the catalog entry is refused", async () => {
    const entry = entryOf(HEALTH);
    const manifest = JSON.parse(readFileSync(join("public", entry.bundle.root, "manifest.json"), "utf8"));
    const other = new TextEncoder().encode(JSON.stringify({ ...manifest, name: "Other" }));
    // Same hash as the catalog cannot be forged; so check the identity rule on a copy of the entry that pins the forged bytes.
    const forged = structuredClone(entry);
    const file = forged.bundle.files.find((candidate) => candidate.path === "manifest.json");
    if (file === undefined) throw new Error("fixture");
    file.sha256 = await sha256Hex(other);
    file.size = other.byteLength;
    forged.manifest.sha256 = file.sha256;
    forged.bundle.digest = await bundleDigest(forged.bundle.files);
    forged.bundle.root = `/apps/b/${forged.bundle.digest}/`;
    const server = { fetch: async (url: string): Promise<FetchResult> => ({ ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(url.endsWith("manifest.json") ? other : readFileSync(join("public", entry.bundle.root, url.slice(forged.bundle.root.length)))) }) };
    await expect(fetchVerifiedBundle(forged, server.fetch)).rejects.toMatchObject({ reason: "catalog" });
  });
});

describe("a hostile or odd catalog entry is rejected at load, before any fetch", () => {
  const hostile = ["../escape.txt", "a/../../b", "/etc/passwd", "a\\b.txt", "a\u0000b.txt", "nul\u0000", ".hidden", "knowledge/.env", "a//b", "a/./b", "", INSTALL_RECORD_PATH, "has space.md", "naïve.md", `${"a/".repeat(9)}b`, "x".repeat(200)];

  it.each(hostile.map((path) => [JSON.stringify(path), path]))("path %s", async (_label, path) => {
    expect(installPathProblem(path)).not.toBeNull();
    expect(buildTimePathProblem(path)).not.toBeNull();
    const entry = structuredClone(entryOf(HEALTH));
    entry.bundle.files.push({ path, sha256: "a".repeat(64), size: 1 });
    const fetchSpy = vi.fn();
    await expect(fetchVerifiedBundle(entry, fetchSpy)).rejects.toMatchObject({ reason: "catalog" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("every committed catalog path passes both copies of the rule, and both rules agree on a sample of paths", () => {
    for (const app of catalog.apps) for (const file of app.bundle.files) {
      expect(installPathProblem(file.path), file.path).toBeNull();
      expect(buildTimePathProblem(file.path), file.path).toBeNull();
    }
    for (const path of [...hostile, "ok.md", "a/b/c.json", "A_b-c.d", "knowledge/tables/meal.md"]) expect(installPathProblem(path) === null, path).toBe(buildTimePathProblem(path) === null);
  });

  it("a bundle root outside /apps/b/<its digest>/ or a digest that does not follow from the files is refused", async () => {
    const wrongRoot = { ...structuredClone(entryOf(HEALTH)), bundle: { ...entryOf(HEALTH).bundle, root: "https://evil.example/" } };
    await expect(fetchVerifiedBundle(wrongRoot, vi.fn())).rejects.toMatchObject({ reason: "catalog" });
    const sibling = { ...structuredClone(entryOf(HEALTH)), bundle: { ...entryOf(HEALTH).bundle, root: `/apps/b/${entryOf(RECIPES).bundle.digest}/` } };
    await expect(fetchVerifiedBundle(sibling, vi.fn())).rejects.toMatchObject({ reason: "catalog" });
    const edited = structuredClone(entryOf(HEALTH));
    edited.bundle.files[0] = { ...(edited.bundle.files[0] as CatalogEntry["bundle"]["files"][number]), size: 1 };
    await expect(fetchVerifiedBundle(edited, vi.fn())).rejects.toMatchObject({ reason: "catalog" });
  });
});

describe("create-only: the person's copy always wins", () => {
  it("keeps a hand-edited knowledge/app.md and every other file that is already there", async () => {
    const entry = entryOf(HEALTH);
    const mine = "# My notes\nEdited by hand and by my agent.\n";
    const node = fakeNode({ existing: { [`${HEALTH}/knowledge/app.md`]: mine, [`${HEALTH}/app/install.json`]: "{\"mine\":true}" } });
    const outcome = await runInstall(entry, node.ports({ fetch: bundleServer(entry).fetch }), () => undefined);
    expect(new TextDecoder().decode(node.store.get(`${HEALTH}/knowledge/app.md`))).toBe(mine);
    expect(new TextDecoder().decode(node.store.get(`${HEALTH}/app/install.json`))).toBe("{\"mine\":true}");
    expect(outcome.kind).toBe("installed");
    expect(outcome.kept).toEqual([`${HEALTH}/knowledge/app.md`, `${HEALTH}/app/install.json`].sort((a, b) => node.calls.indexOf(a) - node.calls.indexOf(b)));
    expect(outcome.written.length).toBe(entry.bundle.files.length - 1);
  });

  it("a second install over a finished one writes nothing and says it is already installed", async () => {
    const entry = entryOf(RECIPES);
    const node = fakeNode();
    const ports = node.ports({ fetch: bundleServer(entry).fetch });
    await runInstall(entry, ports, () => undefined);
    const before = new Map(node.store);
    const again = await runInstall(entry, ports, () => undefined);
    expect(again).toMatchObject({ kind: "already", written: [] });
    expect(again.kept.length).toBe(entry.bundle.files.length + 1);
    expect([...node.store.entries()]).toEqual([...before.entries()]);
  });
});

describe("a failed write leaves a consistent, resumable state", () => {
  it("stops at the failure, lists what was saved, never writes install.json, and a re-install finishes the rest", async () => {
    const entry = entryOf(HEALTH);
    const flaky = fakeNode({ failOnPut: 6 });
    const failure = await runInstall(entry, flaky.ports({ fetch: bundleServer(entry).fetch }), () => undefined).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(InstallError);
    const error = failure as InstallError;
    expect(error.reason).toBe("write-failed");
    expect(error.written).toHaveLength(5);
    expect(error.total).toBe(entry.bundle.files.length + 1);
    expect([...flaky.store.keys()]).toEqual(error.written);
    expect(flaky.store.has(`${HEALTH}/app/install.json`)).toBe(false);
    expect(flaky.sessions[0]?.disposed).toBe(1);

    // Same TinyCloud, node back: what is there is kept, the rest is written, and the record comes last.
    const recovered = fakeNode({ existing: Object.fromEntries([...flaky.store].map(([key, bytes]) => [key, new TextDecoder().decode(bytes)])) });
    const outcome = await runInstall(entry, recovered.ports({ fetch: bundleServer(entry).fetch }), () => undefined);
    expect(outcome.kind).toBe("installed");
    expect(outcome.kept).toEqual(error.written);
    expect(recovered.calls.at(-1)).toBe(`${HEALTH}/app/install.json`);
    expect(recovered.store.size).toBe(entry.bundle.files.length + 1);
  });

  it("a sign-in that fails (cancelled) writes nothing", async () => {
    const entry = entryOf(HEALTH);
    const node = fakeNode();
    const cancelled: InstallPorts = { fetch: bundleServer(entry).fetch, openSession: async () => { throw new InstallError("cancelled"); } };
    await expect(runInstall(entry, cancelled, () => undefined)).rejects.toMatchObject({ reason: "cancelled", written: [] });
    expect(node.calls).toEqual([]);
  });

  it("an apps-list confirmation that fails does not undo or fail the install", async () => {
    const entry = entryOf(HEALTH);
    const node = fakeNode();
    const base = node.ports({ fetch: bundleServer(entry).fetch });
    const ports: InstallPorts = { ...base, openSession: async (manifest, hooks) => ({ ...(await base.openSession(manifest, hooks)), confirmListed: async () => { throw new Error("registry down"); } }) };
    expect(await runInstall(entry, ports, () => undefined)).toMatchObject({ kind: "installed", listed: false });
    expect(node.store.has(`${HEALTH}/app/install.json`)).toBe(true);
  });
});

describe("one install at a time per app", () => {
  it("a double click shares one flight: one sign-in, one set of writes", async () => {
    const entry = entryOf(HEALTH);
    const node = fakeNode();
    const ports = node.ports({ fetch: bundleServer(entry).fetch });
    const first = startInstall(entry, () => ports);
    const second = startInstall(entry, () => ports);
    expect(second).toBe(first);
    await first.done;
    expect(node.sessions).toHaveLength(1);
    expect(node.calls.length).toBe(entry.bundle.files.length + 1);
    expect(first.state).toMatchObject({ phase: "installed" });
    // After it settles, trying again is a new flight (and, here, finds everything already installed).
    const third = startInstall(entry, () => ports);
    expect(third).not.toBe(first);
    await third.done;
    expect(third.state).toMatchObject({ phase: "installed", outcome: { kind: "already" } });
  });

  it("different apps do not share a flight", async () => {
    const node = fakeNode();
    const a = startInstall(entryOf(HEALTH), () => node.ports({ fetch: bundleServer(entryOf(HEALTH)).fetch }));
    const b = startInstall(entryOf(RECIPES), () => node.ports({ fetch: bundleServer(entryOf(RECIPES)).fetch }));
    expect(a).not.toBe(b);
    await Promise.all([a.done, b.done]);
  });
});

describe("what the pre-consent sheet says", () => {
  const manifestOf = (entry: CatalogEntry): unknown => JSON.parse(readFileSync(join("public", entry.bundle.root, "manifest.json"), "utf8"));

  it("a sample that writes SQL says so plainly, and says to use throwaway data", () => {
    const entry = entryOf(HEALTH);
    const { notices, runtime } = consentFor(entry, manifestOf(entry), catalog.apps);
    expect(notices).toContain(SAMPLE_NOTICE);
    expect(notices).toContain(SQL_CHANGE_NOTICE);
    expect(SQL_CHANGE_NOTICE).toBe("This app can change or delete its own tables.");
    expect(SAMPLE_NOTICE).toBe("Sample app: use throwaway data only.");
    expect(runtime.change.some((item) => item.service === "SQL database" && item.actions.includes("schema"))).toBe(true);
  });

  it("an app that reads another app's database lists it as a whole-database read", () => {
    const entry = entryOf(RECIPES);
    const { notices, runtime } = consentFor(entry, manifestOf(entry), catalog.apps);
    expect(notices).toContain("This app can read Health Log (sample)'s database (whole database).");
    expect(notices).toContain(SQL_CHANGE_NOTICE);
    // The cross-app grant is a read: it is not among the changes.
    expect(runtime.change.some((item) => item.target.startsWith(`${HEALTH}/`))).toBe(false);
    expect(runtime.read.some((item) => item.target === `${HEALTH}/healthlog`)).toBe(true);
  });

  it("a non-sample app with the default grants still says it can change or delete its own tables, and no sample notice", () => {
    const entry = entryOf("com.example.notes");
    const { notices } = consentFor(entry, manifestOf(entry), catalog.apps);
    expect(notices).toEqual([SQL_CHANGE_NOTICE]);
  });

  it("an app that does not write SQL has no SQL notice", () => {
    const entry = entryOf(HEALTH);
    const readOnly = { app_id: entry.app_id, name: "R", defaults: false, permissions: [{ service: "tinycloud.sql", path: "db", actions: ["read"] }] };
    const { sample: _sample, ...plain } = entry;
    expect(consentFor(plain, readOnly, catalog.apps).notices).toEqual([]);
  });
});
