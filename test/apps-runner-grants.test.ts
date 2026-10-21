import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { describe, expect, it, vi } from "vitest";

import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { type ManifestSdk, capGrants, makeAuthorizer, pathCovers, runtimeScope } from "../src/apps/grants.ts";
import { ManifestRejectedError, MANIFEST_CHECK_ADDRESS, assertManifestInScope } from "../src/share/manifest-policy.ts";
import type { ManifestResult } from "../src/apps/manifest.ts";
import { codePins, parseInstallRecord, pinProblem, verifyStoredApp } from "../src/apps/stored-app.ts";
import { type StoredOverrides, installRecordBytes, storedFiles } from "./stored-fixtures.ts";

const sdk: ManifestSdk = sdkCore;
const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
const entryOf = (appId: string): CatalogEntry => {
  const found = catalog.apps.find((entry) => entry.app_id === appId);
  if (found === undefined) throw new Error(`no ${appId}`);
  return found;
};
const read = (entry: CatalogEntry, path: string): Uint8Array => new Uint8Array(readFileSync(join("public", entry.bundle.root, path)));
const text = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));
interface TestPermission { service: string; path: string; actions: string[]; skipPrefix?: boolean; space?: string }
interface TestManifest { app_id: string; name: string; permissions: TestPermission[]; [key: string]: unknown }
const manifestOf = (entry: CatalogEntry): TestManifest => JSON.parse(new TextDecoder().decode(read(entry, entry.manifest.path))) as TestManifest;
const permission = (manifest: TestManifest, path: string): TestPermission => {
  const found = manifest.permissions.find((entry) => entry.path === path);
  if (found === undefined) throw new Error(`no ${path} grant`);
  return found;
};
const installRecord = installRecordBytes;
const okCatalogManifest = async (entry: CatalogEntry): Promise<ManifestResult> => ({ ok: true, manifest: manifestOf(entry) });
const deps = { catalog: catalog.apps, loadCatalogManifest: okCatalogManifest, sdk };
const filesFor = (entry: CatalogEntry, manifest: unknown = manifestOf(entry), over: Record<string, Uint8Array> = {}): ReturnType<typeof storedFiles> => storedFiles(entry, { files: { "manifest.json": text(manifest), ...over } });

describe("the grant cap: the stored manifest can narrow what an app is signed for, never widen it", () => {
  const health = entryOf(HEALTH);
  const refusal = async (manifest: unknown): Promise<string> => {
    const result = await verifyStoredApp(HEALTH, filesFor(health, manifest), deps);
    expect(result.ok).toBe(false);
    return result.ok ? "" : `${result.failure.reason}: ${result.failure.detail}`;
  };

  it("runs the manifest the install copied, unchanged, signing for exactly its own grants for one hour", async () => {
    const result = await verifyStoredApp(HEALTH, filesFor(health), deps);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.app.signing.expiry).toBe("1h");
    expect(result.app.signing.includePublicSpace).toBe(false);
    expect(result.app.signing.permissions).toEqual(manifestOf(health).permissions);
    // The ReCap the sign-in would ask for: the app's own four grants, capabilities/read, and the account registry.
    const composed = sdkCore.composeManifestRequest([result.app.signing], { includeAccountRegistryPermissions: true });
    expect(composed.delegationTargets).toEqual([]);
    expect(composed.resources.filter((resource) => resource.space === "applications" && resource.service !== "tinycloud.capabilities").map((resource) => `${resource.service} ${resource.path} ${resource.actions.map((action) => action.split("/")[1]).join(",")}`).sort()).toEqual([
      `tinycloud.kv ${HEALTH}/app/ get`,
      `tinycloud.kv ${HEALTH}/knowledge/ get,put,list`,
      `tinycloud.kv ${HEALTH}/prefs/ get,put`,
      `tinycloud.sql ${HEALTH}/healthlog read,write,schema`,
    ]);
    expect(result.app.entry.bundle.digest).toBe(health.bundle.digest);
  });

  it("the bridge allow-list is the capped stored manifest: app/ is readable but never writable through it", async () => {
    const result = await verifyStoredApp(HEALTH, filesFor(health), deps);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.app.authorize("tinycloud.kv", `${HEALTH}/app/app.jsx`, "get", false)).toBe(true);
    expect(result.app.authorize("tinycloud.kv", `${HEALTH}/app/app.jsx`, "put", false)).toBe(false);
    expect(result.app.authorize("tinycloud.kv", `${HEALTH}/knowledge/a.md`, "put", false)).toBe(true);
  });

  it("allows narrowing: fewer actions, a longer path, a removed grant, defaults already off", async () => {
    const narrowed = manifestOf(health);
    narrowed.permissions = [
      { service: "tinycloud.sql", path: "healthlog", actions: ["read"] },
      { service: "tinycloud.kv", path: "prefs/goals.json", actions: ["get"] },
      { service: "tinycloud.kv", path: "knowledge/app.md", actions: ["get", "put"] },
    ];
    narrowed.name = "My health log";
    const result = await verifyStoredApp(HEALTH, filesFor(health, narrowed), deps);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.app.name).toBe("My health log");
    expect(result.app.authorize("tinycloud.sql", `${HEALTH}/healthlog`, "read", false)).toBe(true);
    expect(result.app.authorize("tinycloud.sql", `${HEALTH}/healthlog`, "write", false)).toBe(false);
    expect(result.app.authorize("tinycloud.kv", `${HEALTH}/prefs/other.json`, "get", false)).toBe(false);
  });

  it("refuses every widening of a grant, with nothing signed", async () => {
    const widen = (change: (manifest: TestManifest) => void): TestManifest => { const manifest = manifestOf(health); change(manifest); return manifest; };
    const cases: Record<string, TestManifest> = {
      "an action the catalog did not declare (put on the app's own code)": widen((m) => { permission(m, "app/").actions.push("put"); }),
      "a delete on prefs": widen((m) => { permission(m, "prefs/").actions.push("del"); }),
      "a shorter path (all of prefs -> the whole app folder)": widen((m) => { permission(m, "prefs/").path = ""; }),
      "a new grant (the app's whole folder)": widen((m) => { m.permissions.push({ service: "tinycloud.kv", path: "", actions: ["get"] }); }),
      "a new SQL database": widen((m) => { m.permissions.push({ service: "tinycloud.sql", path: "other", actions: ["read"] }); }),
      "another app's database (skipPrefix)": widen((m) => { m.permissions.push({ service: "tinycloud.sql", path: "xyz.tinycloud.sample.recipes/recipes", actions: ["read"], skipPrefix: true }); }),
      "another app's files (skipPrefix)": widen((m) => { m.permissions.push({ service: "tinycloud.kv", path: "xyz.tinycloud.sample.recipes/", actions: ["get", "list"], skipPrefix: true }); }),
      "the default tier switched on": widen((m) => { delete m.defaults; }),
      "the admin tier": widen((m) => { m.defaults = "admin"; }),
      "a grant of the whole space": widen((m) => { m.permissions.push({ service: "tinycloud.kv", path: "", actions: ["get", "put", "list", "del"], skipPrefix: true }); }),
    };
    for (const [name, manifest] of Object.entries(cases)) expect(await refusal(manifest), name).toMatch(/^widened: /);
  });

  it("refuses what this page cannot grant, instead of signing it", async () => {
    const edit = (change: (manifest: TestManifest) => void): TestManifest => { const manifest = manifestOf(health); change(manifest); return manifest; };
    expect(await refusal(edit((m) => { m.did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"; }))).toMatch(/^unsupported: /);
    expect(await refusal(edit((m) => { m.secrets = { TOKEN: true }; }))).toMatch(/^unsupported: /);
    expect(await refusal(edit((m) => { m.prefix = ""; }))).toMatch(/^unsupported: /);
    expect(await refusal(edit((m) => { m.space = "secrets"; }))).toMatch(/^unsupported: /);
    expect(await refusal(edit((m) => { m.permissions.push({ service: "tinycloud.vault", path: "x", actions: ["get"], space: "secrets" }); }))).toMatch(/^(unsupported|widened): /);
    expect(await refusal(edit((m) => { permission(m, "healthlog").path = "../recipes/recipes"; }))).toMatch(/^(invalid|widened|unsupported): /);
    expect(await refusal(edit((m) => { m.app_id = RECIPES; }))).toMatch(/^damaged: /);
  });

  it("never signs for more than one hour or for the public space, whatever the copy says", async () => {
    const edit = manifestOf(health);
    edit.expiry = "30d";
    edit.includePublicSpace = true;
    const result = await verifyStoredApp(HEALTH, filesFor(health, edit), deps);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.app.signing.expiry).toBe("1h");
    expect(result.app.signing.includePublicSpace).toBe(false);
    expect(sdkCore.composeManifestRequest([result.app.signing]).expiryMs).toBe(60 * 60 * 1000);
  });

  it("caps against the catalog entry of the digest the install recorded, not any other", async () => {
    const wide = manifestOf(health);
    wide.permissions.push({ service: "tinycloud.kv", path: "extra/", actions: ["get"] });
    // The install recorded a digest the catalog does not list (e.g. an older or invented one).
    const unknown = await verifyStoredApp(HEALTH, filesFor(health, wide, { "install.json": installRecord(health, { digest: "0".repeat(64) }) }), deps);
    expect(unknown).toMatchObject({ ok: false, failure: { reason: "not-listed" } });
    // The recipes entry's digest does not authorise the Health Log either.
    const swapped = await verifyStoredApp(HEALTH, filesFor(health, manifestOf(health), { "install.json": installRecord(entryOf(RECIPES)) }), deps);
    expect(swapped).toMatchObject({ ok: false, failure: { reason: "not-listed" } });
  });

  it("fails closed when the catalog manifest cannot be verified", async () => {
    for (const reason of ["unavailable", "mismatch"] as const) {
      const result = await verifyStoredApp(HEALTH, filesFor(health), { ...deps, loadCatalogManifest: async () => ({ ok: false, reason }) });
      expect(result).toMatchObject({ ok: false, failure: { reason: "catalog-unavailable" } });
    }
  });

  it("refuses a damaged copy instead of guessing", async () => {
    const broken = async (over: Record<string, Uint8Array>, remove: string[] = []): Promise<string> => { const result = await verifyStoredApp(HEALTH, storedFiles(health, { files: over, remove }), deps); return result.ok ? "ok" : result.failure.reason; };
    expect(await broken({ "manifest.json": new TextEncoder().encode("{not json") })).toBe("damaged");
    expect(await broken({ "manifest.json": text({ app_id: HEALTH }) })).toBe("damaged");
    expect(await broken({ "manifest.json": new Uint8Array(0) })).toBe("damaged");
    expect(await broken({ "install.json": new TextEncoder().encode("{}") })).toBe("damaged");
    expect(await broken({ "install.json": text({ source: { repo: "r", tag: null, commit: "abc" }, digest: "xyz", installed_at: "x" }) })).toBe("damaged");
    expect(await broken({}, ["manifest.json"])).toBe("damaged");
    expect(await broken({}, ["install.json"])).toBe("damaged");
    expect(await broken({}, ["app.jsx"])).toBe("damaged");
    expect(await broken({ "manifest.json": new Uint8Array(70 * 1024).fill(32) })).toBe("damaged");
  });

  it("reads the install record the install writes, and nothing looser", () => {
    expect(parseInstallRecord(installRecord(health))).toMatchObject({ digest: health.bundle.digest, source: { commit: health.source.commit } });
    expect(parseInstallRecord(text({ source: { repo: "r", tag: null, commit: "d8739346" }, digest: "a".repeat(64), installed_at: "2026-10-20T10:00:00.000Z" }))).not.toBeNull();
    expect(parseInstallRecord(text([]))).toBeNull();
    expect(parseInstallRecord(text({ source: "x", digest: "a".repeat(64), installed_at: "x" }))).toBeNull();
  });
});

describe("pathCovers", () => {
  it.each([
    ["a/", "a/b", true],
    ["a/", "a/", true],
    ["a/", "a", false],
    ["a", "a", true],
    ["a", "a/b", false],
    ["a", "ab", false],
    ["a/", "ab", false],
    ["", "anything", true],
  ])("%s covers %s: %s", (grant, target, expected) => {
    expect(pathCovers(grant, target)).toBe(expected);
  });
});

describe("the authorizer built from the resolved manifest", () => {
  const recipes = entryOf(RECIPES);
  const authorize = makeAuthorizer(sdkCore.validateManifest(manifestOf(recipes)), sdk);

  it("allows what the manifest says, in the app's own folder", () => {
    expect(authorize("tinycloud.sql", `${RECIPES}/recipes`, "read", false)).toBe(true);
    expect(authorize("tinycloud.sql", `${RECIPES}/recipes`, "write", false)).toBe(true);
    expect(authorize("tinycloud.sql", `${RECIPES}/recipes`, "schema", false)).toBe(true);
    expect(authorize("tinycloud.kv", `${RECIPES}/prefs/settings.json`, "put", false)).toBe(true);
    expect(authorize("tinycloud.kv", `${RECIPES}/knowledge/index.md`, "list", false)).toBe(true);
    expect(authorize("tinycloud.kv", `${RECIPES}/app/app.jsx`, "get", false)).toBe(true);
  });

  it("refuses everything the manifest does not say", () => {
    expect(authorize("tinycloud.kv", `${RECIPES}/app/app.jsx`, "put", false)).toBe(false);
    expect(authorize("tinycloud.kv", `${RECIPES}/app/app.jsx`, "del", false)).toBe(false);
    expect(authorize("tinycloud.kv", `${RECIPES}/`, "list", false)).toBe(false);
    expect(authorize("tinycloud.kv", `${RECIPES}/photos/a.jpg`, "get", false)).toBe(false);
    expect(authorize("tinycloud.sql", `${RECIPES}/other`, "read", false)).toBe(false);
    expect(authorize("tinycloud.sql", `${HEALTH}/healthlog`, "write", true)).toBe(false);
  });

  it("allows another app's database only for the read the manifest names, and only through a skipPrefix grant", () => {
    expect(authorize("tinycloud.sql", `${HEALTH}/healthlog`, "read", true)).toBe(true);
    expect(authorize("tinycloud.sql", `${HEALTH}/healthlog`, "write", true)).toBe(false);
    expect(authorize("tinycloud.sql", `${HEALTH}/healthlog`, "schema", true)).toBe(false);
    expect(authorize("tinycloud.sql", `${HEALTH}/other`, "read", true)).toBe(false);
    expect(authorize("tinycloud.kv", `${HEALTH}/knowledge/index.md`, "get", true)).toBe(false);
    // Spelled without the leading slash it would resolve under the Recipes folder, where nothing grants it.
    expect(authorize("tinycloud.sql", `${RECIPES}/${HEALTH}/healthlog`, "read", false)).toBe(false);
  });

  it("a leading slash on the app's own folder is not a way around the relative grants", () => {
    // Absolute paths need a skipPrefix grant to cover them; the app's own folder has none.
    expect(authorize("tinycloud.kv", `${RECIPES}/prefs/settings.json`, "get", true)).toBe(false);
    expect(authorize("tinycloud.sql", `${RECIPES}/recipes`, "read", true)).toBe(false);
  });
});

describe("the sign-in helper's own scope check, derived from the catalog manifest", () => {
  const scopeCheck = (manifest: unknown, scope: ReturnType<typeof runtimeScope>): string => {
    try { assertManifestInScope(sdkCore.validateManifest(manifest), scope, MANIFEST_CHECK_ADDRESS); return "accepted"; } catch (error) { return error instanceof ManifestRejectedError ? error.code : String(error); }
  };

  it.each([HEALTH, RECIPES])("accepts %s's own manifest, including its cross-app read and its schema action", (appId) => {
    const entry = entryOf(appId);
    const catalogManifest = sdkCore.validateManifest(manifestOf(entry));
    const scope = runtimeScope(catalogManifest, sdk);
    expect(scope.allowedSpaces).toEqual(["applications"]);
    expect(scope.allowedServices).toEqual(["kv", "sql"]);
    expect(scopeCheck({ ...manifestOf(entry), expiry: "1h", includePublicSpace: false }, scope)).toBe("accepted");
  });

  it("refuses what the catalog manifest did not name, before OpenKey would open", () => {
    const entry = entryOf(HEALTH);
    const scope = runtimeScope(sdkCore.validateManifest(manifestOf(entry)), sdk);
    const widen = (change: (manifest: TestManifest) => void): string => { const manifest = manifestOf(entry); change(manifest); return scopeCheck({ ...manifest, expiry: "1h", includePublicSpace: false }, scope); };
    expect(widen((m) => { m.permissions.push({ service: "tinycloud.kv", path: "photos/", actions: ["get"] }); })).toBe("path-not-allowed");
    expect(widen((m) => { m.permissions.push({ service: "tinycloud.sql", path: `${RECIPES}/recipes`, actions: ["read"], skipPrefix: true }); })).toBe("path-not-allowed");
    expect(widen((m) => { m.permissions.push({ service: "tinycloud.kv", path: "prefs/", actions: ["del"] }); })).toBe("action-not-allowed");
    expect(widen((m) => { m.permissions.push({ service: "tinycloud.duckdb", path: "x", actions: ["read"] }); })).toBe("service-not-allowed");
    expect(widen((m) => { m.permissions.push({ service: "tinycloud.kv", path: "x/", actions: ["get"], space: "secrets" }); })).toBe("space-not-allowed");
    expect(widen((m) => { m.defaults = "admin"; })).not.toBe("accepted");
  });
});

describe("the code pin: every code file under app/ is the catalog's, byte for byte", () => {
  const health = entryOf(HEALTH);
  const run = async (over: StoredOverrides): Promise<string> => {
    const result = await verifyStoredApp(HEALTH, storedFiles(health, over), deps);
    return result.ok ? "ok" : `${result.failure.reason}: ${result.failure.detail}`;
  };
  const mutate = (bytes: Uint8Array): Uint8Array => { const copy = new Uint8Array(bytes); copy[copy.length - 1] = copy[copy.length - 1]! ^ 1; return copy; };

  it("runs the installed copy as it is", async () => {
    expect(await run({})).toBe("ok");
    expect(codePins(health).map((pin) => pin.path)).toEqual(expect.arrayContaining(["app.jsx", "schema.sql"]));
    expect(codePins(health).map((pin) => pin.path)).not.toContain("manifest.json");
    expect(codePins(health).some((pin) => pin.path.startsWith("knowledge/"))).toBe(false);
  });

  it("refuses an edited app.jsx, by one bit or by an appended line", async () => {
    expect(await run({ files: { "app.jsx": mutate(read(health, "app.jsx")) } })).toMatch(/^code-mismatch: app\.jsx differs/);
    expect(await run({ files: { "app.jsx": new TextEncoder().encode(`${new TextDecoder().decode(read(health, "app.jsx"))}\nfetch("https://x.example");\n`) } })).toMatch(/^code-mismatch: app\.jsx differs/);
  });

  it("refuses any other edited code file, a missing one, and an extra one", async () => {
    expect(await run({ files: { "schema.sql": mutate(read(health, "schema.sql")) } })).toMatch(/^code-mismatch: schema\.sql differs/);
    expect(await run({ remove: ["schema.sql"] })).toMatch(/^code-mismatch: missing file schema\.sql/);
    expect(await run({ files: { "extra.js": new TextEncoder().encode("1") } })).toMatch(/^code-mismatch: unexpected file extra\.js/);
    expect(await run({ files: { "nested/dir/file.jsx": new TextEncoder().encode("1") } })).toMatch(/^code-mismatch: unexpected file nested\/dir\/file\.jsx/);
  });

  it("refuses a listing or a read that was cut short", async () => {
    expect(await run({ incomplete: true })).toMatch(/^code-mismatch: the saved files could not all be read/);
  });

  it("the manifest is capped, not pinned (a narrowing edit still runs); install.json is the install's own record", async () => {
    const narrowed = manifestOf(health);
    narrowed.permissions = narrowed.permissions.filter((entry) => entry.path !== "knowledge/");
    expect(await run({ files: { "manifest.json": text(narrowed) } })).toBe("ok");
    expect(await run({ files: { "install.json": installRecord(health, { installed_at: "2027-01-01T00:00:00.000Z" }) } })).toBe("ok");
  });

  it("is checked before the catalog manifest is fetched or any grant is looked at", async () => {
    const loader = vi.fn(okCatalogManifest);
    const result = await verifyStoredApp(HEALTH, storedFiles(health, { files: { "app.jsx": mutate(read(health, "app.jsx")) } }), { ...deps, loadCatalogManifest: loader });
    expect(result).toMatchObject({ ok: false, failure: { reason: "code-mismatch" } });
    expect(loader).not.toHaveBeenCalled();
  });

  it("an entry that lists no app.jsx cannot be run", async () => {
    const noSource: CatalogEntry = { ...health, bundle: { ...health.bundle, files: health.bundle.files.filter((file) => file.path !== "app.jsx") } };
    expect(await pinProblem(noSource, storedFiles(health))).toMatch(/no app\.jsx/);
  });
});
