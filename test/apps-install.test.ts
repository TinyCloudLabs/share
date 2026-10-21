import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { type BundleFetch, type BundleResponse, INSTALL_RECORD_PATH, bundleDigest, fetchVerifiedBundle, installPathProblem, sha256Hex } from "../src/apps/bundle.ts";
import { EntryDisabledError, MAX_DISABLED_REASON_CHARS, type CatalogEntry, assertAvailable, availabilityOf, catalog } from "../src/apps/catalog.ts";
import { SQL_CHANGE_NOTICE, consentFor } from "../src/apps/consent.ts";
import { MAX_DISABLED_REASON_CHARS as buildTimeReasonCap, installPathProblem as buildTimePathProblem } from "../scripts/apps-catalog.mjs";

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

describe("a manifest that does not match its catalog entry is refused", () => {
  /** A copy of the entry that pins `manifestBytes` as its manifest (digests recomputed), and a server that serves them. */
  async function forgedWith(manifestBytes: Uint8Array<ArrayBuffer>): Promise<{ forged: CatalogEntry; fetch: BundleFetch }> {
    const entry = entryOf(HEALTH);
    const forged = structuredClone(entry);
    const file = forged.bundle.files.find((candidate) => candidate.path === "manifest.json");
    if (file === undefined) throw new Error("fixture");
    file.sha256 = await sha256Hex(manifestBytes);
    file.size = manifestBytes.byteLength;
    forged.manifest.sha256 = file.sha256;
    forged.bundle.digest = await bundleDigest(forged.bundle.files);
    forged.bundle.root = `/apps/b/${forged.bundle.digest}/`;
    return { forged, fetch: async (url: string): Promise<FetchResult> => ({ ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(url.endsWith("manifest.json") ? manifestBytes : readFileSync(join("public", entry.bundle.root, url.slice(forged.bundle.root.length)))) }) };
  }
  const healthManifest = (): Record<string, unknown> => JSON.parse(readFileSync(join("public", entryOf(HEALTH).bundle.root, "manifest.json"), "utf8"));

  it("a manifest whose app_id or name differs from the catalog entry is refused", async () => {
    const { forged, fetch } = await forgedWith(new TextEncoder().encode(JSON.stringify({ ...healthManifest(), name: "Other" })));
    await expect(fetchVerifiedBundle(forged, fetch)).rejects.toMatchObject({ reason: "catalog" });
  });
});

describe("a hostile or odd catalog entry is rejected at load, before any fetch", () => {
  const hostile = ["../escape.txt", "a/../../b", "/etc/passwd", "a\\b.txt", "a\u0000b.txt", "nul\u0000", ".hidden", "knowledge/.env", "a//b", "a/./b", "", INSTALL_RECORD_PATH, "has space.md", "naïve.md", "dev/shim.mjs", "node_modules/dep/index.js", "knowledge/tests/a.md", "Scripts/run.mjs", "test/x.md", `${"a/".repeat(9)}b`, "x".repeat(200)];

  it.each(hostile.map((path) => [JSON.stringify(path), path]))("path %s", async (_label, path) => {
    expect(installPathProblem(path)).not.toBeNull();
    expect(buildTimePathProblem(path)).not.toBeNull();
    const entry = structuredClone(entryOf(HEALTH));
    entry.bundle.files.push({ path, sha256: "a".repeat(64), size: 1 });
    const fetchSpy = vi.fn();
    // Refused for the PATH (not just because the digest no longer follows), before any fetch.
    await expect(fetchVerifiedBundle(entry, fetchSpy)).rejects.toMatchObject({ reason: "catalog", message: expect.stringContaining("file path") });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses two paths that differ only by case, for that reason, before any fetch", async () => {
    const entry = structuredClone(entryOf(HEALTH));
    entry.bundle.files.push({ path: "App.jsx", sha256: "a".repeat(64), size: 1 });
    const fetchSpy = vi.fn();
    await expect(fetchVerifiedBundle(entry, fetchSpy)).rejects.toMatchObject({ reason: "catalog", message: expect.stringContaining("differ only by case") });
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

describe("what the pre-consent sheet says", () => {
  const manifestOf = (entry: CatalogEntry): unknown => JSON.parse(readFileSync(join("public", entry.bundle.root, "manifest.json"), "utf8"));

  it("an app that writes SQL says so plainly", () => {
    const entry = entryOf(HEALTH);
    const { notices, runtime } = consentFor(entry, manifestOf(entry), catalog.apps);
    expect(notices).toContain(SQL_CHANGE_NOTICE);
    expect(SQL_CHANGE_NOTICE).toBe("This app can change or delete its own tables.");
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

  it("an app with the default grants still says it can change or delete its own tables", () => {
    const entry = entryOf("com.example.notes");
    const { notices } = consentFor(entry, manifestOf(entry), catalog.apps);
    expect(notices).toEqual([SQL_CHANGE_NOTICE]);
  });

  it("an app that does not write SQL has no SQL notice", () => {
    const entry = entryOf(HEALTH);
    const readOnly = { app_id: entry.app_id, name: "R", defaults: false, permissions: [{ service: "tinycloud.sql", path: "db", actions: ["read"] }] };
    expect(consentFor(entry, readOnly, catalog.apps).notices).toEqual([]);
  });
});

describe("the kill switch", () => {
  const off = (reason?: string): CatalogEntry => ({ ...entryOf(HEALTH), disabled: true, ...(reason === undefined ? {} : { disabledReason: reason }) });

  it("an entry is available unless it says otherwise, and a disabled one carries its reason", () => {
    expect(availabilityOf(entryOf(HEALTH))).toEqual({ available: true });
    expect(availabilityOf(off("Pulled."))).toEqual({ available: false, reason: "Pulled." });
    expect(availabilityOf(off("   "))).toEqual({ available: false, reason: "This app is temporarily unavailable." });
    expect(availabilityOf(off())).toEqual({ available: false, reason: "This app is temporarily unavailable." });
    // Only `true` switches it off.
    expect(availabilityOf({ ...entryOf(HEALTH), disabled: false } as unknown as CatalogEntry)).toEqual({ available: true });
  });

  it("cuts a reason over the cap at render time, with a mark, using the same cap as the catalog check", () => {
    expect(MAX_DISABLED_REASON_CHARS).toBe(buildTimeReasonCap);
    const long = off("é".repeat(MAX_DISABLED_REASON_CHARS + 50));
    const shown = availabilityOf(long);
    expect(shown.available).toBe(false);
    if (shown.available) throw new Error("unreachable");
    expect([...shown.reason]).toHaveLength(MAX_DISABLED_REASON_CHARS);
    expect(shown.reason.endsWith("…")).toBe(true);
    const exact = off("x".repeat(MAX_DISABLED_REASON_CHARS));
    expect(availabilityOf(exact)).toEqual({ available: false, reason: "x".repeat(MAX_DISABLED_REASON_CHARS) });
  });

  it("assertAvailable is the runner's gate: it throws for a disabled entry and for nothing else", () => {
    expect(() => assertAvailable(entryOf(HEALTH))).not.toThrow();
    expect(() => assertAvailable(off("Pulled."))).toThrow(EntryDisabledError);
    try { assertAvailable(off("Pulled.")); } catch (error) { expect((error as EntryDisabledError).reason).toBe("Pulled."); }
  });

});
