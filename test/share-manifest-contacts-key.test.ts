// @vitest-environment node
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { afterAll, describe, expect, it } from "vitest";
import type { Plugin } from "vite";
import { OPENKEY_MANIFEST_PATH, renderOpenKeyManifestJson, shareManifest } from "../src/share/share-manifest.js";
import viteConfig from "../vite.config.ts";

const ROOT = resolve(import.meta.dirname, "..");
const run = promisify(execFile);
const outDirs: string[] = [];
const APP_KEYS_FILE = new URL("../public/.well-known/openkey-app-keys.json", import.meta.url);
const OPENKEY_MAX_BYTES = 64 * 1024;
const OPENKEY_ABILITIES = ["key.create", "decrypt", "key.block", "key.unblock"];
/** The exact key sealed Contacts uses (the Share and Contacts contract). */
const CONTACTS_SEAL_KEY_PATH = "apps/xyz.tinycloud.share/xyz.tinycloud.tinyapps.contacts/seal-v1";

/**
 * The rules OpenKey applies to a `keys` block: one of `path` or `prefix` per entry, a non-empty de-duplicated
 * ability list from a fixed set, at most 32 entries, no other field, and a path of `apps/<app id>/` plus 1 to 8
 * segments of [a-z0-9._-] (8 counting `apps`, 255 characters in all). Any fault makes the whole block invalid.
 */
function openKeyAcceptsKeys(appId: string, keys: unknown): boolean {
  if (!Array.isArray(keys) || keys.length > 32) return false;
  const segment = /^[a-z0-9][a-z0-9._-]{0,63}$/;
  const seen = new Set<string>();
  for (const entry of keys) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
    // A plain object, checked just above; read as a record so its fields can be examined.
    const record: Record<string, unknown> = entry;
    if (Object.keys(record).some((field) => !["path", "prefix", "abilities"].includes(field))) return false;
    const abilities = record["abilities"];
    if (!Array.isArray(abilities) || abilities.length === 0 || new Set(abilities).size !== abilities.length) return false;
    if (abilities.some((ability) => typeof ability !== "string" || !OPENKEY_ABILITIES.includes(ability))) return false;
    const hasPath = "path" in record;
    if (hasPath === "prefix" in record) return false;
    if (!hasPath) continue;
    const path = record["path"];
    if (typeof path !== "string" || seen.has(path)) return false;
    seen.add(path);
    const parts = path.split("/");
    // OpenKey: at most 8 segments counting `apps`, at least 3, every segment valid, the whole path at most 255 characters.
    if (path.length > 255 || parts[0] !== "apps" || parts[1] !== appId || parts.length < 3 || parts.length > 8) return false;
    if (!parts.every((part) => segment.test(part))) return false;
  }
  return true;
}

function resolvedConfig() {
  const resolved = typeof viteConfig === "function"
    ? viteConfig({ command: "build", mode: "production", isSsrBuild: false, isPreview: false })
    : viteConfig;
  if (resolved instanceof Promise) throw new Error("unexpected async vite config");
  return resolved;
}

afterAll(() => { for (const dir of outDirs) rmSync(dir, { recursive: true, force: true }); });

describe("TC-4036 the published app-keys file for sealed Contacts", () => {
  const bytes = readFileSync(APP_KEYS_FILE);
  const parsed: unknown = JSON.parse(bytes.toString("utf8"));

  it("is exactly the type tag, the app id and one exact-path entry with decrypt and key.create", () => {
    expect(parsed).toEqual({
      type: "openkey-app-keys",
      app_id: "xyz.tinycloud.share",
      keys: [{ path: CONTACTS_SEAL_KEY_PATH, abilities: ["decrypt", "key.create"] }],
    });
    // OpenKey refuses a file with any other top-level field, so the field list is pinned in order too.
    expect(Object.keys(parsed as object)).toEqual(["type", "app_id", "keys"]);
    expect(bytes.toString("utf8").endsWith("\n")).toBe(true);
  });

  it("passes every rule OpenKey applies, and the checker refuses what OpenKey refuses", () => {
    expect(bytes.length).toBeLessThanOrEqual(OPENKEY_MAX_BYTES);
    const record = parsed as { type: string; app_id: string; keys: unknown };
    expect(record.type).toBe("openkey-app-keys");
    expect(openKeyAcceptsKeys(record.app_id, record.keys)).toBe(true);
    const app = "xyz.tinycloud.share";
    expect(openKeyAcceptsKeys(app, [{ path: CONTACTS_SEAL_KEY_PATH, prefix: `apps/${app}/`, abilities: ["decrypt"] }])).toBe(false);
    expect(openKeyAcceptsKeys(app, [{ path: "apps/xyz.tinycloud.other/a/b", abilities: ["decrypt"] }])).toBe(false);
    expect(openKeyAcceptsKeys(app, [{ path: CONTACTS_SEAL_KEY_PATH, abilities: ["decrypt"], note: "x" }])).toBe(false);
    expect(openKeyAcceptsKeys(app, [{ path: CONTACTS_SEAL_KEY_PATH, abilities: ["decrypt", "decrypt"] }])).toBe(false);
    expect(openKeyAcceptsKeys(app, [{ path: CONTACTS_SEAL_KEY_PATH, abilities: [] }])).toBe(false);
    expect(openKeyAcceptsKeys(app, [{ path: `apps/${app}/a/b/c/d/e/f`, abilities: ["decrypt"] }])).toBe(true);
    expect(openKeyAcceptsKeys(app, [{ path: `apps/${app}/a/b/c/d/e/f/g`, abilities: ["decrypt"] }])).toBe(false);
    expect(openKeyAcceptsKeys(app, [{ path: `apps/${app}/${"a".repeat(64)}/${"b".repeat(64)}/${"c".repeat(64)}/${"d".repeat(64)}`, abilities: ["decrypt"] }])).toBe(false);
  });

  it("is built into the output as a plain file, byte-identical, with no redirect rule that matches it", async () => {
    const out = mkdtempSync(join(tmpdir(), "app-keys-"));
    outDirs.push(out);
    await run(process.execPath, ["node_modules/vite/bin/vite.js", "build", "--outDir", out, "--emptyOutDir"], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });
    const built = readFileSync(join(out, ".well-known/openkey-app-keys.json"));
    expect(built.equals(bytes)).toBe(true);
    // No `_redirects` rule may match this path (a page rule like `/s/* /viewer/ 200` must not catch it). The matcher knows only
    // literal paths and `*` wildcards, which is all `_redirects` uses today; a rule with `:splat` or a `:placeholder` source needs it extended.
    // The build audit (`audit-dist`, with gitleaks) is not run here: the deploy build and the gitleaks CI job run it.
    const rules = readFileSync(join(out, "_redirects"), "utf8").split("\n").map((line) => line.trim()).filter((line) => line !== "" && !line.startsWith("#"));
    const meeting = rules.filter((rule) => new RegExp(`^${(rule.split(/\s+/)[0] ?? "").replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test("/.well-known/openkey-app-keys.json"));
    expect(meeting).toEqual([]);
  }, 180_000);

  it("leaves Share's own published manifest and its digest input without any key declaration", () => {
    const plugin = (resolvedConfig().plugins ?? []).flat().find(
      (entry): entry is Plugin => typeof entry === "object" && entry !== null && "name" in entry && entry.name === "openkey-manifest",
    );
    const hook = plugin?.generateBundle;
    const fn = typeof hook === "function" ? hook : hook?.handler;
    if (fn === undefined) throw new Error("openkey-manifest Vite plugin generateBundle not found");
    const emitted: Array<{ fileName: string; source: string }> = [];
    (fn as (this: { emitFile(file: { type: "asset"; fileName: string; source: string }): void }) => void).call({
      emitFile(file) { emitted.push({ fileName: file.fileName, source: file.source }); },
    });
    expect(emitted).toHaveLength(1);
    expect(`/${emitted[0]!.fileName}`).toBe(OPENKEY_MANIFEST_PATH);
    expect(emitted[0]!.source).toBe(renderOpenKeyManifestJson());
    expect(emitted[0]!.source).toBe(`${JSON.stringify(shareManifest, null, 2)}\n`);
    expect(Object.keys(JSON.parse(emitted[0]!.source) as object)).not.toContain("keys");
    expect(Object.keys(JSON.parse(emitted[0]!.source) as object)).not.toContain("keys_app_id");
    expect(JSON.stringify(shareManifest)).not.toContain("seal-v1");
  });
});
