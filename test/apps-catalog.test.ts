import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { fileListDigest, verifyCatalog } from "../scripts/apps-catalog.mjs";
import { summarizeAccess } from "../src/apps/access.ts";
import { catalog } from "../src/apps/catalog.ts";

const scratch: string[] = [];
afterAll(() => { for (const dir of scratch) rmSync(dir, { recursive: true, force: true }); });
const tempDir = (): string => {
  const dir = mkdtempSync(join(tmpdir(), "apps-catalog-test-"));
  scratch.push(dir);
  return dir;
};

/** A private copy of public/apps and the catalog, free to damage. */
function privateCopy(): { publicDir: string; catalog: typeof catalog; folder: string } {
  const publicDir = tempDir();
  cpSync("public/apps", join(publicDir, "apps"), { recursive: true });
  const copy = structuredClone(catalog);
  return { publicDir, catalog: copy, folder: join(publicDir, "apps", "b", copy.apps[0]?.bundle.digest ?? "") };
}

describe("apps catalog digests", () => {
  it("every entry's digests and file hashes match the committed bytes", () => {
    expect(catalog.apps.length).toBeGreaterThan(0);
    expect(verifyCatalog(catalog, "public")).toEqual([]);
  });

  it("detects a changed byte in a vendored file", () => {
    const { publicDir, catalog: copy, folder } = privateCopy();
    const target = join(folder, "knowledge", "kv.md");
    writeFileSync(target, `${readFileSync(target, "utf8")}\ntampered`);
    const errors = verifyCatalog(copy, publicDir);
    expect(errors.some((error) => error.includes("knowledge/kv.md") && error.includes("do not match"))).toBe(true);
    expect(errors.some((error) => error.includes("does not hash to bundle.digest"))).toBe(true);
  });

  it("detects a file added to or removed from a bundle folder", () => {
    const added = privateCopy();
    writeFileSync(join(added.folder, "extra.js"), "alert(1)");
    expect(verifyCatalog(added.catalog, added.publicDir).some((error) => error.includes("extra.js") && error.includes("not listed"))).toBe(true);

    const removed = privateCopy();
    rmSync(join(removed.folder, "schema.sql"));
    expect(verifyCatalog(removed.catalog, removed.publicDir).some((error) => error.includes("schema.sql") && error.includes("missing"))).toBe(true);
  });

  it("detects a catalog edited to disagree with its own file list", () => {
    const { publicDir, catalog: copy } = privateCopy();
    const entry = copy.apps[0];
    if (entry === undefined) throw new Error("catalog is empty");
    const file = entry.bundle.files.find((candidate) => candidate.path === "schema.sql");
    if (file === undefined) throw new Error("fixture file missing");
    file.sha256 = "0".repeat(64);
    expect(verifyCatalog(copy, publicDir).some((error) => error.includes("bundle.digest does not match the declared file list"))).toBe(true);

    const wrongManifest = structuredClone(catalog);
    const first = wrongManifest.apps[0];
    if (first === undefined) throw new Error("catalog is empty");
    first.manifest.sha256 = "1".repeat(64);
    first.knowledge = { ...(first.knowledge as { root: string; digest: string }), digest: "2".repeat(64) };
    const errors = verifyCatalog(wrongManifest, "public");
    expect(errors.some((error) => error.includes("manifest.sha256"))).toBe(true);
    expect(errors.some((error) => error.includes("knowledge.digest"))).toBe(true);
  });

  it("detects a bundle folder that no entry pins", () => {
    const { publicDir, catalog: copy } = privateCopy();
    mkdirSync(join(publicDir, "apps", "b", "f".repeat(64)));
    expect(verifyCatalog(copy, publicDir)).toEqual([`public/apps/b/${"f".repeat(64)}: not referenced by any catalog entry`]);
  });

  // Independent vectors (sha256sum of the literal text) pin the contract an installer re-implements:
  // sorted by UTF-16 code unit ("B" before "a"), one `<sha256> <size> <path>\n` line per file.
  it("hashes the sorted file list, not the order given or the locale order", () => {
    const sha = "b".repeat(64);
    expect(fileListDigest([{ path: "a.md", sha256: sha, size: 12 }, { path: "B.md", sha256: sha, size: 12 }]))
      .toBe("34778f98a65cd6391358ed6cddf523b3e66a8e54acab5fe31c4fbe5a796106d5");
    expect(fileListDigest([{ path: "knowledge/b c.md", sha256: sha, size: 12 }, { path: "a.md", sha256: "a".repeat(64), size: 3 }]))
      .toBe("bbcfca04f0945912fc62b10154a08346a63b8cbb0d9a0ba6a009339bf4e47347");
  });
});

describe("scripts/vendor-app.mjs", () => {
  const git = (cwd: string, ...args: string[]): string => {
    const result = spawnSync("git", args, { cwd, encoding: "utf8" });
    if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr}`);
    return result.stdout.trim();
  };
  // The catalog only accepts https sources; git's insteadOf points the test's https URL at a local repo.
  let localRepo = "";
  const vendor = (spec: string, catalogFile: string, publicDir: string, ...extra: string[]) =>
    spawnSync("node", ["scripts/vendor-app.mjs", spec, "--catalog", catalogFile, "--public", publicDir, ...extra], {
      encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: `url.file://${localRepo}.insteadOf`, GIT_CONFIG_VALUE_0: "https://example.test/app-repo" },
    });

  it("pins a tag, replaces a superseded bundle on update, and refuses a branch", () => {
    const work = tempDir();
    const repo = join(work, "app-repo");
    mkdirSync(join(repo, "tinycloud", "app", "knowledge"), { recursive: true });
    git(repo, "init", "-q", "-b", "main");
    git(repo, "config", "user.email", "test@example.com");
    git(repo, "config", "user.name", "Test");
    const write = (version: string): void => {
      writeFileSync(join(repo, "tinycloud", "app", "manifest.json"), JSON.stringify({ app_id: "test.vendored", name: "Vendored", description: `Version ${version}.`, defaults: false }));
      writeFileSync(join(repo, "tinycloud", "app", "knowledge", "index.md"), `# ${version}\n`);
    };
    write("one");
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "one"); git(repo, "tag", "v1");
    const first = git(repo, "rev-parse", "HEAD");
    write("two");
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "two"); git(repo, "tag", "v2");

    const catalogFile = join(work, "catalog.json");
    const publicDir = join(work, "public");
    const url = "https://example.test/app-repo";
    localRepo = repo;
    expect(vendor(`${url}@v1`, catalogFile, publicDir).status).toBe(1); // new app needs a publisher
    const added = vendor(`${url}@v1`, catalogFile, publicDir, "--publisher", "Tests");
    expect(added.stderr).toBe("");
    const v1 = JSON.parse(readFileSync(catalogFile, "utf8")).apps[0];
    expect(v1.source).toEqual({ repo: url, tag: "v1", commit: first });
    expect(v1.publisher).toEqual({ name: "Tests" });
    expect(verifyCatalog(JSON.parse(readFileSync(catalogFile, "utf8")), publicDir)).toEqual([]);

    expect(vendor(`${url}@v2`, catalogFile, publicDir).status).toBe(0); // publisher kept from the entry
    const after = JSON.parse(readFileSync(catalogFile, "utf8"));
    expect(after.apps).toHaveLength(1);
    expect(after.apps[0].bundle.digest).not.toBe(v1.bundle.digest);
    expect(after.apps[0].description).toBe("Version two.");
    expect(readdirSync(join(publicDir, "apps", "b"))).toEqual([after.apps[0].bundle.digest]);
    expect(verifyCatalog(after, publicDir)).toEqual([]);

    const branch = vendor(`${url}@main`, catalogFile, publicDir);
    expect(branch.status).toBe(1);
    expect(branch.stderr).toContain("refs/tags/main");
    expect(JSON.parse(readFileSync(catalogFile, "utf8"))).toEqual(after);
  }, 60_000);
});

describe("what an app can read and change", () => {
  const own = <T extends { service: string }>(items: T[]): T[] => items.filter((item) => item.service !== "Capabilities");

  it("lists the vendored example by what the SDK would grant, and not its descriptive resources block", () => {
    const entry = catalog.apps[0];
    if (entry === undefined) throw new Error("catalog is empty");
    const manifest = JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8"));
    expect(manifest.resources).toBeDefined(); // the kit example documents SQL schema changes and a secret there; the SDK grants neither
    const summary = summarizeAccess(manifest);
    const targets = [...summary.read, ...summary.change].map((item) => `${item.service} ${item.actions.join(",")} ${item.target}`);
    expect(targets).toEqual([
      "Key-value get,list,metadata com.example.notes/*",
      "SQL database read com.example.notes/*",
      "Capabilities read applications",
      "Key-value get,metadata everything in your public space",
      "Key-value put,del com.example.notes/*",
      "SQL database write com.example.notes/*",
      "Key-value put everything in your public space",
    ]);
  });

  it("treats a missing or unrecognised `defaults` as the standard grant, and only `false` as none", () => {
    const base = { app_id: "t.app", name: "T" };
    const defaultsFor = (defaults: unknown) => summarizeAccess({ ...base, ...(defaults === undefined ? {} : { defaults }) }).change.filter((item) => item.description?.includes("default grant"));
    expect(defaultsFor(undefined)).toHaveLength(2);
    expect(defaultsFor("none")).toHaveLength(2); // the SDK reads "none" as standard; only boolean false disables it
    expect(defaultsFor(false)).toHaveLength(0);
    expect(summarizeAccess({ ...base, defaults: "admin" }).change.some((item) => item.actions.includes("schema"))).toBe(true);
    expect(summarizeAccess({ ...base, defaults: "all" }).read.some((item) => item.service === "DuckDB")).toBe(true);
  });

  it("counts unknown actions as changes, honours skipPrefix, and shows a missing description as missing", () => {
    const summary = summarizeAccess({
      app_id: "t.app", name: "T", defaults: false, includePublicSpace: false,
      permissions: [
        { service: "tinycloud.kv", path: "other.app/photos/", skipPrefix: true, actions: ["get", "list"], description: "Show photos. Read only." },
        { service: "tinycloud.kv", path: "inbox/", actions: ["tinycloud.kv/put", "frobnicate"] },
      ],
    });
    expect(own(summary.read)).toEqual([{ description: "Show photos. Read only.", service: "Key-value", space: null, target: "other.app/photos/", actions: ["get", "list"] }]);
    expect(own(summary.change)).toEqual([{ description: null, service: "Key-value", space: null, target: "t.app/inbox/", actions: ["put", "frobnicate"] }]);
  });

  it("lists `secrets` (an object keyed by name) as vault grants in the secrets space", () => {
    const summary = summarizeAccess({
      app_id: "t.app", name: "T", defaults: false, includePublicSpace: false,
      secrets: {
        OPENAI_KEY: ["read", "write"],
        TOKEN: true,
        SESSION: { name: "session-key", scope: "chat", actions: "delete", description: "Signs the chat session." },
      },
    });
    expect(own(summary.read).map((item) => `${item.target} ${item.actions}`)).toEqual(["OPENAI_KEY get", "TOKEN get"]);
    expect(own(summary.change)).toEqual([
      { description: null, service: "Secret", space: "secrets", target: "OPENAI_KEY", actions: ["put"] },
      { description: "Signs the chat session.", service: "Secret", space: "secrets", target: "chat/session-key", actions: ["del"] },
    ]);
  });

  it("shows an entry's own space, adds capabilities/read per space, and the public space unless opted out", () => {
    const manifest = { app_id: "t.app", name: "T", defaults: false, permissions: [{ service: "tinycloud.kv", space: "account", path: "prefs/", actions: ["get"] }] };
    const summary = summarizeAccess(manifest);
    expect(summary.read.map((item) => `${item.service} ${item.space ?? "-"} ${item.target}`)).toEqual([
      "Key-value account t.app/prefs/",
      "Capabilities account account",
      "Key-value public everything in your public space",
    ]);
    expect(summarizeAccess({ ...manifest, includePublicSpace: false }).read.some((item) => item.space === "public")).toBe(false);
    // A manifest that asks for nothing is not given the additions.
    expect(summarizeAccess({ app_id: "t.app", name: "T", defaults: false })).toEqual({ read: [], change: [] });
  });

  it("yields an empty summary for a manifest of the wrong shape", () => {
    for (const junk of [null, "x", 3, [], { defaults: false, permissions: "all", secrets: 4 }]) {
      expect(summarizeAccess(junk)).toEqual({ read: [], change: [] });
    }
  });
});
