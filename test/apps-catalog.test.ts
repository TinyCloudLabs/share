import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

import { fileListDigest, releaseDigest, sha256Hex, verifyCatalog } from "../scripts/apps-catalog.mjs";
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

  it("pins the kit samples to a full commit, marks them as samples, and checks the kit's own release digest as well", () => {
    const samples = catalog.apps.filter((app) => app.sample === true);
    expect(samples.map((app) => app.app_id)).toEqual(["xyz.tinycloud.sample.healthlog", "xyz.tinycloud.sample.recipes"]);
    for (const app of samples) {
      expect(app.source.tag).toBeNull();
      expect(app.source.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(app.release?.digest).toMatch(/^[0-9a-f]{64}$/);
      expect(app.release?.digest).not.toBe(app.bundle.digest);
      // Only the app's own files: no dev server, tests, scripts or dependencies.
      expect(app.bundle.files.map((file) => file.path).filter((path) => /^(dev|tests|scripts|node_modules)\//.test(path) || path === "package.json")).toEqual([]);
    }
    const wrongRelease = structuredClone(catalog);
    const sample = wrongRelease.apps.find((app) => app.sample === true);
    if (sample?.release === undefined) throw new Error("fixture");
    sample.release.digest = "9".repeat(64);
    expect(verifyCatalog(wrongRelease, "public").some((error) => error.includes("release.digest differs"))).toBe(true);
    const notBoolean = structuredClone(catalog) as unknown as { apps: { sample?: unknown }[] };
    notBoolean.apps[1]!.sample = "yes";
    expect(verifyCatalog(notBoolean, "public").some((error) => error.includes("sample must be true"))).toBe(true);
  });

  describe("the kill switch", () => {
    const clone = () => structuredClone(catalog) as unknown as { apps: Record<string, unknown>[] };

    it("flipping it changes no digest and the catalog stays valid; the bundle bytes are untouched", () => {
      const before = clone();
      const switched = clone();
      Object.assign(switched.apps[0] as object, { disabled: true, disabledReason: "Pulled while a problem is looked into." });
      expect(verifyCatalog(switched, "public")).toEqual([]);
      expect(switched.apps[0]?.bundle).toEqual(before.apps[0]?.bundle);
      expect(switched.apps[0]?.manifest).toEqual(before.apps[0]?.manifest);
    });

    it.each([
      ["disabled: false", { disabled: false }, "disabled must be true"],
      ["disabled without a reason", { disabled: true }, "needs a disabledReason"],
      ["a blank reason", { disabled: true, disabledReason: "   " }, "needs a disabledReason"],
      ["a reason on an enabled entry", { disabledReason: "Why." }, "only on a disabled entry"],
      ["a reason over the limit", { disabled: true, disabledReason: "x".repeat(281) }, "at most 280"],
      ["a reason that is not text", { disabled: true, disabledReason: 5 }, "needs a disabledReason"],
    ])("refuses %s", (_name, patch, message) => {
      const broken = clone();
      Object.assign(broken.apps[0] as object, patch);
      expect(verifyCatalog(broken, "public").some((error) => error.includes(message))).toBe(true);
    });
  });

  it("refuses a catalog manifest the sheet cannot describe: a delegate DID, a prefix or a space that is not text", () => {
    const { publicDir, catalog: copy, folder } = privateCopy();
    const file = join(folder, "manifest.json");
    const original = JSON.parse(readFileSync(file, "utf8"));
    for (const [patch, message] of [[{ did: "did:key:zExample" }, "delegate DID"], [{ prefix: 5 }, "prefix must be text"], [{ prefix: null }, "prefix must be text"], [{ space: ["applications"] }, "space must be text"], [{ space: "  " }, "space must be text"], [{ permissions: [{ service: "tinycloud.kv", path: "a/", actions: ["put"], space: " " }] }, "a permission's space must be text"], [{ permissions: [{ service: "tinycloud.capabilities", path: "", actions: ["read"], space: "account" }] }, "permission-list read"]] as const) {
      writeFileSync(file, JSON.stringify({ ...original, ...patch }));
      expect(verifyCatalog(copy, publicDir).some((error) => error.includes(message)), message).toBe(true);
    }
  });

  it("refuses a catalog whose file list holds a development folder, a case collision or an unsafe path", () => {
    for (const path of ["dev/shim.mjs", "node_modules/x.js", "tests/a.mjs", "scripts/b.mjs", ".hidden/x", "../up.txt", "a\\b", "/abs"]) {
      const bad = structuredClone(catalog);
      bad.apps[0]?.bundle.files.push({ path, sha256: "a".repeat(64), size: 1 });
      expect(verifyCatalog(bad, "public").some((error) => error.includes(`bundle.files[`) && error.includes("path")), path).toBe(true);
    }
    const collide = structuredClone(catalog);
    const first = collide.apps[0];
    if (first === undefined) throw new Error("fixture");
    first.bundle.files = [...first.bundle.files, { path: "Schema.sql", sha256: "b".repeat(64), size: 1 }].sort((a, b) => (a.path < b.path ? -1 : 1));
    expect(verifyCatalog(collide, "public").some((error) => error.includes("differs only by case"))).toBe(true);
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

  /**
   * A kit-style repo: an app folder with a release.json allow-list, plus folders that must never be vendored.
   * `extra` files are created AND listed with their true sha256 (the hostile case: the hashes are right, the path is the problem);
   * `outside` files live in the repo beside the app folder; `symlinkDir` makes `<name>` a symlink to a folder outside the checkout.
   */
  function releaseRepo(options: { tamper?: boolean; extra?: Record<string, string>; outside?: Record<string, string>; listRaw?: string[]; symlinkDir?: string } = {}): { repo: string; url: string } {
    const work = tempDir();
    const repo = join(work, "app-repo");
    const app = join(repo, "examples", "sample");
    mkdirSync(join(app, "knowledge", "tables"), { recursive: true });
    for (const folder of ["dev", "tests", "scripts", "node_modules/dep"]) mkdirSync(join(app, folder), { recursive: true });
    const files: Record<string, string> = {
      "manifest.json": JSON.stringify({ app_id: "test.sample", name: "Sample", description: "A sample.", defaults: false }),
      "app.jsx": "export default () => null;\n",
      "schema.sql": "CREATE TABLE t (id INTEGER);\n",
      "knowledge/index.md": "# index\n",
      "knowledge/tables/t.md": "# t\n",
    };
    for (const [path, text] of Object.entries(files)) writeFileSync(join(app, path), text);
    writeFileSync(join(app, "dev", "shim.mjs"), "secret dev file");
    writeFileSync(join(app, "tests", "x.test.mjs"), "test");
    writeFileSync(join(app, "scripts", "make.mjs"), "script");
    writeFileSync(join(app, "node_modules", "dep", "index.js"), "dep");
    writeFileSync(join(app, "package.json"), "{}");
    const listed = Object.entries(files).map(([path, text]) => ({ path, sha256: sha256Hex(Buffer.from(text)), size: Buffer.byteLength(text) }));
    for (const [path, text] of Object.entries(options.extra ?? {})) {
      mkdirSync(join(app, path, ".."), { recursive: true });
      writeFileSync(join(app, path), text);
      listed.push({ path, sha256: sha256Hex(Buffer.from(text)), size: Buffer.byteLength(text) });
    }
    for (const [path, text] of Object.entries(options.outside ?? {})) {
      mkdirSync(join(repo, path, ".."), { recursive: true });
      writeFileSync(join(repo, path), text);
    }
    // A listed path written exactly as given (backslash, absolute, ..): its true bytes are `raw`.
    for (const path of options.listRaw ?? []) listed.push({ path, sha256: sha256Hex(Buffer.from("raw")), size: 3 });
    if (options.symlinkDir !== undefined) {
      const outside = join(work, "outside");
      mkdirSync(outside);
      writeFileSync(join(outside, "s.txt"), "outside the checkout");
      symlinkSync(outside, join(app, options.symlinkDir));
      listed.push({ path: `${options.symlinkDir}/s.txt`, sha256: sha256Hex(Buffer.from("outside the checkout")), size: 20 });
    }
    const digest = releaseDigest(listed);
    writeFileSync(join(app, "release.json"), JSON.stringify({ schema: "tinycloud.app-release/v1", app_id: "test.sample", version: "0.1.0", digest, files: listed }));
    if (options.tamper === true) writeFileSync(join(app, "app.jsx"), "export default () => 'changed after the release was made';\n");
    git(repo, "init", "-q", "-b", "main");
    git(repo, "config", "user.email", "test@example.com");
    git(repo, "config", "user.name", "Test");
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "one");
    localRepo = repo;
    return { repo, url: "https://example.test/app-repo" };
  }

  it("with a release.json, copies ONLY the files it lists (never dev/, tests/, scripts/ or node_modules), marks a sample, and records both digests", () => {
    const { repo, url } = releaseRepo();
    const work = tempDir();
    const catalogFile = join(work, "catalog.json");
    const publicDir = join(work, "public");
    const commit = git(repo, "rev-parse", "HEAD");
    const run = vendor(`${url}@${commit}`, catalogFile, publicDir, "--path", "examples/sample", "--sample", "--publisher", "Tests");
    expect(run.stderr).toBe("");
    const written = JSON.parse(readFileSync(catalogFile, "utf8"));
    const entry = written.apps[0];
    expect(entry.sample).toBe(true);
    expect(entry.source).toEqual({ repo: url, tag: null, commit });
    expect(entry.release).toEqual({ version: "0.1.0", digest: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(entry.bundle.files.map((file: { path: string }) => file.path)).toEqual(["app.jsx", "knowledge/index.md", "knowledge/tables/t.md", "manifest.json", "release.json", "schema.sql"]);
    expect(entry.release.digest).not.toBe(entry.bundle.digest); // two schemes: the catalog's is the one an installer verifies
    const folder = join(publicDir, "apps", "b", entry.bundle.digest);
    expect(readdirSync(folder).sort()).toEqual(["app.jsx", "knowledge", "manifest.json", "release.json", "schema.sql"]);
    expect(verifyCatalog(written, publicDir)).toEqual([]);

    // The sample flag survives an update that does not repeat it.
    expect(vendor(`${url}@${commit}`, catalogFile, publicDir, "--path", "examples/sample").status).toBe(0);
    expect(JSON.parse(readFileSync(catalogFile, "utf8")).apps[0].sample).toBe(true);
  }, 60_000);

  it("refuses a listed file whose bytes differ from the release", () => {
    const { repo, url } = releaseRepo({ tamper: true });
    const work = tempDir();
    const run = vendor(`${url}@${git(repo, "rev-parse", "HEAD")}`, join(work, "catalog.json"), join(work, "public"), "--path", "examples/sample", "--publisher", "Tests");
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("does not match the sha256");
    expect(readdirSync(work)).toEqual([]);
  }, 60_000);

  // Every case lists the file with its TRUE sha256, so only the path rule can refuse it.
  const hostile: { name: string; options: Parameters<typeof releaseRepo>[0]; message: RegExp }[] = [
    { name: "a dev/ folder", options: { extra: { "dev/shim2.mjs": "dev code" } }, message: /development folder/ },
    { name: "node_modules/", options: { extra: { "node_modules/dep/index2.js": "dep" } }, message: /development folder/ },
    { name: "tests/ and scripts/", options: { extra: { "tests/a.mjs": "t", "scripts/b.mjs": "s" } }, message: /development folder/ },
    { name: "a nested dev folder", options: { extra: { "knowledge/dev/notes.md": "n" } }, message: /development folder/ },
    { name: "a hidden folder", options: { extra: { ".hidden/x.md": "h" } }, message: /letters, digits/ },
    { name: "a hidden file", options: { extra: { ".env": "SECRET=1" } }, message: /letters, digits/ },
    { name: "a .. segment to a real file beside the app", options: { outside: { "examples/secret.txt": "secret" }, listRaw: ["../secret.txt"] }, message: /"\.\." segment/ },
    { name: "an absolute path", options: { listRaw: ["/etc/hostname"] }, message: /must be relative/ },
    { name: "a backslash path", options: { listRaw: ["dir\\file.md"] }, message: /backslash/ },
    { name: "a NUL byte in a path", options: { listRaw: ["a\u0000b.md"] }, message: /control character/ },
    { name: "the reserved install.json", options: { listRaw: ["install.json"] }, message: /reserved/ },
    { name: "paths that differ only by case", options: { extra: { "Knowledge/Index.md": "x", "knowledge/index.MD": "y" } }, message: /differs only by case/ },
    { name: "a file reached through a symlinked folder", options: { symlinkDir: "lnk" }, message: /symlink/ },
  ];

  it.each(hostile.map((item) => [item.name, item]))("refuses %s in release.json, writing nothing", (_name, item) => {
    const { repo, url } = releaseRepo(item.options);
    const work = tempDir();
    const run = vendor(`${url}@${git(repo, "rev-parse", "HEAD")}`, join(work, "catalog.json"), join(work, "public"), "--path", "examples/sample", "--publisher", "Tests");
    expect(run.status, run.stderr).toBe(1);
    expect(run.stderr).toMatch(item.message);
    expect(readdirSync(work)).toEqual([]); // nothing written
  }, 60_000);

  it("refuses an app folder that is itself a symlink, and a release-less folder with a dev/ folder", () => {
    const work = tempDir();
    const repo = join(work, "app-repo");
    mkdirSync(join(repo, "real", "dev"), { recursive: true });
    writeFileSync(join(repo, "real", "manifest.json"), JSON.stringify({ app_id: "test.plain", name: "Plain", description: "d" }));
    writeFileSync(join(repo, "real", "dev", "x.js"), "x");
    symlinkSync(join(repo, "real"), join(repo, "linked"));
    git(repo, "init", "-q", "-b", "main"); git(repo, "config", "user.email", "t@example.com"); git(repo, "config", "user.name", "T");
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "one");
    localRepo = repo;
    const out = tempDir();
    const commit = git(repo, "rev-parse", "HEAD");
    const viaLink = vendor(`https://example.test/app-repo@${commit}`, join(out, "c.json"), join(out, "p"), "--path", "linked", "--publisher", "T");
    expect(viaLink.status).toBe(1);
    expect(viaLink.stderr).toMatch(/symlink/);
    const withDev = vendor(`https://example.test/app-repo@${commit}`, join(out, "c.json"), join(out, "p"), "--path", "real", "--publisher", "T");
    expect(withDev.status).toBe(1);
    expect(withDev.stderr).toMatch(/development folder/);
    expect(readdirSync(out)).toEqual([]);
  }, 60_000);

  it("keeps a kill switch across an update", () => {
    const { repo, url } = releaseRepo();
    const work = tempDir();
    const catalogFile = join(work, "catalog.json");
    const publicDir = join(work, "public");
    const spec = `${url}@${git(repo, "rev-parse", "HEAD")}`;
    expect(vendor(spec, catalogFile, publicDir, "--path", "examples/sample", "--publisher", "Tests").status).toBe(0);
    const switched = JSON.parse(readFileSync(catalogFile, "utf8"));
    switched.apps[0].disabled = true;
    switched.apps[0].disabledReason = "Pulled while a problem is looked into.";
    writeFileSync(catalogFile, JSON.stringify(switched));
    expect(vendor(spec, catalogFile, publicDir, "--path", "examples/sample").status).toBe(0);
    const after = JSON.parse(readFileSync(catalogFile, "utf8")).apps[0];
    expect(after).toMatchObject({ disabled: true, disabledReason: "Pulled while a problem is looked into." });
    expect(verifyCatalog(JSON.parse(readFileSync(catalogFile, "utf8")), publicDir)).toEqual([]);
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
      "Key-value put,del com.example.notes/*",
      "SQL database write com.example.notes/*",
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
    expect(own(summary.read)).toEqual([{ description: "Show photos. Read only.", service: "Key-value", space: null, target: "other.app/photos/", path: "other.app/photos/", actions: ["get", "list"] }]);
    expect(own(summary.change)).toEqual([{ description: null, service: "Key-value", space: null, target: "t.app/inbox/", path: "t.app/inbox/", actions: ["put", "frobnicate"] }]);
  });

  it("lists `secrets` (an object keyed by name) as vault grants in the secrets space", () => {
    const summary = summarizeAccess({
      app_id: "t.app", name: "T", defaults: false, includePublicSpace: false,
      secrets: {
        OPENAI_KEY: ["read", "write"],
        TOKEN: true,
        SESSION: { name: "SESSION_KEY", scope: "chat", actions: "delete", description: "Signs the chat session." },
      },
    });
    expect(own(summary.read).map((item) => `${item.target} ${item.actions}`)).toEqual(["OPENAI_KEY get", "TOKEN get"]);
    expect(own(summary.change)).toEqual([
      { description: null, service: "Secret", space: "secrets", target: "OPENAI_KEY", path: "vault/secrets/OPENAI_KEY", actions: ["put"] },
      { description: "Signs the chat session.", service: "Secret", space: "secrets", target: "chat/SESSION_KEY", path: "vault/secrets/scoped/chat/SESSION_KEY", actions: ["del"] },
    ]);
  });

  it("shows an entry's own space and adds capabilities/read per space, only when something is granted", () => {
    const manifest = { app_id: "t.app", name: "T", defaults: false, permissions: [{ service: "tinycloud.kv", space: "account", path: "prefs/", actions: ["get"] }] };
    const summary = summarizeAccess(manifest);
    expect(summary.read.map((item) => `${item.service} ${item.space ?? "-"} ${item.target}`)).toEqual([
      "Key-value account t.app/prefs/",
      "Capabilities account account",
    ]);
    // The SDK signs nothing for a public space at sign-in, so none is listed whatever `includePublicSpace` says.
    expect(summarizeAccess({ ...manifest, includePublicSpace: true })).toEqual(summary);
    expect(summarizeAccess({ app_id: "t.app", name: "T", defaults: false })).toEqual({ read: [], change: [] });
  });

  it("yields an empty summary for a manifest of the wrong shape", () => {
    for (const junk of [null, "x", 3, [], { defaults: false, permissions: "all", secrets: 4 }]) {
      expect(summarizeAccess(junk)).toEqual({ read: [], change: [] });
    }
  });
});
