#!/usr/bin/env node
/**
 * Dev-time: copy an app bundle from a git tag into this repo and pin it in
 * apps/catalog.json. The result is committed; the build and the site fetch
 * nothing.
 *
 *   node scripts/vendor-app.mjs <git-url>@<tag> [--path <dir>] [--publisher <name>] [--publisher-did <did>]
 *
 * `<tag>` is a tag name or a full 40-hex commit id. Branch names are refused:
 * they move, and a catalog entry pins one exact commit.
 * `--path` is the folder inside the repo that holds the bundle
 * (default `tinycloud/app`): `manifest.json` at its top, plus `knowledge/**`
 * and whatever else the app ships. Its files are copied to
 * `public/apps/b/<digest>/`, where `<digest>` is the bundle digest defined in
 * scripts/apps-catalog.mjs. `--publisher` is required for a new app and kept
 * for an existing one. Updating an app replaces its entry and removes the
 * bundle folder it supersedes.
 *
 * Test hooks: `--catalog <file>` and `--public <dir>` redirect the outputs.
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { CATALOG_SCHEMA, describeBundle, fileListDigest, listFiles, verifyCatalog } from "./apps-catalog.mjs";

class Fatal extends Error {}

// die() throws so the temp checkout is always removed by the finally below.
function die(message) {
  throw new Fatal(message);
}

process.on("uncaughtException", (error) => {
  if (!(error instanceof Fatal)) throw error;
  console.error(`vendor-app: ${error.message}`);
  process.exit(1);
});

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
const COMMIT_ID = /^[0-9a-f]{40}$/;

function git(cwd, args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } });
  if (result.status !== 0) die(`git ${args[0]} failed: ${(result.stderr || result.error?.message || "").trim()}`);
  return result.stdout.trim();
}

/** `<git-url>@<ref>`; the ref is whatever follows the last "@", if that cannot be part of a URL. */
function splitSpec(spec) {
  const at = spec.lastIndexOf("@");
  const ref = at === -1 ? "" : spec.slice(at + 1);
  if (at <= 0 || ref === "" || ref.includes(":") || ref.startsWith("/")) die("expected <git-url>@<tag>");
  return { url: spec.slice(0, at), ref };
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    path: { type: "string", default: "tinycloud/app" },
    publisher: { type: "string" },
    "publisher-did": { type: "string" },
    catalog: { type: "string", default: join(root, "apps", "catalog.json") },
    public: { type: "string", default: join(root, "public") },
  },
});
if (positionals.length !== 1) die("expected exactly one argument: <git-url>@<tag>");
const { url, ref } = splitSpec(positionals[0]);
const subdir = values.path;
if (subdir.startsWith("/") || subdir.split("/").some((segment) => segment === ".." || segment === "")) die("--path must be a relative folder without \"..\"");

const work = mkdtempSync(join(tmpdir(), "vendor-app-"));
try {
  // Fetch exactly one commit. A tag is fetched as refs/tags/<tag>, so a branch of the same name cannot stand in for it.
  const checkout = join(work, "src");
  mkdirSync(checkout);
  git(checkout, ["init", "-q"]);
  git(checkout, ["fetch", "-q", "--depth", "1", "--no-tags", url, COMMIT_ID.test(ref) ? ref : `refs/tags/${ref}`]);
  const commit = git(checkout, ["rev-parse", "FETCH_HEAD^{commit}"]);
  if (COMMIT_ID.test(ref) && commit !== ref) die(`fetched ${commit}, not ${ref}`);
  git(checkout, ["checkout", "-q", "--detach", "FETCH_HEAD"]);

  const from = join(checkout, subdir);
  if (!existsSync(from)) die(`${subdir} does not exist at ${ref}`);
  const staged = join(work, "bundle");
  cpSync(from, staged, { recursive: true, filter: (source) => !/(^|\/)\.git$/.test(source) });

  const described = describeBundle(staged);
  const tooBig = described.bundle.files.find((file) => file.size > MAX_FILE_BYTES);
  if (tooBig !== undefined) die(`${tooBig.path} is ${tooBig.size} bytes; the limit is ${MAX_FILE_BYTES}`);
  const total = described.bundle.files.reduce((sum, file) => sum + file.size, 0);
  if (total > MAX_BUNDLE_BYTES) die(`bundle is ${total} bytes; the limit is ${MAX_BUNDLE_BYTES}`);

  const manifest = JSON.parse(readFileSync(join(staged, "manifest.json"), "utf8"));
  for (const field of ["app_id", "name", "description"]) {
    if (typeof manifest[field] !== "string" || manifest[field].trim() === "") die(`manifest.json needs a non-empty ${field}`);
  }

  const catalog = existsSync(values.catalog) ? JSON.parse(readFileSync(values.catalog, "utf8")) : { schema: CATALOG_SCHEMA, apps: [] };
  if (catalog.schema !== CATALOG_SCHEMA) die(`${values.catalog} is not a ${CATALOG_SCHEMA} catalog`);
  const previous = catalog.apps.find((app) => app.app_id === manifest.app_id);
  const publisher = values.publisher === undefined ? previous?.publisher : { name: values.publisher, ...(values["publisher-did"] === undefined ? {} : { did: values["publisher-did"] }) };
  if (publisher === undefined) die("--publisher <name> is required for a new app");

  const entry = {
    app_id: manifest.app_id,
    name: manifest.name,
    description: manifest.description,
    publisher,
    source: { repo: url.replace(/\.git$/, ""), tag: COMMIT_ID.test(ref) ? null : ref, commit },
    manifest: described.manifest,
    bundle: described.bundle,
    knowledge: described.knowledge,
  };

  // Put the bundle in place. A folder that already exists must hold exactly these bytes.
  const bundles = join(values.public, "apps", "b");
  const destination = join(bundles, described.bundle.digest);
  if (existsSync(destination)) {
    if (fileListDigest(listFiles(destination)) !== described.bundle.digest) die(`${destination} exists with different bytes`);
  } else {
    mkdirSync(bundles, { recursive: true });
    cpSync(staged, destination, { recursive: true });
  }

  const apps = catalog.apps.filter((app) => app.app_id !== entry.app_id).concat(entry).sort((a, b) => (a.app_id < b.app_id ? -1 : a.app_id > b.app_id ? 1 : 0));
  writeFileSync(values.catalog, `${JSON.stringify({ schema: CATALOG_SCHEMA, apps }, null, 2)}\n`);

  // Drop the folder this update superseded, unless another entry still pins it.
  const superseded = previous?.bundle?.digest;
  if (typeof superseded === "string" && /^[0-9a-f]{64}$/.test(superseded) && superseded !== described.bundle.digest && !apps.some((app) => app.bundle.digest === superseded)) {
    rmSync(join(bundles, superseded), { recursive: true, force: true });
  }

  const problems = verifyCatalog(JSON.parse(readFileSync(values.catalog, "utf8")), values.public);
  if (problems.length > 0) die(`catalog failed verification after the update:\n  ${problems.join("\n  ")}`);
  console.log(`${previous === undefined ? "added" : "updated"} ${entry.app_id}`);
  console.log(`  source  ${entry.source.repo} @ ${entry.source.tag ?? commit} (${commit})`);
  console.log(`  bundle  ${described.bundle.digest} (${described.bundle.files.length} files, ${total} bytes)`);
  console.log(`  folder  ${join(bundles, described.bundle.digest)}`);
  console.log(`  entries ${readdirSync(bundles).length} bundle folder(s)`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
