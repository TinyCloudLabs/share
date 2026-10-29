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
 *
 * If the folder holds a `release.json` (`tinycloud.app-release/v1`), that file's
 * `files` list is the ALLOW-LIST: only those files and `release.json` itself
 * are copied (never `dev/`, `tests/`, `scripts/`, `node_modules` or anything
 * else beside them), each file's bytes must match the sha256 the release
 * lists, and the release's own digest must recompute. The catalog digest is
 * computed separately over what was copied and is the one an installer
 * verifies; the kit's digest and version are recorded as `release`.
 * Every copied path must pass the installer's path rule (no `..`, absolute, backslash, control or hidden-folder paths, no
 * `dev/`, `tests/`, `scripts/` or `node_modules/` folders, no case collisions), and no component of it may be a symlink.
 * An entry's `disabled`/`disabledReason` (the kill switch) is kept on update.
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { CATALOG_SCHEMA, RELEASE_PATH, RELEASE_SCHEMA, caseCollision, describeBundle, fileListDigest, installPathProblem, listFiles, releaseDigest, sha256Hex, verifyCatalog } from "./apps-catalog.mjs";

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

/** Refuses a path whose every component, from the checkout root down, is not a plain directory or file: no symlink anywhere on the way in. */
function assertNoSymlinkOnPath(checkout, absolute) {
  const parts = relative(checkout, absolute).split(sep);
  let current = checkout;
  for (const part of parts) {
    current = join(current, part);
    if (lstatSync(current).isSymbolicLink()) die(`${relative(checkout, current)} is a symlink; a bundle is plain files`);
  }
}

/**
 * Copies the app's files into `staged`. With a `release.json`, ONLY the files
 * it lists (plus the release file) are copied, each checked against the sha256
 * the release declares; without one, the whole folder is the bundle.
 * @returns the parsed release record, or undefined when the folder has none
 */
function stageBundle(checkout, from, staged) {
  const releaseFile = join(from, RELEASE_PATH);
  assertNoSymlinkOnPath(checkout, from);
  if (!existsSync(releaseFile)) {
    cpSync(from, staged, { recursive: true, filter: (source) => !/(^|\/)\.git$/.test(source) });
    return undefined;
  }
  if (!lstatSync(releaseFile).isFile()) die(`${RELEASE_PATH} must be a regular file`);
  const record = JSON.parse(readFileSync(releaseFile, "utf8"));
  if (record.schema !== RELEASE_SCHEMA) die(`${RELEASE_PATH} schema must be ${RELEASE_SCHEMA}`);
  if (typeof record.app_id !== "string" || typeof record.version !== "string" || record.version === "" || typeof record.digest !== "string") die(`${RELEASE_PATH} needs app_id, version and digest`);
  if (!Array.isArray(record.files) || record.files.length === 0) die(`${RELEASE_PATH} lists no files`);
  const seen = new Set();
  const collides = caseCollision(record.files.map((file) => String(file?.path)));
  if (collides !== null) die(`${RELEASE_PATH}: ${collides} differs only by case from another path`);
  mkdirSync(staged, { recursive: true });
  for (const file of record.files) {
    const problem = installPathProblem(file?.path);
    if (problem !== null) die(`${RELEASE_PATH}: ${String(file?.path)} ${problem}`);
    if (file.path === RELEASE_PATH) die(`${RELEASE_PATH} cannot list itself`);
    if (seen.has(file.path)) die(`${RELEASE_PATH}: ${file.path} is listed twice`);
    seen.add(file.path);
    const source = join(from, file.path);
    if (!existsSync(source)) die(`${file.path} is listed by ${RELEASE_PATH} but does not exist`);
    assertNoSymlinkOnPath(checkout, source);
    if (!lstatSync(source).isFile()) die(`${file.path} is listed by ${RELEASE_PATH} but is not a regular file`);
    const bytes = readFileSync(source);
    if (sha256Hex(bytes) !== file.sha256 || (file.size !== undefined && bytes.length !== file.size)) die(`${file.path} does not match the sha256/size in ${RELEASE_PATH}`);
    mkdirSync(dirname(join(staged, file.path)), { recursive: true });
    writeFileSync(join(staged, file.path), bytes);
  }
  if (!seen.has("manifest.json")) die(`${RELEASE_PATH} does not list manifest.json`);
  if (releaseDigest(record.files) !== record.digest) die(`${RELEASE_PATH}: digest does not match its file list`);
  writeFileSync(join(staged, RELEASE_PATH), readFileSync(releaseFile));
  return record;
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
if (!/^https:\/\/[^\s]+$/.test(url)) die("only https sources can be listed in the catalog");
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
  const releaseRecord = stageBundle(checkout, from, staged);

  const described = describeBundle(staged);
  // The same rules the installer applies, over what was copied (a release-less folder included).
  for (const file of described.bundle.files) {
    const problem = file.path === RELEASE_PATH ? null : installPathProblem(file.path);
    if (problem !== null) die(`${file.path} ${problem}`);
  }
  const folded = caseCollision(described.bundle.files.map((file) => file.path));
  if (folded !== null) die(`${folded} differs only by case from another path`);
  const tooBig = described.bundle.files.find((file) => file.size > MAX_FILE_BYTES);
  if (tooBig !== undefined) die(`${tooBig.path} is ${tooBig.size} bytes; the limit is ${MAX_FILE_BYTES}`);
  const total = described.bundle.files.reduce((sum, file) => sum + file.size, 0);
  if (total > MAX_BUNDLE_BYTES) die(`bundle is ${total} bytes; the limit is ${MAX_BUNDLE_BYTES}`);

  const manifest = JSON.parse(readFileSync(join(staged, "manifest.json"), "utf8"));
  if (releaseRecord !== undefined && releaseRecord.app_id !== manifest.app_id) die(`${RELEASE_PATH} is for ${releaseRecord.app_id}, not ${manifest.app_id}`);
  const release = releaseRecord === undefined ? undefined : { version: releaseRecord.version, digest: releaseRecord.digest };
  for (const field of ["app_id", "name", "description"]) {
    if (typeof manifest[field] !== "string" || manifest[field].trim() === "") die(`manifest.json needs a non-empty ${field}`);
  }

  const catalog = existsSync(values.catalog) ? JSON.parse(readFileSync(values.catalog, "utf8")) : { schema: CATALOG_SCHEMA, apps: [] };
  if (catalog.schema !== CATALOG_SCHEMA) die(`${values.catalog} is not a ${CATALOG_SCHEMA} catalog`);
  const previous = catalog.apps.find((app) => app.app_id === manifest.app_id);
  const publisher = values.publisher === undefined ? previous?.publisher : { name: values.publisher, ...(values["publisher-did"] === undefined ? {} : { did: values["publisher-did"] }) };
  if (publisher === undefined) die("--publisher <name> is required for a new app");

  // A kill switch survives an update: re-vendoring must not quietly re-enable an app someone switched off.
  const killSwitch = previous?.disabled === true ? { disabled: true, disabledReason: previous.disabledReason } : {};
  const entry = {
    app_id: manifest.app_id,
    name: manifest.name,
    description: manifest.description,
    ...killSwitch,
    publisher,
    source: { repo: url.replace(/\.git$/, ""), tag: COMMIT_ID.test(ref) ? null : ref, commit },
    ...(release === undefined ? {} : { release }),
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
