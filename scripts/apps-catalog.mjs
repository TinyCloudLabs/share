/**
 * Shared catalog logic for scripts/vendor-app.mjs and the catalog test.
 * Node only (node:crypto, node:fs); nothing here ships to the browser.
 *
 * Digest contract (apps/catalog.json, `tinycloud.share.apps-catalog/v1`):
 *   - A bundle is a set of files addressed by POSIX paths relative to the
 *     bundle root, with no leading "/", no empty, "." or ".." segment, no
 *     backslash and no control character.
 *   - Files are sorted by path, comparing UTF-16 code units (the default
 *     `Array.prototype.sort` order, not locale order).
 *   - The file-list text is one line per file, `<sha256 hex> <size> <path>\n`.
 *   - `digest` is the lowercase hex sha256 of the UTF-8 bytes of that text.
 *   - `bundle.digest` covers every file of the bundle; `knowledge.digest`
 *     covers the files under `knowledge/` with paths relative to that folder.
 * An installer recomputes the same digests from the fetched bytes before it
 * writes anything.
 */
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const CATALOG_SCHEMA = "tinycloud.share.apps-catalog/v1";
export const BUNDLE_URL_PREFIX = "/apps/b/";
export const MANIFEST_PATH = "manifest.json";
export const KNOWLEDGE_DIR = "knowledge";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** @returns {string|null} why the path is not a valid bundle path, or null. */
export function bundlePathProblem(path) {
  if (typeof path !== "string" || path.length === 0) return "must be a non-empty string";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(path)) return "contains a control character or backslash";
  if (path.startsWith("/")) return "must be relative";
  if (path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) return "has an empty, \".\" or \"..\" segment";
  return null;
}

/** Written by the installer next to the app's files; a bundle can never carry it. */
export const INSTALL_RECORD_PATH = "install.json";
export const MAX_INSTALL_PATH_LENGTH = 128;
export const MAX_INSTALL_PATH_DEPTH = 8;
const INSTALL_SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

/**
 * The stricter rule for a file an installer will write into the user's
 * TinyCloud: bundle path rules plus ASCII segments of `[A-Za-z0-9._-]` (the
 * node refuses other characters in a key, and a plain alphabet leaves no room
 * for tricks), no leading dot, a bounded length and depth, and not the
 * installer's own record. src/apps/bundle.ts holds the same rule for the page.
 * @returns {string|null} why the path cannot be installed, or null.
 */
export function installPathProblem(path) {
  const problem = bundlePathProblem(path);
  if (problem !== null) return problem;
  if (path.length > MAX_INSTALL_PATH_LENGTH) return `is longer than ${MAX_INSTALL_PATH_LENGTH} characters`;
  const segments = path.split("/");
  if (segments.length > MAX_INSTALL_PATH_DEPTH) return `is more than ${MAX_INSTALL_PATH_DEPTH} folders deep`;
  if (!segments.every((segment) => INSTALL_SEGMENT.test(segment))) return "may only use letters, digits, \".\", \"_\" and \"-\" (no leading dot)";
  if (path === INSTALL_RECORD_PATH) return `${INSTALL_RECORD_PATH} is reserved for the installer`;
  return null;
}

/**
 * The kit's own release digest (`tinycloud.app-release/v1`): sha256 over the
 * path-sorted `<path> <sha256>` lines joined by "\n". It is recorded next to
 * the catalog digest, which stays the one an installer verifies.
 */
export function releaseDigest(files) {
  return sha256Hex(Buffer.from([...files].sort(compareByPath).map((file) => `${file.path} ${file.sha256}`).join("\n"), "utf8"));
}

export function compareByPath(a, b) {
  return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
}

export function sortedFiles(files) {
  return files.map(({ path, sha256, size }) => ({ path, sha256, size })).sort(compareByPath);
}

export function fileListText(files) {
  return sortedFiles(files).map((file) => `${file.sha256} ${file.size} ${file.path}\n`).join("");
}

export function fileListDigest(files) {
  return sha256Hex(Buffer.from(fileListText(files), "utf8"));
}

export function bundleRootFor(digest) {
  return `${BUNDLE_URL_PREFIX}${digest}/`;
}

/** Files under `knowledge/`, with paths relative to that folder. */
export function knowledgeFiles(files) {
  const prefix = `${KNOWLEDGE_DIR}/`;
  return files.filter((file) => file.path.startsWith(prefix)).map((file) => ({ ...file, path: file.path.slice(prefix.length) }));
}

/**
 * Hashes every file under `dir`. Symlinks and special files are rejected: a
 * bundle is plain bytes.
 * @returns {{path: string, sha256: string, size: number}[]} sorted by path
 */
export function listFiles(dir) {
  const files = [];
  const walk = (relative) => {
    for (const entry of readdirSync(join(dir, relative), { withFileTypes: true })) {
      const path = relative === "" ? entry.name : `${relative}/${entry.name}`;
      const stat = lstatSync(join(dir, path));
      if (stat.isDirectory()) { walk(path); continue; }
      if (!stat.isFile()) throw new Error(`${path}: only regular files can be part of a bundle`);
      const problem = bundlePathProblem(path);
      if (problem !== null) throw new Error(`${path}: ${problem}`);
      const bytes = readFileSync(join(dir, path));
      files.push({ path, sha256: sha256Hex(bytes), size: bytes.length });
    }
  };
  walk("");
  return sortedFiles(files);
}

/** Catalog `bundle`, `manifest` and `knowledge` blocks for a bundle on disk. */
export function describeBundle(dir) {
  const files = listFiles(dir);
  const manifest = files.find((file) => file.path === MANIFEST_PATH);
  if (manifest === undefined) throw new Error(`${MANIFEST_PATH} is missing from the bundle`);
  const digest = fileListDigest(files);
  const knowledge = knowledgeFiles(files);
  return {
    manifest: { path: MANIFEST_PATH, sha256: manifest.sha256 },
    bundle: { root: bundleRootFor(digest), files, digest },
    knowledge: knowledge.length === 0 ? null : { root: `${bundleRootFor(digest)}${KNOWLEDGE_DIR}/`, digest: fileListDigest(knowledge) },
  };
}

export const RELEASE_PATH = "release.json";
export const RELEASE_SCHEMA = "tinycloud.app-release/v1";

/** An app id becomes the first segment of every key the installer writes. @returns {string|null} */
export function installAppIdProblem(appId) {
  if (typeof appId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(appId) || appId.includes("..")) return "may only use letters, digits, \".\", \"_\" and \"-\" (at most 128 characters, no \"..\")";
  return null;
}

const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const isText = (value) => typeof value === "string" && value.trim() !== "";

/**
 * Checks the catalog structure and recomputes every digest and file hash
 * against the bytes under `<publicDir>/apps/b/`.
 * @returns {string[]} one message per problem; empty when the catalog is sound
 */
export function verifyCatalog(catalog, publicDir) {
  const errors = [];
  if (!isObject(catalog)) return ["catalog must be an object"];
  if (catalog.schema !== CATALOG_SCHEMA) errors.push(`schema must be ${CATALOG_SCHEMA}`);
  if (!Array.isArray(catalog.apps)) return [...errors, "apps must be an array"];

  const seenIds = new Set();
  const referenced = new Set();
  for (const [index, entry] of catalog.apps.entries()) {
    const label = isObject(entry) && isText(entry.app_id) ? entry.app_id : `apps[${index}]`;
    const fail = (message) => errors.push(`${label}: ${message}`);
    if (!isObject(entry)) { fail("must be an object"); continue; }
    if (!isText(entry.app_id)) fail("app_id is required");
    else if (seenIds.has(entry.app_id)) fail("duplicate app_id");
    else seenIds.add(entry.app_id);
    if (isText(entry.app_id) && installAppIdProblem(entry.app_id) !== null) fail(`app_id ${installAppIdProblem(entry.app_id)}`);
    if (entry.sample !== undefined && entry.sample !== true) fail("sample must be true when present");
    for (const field of ["name", "description"]) if (!isText(entry[field])) fail(`${field} is required`);
    if (!isObject(entry.publisher) || !isText(entry.publisher.name)) fail("publisher.name is required");
    else if (entry.publisher.did !== undefined && !isText(entry.publisher.did)) fail("publisher.did must be a non-empty string when present");

    const source = entry.source;
    if (!isObject(source)) fail("source is required");
    else {
      if (!isText(source.repo) || !/^https:\/\/[^\s]+$/.test(source.repo)) fail("source.repo must be an https URL");
      if (source.tag !== null && !isText(source.tag)) fail("source.tag must be a tag name, or null for a bare commit");
      if (typeof source.commit !== "string" || !HEX40.test(source.commit)) fail("source.commit must be a 40-hex commit id");
    }

    const bundle = entry.bundle;
    if (!isObject(bundle) || !Array.isArray(bundle.files) || typeof bundle.digest !== "string") { fail("bundle {root, files, digest} is required"); continue; }
    if (!HEX64.test(bundle.digest)) { fail("bundle.digest must be 64 lowercase hex characters"); continue; }
    referenced.add(bundle.digest);
    if (bundle.root !== bundleRootFor(bundle.digest)) fail(`bundle.root must be ${bundleRootFor(bundle.digest)}`);

    // The declared list: well-formed, strictly sorted, and the digest follows from it.
    let listOk = true;
    for (const [position, file] of bundle.files.entries()) {
      const problem = isObject(file) ? installPathProblem(file.path) : "must be an object";
      if (problem !== null) { fail(`bundle.files[${position}].path ${problem}`); listOk = false; continue; }
      if (typeof file.sha256 !== "string" || !HEX64.test(file.sha256)) { fail(`${file.path}: sha256 must be 64 lowercase hex characters`); listOk = false; }
      if (!Number.isSafeInteger(file.size) || file.size < 0) { fail(`${file.path}: size must be a non-negative integer`); listOk = false; }
      const previous = bundle.files[position - 1];
      if (position > 0 && isObject(previous) && typeof previous.path === "string" && compareByPath(previous, file) >= 0) { fail(`${file.path}: files must be sorted by path without duplicates`); listOk = false; }
    }
    if (!listOk) continue;
    if (fileListDigest(bundle.files) !== bundle.digest) fail("bundle.digest does not match the declared file list");

    // The declared list against the bytes on disk.
    const dir = join(publicDir, "apps", "b", bundle.digest);
    let actual = [];
    try { actual = listFiles(dir); } catch (error) { fail(`bundle folder ${bundle.digest} cannot be read: ${error instanceof Error ? error.message : String(error)}`); continue; }
    const declared = new Map(bundle.files.map((file) => [file.path, file]));
    const present = new Map(actual.map((file) => [file.path, file]));
    for (const [path, file] of declared) {
      const onDisk = present.get(path);
      if (onDisk === undefined) fail(`${path}: listed but missing from the bundle folder`);
      else if (onDisk.sha256 !== file.sha256 || onDisk.size !== file.size) fail(`${path}: bytes do not match the catalog (sha256 or size differs)`);
    }
    for (const path of present.keys()) if (!declared.has(path)) fail(`${path}: in the bundle folder but not listed`);
    if (fileListDigest(actual) !== bundle.digest) fail("the bundle folder does not hash to bundle.digest");

    // Manifest: the pinned file, and the identity the catalog repeats from it.
    const manifestFile = isObject(entry.manifest) ? declared.get(entry.manifest.path) : undefined;
    if (!isObject(entry.manifest) || entry.manifest.path !== MANIFEST_PATH) fail(`manifest.path must be ${MANIFEST_PATH}`);
    else if (manifestFile === undefined) fail("manifest.path is not in bundle.files");
    else {
      if (entry.manifest.sha256 !== manifestFile.sha256) fail("manifest.sha256 does not match the manifest file in bundle.files");
      try {
        const manifest = JSON.parse(readFileSync(join(dir, MANIFEST_PATH), "utf8"));
        for (const [field, value] of [["app_id", entry.app_id], ["name", entry.name], ["description", entry.description]]) {
          if (manifest[field] !== value) fail(`${field} differs from ${MANIFEST_PATH}`);
        }
      } catch (error) { fail(`${MANIFEST_PATH} cannot be read as JSON: ${error instanceof Error ? error.message : String(error)}`); }
    }

    // Knowledge: the files under knowledge/, hashed with paths relative to it.
    const knowledge = knowledgeFiles(bundle.files);
    if (entry.knowledge === null) {
      if (knowledge.length > 0) fail("bundle has knowledge/ files but the entry has no knowledge block");
    } else if (!isObject(entry.knowledge)) fail("knowledge must be an object or null");
    else {
      if (knowledge.length === 0) fail("knowledge block present but the bundle has no knowledge/ files");
      if (entry.knowledge.root !== `${bundleRootFor(bundle.digest)}${KNOWLEDGE_DIR}/`) fail("knowledge.root must be the bundle's knowledge/ folder");
      if (entry.knowledge.digest !== fileListDigest(knowledge)) fail("knowledge.digest does not match the knowledge files");
    }

    // The kit's own release record, when the bundle ships one: its file list is the allow-list the vendoring used.
    if (entry.release !== undefined) {
      const release = entry.release;
      const releaseFile = declared.get(RELEASE_PATH);
      if (!isObject(release) || !isText(release.version) || typeof release.digest !== "string" || !HEX64.test(release.digest)) fail("release must be {version, digest}");
      else if (releaseFile === undefined) fail(`release is declared but ${RELEASE_PATH} is not in bundle.files`);
      else {
        try {
          const record = JSON.parse(readFileSync(join(dir, RELEASE_PATH), "utf8"));
          if (record.schema !== RELEASE_SCHEMA) fail(`${RELEASE_PATH} schema must be ${RELEASE_SCHEMA}`);
          if (record.app_id !== entry.app_id) fail(`app_id differs from ${RELEASE_PATH}`);
          if (record.version !== release.version) fail(`release.version differs from ${RELEASE_PATH}`);
          if (record.digest !== release.digest) fail(`release.digest differs from ${RELEASE_PATH}`);
          const listed = Array.isArray(record.files) ? record.files : [];
          if (listed.length === 0) fail(`${RELEASE_PATH} lists no files`);
          if (releaseDigest(listed) !== release.digest) fail(`release.digest does not match the files ${RELEASE_PATH} lists`);
          for (const file of listed) {
            const own = declared.get(file.path);
            if (own === undefined) fail(`${file.path}: listed by ${RELEASE_PATH} but not in bundle.files`);
            else if (own.sha256 !== file.sha256 || (file.size !== undefined && own.size !== file.size)) fail(`${file.path}: differs from ${RELEASE_PATH}`);
          }
          const allowed = new Set([...listed.map((file) => file.path), RELEASE_PATH]);
          for (const path of declared.keys()) if (!allowed.has(path)) fail(`${path}: in the bundle but not listed by ${RELEASE_PATH}`);
        } catch (error) { fail(`${RELEASE_PATH} cannot be read as JSON: ${error instanceof Error ? error.message : String(error)}`); }
      }
    }
  }

  // Every bundle folder belongs to an entry: nothing unlisted ships.
  let folders = [];
  try { folders = readdirSync(join(publicDir, "apps", "b")); } catch { /* no bundles yet */ }
  for (const folder of folders) if (!referenced.has(folder)) errors.push(`public/apps/b/${folder}: not referenced by any catalog entry`);
  return errors;
}
