/**
 * The catalog's bundle, checked in the browser before anything is written.
 *
 * Two rules protect the install:
 *  1. A catalog entry is only believed if its own file list is well formed
 *     (safe relative paths, a plain alphabet, no installer-reserved name) and
 *     hashes to the digest in the entry's own bundle root.
 *  2. Every file is fetched from that same-origin root and must match the
 *     catalog's sha256 and size. One mismatch refuses the whole bundle, and
 *     nothing has been written by then.
 *
 * scripts/apps-catalog.mjs holds the same path rule for the build-time check
 * (the unit test keeps the two in step).
 */
import type { CatalogEntry } from "./catalog.ts";

export const INSTALL_RECORD_PATH = "install.json";
const MAX_PATH_LENGTH = 128;
const MAX_PATH_DEPTH = 8;
export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
const MAX_FILES = 64;
const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
/** Folders that belong to an app's development, never to the app an installer copies (mirrors scripts/apps-catalog.mjs). */
const FORBIDDEN_FOLDERS: readonly string[] = ["dev", "tests", "test", "scripts", "node_modules"];
const HEX64 = /^[0-9a-f]{64}$/;
const APP_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Why `appId` cannot be the first segment of the keys an installer writes, or null. */
export function appIdProblem(appId: unknown): string | null {
  if (typeof appId !== "string" || !APP_ID.test(appId) || appId.includes("..")) return "is not a plain app id";
  return null;
}

/** Why `path` cannot be installed, or null. Rejects `../`, absolute, backslash, NUL and any other control character. */
export function installPathProblem(path: unknown): string | null {
  if (typeof path !== "string" || path.length === 0) return "must be a non-empty string";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(path)) return "contains a control character or backslash";
  if (path.startsWith("/")) return "must be relative";
  if (path.length > MAX_PATH_LENGTH) return "is too long";
  const segments = path.split("/");
  if (segments.length > MAX_PATH_DEPTH) return "is too deep";
  if (segments.some((segment) => segment === "." || segment === ".." || !SEGMENT.test(segment))) return "may only use letters, digits, \".\", \"_\" and \"-\"";
  if (path === INSTALL_RECORD_PATH) return "is reserved for the installer";
  if (segments.slice(0, -1).some((segment) => FORBIDDEN_FOLDERS.includes(segment.toLowerCase()))) return "is inside a development folder";
  return null;
}

/** Why an install stopped before any write. `tampered` is a file whose bytes differ from the catalog. */
export type RefusalReason = "catalog" | "tampered" | "unavailable";

export class BundleRefusal extends Error {
  readonly reason: RefusalReason;
  constructor(reason: RefusalReason, detail: string) {
    super(`bundle-${reason}: ${detail}`);
    this.name = "BundleRefusal";
    this.reason = reason;
  }
}

export interface BundleFile {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface VerifiedBundle {
  readonly files: readonly (BundleFile & { readonly bytes: Uint8Array })[];
  readonly manifest: unknown;
}

export async function sha256Hex(bytes: BufferSource): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** `docs/apps-catalog.md` §Digest: sha256 of the `<sha256> <size> <path>\n` lines, sorted by path in UTF-16 code-unit order. */
export async function bundleDigest(files: readonly BundleFile[]): Promise<string> {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return sha256Hex(new TextEncoder().encode(sorted.map((file) => `${file.sha256} ${file.size} ${file.path}\n`).join("")));
}

/**
 * The entry's declared files, once the entry is believable. Throws
 * `BundleRefusal("catalog")` for a hostile or inconsistent entry; the browser
 * has fetched nothing at that point.
 */
export async function declaredFiles(entry: CatalogEntry): Promise<readonly BundleFile[]> {
  const refuse = (detail: string): never => { throw new BundleRefusal("catalog", detail); };
  if (appIdProblem(entry.app_id) !== null) refuse("app id");
  const { bundle } = entry;
  if (typeof bundle?.digest !== "string" || !HEX64.test(bundle.digest) || bundle.root !== `/apps/b/${bundle.digest}/`) refuse("bundle root");
  if (!Array.isArray(bundle.files) || bundle.files.length === 0 || bundle.files.length > MAX_FILES) refuse("file list");
  const seen = new Set<string>();
  let total = 0;
  for (const file of bundle.files) {
    const problem = installPathProblem(file?.path);
    if (problem !== null) refuse(`file path ${problem}`);
    if (seen.has(file.path.toLowerCase())) refuse("duplicate file path (paths that differ only by case collide)");
    seen.add(file.path.toLowerCase());
    if (typeof file.sha256 !== "string" || !HEX64.test(file.sha256)) refuse("file sha256");
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_BYTES) refuse("file size");
    total += file.size;
  }
  if (total > MAX_BUNDLE_BYTES) refuse("bundle size");
  if (entry.manifest?.path !== "manifest.json" || !bundle.files.some((file) => file.path === "manifest.json")) refuse("manifest path");
  if (bundle.files.find((file) => file.path === "manifest.json")?.sha256 !== entry.manifest.sha256) refuse("manifest sha256");
  // The list is its own check: it must hash to the digest the bundle root is named after.
  if (await bundleDigest(bundle.files) !== bundle.digest) refuse("digest");
  return bundle.files;
}

/** The slice of `Response` the installer reads. */
export type BundleResponse = Pick<Response, "ok" | "status" | "arrayBuffer">;
/** `fetch`, as the installer calls it: a same-origin path and fixed options. */
export type BundleFetch = (input: string, init?: RequestInit) => Promise<BundleResponse>;

async function fetchOne(entry: CatalogEntry, file: BundleFile, fetchFn: BundleFetch): Promise<Uint8Array> {
  // The path alphabet has nothing to escape, and the root is `/apps/b/<64 hex>/`: this can only be a same-origin path.
  const response = await fetchFn(`${entry.bundle.root}${file.path}`, { credentials: "omit", referrerPolicy: "no-referrer", redirect: "error", cache: "no-store" });
  if (!response.ok) throw new BundleRefusal("unavailable", `${file.path}: ${response.status}`);
  // Only the decoded bytes are judged: an edge that compresses the response reports the encoded length in content-length.
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength !== file.size) throw new BundleRefusal("tampered", `${file.path}: size differs from the catalog`);
  if (await sha256Hex(buffer) !== file.sha256) throw new BundleRefusal("tampered", `${file.path}: sha256 differs from the catalog`);
  return new Uint8Array(buffer);
}

/**
 * Fetches every file of the bundle from the entry's own `/apps/b/<digest>/`
 * root and verifies each against the catalog. Resolves only with bytes that
 * all match; any failure rejects with a `BundleRefusal`, before the caller has
 * a single byte to write.
 */
export async function fetchVerifiedBundle(entry: CatalogEntry, fetchFn: BundleFetch = (input, init) => fetch(input, init)): Promise<VerifiedBundle> {
  const declared = await declaredFiles(entry);
  const files = await Promise.all(declared.map(async (file) => ({ ...file, bytes: await fetchOne(entry, file, fetchFn) })));
  const manifestBytes = files.find((file) => file.path === "manifest.json")?.bytes;
  let manifest: unknown;
  try { manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)); } catch { throw new BundleRefusal("catalog", "manifest is not JSON"); }
  // The entry repeats the manifest's identity; the installer signs in with the entry's copy, so the two must agree.
  if (typeof manifest !== "object" || manifest === null || !("app_id" in manifest) || !("name" in manifest) || !("description" in manifest)
    || manifest.app_id !== entry.app_id || manifest.name !== entry.name || manifest.description !== entry.description) throw new BundleRefusal("catalog", "manifest identity differs from the catalog");
  return { files, manifest };
}
