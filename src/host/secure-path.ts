import { closeSync, constants, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

export const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
export const SECURE_READ = constants.O_RDONLY | NO_FOLLOW;
export const SECURE_CREATE = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW;
export const SECURE_APPEND = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | NO_FOLLOW;

const NUL = String.fromCharCode(0);

/**
 * Rejects a path that is not an absolute, normalized, traversal-free,
 * NUL-free filename. Shape only; `assertSecurePath` checks the filesystem.
 */
export function assertCanonicalPath(value: string, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes(NUL) || value.endsWith("/")) throw new Error(`${label} must be an absolute path`);
  if (value.split("/").slice(1).some((segment) => segment === "" || segment === "." || segment === "..")) throw new Error(`${label} must be normalized and traversal-free`);
  return resolve(value);
}

/** Rejects a path that is not a strict descendant of `root`. */
export function assertInsideRoot(value: string, root: string, label: string): string {
  const normalized = assertCanonicalPath(value, label);
  const remainder = relative(assertCanonicalPath(root, `${label} root`), normalized);
  if (remainder === "" || remainder.startsWith("..") || isAbsolute(remainder)) throw new Error(`${label} must be a descendant of the configured persistent Share volume`);
  return normalized;
}

/**
 * Walks every component of `path` and refuses any symlink, so a writable
 * parent directory cannot redirect a read or create outside the volume.
 */
export function assertSecurePath(path: string, allowMissingLeaf = true): void {
  const segments = path.split("/").slice(1);
  let current = "";
  for (const [index, segment] of segments.entries()) {
    current += `/${segment}`;
    let entry;
    try { entry = lstatSync(current); }
    catch (error) {
      if (allowMissingLeaf && index === segments.length - 1 && (error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    // macOS exposes /var as a fixed system alias for /private/var; it is not
    // operator-controlled and is needed for the local temp-root security tests.
    if (entry.isSymbolicLink()) {
      if (!(process.platform === "darwin" && current === "/var")) throw new Error("path contains a symlink");
      continue;
    }
    if (index < segments.length - 1 && !entry.isDirectory()) throw new Error("path parent is not a directory");
  }
  const parent = path.slice(0, path.lastIndexOf("/"));
  realpathSync(parent);
}

export function secureReadSync(path: string): string {
  assertSecurePath(path);
  const descriptor = openSync(path, SECURE_READ);
  try { return readFileSync(descriptor, "utf8"); }
  finally { closeSync(descriptor); }
}
