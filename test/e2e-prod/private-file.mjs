// Private files the production smokes keep under /var/tmp: the opt-in owner record (did-file.mjs)
// and a recipient-gate inbox file (mail-tm.mjs). The path must be plain, absolute and in an
// existing directory under /var/tmp; the directory is checked again right before each open. Files
// are opened without following a symlink and without blocking on a FIFO, and must be 0600 regular
// files of this user; a new one is set 0600 whatever the umask. Everything here is synchronous, so
// a signal handler can use it.
import { closeSync, constants, fchmodSync, fstatSync, openSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";

const ROOT = "/var/tmp";
const underRoot = (directory) => directory === ROOT || directory.startsWith(`${ROOT}/`);

/** `value` as a checked path under /var/tmp (its directory resolved). `name` labels the errors. */
export function varTmpPath(value, name) {
  if (typeof value !== "string" || !isAbsolute(value) || normalize(value) !== value) throw new Error(`${name} must be a plain absolute path under /var/tmp`);
  let directory;
  try { directory = realpathSync(dirname(value)); } catch { throw new Error(`${name} must be in an existing directory under /var/tmp`); }
  if (!underRoot(directory)) throw new Error(`${name} must be under /var/tmp`);
  return join(directory, basename(value));
}

/** The directory checked by varTmpPath must still be itself (no symlink swapped in since). */
export function recheckDirectory(path, name) {
  const directory = dirname(path);
  let now;
  try { now = realpathSync(directory); } catch { now = undefined; }
  if (now !== directory || !underRoot(now)) throw new Error(`${name}'s directory changed since the run started`);
}

const BASE = constants.O_NOFOLLOW | constants.O_NONBLOCK;

/**
 * Opens a private file at a varTmpPath `path` and returns its descriptor.
 * - "create": a new file only (an existing one is refused), write-only.
 * - "append": appends, creating the file if it is missing.
 * - "read": an existing file, read-only.
 */
export function openPrivateFile(path, name, mode) {
  recheckDirectory(path, name);
  const access = mode === "read" ? constants.O_RDONLY : constants.O_WRONLY | (mode === "append" ? constants.O_APPEND : 0);
  let fd;
  if (mode !== "read") {
    try {
      fd = openSync(path, BASE | access | constants.O_CREAT | constants.O_EXCL, 0o600);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (mode === "create") throw new Error(`${name} already exists; it must be a new file`);
    }
    if (fd !== undefined) {
      try { fchmodSync(fd, 0o600); } catch (error) { closeSync(fd); throw error; } // a restrictive umask must not leave it 0400
    }
  }
  fd ??= openSync(path, BASE | access); // a FIFO without a writer/reader fails instead of blocking
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error(`${name} exists with other permissions or owner; it must be a 0600 file of this user`);
    }
  } catch (error) {
    closeSync(fd);
    throw error;
  }
  return fd;
}
