// Opt-in record of the smoke's throwaway owners, for the QA exclusion list (TC-2242).
// Off unless COURIER_SMOKE_DID_FILE is set. The path must be under /var/tmp, and its directory is
// checked again right before the open. The file is created 0600 (an existing one must already be a
// 0600 regular file of this user; a symlink or FIFO is refused without blocking). Each line is one
// owner: "<owner DID> <inbox email>", nothing else. The contents are never printed or reported.
// Everything here is synchronous, so a signal handler can record the owners before it exits.
import { closeSync, constants, fchmodSync, fstatSync, openSync, realpathSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";

const ROOT = "/var/tmp";
const underRoot = (directory) => directory === ROOT || directory.startsWith(`${ROOT}/`);

/** The DID file to write, or undefined when the option is off. Throws for a path outside /var/tmp. */
export function didFileTarget(env = process.env) {
  const value = env.COURIER_SMOKE_DID_FILE;
  if (value === undefined || value === "") return undefined;
  if (!isAbsolute(value) || normalize(value) !== value) throw new Error("COURIER_SMOKE_DID_FILE must be a plain absolute path under /var/tmp");
  let directory;
  try { directory = realpathSync(dirname(value)); } catch { throw new Error("COURIER_SMOKE_DID_FILE must be in an existing directory under /var/tmp"); }
  if (!underRoot(directory)) throw new Error("COURIER_SMOKE_DID_FILE must be under /var/tmp");
  return join(directory, basename(value));
}

/** The owner DID a signed SIWE sign-in message names (its address as signed, EIP-55), or undefined. */
export function didFromSiwe(message) {
  const address = /^0x[0-9a-fA-F]{40}$/m.exec(String(message ?? ""))?.[0];
  const chain = /^Chain ID: (\d+)$/m.exec(String(message ?? ""))?.[1];
  return address && chain ? `did:pkh:eip155:${chain}:${address}` : undefined;
}

const OPEN = constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW | constants.O_NONBLOCK;

/** Appends one line per owner ("<did> <email>") to a 0600 file at `path` (from didFileTarget). */
export function writeDidFile(path, owners) {
  const recorded = owners.filter((owner) => owner.did && owner.email);
  // The directory validated at start must still be itself (no symlink swapped in since).
  const directory = dirname(path);
  let now;
  try { now = realpathSync(directory); } catch { now = undefined; }
  if (now !== directory || !underRoot(now)) throw new Error("COURIER_SMOKE_DID_FILE's directory changed since the run started");
  let fd;
  try {
    fd = openSync(path, OPEN | constants.O_CREAT | constants.O_EXCL, 0o600);
    fchmodSync(fd, 0o600); // a restrictive umask must not leave it 0400
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    fd = openSync(path, OPEN); // a FIFO without a reader fails (ENXIO) instead of blocking
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error("COURIER_SMOKE_DID_FILE exists with other permissions or owner; it must be a 0600 file of this user");
    }
    const lines = recorded.map((owner) => `${owner.did} ${owner.email}\n`).join("");
    if (lines) writeSync(fd, lines);
  } finally {
    closeSync(fd);
  }
  return recorded.length;
}
