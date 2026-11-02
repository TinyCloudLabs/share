// Opt-in record of the smoke's throwaway owners, for the QA exclusion list (TC-2242).
// Off unless COURIER_SMOKE_DID_FILE is set. The path must be under /var/tmp; the file is created
// 0600 (an existing one must already be 0600 and ours; a symlink is refused). Each line is one
// owner: "<owner DID> <inbox email>", nothing else. The contents are never printed or reported.
import { closeSync, constants, fstatSync, openSync, realpathSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";

const ROOT = "/var/tmp";

/** The DID file to write, or undefined when the option is off. Throws for a path outside /var/tmp. */
export function didFileTarget(env = process.env) {
  const value = env.COURIER_SMOKE_DID_FILE;
  if (value === undefined || value === "") return undefined;
  if (!isAbsolute(value) || normalize(value) !== value) throw new Error("COURIER_SMOKE_DID_FILE must be a plain absolute path under /var/tmp");
  let directory;
  try { directory = realpathSync(dirname(value)); } catch { throw new Error("COURIER_SMOKE_DID_FILE must be in an existing directory under /var/tmp"); }
  if (directory !== ROOT && !directory.startsWith(`${ROOT}/`)) throw new Error("COURIER_SMOKE_DID_FILE must be under /var/tmp");
  return join(directory, basename(value));
}

/** The owner DID a signed SIWE sign-in message names, or undefined. */
export function didFromSiwe(message) {
  const address = /^0x[0-9a-fA-F]{40}$/m.exec(String(message ?? ""))?.[0];
  const chain = /^Chain ID: (\d+)$/m.exec(String(message ?? ""))?.[1];
  return address && chain ? `did:pkh:eip155:${chain}:${address}` : undefined;
}

/** Appends one line per owner ("<did> <email>") to a 0600 file at `path` (from didFileTarget). */
export function writeDidFile(path, owners) {
  const lines = owners.filter((owner) => owner.did && owner.email).map((owner) => `${owner.did} ${owner.email}\n`).join("");
  const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error("COURIER_SMOKE_DID_FILE exists with other permissions or owner; it must be a 0600 file of this user");
    }
    if (lines) writeSync(fd, lines);
  } finally {
    closeSync(fd);
  }
  return owners.filter((owner) => owner.did && owner.email).length;
}
