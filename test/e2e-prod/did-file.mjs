// Opt-in record of the smoke's throwaway owners, for the QA exclusion list (TC-2242).
// Off unless COURIER_SMOKE_DID_FILE is set. The path rules and the 0600 checks are private-file.mjs's.
// Each line is one owner: "<owner DID> <inbox email>", nothing else. The contents are never printed
// or reported. Everything here is synchronous, so a signal handler can record the owners before it exits.
import { closeSync, writeSync } from "node:fs";
import { openPrivateFile, varTmpPath } from "./private-file.mjs";

const NAME = "COURIER_SMOKE_DID_FILE";

/** The DID file to write, or undefined when the option is off. Throws for a path outside /var/tmp. */
export function didFileTarget(env = process.env) {
  const value = env[NAME];
  if (value === undefined || value === "") return undefined;
  return varTmpPath(value, NAME);
}

/** The owner DID a signed SIWE sign-in message names (its address as signed, EIP-55), or undefined. */
export function didFromSiwe(message) {
  const address = /^0x[0-9a-fA-F]{40}$/m.exec(String(message ?? ""))?.[0];
  const chain = /^Chain ID: (\d+)$/m.exec(String(message ?? ""))?.[1];
  return address && chain ? `did:pkh:eip155:${chain}:${address}` : undefined;
}

/** Appends one line per owner ("<did> <email>") to a 0600 file at `path` (from didFileTarget). */
export function writeDidFile(path, owners) {
  const recorded = owners.filter((owner) => owner.did && owner.email);
  const fd = openPrivateFile(path, NAME, "append");
  try {
    const lines = recorded.map((owner) => `${owner.did} ${owner.email}\n`).join("");
    if (lines) writeSync(fd, lines);
  } finally {
    closeSync(fd);
  }
  return recorded.length;
}
