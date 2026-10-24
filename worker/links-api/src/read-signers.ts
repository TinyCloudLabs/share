import { parseEd25519DidKey, pointProblem } from "./ed25519.ts";

/**
 * The allow-list of keys whose signed reads are served from a label's own bucket (contract 4.11,
 * `links.readSigners`). The list is operator configuration; it grants no create, delete or take.
 */

const LABEL_RE = /^service:[a-z0-9][a-z0-9-]{0,31}$/;
export const MAX_SIGNERS_PER_LABEL = 2;
/** The environment variable that carries the list as JSON: `[{"label":"service:node","did":"did:key:z6Mk..."}]`. */
export const READ_SIGNERS_ENV = "LINKS_READ_SIGNERS";

export interface ReadSigner {
  readonly label: string;
  readonly did: string;
  /** The Ed25519 public key the DID names. */
  readonly publicKey: Uint8Array;
}

/** Parses and validates the list; throws with a message that names the entry index, never a key. */
export function parseReadSigners(raw: unknown): readonly ReadSigner[] {
  if (raw === undefined || raw === null || raw === "") {
    return [];
  }
  let entries: unknown = raw;
  if (typeof raw === "string") {
    try {
      entries = JSON.parse(raw);
    } catch {
      throw new Error(`config: ${READ_SIGNERS_ENV} is not valid JSON`);
    }
  }
  if (!Array.isArray(entries)) {
    throw new Error(`config: ${READ_SIGNERS_ENV} must be a list`);
  }
  const signers: ReadSigner[] = [];
  entries.forEach((entry: unknown, index) => {
    const fields = typeof entry === "object" && entry !== null && !Array.isArray(entry) ? Object.entries(entry) : null;
    const label = fields?.find(([k]) => k === "label")?.[1];
    const did = fields?.find(([k]) => k === "did")?.[1];
    if (fields === null || fields.length !== 2 || typeof label !== "string" || typeof did !== "string") {
      throw new Error(`config: ${READ_SIGNERS_ENV} entry ${index} must be exactly {label, did}`);
    }
    if (!LABEL_RE.test(label)) {
      throw new Error(`config: ${READ_SIGNERS_ENV} entry ${index} has a label that is not service:<name>`);
    }
    const key = parseEd25519DidKey(did);
    if (!key.ok) {
      throw new Error(`config: ${READ_SIGNERS_ENV} entry ${index} is not an Ed25519 did:key`);
    }
    if (pointProblem(key.publicKey) !== null) {
      throw new Error(`config: ${READ_SIGNERS_ENV} entry ${index} has a key that is not usable`);
    }
    if (signers.some((s) => s.did === did)) {
      throw new Error(`config: ${READ_SIGNERS_ENV} entry ${index} repeats a key`);
    }
    if (signers.filter((s) => s.label === label).length >= MAX_SIGNERS_PER_LABEL) {
      throw new Error(`config: ${READ_SIGNERS_ENV} entry ${index} is a third key for its label (at most ${MAX_SIGNERS_PER_LABEL})`);
    }
    signers.push({ label, did, publicKey: key.publicKey });
  });
  return signers;
}
