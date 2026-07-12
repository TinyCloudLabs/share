import { CID } from "multiformats/cid";
import * as raw from "multiformats/codecs/raw";
import { sha256 } from "multiformats/hashes/sha2";

/**
 * Compute the CID of a single raw block, per sharing-viewer-and-registry.md §6.3:
 * CIDv1, codec raw (0x55), sha2-256, canonical lowercase base32 ("bafkr…").
 * Hashes the exact bytes given — no chunking, no UnixFS/dag-pb wrapping.
 */
export async function computeCid(bytes: Uint8Array): Promise<string> {
  const digest = await sha256.digest(bytes);
  return CID.create(1, raw.code, digest).toString();
}

/**
 * Verify that `cidString` is the canonical CIDv1/raw/sha2-256 base32 CID of `bytes`.
 * Returns false for any mismatch: wrong hash, wrong version/codec, or a
 * non-canonical string form of the right CID.
 */
export async function verifyCid(
  bytes: Uint8Array,
  cidString: string,
): Promise<boolean> {
  let cid: CID;
  try {
    cid = CID.parse(cidString);
  } catch {
    return false;
  }
  if (cid.version !== 1 || cid.code !== raw.code) return false;
  // Require the canonical lowercase base32 string form.
  if (cid.toString() !== cidString) return false;
  return (await computeCid(bytes)) === cidString;
}
