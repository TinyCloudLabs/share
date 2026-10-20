import type { IKVService } from "@tinycloud/sdk-services";
import { FILES_FOR_YOU_PREFIX, FILES_FOR_YOU_SPACE } from "./openkey-session.js";

/** What the viewer hands over: the verified bytes it rendered, a name that already passed the download-name policy, and the media type to store. */
export interface SavedCopyInput {
  readonly bytes: Uint8Array;
  readonly filename: string;
  readonly mediaType: string;
}

export interface SavedCopy {
  /** Space-relative key, `v1/<name>`, the name percent-encoded (see `savedCopyKey`). */
  readonly key: string;
  /** Where a person finds it: `files-for-you/v1/<name>`. */
  readonly path: string;
}

type SavedCopyKv = Pick<IKVService, "put">;

/** More saved copies of one name than this is a loop, not a person. */
const MAX_NAME_ATTEMPTS = 100;
const SAFE_NAME = /^[^/\\\u0000-\u001f\u007f]+$/;

/** `report.md`, then `report (2).md`, `report (3).md`. The extension stays last so the file keeps its type. */
export function savedCopyName(filename: string, attempt: number): string {
  if (attempt <= 1) return filename;
  const dot = filename.lastIndexOf(".");
  return dot > 0 ? `${filename.slice(0, dot)} (${attempt})${filename.slice(dot)}` : `${filename} (${attempt})`;
}

/**
 * A key is part of a resource URI on the node, and the node refuses (401) one
 * with a space or a non-ASCII character in it. The name is therefore stored
 * percent-encoded (`q3 report.md` is `q3%20report.md`); `decodeURIComponent`
 * gives the name back.
 */
export function savedCopyKey(name: string): string {
  return `${FILES_FOR_YOU_PREFIX}${encodeURIComponent(name).replace(/[!'*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)}`;
}

/**
 * Stores the exact bytes under `files-for-you/v1/<name>` and never replaces an
 * earlier copy: each attempt is a create-only write (`If-None-Match: *`), and
 * a name that is taken moves on to the next suffix. Only the bytes, name and
 * media type are written: nothing about the share (its link, id, sender or
 * expiry) is stored, so the copy outlives the share without naming it.
 */
export async function writeSavedCopy(kv: SavedCopyKv, copy: SavedCopyInput): Promise<SavedCopy> {
  if (!SAFE_NAME.test(copy.filename)) throw new Error("saved-copy-unsafe-name");
  for (let attempt = 1; attempt <= MAX_NAME_ATTEMPTS; attempt += 1) {
    const key = savedCopyKey(savedCopyName(copy.filename, attempt));
    const written = await kv.put(key, copy.bytes, { contentType: copy.mediaType, ifNoneMatch: "*" });
    if (written.ok) return { key, path: `${FILES_FOR_YOU_SPACE}/${key}` };
    if (written.error.code !== "KV_PRECONDITION_FAILED") throw new Error(`saved-copy-write-failed:${written.error.code}`);
  }
  throw new Error("saved-copy-no-free-name");
}
