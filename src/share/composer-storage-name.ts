import { canonicalShareFilename } from "../filename-policy.js";
import { fail } from "./sender-failure.js";

/**
 * TC-1610. The name a file is stored under in the owner's TinyCloud.
 *
 * The node answers 401 to any key with a space or a non-ASCII character, so a
 * file named `q3 report.md` or `über.md` cannot be stored under its own name.
 * The key gets a readable URI-safe name instead, by the same rule as
 * `tc share publish` (js-sdk packages/cli/src/share/adapters.ts,
 * `safeStorageFilename`): a name that already is `[A-Za-z0-9][A-Za-z0-9._-]*`
 * (at most 128 characters, no `..`) is kept; otherwise accents are folded, the
 * other characters become `-`, a plain extension (1-16 ASCII letters or digits)
 * is kept and never added, and a leading dot is dropped (`.env` -> `share.env`).
 * The name the sender chose is the display name: it stays in the saved record
 * and, for an addressed share, in the signed metadata.
 */
const URI_SAFE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function safeStorageFilename(filename: string): string {
  if (URI_SAFE_FILENAME.test(filename) && !filename.includes("..")) return filename;
  const dot = filename.lastIndexOf(".");
  const extension = dot >= 0 && /^[A-Za-z0-9]{1,16}$/.test(filename.slice(dot + 1)) ? filename.slice(dot + 1) : "";
  const stem = (extension === "" ? filename : filename.slice(0, dot))
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(extension === "" ? /[^A-Za-z0-9_-]+/g : /[^A-Za-z0-9._-]+/g, "-")
    .replace(/\.{2,}/g, ".")
    .replace(/-{2,}/g, "-")
    .slice(0, 100)
    .replace(/^[^A-Za-z0-9]+|[-.]+$/g, "");
  return `${stem === "" ? "share" : stem}${extension === "" ? "" : `.${extension}`}`;
}

/**
 * The stored name for one display name. A name the share viewer would refuse
 * (a control or bidi character, a slash, `..`) is refused here with the
 * ordinary "can't be shared, rename it" message instead of being rewritten.
 */
export function storageFilenameFor(displayName: string): string {
  try {
    canonicalShareFilename(displayName);
  } catch {
    throw fail("filename", "share filename is unsafe");
  }
  const stored = safeStorageFilename(displayName.normalize("NFC"));
  if (!URI_SAFE_FILENAME.test(stored) || stored.includes("..")) throw fail("filename", "share filename cannot be made URI-safe");
  return stored;
}

/** `name.ext` -> `name-2.ext`, within the 128-character limit. */
function withSuffix(stored: string, n: number): string {
  const dot = stored.lastIndexOf(".");
  const hasExtension = dot > 0;
  const stem = hasExtension ? stored.slice(0, dot) : stored;
  const extension = hasExtension ? stored.slice(dot) : "";
  const suffix = `-${n}`;
  return `${stem.slice(0, 128 - extension.length - suffix.length)}${suffix}${extension}`;
}

/**
 * Stored paths for files that land in one share: every segment gets its own
 * safe name (a folder called `my notes` is stored as `my-notes`), and a numeric
 * suffix on the file name (`a-b.md`, `a-b-2.md`) when two paths would be the
 * same (compared without regard to case). The result is in the order of `paths`.
 */
export function uniqueStoragePaths(paths: readonly string[]): string[] {
  const taken = new Set<string>();
  return paths.map((path) => {
    const segments = path.split("/").map(storageFilenameFor);
    const folder = segments.slice(0, -1).join("/");
    const name = segments.at(-1)!;
    const join = (leaf: string): string => (folder === "" ? leaf : `${folder}/${leaf}`);
    let candidate = name;
    for (let n = 2; taken.has(join(candidate).toLowerCase()); n += 1) candidate = withSuffix(name, n);
    taken.add(join(candidate).toLowerCase());
    return join(candidate);
  });
}
