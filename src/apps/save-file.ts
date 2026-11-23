/**
 * What an installed app may offer the owner to save as a file (`file.save` on the runner bridge, TC-3995).
 *
 * The runner decides here, before anything is shown: the file's name, its type and its size. The app never
 * writes to disk and never clicks anything; it hands the runner a file it built, the runner shows it in its own
 * bar (src/apps/file-offer.ts), and only the owner's click on Save there starts a download.
 *
 * Types are a short list the runner owns. A browser or a desktop opens HTML, SVG, scripts, executables and
 * archives by running or rendering them, so none of those is on it; adding a type is a reviewed change.
 */

export interface SaveFileType {
  /** The extension a file of this type must end with, lower case, with its dot. */
  readonly extension: string;
  /** What the owner sees the type called. */
  readonly label: string;
}

export const SAVE_FILE_TYPES: Readonly<Record<string, SaveFileType>> = Object.freeze({
  "text/plain": { extension: ".txt", label: "text" },
  "text/csv": { extension: ".csv", label: "spreadsheet text (CSV)" },
  "text/vcard": { extension: ".vcf", label: "contact card (vCard)" },
  "text/markdown": { extension: ".md", label: "Markdown text" },
  "application/json": { extension: ".json", label: "JSON data" },
});

export const SAVE_FILE_NAME_MAX = 100;

/** A file the runner has checked and holds as bytes. */
export interface SaveFile {
  readonly name: string;
  readonly type: string;
  readonly bytes: Uint8Array;
}

export type SaveFileCheck = { readonly ok: true; readonly file: SaveFile } | { readonly ok: false; readonly message: string };

// Characters a name may not carry: a path separator, the characters Windows refuses, controls, and the invisible
// formatting characters (direction overrides, zero-width and byte-order marks) that make a name read as another.
const REFUSED_NAME_CHARACTER = /[/\\:*?"<>|\p{Cc}\p{Cf}]/u;
const WINDOWS_DEVICE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

const fail = (message: string): SaveFileCheck => ({ ok: false, message });

/** The type whose extension ends `name`, or undefined. */
function typeForName(name: string): string | undefined {
  const lower = name.toLowerCase();
  return Object.keys(SAVE_FILE_TYPES).find((type) => lower.endsWith(SAVE_FILE_TYPES[type]!.extension));
}

/** Checks the arguments of one `file.save` call: `{ name, body, type? }`. `type` is taken from the name's extension when it is left out. */
export function checkSaveFile(args: Readonly<Record<string, unknown>>): SaveFileCheck {
  const name = args["name"];
  const body = args["body"];
  const given = args["type"];
  if (typeof name !== "string") return fail("The file name must be a string.");
  if (name.length === 0 || name.length > SAVE_FILE_NAME_MAX) return fail(`The file name must be 1 to ${SAVE_FILE_NAME_MAX} characters.`);
  if (REFUSED_NAME_CHARACTER.test(name)) return fail("The file name can't hold a slash, a character Windows refuses, or a hidden or control character.");
  if (name.startsWith(".") || name.endsWith(".") || name.startsWith(" ") || name.endsWith(" ")) return fail("The file name can't start or end with a dot or a space.");
  if (WINDOWS_DEVICE.test(name.split(".")[0]!)) return fail("That file name is reserved.");
  if (given !== undefined && typeof given !== "string") return fail("The type must be a string.");
  const type = given ?? typeForName(name);
  const known = type === undefined ? undefined : SAVE_FILE_TYPES[type];
  if (type === undefined || known === undefined || !Object.hasOwn(SAVE_FILE_TYPES, type)) {
    return fail(`The type must be one of: ${Object.keys(SAVE_FILE_TYPES).join(", ")}.`);
  }
  if (!name.toLowerCase().endsWith(known.extension) || name.length === known.extension.length) {
    return fail(`A ${type} file must have a name that ends with ${known.extension}.`);
  }
  let bytes: Uint8Array;
  if (typeof body === "string") bytes = new TextEncoder().encode(body);
  // A copy: the frame's own buffer is never what the owner saves.
  else if (Object.prototype.toString.call(body) === "[object Uint8Array]") bytes = new Uint8Array(body as Uint8Array);
  else return fail("body must be a string or Uint8Array.");
  if (bytes.byteLength === 0) return fail("The file is empty.");
  return { ok: true, file: { name, type, bytes } };
}

/** "12 KB", "1.5 MB": what the owner reads beside the name. */
export function fileSizeLabel(bytes: number): string {
  if (bytes < 1000) return bytes === 1 ? "1 byte" : `${bytes} bytes`;
  if (bytes < 999_500) return `${Math.max(1, Math.round(bytes / 1000))} KB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}
