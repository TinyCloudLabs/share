/**
 * Canonical JSON and the request hash an approval carries.
 *
 * Mirrors packages/courier/src/canonical.ts in TinyCloudLabs/js-sdk (the CLI
 * recomputes this hash before it acts on an approval). Both must produce the
 * same string: recursively sorted object keys (UTF-16 code-unit order), no
 * whitespace, arrays in order. `requestHash` is the lowercase hex SHA-256 of
 * the UTF-8 bytes of that string.
 *
 * Two inputs have no honest canonical form and throw, on both sides, so a file
 * can never hash the same as a different one: a number that is not finite
 * (`1e999` parses to Infinity, which JSON.stringify would write as `null`), and
 * nesting deeper than `MAX_DEPTH`. The caller treats a throw as "this request
 * can't be reviewed", never as a reason to stop showing the others.
 */

/** The outermost array or object is level 1. */
export const MAX_DEPTH = 64;

export function canonicalJson(value: unknown, depth = 0): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical-json-number");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw new TypeError("canonical-json-type");
  if (depth + 1 > MAX_DEPTH) throw new TypeError("canonical-json-depth");
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item === undefined ? null : item, depth + 1)).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key], depth + 1)}`).join(",")}}`;
}

export async function requestHash(request: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(request)));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
