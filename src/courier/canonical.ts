/**
 * Canonical JSON and the request hash an approval carries.
 *
 * Mirrors packages/courier/src/canonical.ts in TinyCloudLabs/js-sdk (the CLI
 * recomputes this hash before it acts on an approval). Both must produce the
 * same string: recursively sorted object keys (UTF-16 code-unit order), no
 * whitespace, arrays in order. `requestHash` is the lowercase hex SHA-256 of
 * the UTF-8 bytes of that string.
 */

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical-json-number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item === undefined ? null : item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("canonical-json-type");
}

export async function requestHash(request: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(request)));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
