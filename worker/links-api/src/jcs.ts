/**
 * RFC 8785 canonical JSON for the value space the signed objects use: objects, arrays, strings,
 * safe integers, booleans and null. Object keys sort by UTF-16 code unit; strings serialise as
 * ECMAScript JSON strings.
 */
export function jcs(value: unknown): string {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new TypeError("jcs: integers only");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map(jcs).join(",")}]`;
      }
      const record = value as Record<string, unknown>;
      return `{${Object.keys(record)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${jcs(record[k])}`)
        .join(",")}}`;
    }
    default:
      throw new TypeError("jcs: unsupported value");
  }
}
