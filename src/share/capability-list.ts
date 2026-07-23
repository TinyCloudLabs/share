export function parseCapabilityList(value: unknown): readonly unknown[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("share capability list is invalid");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Array.isArray(record.capabilities)) throw new TypeError("share capability list is invalid");
  return record.capabilities;
}
