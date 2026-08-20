/** Canonical email normalization shared by addressed-link parsing. */
export function normalizeExactEmail(value: string): string {
  const at = value.indexOf("@");
  if (at <= 0 || at !== value.lastIndexOf("@")) throw new TypeError("email");
  const local = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();
  if (!/^[^@\s]+$/.test(local) || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/.test(domain)) throw new TypeError("email");
  return `${local}@${domain}`;
}
