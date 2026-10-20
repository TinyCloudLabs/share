/**
 * Browser-storage keys that must not reveal which shares a person opened: the
 * share id goes in only as a SHA-256 digest, behind a per-feature prefix.
 */
export async function hashedShareKey(prefix: string, shareId: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(shareId)));
  return `${prefix}${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
