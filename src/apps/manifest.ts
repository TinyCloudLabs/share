import type { CatalogEntry } from "./catalog.ts";

const BUNDLE_ROOT = /^\/apps\/b\/[0-9a-f]{64}\/$/;
const FILE_NAME = /^[A-Za-z0-9._-]+$/;

export type ManifestResult =
  | { ok: true; manifest: unknown }
  | { ok: false; reason: "unavailable" | "mismatch" };

const toHex = (bytes: ArrayBuffer): string => [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const cache = new Map<string, Promise<ManifestResult>>();

async function load(entry: CatalogEntry): Promise<ManifestResult> {
  const { root } = entry.bundle;
  if (!BUNDLE_ROOT.test(root) || !FILE_NAME.test(entry.manifest.path)) return { ok: false, reason: "unavailable" };
  try {
    // Same-origin static file; credentials and referrer are never sent.
    const response = await fetch(`${root}${entry.manifest.path}`, { credentials: "omit", referrerPolicy: "no-referrer" });
    if (!response.ok) return { ok: false, reason: "unavailable" };
    const bytes = await response.arrayBuffer();
    // What the sheet shows is only what the catalog pinned.
    if (toHex(await crypto.subtle.digest("SHA-256", bytes)) !== entry.manifest.sha256) return { ok: false, reason: "mismatch" };
    return { ok: true, manifest: JSON.parse(new TextDecoder().decode(bytes)) as unknown };
  } catch {
    return { ok: false, reason: "unavailable" };
  }
}

/** Fetches each app version's manifest once and checks it against that version's sha256. */
export function loadManifest(entry: CatalogEntry): Promise<ManifestResult> {
  const key = `${entry.app_id}:${entry.bundle.digest}`;
  const cached = cache.get(key);
  if (cached !== undefined) return cached;
  const pending = load(entry).then((result) => {
    // A failure may be transient: let the next open retry it.
    if (!result.ok) cache.delete(key);
    return result;
  });
  cache.set(key, pending);
  return pending;
}
