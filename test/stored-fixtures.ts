import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { CatalogEntry } from "../src/apps/catalog.ts";
import type { StoredFiles } from "../src/apps/stored-app.ts";

export const bundleBytes = (entry: CatalogEntry, path: string): Uint8Array => new Uint8Array(readFileSync(join("public", entry.bundle.root, path)));

export const installRecordBytes = (entry: CatalogEntry, overrides: Record<string, unknown> = {}): Uint8Array =>
  new TextEncoder().encode(JSON.stringify({ source: { repo: entry.source.repo, tag: entry.source.tag, commit: entry.source.commit }, digest: entry.bundle.digest, installed_at: "2026-10-20T10:00:00.000Z", ...overrides }));

export interface StoredOverrides {
  /** Replaces a file's bytes (or adds one). */
  readonly files?: Readonly<Record<string, Uint8Array>>;
  /** Files left out. */
  readonly remove?: readonly string[];
  readonly incomplete?: boolean;
}

/**
 * What the installer leaves under `<app_id>/app/`: every catalog file outside `knowledge/` byte for byte, plus
 * `install.json`; `overrides` edits that set the way a person (or their agent) could.
 */
export function storedFiles(entry: CatalogEntry, overrides: StoredOverrides = {}): StoredFiles {
  const entries = new Map<string, Uint8Array>();
  for (const file of entry.bundle.files) if (!file.path.startsWith("knowledge/")) entries.set(file.path, bundleBytes(entry, file.path));
  entries.set("install.json", installRecordBytes(entry));
  for (const [path, bytes] of Object.entries(overrides.files ?? {})) entries.set(path, bytes);
  for (const path of overrides.remove ?? []) entries.delete(path);
  return { entries, ...(overrides.incomplete === true ? { incomplete: true } : {}) };
}
