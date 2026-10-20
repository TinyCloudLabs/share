/**
 * Where an app's files are saved in the person's TinyCloud: the space, the key
 * layout, the write order, the saved record, and the registry grants the
 * shared sign-in adds. Pure: no DOM, no network, no SDK.
 *
 * Opening an app saves its files under `<app_id>/app/` and `<app_id>/knowledge/`
 * in the `applications` space (run.ts, run-session.ts). `install.json` is written
 * last in that order, so a folder that has it is complete.
 */
import { INSTALL_RECORD_PATH } from "./bundle.ts";
import type { CatalogEntry } from "./catalog.ts";

export const INSTALL_SPACE = "applications";
/** The read session that also saves the files is short. Everything below derives from this one constant. */
export const INSTALL_EXPIRY_MS = 15 * 60 * 1000;
/** The manifest's own expiry string (ms-format), derived from the constant. */
export const INSTALL_EXPIRY = `${INSTALL_EXPIRY_MS / 60_000}m`;

const CONTENT_TYPES: Record<string, string> = { json: "application/json", md: "text/markdown; charset=utf-8", jsx: "text/plain; charset=utf-8", sql: "text/plain; charset=utf-8" };

/** The content type a saved file is written with, by extension. */
export function contentTypeOf(path: string): string {
  const extension = path.slice(path.lastIndexOf(".") + 1);
  return Object.hasOwn(CONTENT_TYPES, extension) ? (CONTENT_TYPES[extension] ?? "application/octet-stream") : "application/octet-stream";
}

/** Why a save or a repair did not finish. */
export type InstallFailure = "disabled" | "catalog" | "tampered" | "unavailable" | "cancelled" | "timeout" | "busy" | "wrong-account" | "write-failed" | "failed";

/** `<app_id>/app/` for the app's files and `<app_id>/knowledge/` for its notes; nothing else is written. */
export function installKey(appId: string, path: string): string {
  return path.startsWith("knowledge/") ? `${appId}/${path}` : `${appId}/app/${path}`;
}

export function installRecordKey(appId: string): string {
  return `${appId}/app/${INSTALL_RECORD_PATH}`;
}

/**
 * The order an app's files are written in: the app's files, then its notes, both sorted by path. `install.json` is
 * written after this list by every caller, so a folder that has it is complete (the commit point). Nothing writes it earlier.
 */
export function installOrder<T extends { path: string }>(files: readonly T[]): T[] {
  const byPath = (a: T, b: T) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const app = files.filter((file) => !file.path.startsWith("knowledge/")).sort(byPath);
  const knowledge = files.filter((file) => file.path.startsWith("knowledge/")).sort(byPath);
  return [...app, ...knowledge];
}

/** `{ service, space, path, actions }` the way the SDK's `composeManifestRequest` reports a resource. */
export interface RequestedResource {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

/**
 * The SDK adds these itself when a manifest asks for the account registry
 * (`includeAccountRegistryPermissions`, which the shared sign-in always sets):
 * Share keeps the person's list of apps and spaces in their `account` space.
 * They mirror `ACCOUNT_MANIFEST_PERMISSIONS` in @tinycloud/bootstrap; the
 * tests compare them with the SDK's own list.
 */
export const REGISTRY_RESOURCES: readonly RequestedResource[] = [
  { service: "tinycloud.kv", space: "account", path: "applications/", actions: ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/list"] },
  { service: "tinycloud.kv", space: "account", path: "spaces/", actions: ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/list"] },
  { service: "tinycloud.kv", space: "account", path: "system/bootstrap/complete", actions: ["tinycloud.kv/get", "tinycloud.kv/put"] },
  { service: "tinycloud.delegation", space: "account", path: "", actions: ["tinycloud.delegation/list"] },
  { service: "tinycloud.sql", space: "account", path: "account", actions: ["tinycloud.sql/read", "tinycloud.sql/write", "tinycloud.sql/schema"] },
  { service: "tinycloud.capabilities", space: "account", path: "", actions: ["tinycloud.capabilities/read"] },
];

/** What `<app_id>/app/install.json` holds: where the files came from, which bundle, and when. */
export function installRecord(entry: CatalogEntry, installedAt: Date): Uint8Array {
  const record = { source: { repo: entry.source.repo, tag: entry.source.tag, commit: entry.source.commit }, digest: entry.bundle.digest, installed_at: installedAt.toISOString() };
  return new TextEncoder().encode(`${JSON.stringify(record, null, 2)}\n`);
}

/** Where "Open" goes: the runner page for an app. */
export function runnerHref(appId: string): string {
  return `/apps/run#${appId}`;
}
