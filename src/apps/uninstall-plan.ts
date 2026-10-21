/**
 * What an uninstall may delete and how it asks for that. Pure: no DOM, no
 * network, no SDK.
 *
 * Uninstall removes the app's code (`<app_id>/app/`), its agent notes
 * (`<app_id>/knowledge/`) and its entry in the person's apps list
 * (`applications/<app_id>` in the account space). It keeps everything else
 * under `<app_id>/`: SQL databases, `prefs/`, and the person's files.
 *
 * The sign-in is a Share maintenance identity, never the app's own id. A
 * sign-in that registers under the app's id would re-create the record this
 * removes. The identity's manifest sets `prefix` to the app id so the folder
 * grants resolve to `<app_id>/…`, and it leaves the SDK's registry grants out
 * (`includeAccountRegistryPermissions: false`), so no apps-list record is
 * written for the identity itself.
 */
import type { Manifest } from "@tinycloud/web-sdk";

import type { ManifestScope } from "../share/manifest-policy.js";
import { type RequestedResource, INSTALL_EXPIRY, INSTALL_SPACE, installRecordKey } from "./install-plan.ts";
import { type AccessSummary, summarizeAccess } from "./access.ts";

/** The Share maintenance identity. Not any app's id: see the header. */
export const UNINSTALL_IDENTITY_ID = "tinycloud-share-uninstall";

export const ACCOUNT_SPACE = "account";

/** Page size for listing a folder; the loop pages until the list is complete or `MAX_LIST_PAGES` is reached. */
export const LIST_PAGE_LIMIT = 500;
export const MAX_LIST_PAGES = 200;

export type UninstallFailure = "refused" | "truncated" | "cancelled" | "timeout" | "wrong-account" | "busy" | "not-started" | "failed" | "write-failed";

export class UninstallError extends Error {
  readonly reason: UninstallFailure;
  /** Keys already deleted when the uninstall stopped; a retry removes the rest. */
  readonly deleted: readonly string[];
  constructor(reason: UninstallFailure, detail: { deleted?: readonly string[]; cause?: unknown } = {}) {
    super(`uninstall-${reason}`, detail.cause === undefined ? undefined : { cause: detail.cause });
    this.name = "UninstallError";
    this.reason = reason;
    this.deleted = detail.deleted ?? [];
  }
}

const APP_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Throws `refused` unless `appId` is one plain path segment (no separators, no `..`). */
export function assertPlainAppId(appId: string): void {
  if (!APP_ID_RE.test(appId) || appId.includes("..")) throw new UninstallError("refused");
}

/** The two folders uninstall may delete from, both with their trailing slash. */
export function folderPrefixes(appId: string): readonly string[] {
  assertPlainAppId(appId);
  return [`${appId}/app/`, `${appId}/knowledge/`];
}

/** The app's entry in the account space's apps list. */
export function registryKey(appId: string): string {
  assertPlainAppId(appId);
  return `applications/${appId}`;
}

/**
 * True when `key` is one file under `<appId>/app/` or `<appId>/knowledge/`.
 * The trailing slash on each prefix keeps `<appId>2/…` out; any empty, `.`,
 * `..`, percent-escaped dot or slash, backslash, or control segment is refused.
 */
export function isOwnedKey(appId: string, key: string): boolean {
  for (const prefix of folderPrefixes(appId)) {
    if (!key.startsWith(prefix)) continue;
    const rest = key.slice(prefix.length);
    if (rest.length === 0) return false;
    return rest.split("/").every((segment) => segment !== "" && segment !== "." && segment !== ".." && !/%2e|%2f|%5c|\\|[\u0000-\u001f\u007f]/i.test(segment));
  }
  return false;
}

/**
 * Order for the folder keys (the registry key is removed last, by the runner):
 * `knowledge/index.md`, then `install.json`, then everything else sorted. The
 * install record goes early so an interrupted run leaves a partial install
 * (which Open heals) rather than an installed record with missing files.
 * Keys outside the two folders are ignored, not deleted, so a listing can never widen the delete set.
 */
export function deleteOrder(appId: string, listed: readonly string[]): string[] {
  const owned = listed.filter((key) => isOwnedKey(appId, key));
  const unique = [...new Set(owned)].sort();
  const index = `${appId}/knowledge/index.md`;
  const record = installRecordKey(appId);
  const first = [index, record].filter((key) => unique.includes(key));
  return [...first, ...unique.filter((key) => !first.includes(key))];
}

/** What the uninstall may ask OpenKey for: list and del on the two folders, and del on the one registry key. */
export function uninstallScope(appId: string): ManifestScope {
  assertPlainAppId(appId);
  return {
    allowedSpaces: [INSTALL_SPACE, ACCOUNT_SPACE],
    allowedServices: ["kv"],
    allowedActions: ["list", "del"],
    allowedPathPrefixes: [
      { space: INSTALL_SPACE, prefix: `${appId}/app/` },
      { space: INSTALL_SPACE, prefix: `${appId}/knowledge/` },
      { space: ACCOUNT_SPACE, prefix: registryKey(appId) },
    ],
  };
}

/** The app's name as the uninstall shows it; the sign-in label stays short. */
export function uninstallAppName(appName: string): string {
  const name = appName.trim() === "" ? "Tiny app" : appName.trim();
  return `TinyCloud Share: uninstall ${name}`.slice(0, 64);
}

/** The manifest the uninstall signs in with. Its `app_id` is the maintenance identity; `prefix` is the app, so the folder grants land on `<app_id>/…`. */
export function uninstallManifest(app: { app_id: string; name: string }): Manifest {
  assertPlainAppId(app.app_id);
  return {
    manifest_version: 1,
    app_id: UNINSTALL_IDENTITY_ID,
    name: uninstallAppName(app.name),
    space: INSTALL_SPACE,
    prefix: app.app_id,
    defaults: false,
    includePublicSpace: false,
    expiry: INSTALL_EXPIRY,
    permissions: [
      { service: "tinycloud.kv", path: "app/", actions: ["list", "del"], description: "Remove the app's code files. Your data and settings are not touched." },
      { service: "tinycloud.kv", path: "knowledge/", actions: ["list", "del"], description: "Remove the app's agent notes, including any you edited." },
      { service: "tinycloud.kv", space: ACCOUNT_SPACE, path: registryKey(app.app_id), skipPrefix: true, actions: ["del"], description: "Remove the app from your apps list." },
    ],
  } as Manifest;
}

/** What the uninstall's composed request must be, resource for resource: the two folders, the registry key, and the capabilities reads the SDK adds per hosted space. */
export function expectedUninstallResources(appId: string): RequestedResource[] {
  assertPlainAppId(appId);
  return [
    { service: "tinycloud.kv", space: INSTALL_SPACE, path: `${appId}/app/`, actions: ["tinycloud.kv/list", "tinycloud.kv/del"] },
    { service: "tinycloud.kv", space: INSTALL_SPACE, path: `${appId}/knowledge/`, actions: ["tinycloud.kv/list", "tinycloud.kv/del"] },
    { service: "tinycloud.kv", space: ACCOUNT_SPACE, path: registryKey(appId), actions: ["tinycloud.kv/del"] },
    { service: "tinycloud.capabilities", space: INSTALL_SPACE, path: "", actions: ["tinycloud.capabilities/read"] },
    { service: "tinycloud.capabilities", space: ACCOUNT_SPACE, path: "", actions: ["tinycloud.capabilities/read"] },
  ];
}

/** Everything one uninstall needs, built once from the app: what is signed, what the sheet lists, and what the signed request must be. */
export interface UninstallPlan {
  readonly app_id: string;
  /** What is signed: the maintenance identity's manifest. */
  readonly manifest: Manifest;
  /** The app's name as the sign-in shows it. */
  readonly appName: string;
  readonly scope: ManifestScope;
  /** What the sheet lists: `summarizeAccess` over `manifest`, the same manifest that is signed. */
  readonly rows: AccessSummary;
  /** What the composed request must match, resource for resource. */
  readonly resources: RequestedResource[];
}

/** Builds the plan for one app. Throws `refused` for an unsafe id, before anything is shown or signed. */
export function uninstallPlan(app: { app_id: string; name: string }): UninstallPlan {
  assertPlainAppId(app.app_id);
  const manifest = uninstallManifest(app);
  return {
    app_id: app.app_id,
    appName: uninstallAppName(app.name),
    manifest,
    scope: uninstallScope(app.app_id),
    rows: summarizeAccess(manifest),
    resources: expectedUninstallResources(app.app_id),
  };
}
