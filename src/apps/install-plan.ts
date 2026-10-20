/**
 * What an install is allowed to ask for and to write. Pure: no DOM, no
 * network, no SDK.
 *
 * The sign-in the install needs is NOT the app's own manifest. The app's
 * runtime grants (SQL, key-value prefixes, reads of another app's database)
 * are what the app asks for when it is opened, with its own sign-in; asking
 * for them at install would hand them to a session that only copies files. The
 * installer's manifest therefore takes the app's identity (id, name,
 * description, version) from the verified catalog manifest and nothing else:
 * `defaults: false`, no `secrets`, no `did`, no delegations, no public space,
 * and exactly two write grants, `<app_id>/app/` and `<app_id>/knowledge/`,
 * with `put` as the only action (a create-only write needs nothing more).
 *
 * `installerAccess` renders that request for the sheet through the same
 * `summarizeAccess` the app's own lists use; the SDK's own composition of the
 * same manifest is compared with it in the tests and again, from the real SDK,
 * just before the sign-in opens (see install-session.ts).
 */
import type { Manifest } from "@tinycloud/web-sdk";

import type { ManifestScope } from "../share/manifest-policy.js";
import { isSignInLabel } from "../share/sign-in-label.js";
import { type AccessItem, type AccessSummary, summarizeAccess } from "./access.ts";
import { INSTALL_RECORD_PATH } from "./bundle.ts";
import type { CatalogEntry } from "./catalog.ts";

export const INSTALL_SPACE = "applications";
/** The install only copies files, so its session is short (a brand-new account is asked several times). Everything below derives from this one constant. */
export const INSTALL_EXPIRY_MS = 15 * 60 * 1000;
/** The manifest's own expiry string (ms-format), derived from the constant. */
export const INSTALL_EXPIRY = `${INSTALL_EXPIRY_MS / 60_000}m`;
/** How the sheet says how long the install's session lasts: "15 minutes". */
export const INSTALL_SESSION_LABEL = `${INSTALL_EXPIRY_MS / 60_000} ${INSTALL_EXPIRY_MS === 60_000 ? "minute" : "minutes"}`;

/** The most characters the shared sign-in accepts in the name OpenKey shows. */
const APP_NAME_MAX_CHARS = 64;
const APP_NAME_PREFIX = "TinyCloud Share: install ";
/** Used where the catalog's own name is not a name the shared sign-in accepts. */
export const APP_NAME_FALLBACK = "Tiny app";

/**
 * The name OpenKey shows for the install. DISPLAY ONLY: it never identifies the app (the app id and the grants come
 * from the catalog entry). The catalog's name goes in only if the shared sign-in would accept it as a name
 * (`isSignInLabel`: no link-like text such as "Node.js Notes", no invisible characters); otherwise the fixed
 * name "Tiny app" stands in, and the install proceeds. The whole line is cut to 64 characters, which the helper allows.
 */
export function installAppName(appName: string): string {
  const named = isSignInLabel(appName) ? appName : APP_NAME_FALLBACK;
  const cut = [...`${APP_NAME_PREFIX}${named}`].slice(0, APP_NAME_MAX_CHARS).join("").trimEnd();
  return isSignInLabel(cut) ? cut : `${APP_NAME_PREFIX}${APP_NAME_FALLBACK}`;
}

/**
 * What `signInWithManifest` may let the installer manifest ask for: `put` on
 * `<app_id>/app/` and `<app_id>/knowledge/` in `applications`, and nothing
 * else. The helper resolves the manifest as the SDK would (defaults expanded,
 * prefix applied) and refuses it before OpenKey opens if anything falls
 * outside this, so a widened manifest (another prefix or space, a `del`, SQL,
 * `defaults` on) cannot reach the sign-in. The SDK's account-registry
 * permissions are added on top by the helper and are not part of the scope.
 */
export function installerScope(appId: string): ManifestScope {
  return {
    allowedSpaces: [INSTALL_SPACE],
    allowedServices: ["kv"],
    allowedActions: ["put"],
    allowedPathPrefixes: [
      { space: INSTALL_SPACE, prefix: `${appId}/app/` },
      { space: INSTALL_SPACE, prefix: `${appId}/knowledge/` },
    ],
  };
}

/** `<app_id>/app/` for the app's files and `<app_id>/knowledge/` for its notes; nothing else is written. */
export function installKey(appId: string, path: string): string {
  return path.startsWith("knowledge/") ? `${appId}/${path}` : `${appId}/app/${path}`;
}

export function installRecordKey(appId: string): string {
  return `${appId}/app/${INSTALL_RECORD_PATH}`;
}

/** The manifest the install signs in with. `app` is the verified catalog manifest; only its identity is read. */
export function installerManifest(app: { app_id: string; name: string; description?: string; appVersion?: string }): Manifest {
  return {
    manifest_version: 1,
    app_id: app.app_id,
    name: app.name,
    ...(typeof app.description === "string" ? { description: app.description } : {}),
    ...(typeof app.appVersion === "string" ? { appVersion: app.appVersion } : {}),
    space: INSTALL_SPACE,
    defaults: false,
    includePublicSpace: false,
    expiry: INSTALL_EXPIRY,
    permissions: [
      { service: "tinycloud.kv", path: "app/", actions: ["put"], description: "Save the app's files. Files that already exist are kept, never replaced." },
      { service: "tinycloud.kv", path: "knowledge/", actions: ["put"], description: "Save the app's notes for agents. Files that already exist are kept, never replaced." },
    ],
  };
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

/** Plain-language reason for each registry grant, in the order of REGISTRY_RESOURCES. */
const REGISTRY_DESCRIPTIONS = [
  "Your account's list of apps (this is where the installed app is recorded).",
  "Your account's list of spaces.",
  "A marker that your account's setup finished.",
  "See which delegations your account has made.",
  "Your account's own index database, where those lists are kept.",
  "See which permissions it has been given in your account space (added automatically).",
] as const;

const SERVICE_LABEL: Record<string, string> = {
  "tinycloud.kv": "Key-value",
  "tinycloud.sql": "SQL database",
  "tinycloud.delegation": "Delegation",
  "tinycloud.capabilities": "Capabilities",
};

function registryItems(): { read: AccessItem[]; change: AccessItem[] } {
  const read: AccessItem[] = [];
  const change: AccessItem[] = [];
  REGISTRY_RESOURCES.forEach((resource, index) => {
    const actions = resource.actions.map((action) => action.slice(action.lastIndexOf("/") + 1));
    const base = { description: REGISTRY_DESCRIPTIONS[index] ?? null, service: SERVICE_LABEL[resource.service] ?? resource.service, space: resource.space, target: resource.path === "" ? resource.space : resource.path, path: resource.path };
    const isRead = (action: string): boolean => action === "get" || action === "list" || action === "read";
    const reads = actions.filter(isRead);
    const changes = actions.filter((action) => !isRead(action));
    if (reads.length > 0) read.push({ ...base, actions: reads });
    if (changes.length > 0) change.push({ ...base, actions: changes });
  });
  return { read, change };
}

/** Everything the install's sign-in requests, for the sheet. */
export interface InstallerAccess {
  /** The two folders the installer writes into. */
  app: AccessSummary;
  /** The account-registry grants the SDK adds to every sign-in that keeps the apps list. */
  registry: AccessSummary;
}

export function installerAccess(manifest: Manifest): InstallerAccess {
  return { app: summarizeAccess(manifest), registry: registryItems() };
}

/** What the SDK should compose from `installerManifest`: the two folders, the implicit `applications` capabilities read, and the registry. */
export function expectedInstallerResources(manifest: Manifest): RequestedResource[] {
  return [
    ...["app/", "knowledge/"].map((folder) => ({ service: "tinycloud.kv", space: INSTALL_SPACE, path: `${manifest.app_id}/${folder}`, actions: ["tinycloud.kv/put"] })),
    { service: "tinycloud.capabilities", space: INSTALL_SPACE, path: "", actions: ["tinycloud.capabilities/read"] },
    ...REGISTRY_RESOURCES.map((resource) => ({ ...resource, actions: [...resource.actions] })),
  ];
}

const resourceKey = (resource: RequestedResource): string => `${resource.service}|${resource.space}|${resource.path}|${[...resource.actions].sort().join(",")}`;

/** Why `actual` (the SDK's composition) is not exactly what the sheet shows, or null. */
export function resourceMismatch(expected: readonly RequestedResource[], actual: readonly RequestedResource[]): string | null {
  const want = new Set(expected.map(resourceKey));
  const got = new Set(actual.map(resourceKey));
  const extra = [...got].filter((key) => !want.has(key));
  const missing = [...want].filter((key) => !got.has(key));
  if (extra.length === 0 && missing.length === 0 && actual.length === expected.length) return null;
  return `unexpected: ${extra.join("; ") || "none"}; missing: ${missing.join("; ") || "none"}`;
}

/** What `<app_id>/app/install.json` holds: where the files came from, which bundle, and when. */
export function installRecord(entry: CatalogEntry, installedAt: Date): Uint8Array {
  const record = { source: { repo: entry.source.repo, tag: entry.source.tag, commit: entry.source.commit }, digest: entry.bundle.digest, installed_at: installedAt.toISOString() };
  return new TextEncoder().encode(`${JSON.stringify(record, null, 2)}\n`);
}

/** Where "Open" goes once the runner exists (T5b). */
export function runnerHref(appId: string): string {
  return `/apps/run#${appId}`;
}
