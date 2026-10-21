/**
 * Turns the three files an install left in the person's TinyCloud into something
 * the runner may sign in for and run, or says plainly why not. Pure apart from
 * the injected catalog-manifest loader.
 *
 *   <app_id>/app/install.json   what was installed: {source, digest, installed_at} (written by the install)
 *   <app_id>/app/manifest.json  the person's copy of the manifest (theirs to edit)
 *   <app_id>/app/app.jsx        the person's copy of the code (theirs to edit)
 *
 * The code and the knowledge are the person's: whatever is stored runs. The
 * GRANTS are not: the stored manifest is re-validated with the SDK's
 * `validateManifest` and capped against the catalog manifest of the digest the
 * install recorded (grants.ts), so editing the copy can narrow what the bridge
 * lets the app call but never widen it.
 *
 * The CODE is pinned. Every file under `<app_id>/app/` other than manifest.json
 * (checked by the cap above) and install.json (the install's own record) must be
 * one the catalog lists for the installed digest, byte for byte (sha256 and size),
 * and every file the catalog lists there must be present. Anything else (an edited
 * app.jsx, an extra file, a missing one) is refused before any session or frame:
 * a hand-edited copy of the code no longer runs. The knowledge folder is not read
 * here and stays the person's.
 */
import type { Manifest } from "@tinycloud/sdk-core";

import { sha256Hex } from "./bundle.ts";
import type { CatalogEntry } from "./catalog.ts";
import type { ManifestScope } from "../share/manifest-policy.js";
import { type Authorizer, type GrantRefusal, type ManifestSdk, capGrants, makeAuthorizer, runtimeScope } from "./grants.ts";
import type { ManifestResult } from "./manifest.ts";

export const MAX_MANIFEST_BYTES = 64 * 1024;
export const MAX_INSTALL_RECORD_BYTES = 8 * 1024;
/** UTF-8 bytes; the sandbox limits the source by characters (512 K). */
export const MAX_APP_SOURCE_BYTES = 3 * 512 * 1024;

export interface InstallRecord {
  readonly source: { readonly repo: string; readonly tag: string | null; readonly commit: string };
  readonly digest: string;
  readonly installedAt: string;
}

/** The saved files under `<app_id>/app/`, keyed by path relative to it (`app.jsx`, `manifest.json`, `install.json`, ...). */
export interface StoredFiles {
  readonly entries: ReadonlyMap<string, Uint8Array>;
  /** The listing or a read was cut short (too many files or bytes): the code cannot be vouched for. */
  readonly incomplete?: boolean;
}

export const MANIFEST_FILE = "manifest.json";
export const SOURCE_FILE = "app.jsx";
/** Files under `app/` that are not pinned: the manifest (capped by grants.ts) and the install's own record. */
const UNPINNED: ReadonlySet<string> = new Set([MANIFEST_FILE, "install.json"]);

/** The catalog's code files for an entry: what it installs under `app/`, except the manifest. */
export function codePins(entry: CatalogEntry): readonly { path: string; sha256: string; size: number }[] {
  return entry.bundle.files.filter((file) => !file.path.startsWith("knowledge/") && !UNPINNED.has(file.path));
}

/** Why the saved code is not the pinned version, or undefined when it is exactly that. */
export async function pinProblem(entry: CatalogEntry, stored: StoredFiles): Promise<string | undefined> {
  const pins = codePins(entry);
  if (!pins.some((pin) => pin.path === SOURCE_FILE)) return "the catalog lists no app.jsx for this version";
  if (stored.incomplete === true) return "the saved files could not all be read";
  const wanted = new Set(pins.map((pin) => pin.path));
  for (const path of stored.entries.keys()) if (!wanted.has(path) && !UNPINNED.has(path)) return `unexpected file ${path}`;
  for (const pin of pins) {
    const bytes = stored.entries.get(pin.path);
    if (bytes === undefined) return `missing file ${pin.path}`;
    if (bytes.byteLength !== pin.size || await sha256Hex(new Uint8Array(bytes)) !== pin.sha256) return `${pin.path} differs from the pinned version`;
  }
  return undefined;
}

/** Why a stored app cannot be run. `detail` is for logs and tests; the page says it in plain words. */
export type StoredAppFailure =
  | { readonly reason: "damaged"; readonly detail: string }
  | { readonly reason: "code-mismatch"; readonly detail: string }
  | { readonly reason: "not-listed"; readonly detail: string }
  | { readonly reason: "catalog-unavailable"; readonly detail: string }
  | GrantRefusal;

export interface RunnableApp {
  readonly appId: string;
  /** The name in the person's copy of the manifest (shown as text only). */
  readonly name: string;
  /** The catalog entry of the installed bundle: where the app came from, verified. */
  readonly entry: CatalogEntry;
  readonly install: InstallRecord;
  /** The capped copy: the source of the bridge allow-list and the consent lists (grants.ts). */
  readonly signing: Manifest;
  /** What the sign-in helper may let the open ask for: derived from the catalog manifest, not the stored one. */
  readonly scope: ManifestScope;
  readonly authorize: Authorizer;
  /** app.jsx, byte for byte the pinned file. */
  readonly source: Uint8Array;
}

export interface VerifyDeps {
  readonly catalog: readonly CatalogEntry[];
  readonly loadCatalogManifest: (entry: CatalogEntry) => Promise<ManifestResult>;
  readonly sdk: ManifestSdk;
}

const HEX64 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{7,64}$/;

function parseJson(bytes: Uint8Array, limit: number): unknown {
  if (bytes.byteLength === 0 || bytes.byteLength > limit) throw new Error("size");
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** `{source:{repo,tag,commit}, digest, installed_at}` as the install writes it; null for anything else. */
export function parseInstallRecord(bytes: Uint8Array): InstallRecord | null {
  let json: unknown;
  try { json = parseJson(bytes, MAX_INSTALL_RECORD_BYTES); } catch { return null; }
  if (!isObject(json) || !isObject(json["source"])) return null;
  const { repo, tag, commit } = json["source"];
  const digest = json["digest"];
  const installedAt = json["installed_at"];
  if (typeof repo !== "string" || repo.length === 0 || repo.length > 300) return null;
  if (tag !== null && (typeof tag !== "string" || tag.length > 100)) return null;
  if (typeof commit !== "string" || !COMMIT.test(commit)) return null;
  if (typeof digest !== "string" || !HEX64.test(digest)) return null;
  if (typeof installedAt !== "string" || installedAt.length > 40) return null;
  return { source: { repo, tag, commit }, digest, installedAt };
}

export async function verifyStoredApp(appId: string, files: StoredFiles, deps: VerifyDeps): Promise<{ ok: true; app: RunnableApp } | { ok: false; failure: StoredAppFailure }> {
  const fail = (failure: StoredAppFailure): { ok: false; failure: StoredAppFailure } => ({ ok: false, failure });
  const installBytes = files.entries.get("install.json");
  const manifestBytes = files.entries.get(MANIFEST_FILE);
  const source = files.entries.get(SOURCE_FILE);
  if (installBytes === undefined || manifestBytes === undefined || source === undefined) return fail({ reason: "damaged", detail: "a saved file is missing" });
  const install = parseInstallRecord(installBytes);
  if (install === null) return fail({ reason: "damaged", detail: "install.json is not a valid install record" });
  if (source.byteLength === 0 || source.byteLength > MAX_APP_SOURCE_BYTES) return fail({ reason: "damaged", detail: "app.jsx is empty or too large" });

  let stored: Manifest;
  try {
    stored = deps.sdk.validateManifest(parseJson(manifestBytes, MAX_MANIFEST_BYTES));
  } catch (error) {
    return fail({ reason: "damaged", detail: `manifest.json: ${error instanceof Error ? error.message.slice(0, 200) : "unreadable"}` });
  }
  if (stored.app_id !== appId) return fail({ reason: "damaged", detail: "manifest.json names a different app" });

  // The catalog entry of the exact bundle that was installed; its pins are the code, its manifest is the cap.
  const entry = deps.catalog.find((candidate) => candidate.app_id === appId && candidate.bundle.digest === install.digest);
  if (entry === undefined) return fail({ reason: "not-listed", detail: "the installed bundle is not in the catalog" });
  const pin = await pinProblem(entry, files);
  if (pin !== undefined) return fail({ reason: "code-mismatch", detail: pin });
  const loaded = await deps.loadCatalogManifest(entry);
  if (!loaded.ok) return fail({ reason: "catalog-unavailable", detail: loaded.reason });
  let catalogManifest: Manifest;
  try {
    catalogManifest = deps.sdk.validateManifest(loaded.manifest);
  } catch {
    return fail({ reason: "catalog-unavailable", detail: "the catalog manifest is not valid" });
  }

  const capped = capGrants(stored, catalogManifest, deps.sdk);
  if (!capped.ok) return fail(capped.refusal);
  return {
    ok: true,
    app: {
      appId,
      name: stored.name.slice(0, 80),
      entry,
      install,
      signing: capped.value.signing,
      scope: runtimeScope(catalogManifest, deps.sdk),
      authorize: makeAuthorizer(capped.value.signing, deps.sdk),
      source,
    },
  };
}
