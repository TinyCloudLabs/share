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
 * install recorded (grants.ts), so editing the copy can narrow what the app is
 * signed for but never widen it.
 */
import type { Manifest } from "@tinycloud/sdk-core";

import type { CatalogEntry } from "./catalog.ts";
import { type Authorizer, type GrantRefusal, type ManifestSdk, capGrants, makeAuthorizer } from "./grants.ts";
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

export interface StoredFiles {
  readonly manifest: Uint8Array;
  readonly install: Uint8Array;
  readonly source: Uint8Array;
}

/** Why a stored app cannot be run. `detail` is for logs and tests; the page says it in plain words. */
export type StoredAppFailure =
  | { readonly reason: "damaged"; readonly detail: string }
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
  /** What the runner signs in with (grants.ts). */
  readonly signing: Manifest;
  readonly authorize: Authorizer;
  /** The person's copy of app.jsx, as stored. */
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
  const install = parseInstallRecord(files.install);
  if (install === null) return fail({ reason: "damaged", detail: "install.json is not a valid install record" });
  if (files.source.byteLength === 0 || files.source.byteLength > MAX_APP_SOURCE_BYTES) return fail({ reason: "damaged", detail: "app.jsx is empty or too large" });

  let stored: Manifest;
  try {
    stored = deps.sdk.validateManifest(parseJson(files.manifest, MAX_MANIFEST_BYTES));
  } catch (error) {
    return fail({ reason: "damaged", detail: `manifest.json: ${error instanceof Error ? error.message.slice(0, 200) : "unreadable"}` });
  }
  if (stored.app_id !== appId) return fail({ reason: "damaged", detail: "manifest.json names a different app" });

  // The catalog entry of the exact bundle that was installed; its manifest is the cap.
  const entry = deps.catalog.find((candidate) => candidate.app_id === appId && candidate.bundle.digest === install.digest);
  if (entry === undefined) return fail({ reason: "not-listed", detail: "the installed bundle is not in the catalog" });
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
      authorize: makeAuthorizer(capped.value.signing, deps.sdk),
      source: files.source,
    },
  };
}
