/**
 * Repair: put the catalog's CODE files back over the saved ones.
 *
 * The runner refuses to open an app whose saved code is not the pinned version (stored-app.ts). Repair is the way
 * back: it re-installs the catalog's code files for the installed digest, overwriting what is stored, and removes
 * any other file in `<app_id>/app/`. It touches nothing else: not `knowledge/`, not the app's databases or settings,
 * not `install.json`. One OpenKey approval, for `put`, `del` and `list` on `<app_id>/app/` only, 15 minutes.
 *
 * Order, as for the install: every file is fetched from the entry's own `/apps/b/<digest>/` and checked against the
 * catalog BEFORE OpenKey opens (a tampered file: zero writes, zero approvals); a disabled entry is refused before
 * anything is fetched. Files are written first and strays removed last, so an interrupted repair leaves the code files
 * the catalog lists in place and Try again finishes it.
 *
 * An installed version that has left the catalog cannot be repaired (there is no pin to repair to): the runner says
 * what to delete instead.
 */
import type { Manifest } from "@tinycloud/web-sdk";
import { RunError } from "./run.ts";

import type { ManifestScope } from "../share/manifest-policy.js";
import { type BundleFetch, BundleRefusal, fetchVerifiedBundle } from "./bundle.ts";
import { type CatalogEntry, EntryDisabledError, assertAvailable } from "./catalog.ts";
import { type InstallFailure, INSTALL_EXPIRY, INSTALL_SPACE, contentTypeOf, installKey, installRecordKey } from "./install-plan.ts";

export type RepairFailure = InstallFailure;

export class RepairError extends Error {
  readonly reason: RepairFailure;
  readonly written: readonly string[];
  constructor(reason: RepairFailure, detail: { written?: readonly string[]; cause?: unknown } = {}) {
    super(`repair-${reason}`, detail.cause === undefined ? undefined : { cause: detail.cause });
    this.name = "RepairError";
    this.reason = reason;
    this.written = detail.written ?? [];
  }
}

/** What Repair may ask OpenKey for: `put`, `del` and `list` on the one app's `app/` folder. The helper refuses anything else before OpenKey opens. */
export function repairScope(appId: string): ManifestScope {
  return { allowedSpaces: [INSTALL_SPACE], allowedServices: ["kv"], allowedActions: ["put", "del", "list"], allowedPathPrefixes: [{ space: INSTALL_SPACE, prefix: `${appId}/app/` }] };
}

export function repairManifest(app: { app_id: string; name: string }): Manifest {
  return {
    manifest_version: 1,
    app_id: app.app_id,
    name: app.name,
    space: INSTALL_SPACE,
    defaults: false,
    includePublicSpace: false,
    expiry: INSTALL_EXPIRY,
    permissions: [{ service: "tinycloud.kv", path: "app/", actions: ["put", "del", "list"], description: "Replace the app's code files with the pinned version and remove any other file in that folder. Your data and notes are not touched." }],
  };
}

/** The key under `<app_id>/app/` for each catalog file that Repair writes: every file the install puts there, the manifest included. */
export function repairWrites(entry: CatalogEntry): readonly { path: string; key: string }[] {
  return entry.bundle.files
    .filter((file) => !file.path.startsWith("knowledge/"))
    .map((file) => ({ path: file.path, key: installKey(entry.app_id, file.path) }))
    .sort((a, b) => (a.path < b.path ? -1 : 1));
}

export interface RepairSession {
  /** Overwrites `key`. */
  put(key: string, bytes: Uint8Array, contentType: string): Promise<void>;
  /** Every key under `prefix`. */
  list(prefix: string): Promise<readonly string[]>;
  del(key: string): Promise<void>;
  dispose(): Promise<void> | void;
}

export interface RepairPorts {
  readInstallDigest(entry: CatalogEntry, hooks: { approval(open: boolean): void }): Promise<string | null>;
  openSession(manifest: Manifest, hooks: { approval(open: boolean): void }): Promise<RepairSession>;
  fetch?: BundleFetch;
}

export interface RepairOutcome {
  readonly written: readonly string[];
  readonly removed: readonly string[];
}

export type RepairProgress =
  | { phase: "checking-version" }
  | { phase: "checking" }
  | { phase: "signing-in" }
  | { phase: "approval" }
  | { phase: "repairing"; done: number; total: number };

function throwLookupFailure(error: unknown): never {
  if (error instanceof RepairError) throw error;
  if (error instanceof RunError) {
    switch (error.reason) {
      case "cancelled": case "timeout": case "busy": case "wrong-account": throw new RepairError(error.reason, { cause: error });
      case "damaged": case "not-listed": case "catalog-unavailable": throw new RepairError("catalog", { cause: error });
      default: throw new RepairError("failed", { cause: error });
    }
  }
  throw new RepairError("failed", { cause: error });
}

export async function runRepair(entry: CatalogEntry, ports: RepairPorts, report: (progress: RepairProgress) => void, versions: readonly CatalogEntry[] = [entry]): Promise<RepairOutcome> {
  report({ phase: "checking-version" });
  let digest: string | null;
  try {
    report({ phase: "signing-in" });
    digest = await ports.readInstallDigest(entry, { approval: (open) => report({ phase: open ? "approval" : "signing-in" }) });
  } catch (error) {
    throwLookupFailure(error);
  }
  if (digest === null) throw new RepairError("catalog");
  const installedEntry = versions.find((candidate) => candidate.app_id === entry.app_id && candidate.bundle.digest === digest);
  if (installedEntry === undefined) throw new RepairError("catalog");
  try { assertAvailable(installedEntry); } catch (error) {
    if (error instanceof EntryDisabledError) throw new RepairError("disabled");
    throw error;
  }
  report({ phase: "checking" });
  let bundle;
  try {
    bundle = await fetchVerifiedBundle(installedEntry, ports.fetch);
  } catch (error) {
    if (error instanceof BundleRefusal) throw new RepairError(error.reason, { cause: error });
    throw new RepairError("failed", { cause: error });
  }
  const wanted = repairWrites(installedEntry);
  const prefix = `${installedEntry.app_id}/app/`;
  const bytesOf = new Map(bundle.files.map((file) => [file.path, file.bytes]));

  report({ phase: "signing-in" });
  let session: RepairSession;
  try {
    session = await ports.openSession(repairManifest({ app_id: installedEntry.app_id, name: installedEntry.name }), { approval: (open) => report({ phase: open ? "approval" : "signing-in" }) });
  } catch (error) {
    throw error instanceof RepairError ? error : new RepairError("failed", { cause: error });
  }
  const written: string[] = [];
  const removed: string[] = [];
  try {
    for (const [index, write] of wanted.entries()) {
      report({ phase: "repairing", done: index, total: wanted.length });
      const bytes = bytesOf.get(write.path);
      if (bytes === undefined) throw new RepairError("catalog");
      try { await session.put(write.key, bytes, contentTypeOf(write.path)); } catch (error) { throw new RepairError("write-failed", { written, cause: error }); }
      written.push(write.key);
    }
    // Strays last: anything else under app/ except the install's own record.
    const keep = new Set([...wanted.map((write) => write.key), installRecordKey(installedEntry.app_id)]);
    let listed: readonly string[];
    try { listed = await session.list(prefix); } catch (error) { throw new RepairError("write-failed", { written, cause: error }); }
    for (const key of listed) {
      if (!key.startsWith(prefix) || keep.has(key)) continue;
      try { await session.del(key); } catch (error) { throw new RepairError("write-failed", { written, cause: error }); }
      removed.push(key);
    }
    return { written, removed };
  } finally {
    await Promise.resolve(session.dispose()).catch(() => undefined);
  }
}
