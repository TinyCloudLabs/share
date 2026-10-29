/**
 * Opening uses the app's own session to read install.json, select the pinned catalog version,
 * and request only that version's grant. Existing code is never replaced; missing files are
 * saved create-only before the verified app runs on the same session.
 */
import type { Manifest } from "@tinycloud/sdk-core";

import type { AppData } from "./bridge.ts";
import { type CatalogEntry, EntryDisabledError, assertAvailable, catalog as bundledCatalog } from "./catalog.ts";
import { type ManifestSdk, openManifest, openScope } from "./grants.ts";
import type { ManifestScope } from "../share/manifest-policy.js";
import { INSTALL_RECORD_PATH, type VerifiedBundle } from "./bundle.ts";
import { type ManifestResult } from "./manifest.ts";
import { contentTypeOf, installKey, installOrder, installRecord, installRecordKey } from "./install-plan.ts";
import { type RunnableApp, type StoredAppFailure, type StoredFiles, parseInstallRecord, pinProblem, verifyStoredApp } from "./stored-app.ts";

export interface RunHooks {
  /** `true` while an OpenKey approval is open. */
  approval(open: boolean): void;
}

/** A create-only write: `created`, or `exists` (the stored file is left as it is). */
export type PutResult = "created" | "exists";

/** What the one sign-in is asked for: the union manifest (grants.ts) and its scope. */
export interface SignInPlan {
  readonly manifest: Manifest;
  readonly scope: ManifestScope;
}

/** The runtime session: the app's data, and when it may no longer be used. */
export interface RuntimeSession {
  readonly data: AppData;
  /** Epoch ms after which the session may no longer be used (the signed session's own expiry, less a margin). */
  readonly expiresAt: number;
  /** Ends the session and OpenKey's sign-in, clearing the saved session. Safe to call twice. */
  end(): Promise<void>;
  /**
   * Drops this page's hold on the session for an unload or teardown that is not a sign-out:
   * the saved session stays, so a later open of the same app restores it. Safe to call twice.
   */
  detach(): Promise<void>;
}

/** The one sign-in yields saved files, a create-only write, and the runtime session. */
export interface RunSession {
  readonly files: StoredFiles;
  /** Request this installed version's permissions on the same client session; covered grants require no prompt. */
  readonly authorize: (entry: CatalogEntry, plan: SignInPlan, sdk: ManifestSdk) => Promise<void>;
  /** Create-only write under the app's folder and notes. */
  readonly put: (key: string, bytes: Uint8Array, contentType: string) => Promise<PutResult>;
  readonly runtime: RuntimeSession;
}

/** What step 2 produces: the catalog bundle, hashed, and the catalog manifest, loaded. */
export interface PreparedApp {
  readonly bundle: VerifiedBundle;
  readonly manifest: ManifestResult;
}

export interface RunPorts {
  /** Step 2: fetch and verify the catalog bundle, and load the catalog manifest. No approval happens here. */
  prepare(entry: CatalogEntry): Promise<PreparedApp>;
  /** Whether this app has a persisted grant which may cover the saved installation. */
  hasPersistedSession?(appId: string): Promise<boolean>;
  /** The app's own session reads install.json, saves and runs the app. */
  signIn(entry: CatalogEntry, plan: SignInPlan, hooks: RunHooks): Promise<RunSession>;
  /** Loads the exact version's pinned manifest when an existing install names an older bundle. */
  loadCatalogManifest(entry: CatalogEntry): Promise<ManifestResult>;
  /** Lazily loads the SDK after the entry has passed availability checks. */
  sdk(): Promise<ManifestSdk>;
  readonly catalog?: readonly CatalogEntry[];
}


/**
 * A restored app grant needs only this narrow plan to inspect install.json. After
 * resolving the saved digest, the same TinyCloud session may request that version's
 * exact grant; already-covered permissions do not trigger a new approval.
 */
export function installRecordPlan(entry: CatalogEntry): SignInPlan {
  const key = installRecordKey(entry.app_id);
  return {
    manifest: {
      manifest_version: 1,
      app_id: entry.app_id,
      name: entry.name,
      space: "applications",
      defaults: false,
      includePublicSpace: false,
      permissions: [{ service: "tinycloud.kv", path: key, actions: ["get"], skipPrefix: true }],
    },
    scope: {
      allowedSpaces: ["applications"],
      allowedServices: ["kv"],
      allowedActions: ["get"],
      allowedPathPrefixes: [{ space: "applications", prefix: key }],
    },
  };
}

export type RunFailure =
  | "unknown-app"
  | "unavailable"
  | "no-code"
  | "damaged"
  | "code-mismatch"
  | "not-listed"
  | "catalog-unavailable"
  | "widened"
  | "unsupported"
  | "cancelled"
  | "timeout"
  | "busy"
  | "wrong-account"
  | "failed";

export class RunError extends Error {
  readonly reason: RunFailure;
  readonly detail: string | undefined;
  constructor(reason: RunFailure, options: { detail?: string; cause?: unknown } = {}) {
    super(`run-${reason}`, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "RunError";
    this.reason = reason;
    this.detail = options.detail;
  }
}

export type RunProgress =
  | { readonly phase: "checking" }
  | { readonly phase: "reading"; readonly approval: boolean }
  | { readonly phase: "saving"; readonly done: number; readonly total: number }
  | { readonly phase: "verifying" }
  | { readonly phase: "disclosing"; readonly entry: CatalogEntry; readonly manifest: unknown }
  | { readonly phase: "starting" };

export interface RunningApp {
  readonly app: RunnableApp;
  /** The page sees only the runtime session: it never holds the write. */
  readonly session: RuntimeSession;
}

/** An app id as the page accepts it from the address: a reverse-DNS style name, no slashes. */
export const APP_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const toFailure = (failure: StoredAppFailure): RunFailure => failure.reason === "invalid" ? "damaged" : failure.reason;

export function catalogEntryFor(appId: string, entries: readonly CatalogEntry[] = bundledCatalog.apps): CatalogEntry | undefined {
  return APP_ID.test(appId) ? entries.find((entry) => entry.app_id === appId) : undefined;
}

/**
 * The union sign-in's manifest and scope, from the catalog manifest of the installed digest. Refuses with `catalog-unavailable`
 * when that manifest does not load or does not validate, before any approval is asked.
 */
export function signInPlan(loaded: ManifestResult, sdk: ManifestSdk): SignInPlan {
  if (!loaded.ok) throw new RunError("catalog-unavailable", { detail: loaded.reason });
  let catalog: Manifest;
  try {
    catalog = sdk.validateManifest(loaded.manifest);
  } catch (cause) {
    throw new RunError("catalog-unavailable", { cause, detail: "the catalog manifest is not valid" });
  }
  return { manifest: openManifest(catalog), scope: openScope(catalog, sdk) };
}

/**
 * Writes what is missing from the saved copy, create-only, inside the sign-in. Returns the files as they now stand.
 * A saved copy recorded for another digest is left alone: verification then refuses it, nothing is written into it.
 * Order: the app's files (each one not already saved), then `install.json` (only when no record is saved, and only once the saved
 * code files pass `pinProblem`, the same check as the open), then the notes with `knowledge/index.md` last. Nothing is cleaned up on failure.
 */
async function saveMissing(entry: CatalogEntry, bundle: VerifiedBundle, files: StoredFiles, put: RunSession["put"], report: (progress: RunProgress) => void, signal: AbortSignal | undefined): Promise<StoredFiles> {
  const recordBytes = files.entries.get(INSTALL_RECORD_PATH);
  if (recordBytes !== undefined && parseInstallRecord(recordBytes)?.digest !== entry.bundle.digest) return files;
  const entries = new Map(files.entries);
  const order = installOrder(bundle.files);
  const appFiles = order.filter((file) => !file.path.startsWith("knowledge/"));
  const notes = order.filter((file) => file.path.startsWith("knowledge/"));
  const total = order.length + 1;
  let done = 0;
  try {
    for (const file of appFiles) {
      if (signal?.aborted) throw new RunError("cancelled");
      // Already saved: kept, never rewritten.
      if (entries.has(file.path)) { done += 1; continue; }
      report({ phase: "saving", done, total });
      const result = await put(installKey(entry.app_id, file.path), file.bytes, contentTypeOf(file.path));
      // Listed and read a moment ago, now present but not in the read: the copy changed under the open, so refuse rather than guess.
      if (result === "exists") throw new RunError("failed", { detail: "saved files changed while opening" });
      entries.set(file.path, file.bytes);
      done += 1;
    }
    if (recordBytes === undefined) {
      // Commit guard: install.json is written only over a copy that verification would accept.
      const problem = await pinProblem(entry, { entries, ...(files.incomplete === undefined ? {} : { incomplete: files.incomplete }) });
      if (problem !== undefined) throw new RunError("damaged", { detail: `${problem}, so install.json was not written` });
      if (signal?.aborted) throw new RunError("cancelled");
      report({ phase: "saving", done, total });
      const record = installRecord(entry, new Date());
      const written = await put(installRecordKey(entry.app_id), record, contentTypeOf("install.json"));
      if (written === "exists") throw new RunError("failed", { detail: "saved files changed while opening" });
      entries.set(INSTALL_RECORD_PATH, record);
      done += 1;
    }
    // Notes are create-only: a note already saved is left as it is, so the write result is not checked.
    for (const file of notes) {
      if (signal?.aborted) throw new RunError("cancelled");
      report({ phase: "saving", done, total });
      await put(installKey(entry.app_id, file.path), file.bytes, contentTypeOf(file.path));
      done += 1;
    }
  } catch (error) {
    throw error instanceof RunError ? error : new RunError("failed", { cause: error, detail: "saving the app's files" });
  }
  return { entries, ...(files.incomplete === undefined ? {} : { incomplete: files.incomplete }) };
}

export async function openApp(appId: string, ports: RunPorts, report: (progress: RunProgress) => void, signal?: AbortSignal): Promise<RunningApp> {
  const entries = ports.catalog ?? bundledCatalog.apps;
  const currentEntry = catalogEntryFor(appId, entries);
  if (currentEntry === undefined) throw new RunError("unknown-app");
  report({ phase: "checking" });
  if (signal?.aborted) throw new RunError("cancelled");

  const hasPersistedSession = await ports.hasPersistedSession?.(appId).catch((cause: unknown) => { throw new RunError("failed", { cause }); }) ?? false;
  if (!hasPersistedSession) {
    try { assertAvailable(currentEntry); } catch (error) {
      if (error instanceof EntryDisabledError) throw new RunError(error.temporary ? "unavailable" : "no-code", { detail: error.reason });
      throw error;
    }
  }

  const sdk = await ports.sdk().catch((cause: unknown) => { throw new RunError("failed", { cause }); });
  let prepared: PreparedApp | undefined;
  let initialPlan: SignInPlan;
  if (hasPersistedSession) {
    initialPlan = installRecordPlan(currentEntry);
  } else {
    prepared = await ports.prepare(currentEntry).catch((cause: unknown) => { throw cause instanceof RunError ? cause : new RunError("failed", { cause }); });
    try { initialPlan = signInPlan(prepared.manifest, sdk); } catch (cause) { throw cause instanceof RunError ? cause : new RunError("failed", { cause }); }
    if (prepared.manifest.ok) report({ phase: "disclosing", entry: currentEntry, manifest: prepared.manifest.manifest });
  }
  if (signal?.aborted) throw new RunError("cancelled");

  report({ phase: "reading", approval: false });
  const session = await ports.signIn(currentEntry, initialPlan, { approval: (open) => report({ phase: "reading", approval: open }) }).catch((cause: unknown) => {
    throw cause instanceof RunError ? cause : new RunError("failed", { cause });
  });
  let app: RunnableApp;
  try {
    if (signal?.aborted) throw new RunError("cancelled");
    const installBytes = session.files.entries.get(INSTALL_RECORD_PATH);
    const sessionDigest = installBytes === undefined ? null : parseInstallRecord(installBytes)?.digest ?? null;
    let entry = currentEntry;
    if (sessionDigest !== null) {
      const installedEntry = entries.find((candidate) => candidate.app_id === appId && candidate.bundle.digest === sessionDigest);
      if (installedEntry === undefined) throw new RunError("not-listed");
      entry = installedEntry;
    }
    try { assertAvailable(entry); } catch (error) {
      if (error instanceof EntryDisabledError) throw new RunError(error.temporary ? "unavailable" : "no-code", { detail: error.reason });
      throw error;
    }
    if (prepared === undefined || entry.bundle.digest !== currentEntry.bundle.digest) {
      prepared = await ports.prepare(entry).catch((cause: unknown) => { throw cause instanceof RunError ? cause : new RunError("failed", { cause }); });
    }
    const plan = signInPlan(prepared.manifest, sdk);
    if (prepared.manifest.ok) report({ phase: "disclosing", entry, manifest: prepared.manifest.manifest });
    await session.authorize(entry, plan, sdk);
    const files = await saveMissing(entry, prepared.bundle, session.files, session.put, report, signal);
    if (signal?.aborted) throw new RunError("cancelled");
    report({ phase: "verifying" });
    const verified = await verifyStoredApp(appId, files, {
      catalog: entries,
      loadCatalogManifest: async (candidate) => candidate.bundle.digest === entry.bundle.digest ? prepared!.manifest : ports.loadCatalogManifest(candidate),
      sdk,
    });
    if (!verified.ok) throw new RunError(toFailure(verified.failure), { detail: verified.failure.detail });
    app = verified.app;
  } catch (error) {
    const failure = error instanceof RunError ? error : new RunError("failed", { cause: error });
    await (failure.reason === "cancelled" && failure.detail === "permission-declined" ? session.runtime.detach() : session.runtime.end()).catch(() => undefined);
    throw failure;
  }

  if (signal?.aborted) {
    await session.runtime.end().catch(() => undefined);
    throw new RunError("cancelled");
  }
  report({ phase: "starting" });
  return { app, session: session.runtime };
}
