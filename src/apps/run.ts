/**
 * Opening an app: check it, sign in once, save any missing files, verify the saved copy, and hand back what the page needs to run it.
 *
 * Order is the safety argument:
 *  1. The app must be in the catalog (the page's own copy of it) and not switched
 *     off (`assertAvailable`), and its catalog entry must carry the code it runs
 *     (`app.jsx`). Nothing is signed for an id the catalog does not list, has
 *     disabled, or cannot run.
 *  2. The catalog bundle is fetched and every file is checked against the catalog's
 *     sha256 and size, and the catalog manifest is loaded (`prepare`). A failure
 *     here refuses the open before any approval is asked.
 *  3. ONE sign-in (`signIn`) for the union grant set built from the catalog manifest
 *     (`signInPlan`, grants.ts): the catalog's runtime grants, plus create-only writes
 *     for the app's folder and notes. Missing files are saved under this same approval,
 *     and the app runs on the same session.
 *  4. Missing files are saved, create-only, in order: app files, then `install.json`,
 *     then the notes with `knowledge/index.md` last. A folder with `install.json` and
 *     every app file is complete. Existing files are never replaced.
 *  5. The saved copy is verified (stored-app.ts): every code file is hashed and compared
 *     with the catalog's pins for the installed digest (an edited, extra or missing file
 *     refuses the open), and the manifest is re-validated and capped against the catalog
 *     manifest. Nothing runs until this has passed.
 * The sign-in, the node, the SDK and the clock are ports so tests can drive each step.
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

/** What the one sign-in yields: the saved files as read, a create-only write, and the runtime session the app runs on. */
export interface RunSession {
  readonly files: StoredFiles;
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
  /** Step 3: one approval. The sign-in carries the union grants from `plan`, and the same session saves and runs the app. */
  signIn(entry: CatalogEntry, plan: SignInPlan, hooks: RunHooks): Promise<RunSession>;
  /** The SDK's manifest functions; loaded when the open starts, before the sign-in. */
  sdk(): Promise<ManifestSdk>;
  readonly catalog?: readonly CatalogEntry[];
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
  const entry = catalogEntryFor(appId, entries);
  if (entry === undefined) throw new RunError("unknown-app");
  try { assertAvailable(entry); } catch (error) {
    if (error instanceof EntryDisabledError) throw new RunError(error.temporary ? "unavailable" : "no-code", { detail: error.reason });
    throw error;
  }
  report({ phase: "checking" });
  const sdk = await ports.sdk().catch((cause: unknown) => { throw new RunError("failed", { cause }); });
  const prepared = await ports.prepare(entry).catch((cause: unknown) => { throw cause instanceof RunError ? cause : new RunError("failed", { cause }); });
  let plan: SignInPlan;
  try {
    plan = signInPlan(prepared.manifest, sdk);
  } catch (cause) {
    throw cause instanceof RunError ? cause : new RunError("failed", { cause });
  }
  // Cancel before any approval window opens: nothing is signed or written.
  if (signal?.aborted) throw new RunError("cancelled");

  report({ phase: "reading", approval: false });
  const session = await ports.signIn(entry, plan, { approval: (open) => report({ phase: "reading", approval: open }) }).catch((cause: unknown) => {
    throw cause instanceof RunError ? cause : new RunError("failed", { cause });
  });
  let app: RunnableApp;
  try {
    // Cancel while OpenKey was asking: nothing is written and the session is closed below.
    if (signal?.aborted) throw new RunError("cancelled");
    const files = await saveMissing(entry, prepared.bundle, session.files, session.put, report, signal);
    if (signal?.aborted) throw new RunError("cancelled");
    report({ phase: "verifying" });
    const verified = await verifyStoredApp(appId, files, { catalog: entries, loadCatalogManifest: async () => prepared.manifest, sdk });
    if (!verified.ok) throw new RunError(toFailure(verified.failure), { detail: verified.failure.detail });
    app = verified.app;
  } catch (error) {
    await session.runtime.end().catch(() => undefined);
    throw error instanceof RunError ? error : new RunError("failed", { cause: error });
  }

  if (signal?.aborted) {
    await session.runtime.end().catch(() => undefined);
    throw new RunError("cancelled");
  }
  report({ phase: "starting" });
  return { app, session: session.runtime };
}
