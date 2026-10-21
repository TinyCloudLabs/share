/**
 * Opening an app: check it, save any missing files, read and check the saved copy, sign in for exactly its grants, hand back what the page needs to run it.
 *
 * Order is the safety argument:
 *  1. The app must be in the catalog (the page's own copy of it) and not switched
 *     off (`assertAvailable`), and its catalog entry must carry the code it runs
 *     (`app.jsx`). Nothing is signed for an id the catalog does not list, has
 *     disabled, or cannot run.
 *  2. The catalog bundle is fetched and every file is checked against the catalog's
 *     sha256 and size, and the catalog manifest is loaded (`prepare`). A failure
 *     here refuses the open before any approval is asked.
 * 3. ONE read sign-in (`readStored`). It always carries create-only write grants for the
 *     app's folder and notes, so missing files are saved within that one approval.
 *     Writes go: app files, then `install.json`, then the notes with `knowledge/index.md`
 *     last. A folder with `install.json` and every app file is complete. Existing files
 *     are never replaced.
 *  4. The saved copy is verified (stored-app.ts): every code file is hashed and
 *     compared with the catalog's pins for the installed digest (an edited, extra or
 *     missing file refuses the open), and the manifest is re-validated and capped
 *     against the catalog manifest. Nothing runs, and no runtime session exists,
 *     until this has passed.
 *  5. The runtime sign-in (`openRuntime`): the person's manifest, one hour, nothing
 *     persisted, no signer left behind (run-session.ts). The read session has ended
 *     before this starts, so no install-capable session outlives the save.
 * The sign-in, the node, the SDK and the clock are ports so tests can drive each step.
 */
import type { AppData } from "./bridge.ts";
import { type CatalogEntry, EntryDisabledError, assertAvailable, catalog as bundledCatalog } from "./catalog.ts";
import type { ManifestSdk } from "./grants.ts";
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

/** The read-only session of step 3. */
export interface ReadSession {
  readonly files: StoredFiles;
  /** Create-only write under the app's folder and notes. */
  readonly put: (key: string, bytes: Uint8Array, contentType: string) => Promise<PutResult>;
  /** Ends the session. `keepOpenKey` leaves OpenKey connected so the next sign-in needs no second connect. */
  end(options: { keepOpenKey: boolean }): Promise<void>;
}

/** The runtime session of step 5. */
export interface RuntimeSession {
  readonly data: AppData;
  /** Epoch ms after which the session may no longer be used (the sign-in time plus one hour, less a margin). */
  readonly expiresAt: number;
  /** Ends the session and OpenKey's sign-in. Safe to call twice. */
  end(): Promise<void>;
}

/** What step 2 produces: the catalog bundle, hashed, and the catalog manifest, loaded. */
export interface PreparedApp {
  readonly bundle: VerifiedBundle;
  readonly manifest: ManifestResult;
}

export interface RunPorts {
  /** Step 2: fetch and verify the catalog bundle, and load the catalog manifest. No approval happens here. */
  prepare(entry: CatalogEntry): Promise<PreparedApp>;
  /** Step 3: one approval. The sign-in always carries the create-only write grants for the app's folder and notes. */
  readStored(entry: CatalogEntry, hooks: RunHooks): Promise<ReadSession>;
  /** Step 5: signs in with `app.signing`. `previous` is the read session, already verified. */
  openRuntime(app: RunnableApp, previous: ReadSession, hooks: RunHooks): Promise<RuntimeSession>;
  /** The SDK's manifest functions; loaded only after the person clicked. */
  sdk(): Promise<ManifestSdk>;
  readonly catalog?: readonly CatalogEntry[];
}

export type RunFailure =
  | "unknown-app"
  | "unavailable"
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
  | { readonly phase: "starting"; readonly approval: boolean };

export interface RunningApp {
  readonly app: RunnableApp;
  readonly session: RuntimeSession;
}

/** An app id as the page accepts it from the address: a reverse-DNS style name, no slashes. */
export const APP_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const toFailure = (failure: StoredAppFailure): RunFailure => failure.reason === "invalid" ? "damaged" : failure.reason;

export function catalogEntryFor(appId: string, entries: readonly CatalogEntry[] = bundledCatalog.apps): CatalogEntry | undefined {
  return APP_ID.test(appId) ? entries.find((entry) => entry.app_id === appId) : undefined;
}

/**
 * Writes what is missing from the saved copy, create-only, inside the read session. Returns the files as they now stand.
 * A saved copy recorded for another digest is left alone: verification then refuses it, nothing is written into it.
 * Order: the app's files (each one not already saved), then `install.json` (only when no record is saved, and only once every
 * app file is byte-identical to the catalog's), then the notes with `knowledge/index.md` last. Nothing is cleaned up on failure.
 */
async function saveMissing(entry: CatalogEntry, bundle: VerifiedBundle, files: StoredFiles, put: ReadSession["put"], report: (progress: RunProgress) => void, signal: AbortSignal | undefined): Promise<StoredFiles> {
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
    if (error instanceof EntryDisabledError) throw new RunError("unavailable", { detail: error.reason });
    throw error;
  }
  // The catalog lists the app, but without its code the page cannot run it: refused before any approval.
  if (!entry.bundle.files.some((file) => file.path === "app.jsx")) throw new RunError("unavailable", { detail: "The catalog lists no code for this app, so it can't be opened." });
  report({ phase: "checking" });
  const sdk = await ports.sdk().catch((cause: unknown) => { throw new RunError("failed", { cause }); });
  const prepared = await ports.prepare(entry).catch((cause: unknown) => { throw cause instanceof RunError ? cause : new RunError("failed", { cause }); });
  // Cancel before any approval window opens: nothing is signed or written.
  if (signal?.aborted) throw new RunError("cancelled");

  report({ phase: "reading", approval: false });
  const read = await ports.readStored(entry, { approval: (open) => report({ phase: "reading", approval: open }) }).catch((cause: unknown) => {
    throw cause instanceof RunError ? cause : new RunError("failed", { cause });
  });
  let app: RunnableApp;
  try {
    // Cancel while OpenKey was asking: the late session is closed and nothing is written.
    if (signal?.aborted) throw new RunError("cancelled");
    const files = await saveMissing(entry, prepared.bundle, read.files, read.put, report, signal);
    if (signal?.aborted) throw new RunError("cancelled");
    report({ phase: "verifying" });
    const verified = await verifyStoredApp(appId, files, { catalog: entries, loadCatalogManifest: async () => prepared.manifest, sdk });
    if (!verified.ok) throw new RunError(toFailure(verified.failure), { detail: verified.failure.detail });
    app = verified.app;
  } catch (error) {
    await read.end({ keepOpenKey: false }).catch(() => undefined);
    throw error instanceof RunError ? error : new RunError("failed", { cause: error });
  }

  if (signal?.aborted) { await read.end({ keepOpenKey: false }).catch(() => undefined); throw new RunError("cancelled"); }
  report({ phase: "starting", approval: false });
  try {
    const session = await ports.openRuntime(app, read, { approval: (open) => report({ phase: "starting", approval: open }) });
    return { app, session };
  } catch (error) {
    await read.end({ keepOpenKey: false }).catch(() => undefined);
    throw error instanceof RunError ? error : new RunError("failed", { cause: error });
  }
}
