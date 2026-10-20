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
 *  3. ONE read sign-in (`readStored`). On a device where this app is not recorded as
 *     installed, the same sign-in also carries create-only write grants for the
 *     app's folder and notes, so missing files are saved within that one approval.
 *     Writes go app files first, then notes, and `install.json` last: a folder
 *     with `install.json` is complete. Existing files are never replaced.
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
import { installKey, installOrder, installRecord, installRecordKey } from "./install-plan.ts";
import { contentTypeOf } from "./install.ts";
import { type RunnableApp, type StoredAppFailure, type StoredFiles, parseInstallRecord, verifyStoredApp } from "./stored-app.ts";

export interface RunHooks {
  /** `true` while an OpenKey approval is open. */
  approval(open: boolean): void;
}

/** A create-only write: `created`, or `exists` (the stored file is left as it is). */
export type PutResult = "created" | "exists";

/** The read-only session of step 3. */
export interface ReadSession {
  readonly files: StoredFiles;
  /** Create-only write under the app's folder. Present only when the session was opened with install grants. */
  readonly put?: (key: string, bytes: Uint8Array, contentType: string) => Promise<PutResult>;
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

/**
 * Which app digest this device last verified and saved, per app id. It only chooses the read's grants (with or without the
 * write grants); it is never taken as proof that the files are there. Verification always reads the files.
 */
export interface InstalledHints {
  get(appId: string): string | undefined;
  set(appId: string, digest: string): void;
  clear(appId: string): void;
}

export interface RunPorts {
  /** Step 2: fetch and verify the catalog bundle, and load the catalog manifest. No approval happens here. */
  prepare(entry: CatalogEntry): Promise<PreparedApp>;
  /** Step 3: one approval. `install` adds the create-only write grants to the same sign-in. */
  readStored(entry: CatalogEntry, hooks: RunHooks, options: { install: boolean }): Promise<ReadSession>;
  /** Step 5: signs in with `app.signing`. `previous` is the read session, already verified. */
  openRuntime(app: RunnableApp, previous: ReadSession, hooks: RunHooks): Promise<RuntimeSession>;
  /** The SDK's manifest functions; loaded only after the person clicked. */
  sdk(): Promise<ManifestSdk>;
  readonly hints: InstalledHints;
  readonly catalog?: readonly CatalogEntry[];
}

export type RunFailure =
  | "unknown-app"
  | "unavailable"
  | "not-installed"
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
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, index) => byte === b[index]);

export function catalogEntryFor(appId: string, entries: readonly CatalogEntry[] = bundledCatalog.apps): CatalogEntry | undefined {
  return APP_ID.test(appId) ? entries.find((entry) => entry.app_id === appId) : undefined;
}

/**
 * Writes what is missing from the saved copy, create-only, inside the read session. Returns the files as they now stand.
 * A saved copy recorded for another digest is left alone: verification then refuses it, nothing is written into it.
 */
async function saveMissing(entry: CatalogEntry, bundle: VerifiedBundle, files: StoredFiles, put: NonNullable<ReadSession["put"]>, report: (progress: RunProgress) => void): Promise<StoredFiles> {
  const recordBytes = files.entries.get(INSTALL_RECORD_PATH);
  if (recordBytes !== undefined && parseInstallRecord(recordBytes)?.digest !== entry.bundle.digest) return files;
  const entries = new Map(files.entries);
  const order = installOrder(bundle.files);
  const total = order.length + 1;
  let done = 0;
  try {
    for (const file of order) {
      const note = file.path.startsWith("knowledge/");
      // A file that is already saved is kept, never rewritten. Notes are create-only too, so a re-run leaves existing notes as they are.
      if (!note && entries.has(file.path)) { done += 1; continue; }
      report({ phase: "saving", done, total });
      const result = await put(installKey(entry.app_id, file.path), file.bytes, contentTypeOf(file.path));
      if (!note) {
        // Listed and read a moment ago, now present but not in the read: the copy changed under the open, so refuse rather than guess.
        if (result === "exists") throw new RunError("failed", { detail: "saved files changed while opening" });
        entries.set(file.path, file.bytes);
      }
      done += 1;
    }
    // install.json last: it is the commit point. Written only once every app file and note is in place. A record already saved for this digest (checked above) is kept as it is: rewriting it would read as "changed while opening".
    if (recordBytes === undefined) {
    // Only a copy whose app files are byte-identical to the catalog's verified bundle is committed: install.json is never written over a copy verification would refuse.
    for (const file of order) {
      if (file.path.startsWith("knowledge/")) continue;
      const saved = entries.get(file.path);
      if (saved === undefined || !sameBytes(saved, file.bytes)) throw new RunError("damaged", { detail: "saved files differ from the catalog copy, so install.json was not written" });
    }
      report({ phase: "saving", done, total });
      const record = installRecord(entry, new Date());
      const written = await put(installRecordKey(entry.app_id), record, contentTypeOf("install.json"));
      if (written === "exists") throw new RunError("failed", { detail: "saved files changed while opening" });
      entries.set(INSTALL_RECORD_PATH, record);
    }
  } catch (error) {
    // Nothing is cleaned up: whatever was written stays, and the next open saves the rest (create-only, so nothing is lost).
    throw error instanceof RunError ? error : new RunError("failed", { cause: error, detail: "saving the app's files" });
  }
  return { entries, ...(files.incomplete === undefined ? {} : { incomplete: files.incomplete }) };
}

export async function openApp(appId: string, ports: RunPorts, report: (progress: RunProgress) => void): Promise<RunningApp> {
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

  // A device that has not verified this digest yet asks for the write grants too (one approval covers the save and the read).
  const install = ports.hints.get(appId) !== entry.bundle.digest;
  report({ phase: "reading", approval: false });
  const read = await ports.readStored(entry, { approval: (open) => report({ phase: "reading", approval: open }) }, { install }).catch((cause: unknown) => {
    throw cause instanceof RunError ? cause : new RunError("failed", { cause });
  });
  let app: RunnableApp;
  try {
    let files = read.files;
    if (install && read.put !== undefined) files = await saveMissing(entry, prepared.bundle, files, read.put, report);
    // Nothing saved under app/ at all, and this device had no record of it: nothing to open. The copy is the install that just ran.
    if (files.entries.size === 0) { ports.hints.clear(appId); throw new RunError("not-installed"); }
    report({ phase: "verifying" });
    const verified = await verifyStoredApp(appId, files, { catalog: entries, loadCatalogManifest: async () => prepared.manifest, sdk });
    if (!verified.ok) {
      ports.hints.clear(appId);
      throw new RunError(toFailure(verified.failure), { detail: verified.failure.detail });
    }
    ports.hints.set(appId, entry.bundle.digest);
    app = verified.app;
  } catch (error) {
    await read.end({ keepOpenKey: false }).catch(() => undefined);
    throw error instanceof RunError ? error : new RunError("failed", { cause: error });
  }

  report({ phase: "starting", approval: false });
  try {
    const session = await ports.openRuntime(app, read, { approval: (open) => report({ phase: "starting", approval: open }) });
    return { app, session };
  } catch (error) {
    await read.end({ keepOpenKey: false }).catch(() => undefined);
    throw error instanceof RunError ? error : new RunError("failed", { cause: error });
  }
}
