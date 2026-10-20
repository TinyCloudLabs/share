/**
 * Opening an installed app: look it up, read the person's saved copy, check it,
 * sign in for exactly its grants, hand back what the page needs to run it.
 *
 * Order is the safety argument:
 *  1. The app must be in the catalog (the page's own copy of it). Nothing is
 *     signed for an id the catalog does not list.
 *  2. ONE read-only sign-in (`readStored`): `get` on `<app_id>/app/` and nothing
 *     else, to read manifest.json, app.jsx and install.json. The session ends
 *     before step 4; only OpenKey's own connection is kept, so the second
 *     approval is a signature, not a second connect.
 *  3. The saved copy is verified (stored-app.ts): the manifest is re-validated and
 *     capped against the catalog manifest of the digest the install recorded. A
 *     copy that widens is refused here, with nothing more signed.
 *  4. The runtime sign-in (`openRuntime`): the person's manifest, one hour, nothing
 *     persisted, no signer left behind (run-session.ts).
 * The sign-in, the node, the SDK and the clock are ports so tests can drive each step.
 */
import type { AppData } from "./bridge.ts";
import { type CatalogEntry, catalog as bundledCatalog } from "./catalog.ts";
import type { ManifestSdk } from "./grants.ts";
import { type ManifestResult, loadManifest } from "./manifest.ts";
import { type RunnableApp, type StoredAppFailure, verifyStoredApp } from "./stored-app.ts";

export interface RunHooks {
  /** `true` while an OpenKey approval is open. */
  approval(open: boolean): void;
}

export interface StoredBytes {
  readonly manifest?: Uint8Array | undefined;
  readonly install?: Uint8Array | undefined;
  readonly source?: Uint8Array | undefined;
}

/** The read-only session of step 2. */
export interface ReadSession {
  readonly files: StoredBytes;
  /** Ends the session. `keepOpenKey` leaves OpenKey connected so the next sign-in needs no second connect. */
  end(options: { keepOpenKey: boolean }): Promise<void>;
}

/** The runtime session of step 4. */
export interface RuntimeSession {
  readonly data: AppData;
  /** Epoch ms after which the session may no longer be used (the sign-in time plus one hour, less a margin). */
  readonly expiresAt: number;
  /** Ends the session and OpenKey's sign-in. Safe to call twice. */
  end(): Promise<void>;
}

export interface RunPorts {
  /** Step 2: one approval; reads the three stored files. */
  readStored(entry: CatalogEntry, hooks: RunHooks): Promise<ReadSession>;
  /** Step 4: signs in with `app.signing`. `previous` is the read session, already verified. */
  openRuntime(app: RunnableApp, previous: ReadSession, hooks: RunHooks): Promise<RuntimeSession>;
  /** The SDK's manifest functions; loaded only after the person clicked. */
  sdk(): Promise<ManifestSdk>;
  readonly catalog?: readonly CatalogEntry[];
  readonly loadCatalogManifest?: (entry: CatalogEntry) => Promise<ManifestResult>;
}

export type RunFailure =
  | "unknown-app"
  | "not-installed"
  | "damaged"
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

export async function openApp(appId: string, ports: RunPorts, report: (progress: RunProgress) => void): Promise<RunningApp> {
  const entries = ports.catalog ?? bundledCatalog.apps;
  const entry = catalogEntryFor(appId, entries);
  if (entry === undefined) throw new RunError("unknown-app");
  report({ phase: "checking" });
  const sdk = await ports.sdk().catch((cause: unknown) => { throw new RunError("failed", { cause }); });

  report({ phase: "reading", approval: false });
  const read = await ports.readStored(entry, { approval: (open) => report({ phase: "reading", approval: open }) }).catch((cause: unknown) => {
    throw cause instanceof RunError ? cause : new RunError("failed", { cause });
  });
  let app: RunnableApp;
  try {
    const { manifest, install, source } = read.files;
    if (manifest === undefined || install === undefined || source === undefined) throw new RunError("not-installed");
    report({ phase: "verifying" });
    const verified = await verifyStoredApp(appId, { manifest, install, source }, { catalog: entries, loadCatalogManifest: ports.loadCatalogManifest ?? loadManifest, sdk });
    if (!verified.ok) throw new RunError(toFailure(verified.failure), { detail: verified.failure.detail });
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
