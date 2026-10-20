/**
 * The install flow: verify, sign in once, copy create-only, record, list.
 *
 * Order matters and is the safety argument:
 *  1. Every file is fetched from the entry's own `/apps/b/<digest>/` and
 *     checked against the catalog. A bad file refuses the install here, before
 *     OpenKey is opened: zero writes, zero approvals.
 *  2. One sign-in, with the installer manifest (install-plan.ts).
 *  3. Files are put create-only, one at a time. A file that already exists is
 *     the person's copy and is kept. A failed write stops the install; what was
 *     written stays (re-installing resumes: it keeps those and writes the rest).
 *  4. `install.json` is written LAST, so "installed" is only ever said about a
 *     bundle that is entirely in place.
 *  5. The account apps list is confirmed.
 * The sign-in, the node and the clock are ports so tests can drive each step.
 */
import { type BundleFetch, BundleRefusal, fetchVerifiedBundle } from "./bundle.ts";
import { type CatalogEntry, availabilityOf } from "./catalog.ts";
import { installKey, installOrder, installRecord, installRecordKey, installerManifest } from "./install-plan.ts";
import type { Manifest } from "@tinycloud/web-sdk";

export type PutResult = "created" | "exists";

/** One signed-in installer session. It can only create files and confirm the apps list. */
export interface InstallSession {
  /** Create-only write of `key`. `exists` means the key was already there; the value is untouched. Any other failure throws. */
  put(key: string, bytes: Uint8Array, contentType: string): Promise<PutResult>;
  /** True once the account apps list shows the app (after the sync, or an explicit registration). */
  confirmListed(manifest: Manifest): Promise<boolean>;
  /** Ends the session: closes OpenKey and forgets the keys. Called once, always. */
  dispose(): Promise<void> | void;
}

export interface InstallPorts {
  /** Signs in (the one approval) with `manifest`; `approval(true)` while an OpenKey window is open. */
  openSession(manifest: Manifest, hooks: { approval(open: boolean): void }): Promise<InstallSession>;
  fetch?: BundleFetch;
  now?: () => Date;
}

export type InstallFailure = "disabled" | "catalog" | "tampered" | "unavailable" | "cancelled" | "timeout" | "busy" | "wrong-account" | "write-failed" | "failed";

/** An install that did not finish. `written` is what is in the person's TinyCloud now. */
export class InstallError extends Error {
  readonly reason: InstallFailure;
  readonly written: readonly string[];
  readonly total: number;
  constructor(reason: InstallFailure, detail: { written?: readonly string[]; total?: number; cause?: unknown } = {}) {
    super(`install-${reason}`, detail.cause === undefined ? undefined : { cause: detail.cause });
    this.name = "InstallError";
    this.reason = reason;
    this.written = detail.written ?? [];
    this.total = detail.total ?? 0;
  }
}

export interface InstallOutcome {
  /** `already`: every file, install.json included, was there and nothing was written. */
  kind: "installed" | "already";
  /** Keys created by this run (install.json last when it was written). */
  written: readonly string[];
  /** Keys that were already there and were kept. */
  kept: readonly string[];
  /** False when the account apps list had not shown the app by the time the install finished. */
  listed: boolean;
}

export type InstallProgress =
  | { phase: "checking" }
  | { phase: "signing-in" }
  | { phase: "approval" }
  | { phase: "installing"; done: number; total: number }
  | { phase: "registering" };

const CONTENT_TYPES: Record<string, string> = { json: "application/json", md: "text/markdown; charset=utf-8", jsx: "text/plain; charset=utf-8", sql: "text/plain; charset=utf-8" };

export function contentTypeOf(path: string): string {
  const extension = path.slice(path.lastIndexOf(".") + 1);
  return Object.hasOwn(CONTENT_TYPES, extension) ? (CONTENT_TYPES[extension] ?? "application/octet-stream") : "application/octet-stream";
}

export async function runInstall(entry: CatalogEntry, ports: InstallPorts, report: (progress: InstallProgress) => void): Promise<InstallOutcome> {
  // The kill switch: a disabled entry is refused before anything is fetched or any OpenKey window opens.
  if (!availabilityOf(entry).available) throw new InstallError("disabled");
  report({ phase: "checking" });
  let bundle;
  try {
    bundle = await fetchVerifiedBundle(entry, ports.fetch);
  } catch (error) {
    if (error instanceof BundleRefusal) throw new InstallError(error.reason, { cause: error });
    throw new InstallError("failed", { cause: error });
  }
  // Identity only (id, name, description): the app's own grants are never part of the install sign-in.
  const manifest = installerManifest({ app_id: entry.app_id, name: entry.name, description: entry.description });

  // The files in a fixed order; the record is last and is never part of the bundle.
  const writes = installOrder(bundle.files).map((file) => ({ key: installKey(entry.app_id, file.path), bytes: file.bytes, contentType: contentTypeOf(file.path) }));
  const recordWrite = { key: installRecordKey(entry.app_id), bytes: installRecord(entry, (ports.now ?? (() => new Date()))()), contentType: contentTypeOf("install.json") };
  const total = writes.length + 1;

  const hooks = { approval: (open: boolean) => report({ phase: open ? "approval" : "signing-in" }) };
  let session: InstallSession;
  try {
    report({ phase: "signing-in" });
    session = await ports.openSession(manifest, hooks);
  } catch (error) {
    throw error instanceof InstallError ? error : new InstallError("failed", { cause: error });
  }

  const written: string[] = [];
  const kept: string[] = [];
  try {
    for (const [index, write] of [...writes, recordWrite].entries()) {
      report({ phase: "installing", done: index, total });
      let result: PutResult;
      try {
        result = await session.put(write.key, write.bytes, write.contentType);
      } catch (error) {
        throw new InstallError("write-failed", { written, total, cause: error });
      }
      (result === "created" ? written : kept).push(write.key);
    }
    report({ phase: "registering" });
    // Confirming the list is not part of "the files are in": a failure here is reported as `listed: false`, never as a failed install.
    const listed = await session.confirmListed(manifest).catch(() => false);
    return { kind: written.length === 0 ? "already" : "installed", written, kept, listed };
  } finally {
    await Promise.resolve(session.dispose()).catch(() => undefined);
  }
}
