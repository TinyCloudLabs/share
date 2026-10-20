/**
 * The uninstall run: list the app's two folders completely, delete the files
 * in plan order, then remove the app's entry from the apps list.
 *
 * Nothing is deleted until both folders are listed completely (a truncated
 * listing is refused before the first delete). Files go first; the registry
 * entry goes last and its failure does not undo the file deletion: the app is
 * already removed and a retry removes the entry. A missing key is success
 * everywhere, so a retry after any interruption finishes the job.
 */
import { LIST_PAGE_LIMIT, MAX_LIST_PAGES, UninstallError, assertOwnedKey, assertPlainAppId, deleteOrder, folderPrefixes } from "./uninstall-plan.ts";

export interface ListPage {
  keys: string[];
  truncated: boolean;
  nextCursor?: string;
}

/** One signed-in uninstall session. `del` and `removeRegistry` resolve when the key is gone, including when it was already missing. */
export interface UninstallSession {
  list(prefix: string, cursor?: string): Promise<ListPage>;
  del(key: string): Promise<void>;
  removeRegistry(appId: string): Promise<void>;
  dispose(): Promise<void>;
}

export interface UninstallPorts {
  openSession(app: { app_id: string; name: string }, hooks: { approval(open: boolean): void }): Promise<UninstallSession>;
}

export type UninstallProgress =
  | { phase: "checking" }
  | { phase: "signing-in" }
  | { phase: "approval"; open: boolean }
  | { phase: "removing"; done: number; total: number }
  | { phase: "registry" };

export interface UninstallResult {
  /** Files deleted in this run (zero on a retry that found nothing left). */
  removed: number;
  /** `failed`: the files are gone but the app's entry in the apps list could not be removed; a retry removes it. */
  registry: "removed" | "failed";
}

/** Lists every key under `prefix`, following cursors up to `MAX_LIST_PAGES`. Refuses a listing still truncated at the cap. */
async function listAll(session: UninstallSession, prefix: string): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  for (let page = 1; ; page += 1) {
    const listed = await session.list(prefix, cursor);
    keys.push(...listed.keys);
    if (!listed.truncated) return keys;
    if (page >= MAX_LIST_PAGES || listed.nextCursor === undefined) throw new UninstallError("truncated");
    cursor = listed.nextCursor;
  }
}

export async function runUninstall(
  app: { app_id: string; name: string },
  ports: UninstallPorts,
  report: (progress: UninstallProgress) => void,
): Promise<UninstallResult> {
  assertPlainAppId(app.app_id);
  let session: UninstallSession | undefined;
  try {
    report({ phase: "signing-in" });
    session = await ports.openSession(app, { approval: (open) => report({ phase: "approval", open }) });

    report({ phase: "checking" });
    const listed: string[] = [];
    for (const prefix of folderPrefixes(app.app_id)) {
      try {
        listed.push(...(await listAll(session, prefix)));
      } catch (error) {
        if (error instanceof UninstallError) throw error;
        throw new UninstallError("failed", { cause: error });
      }
    }
    const order = deleteOrder(app.app_id, listed);

    const deleted: string[] = [];
    for (const key of order) {
      assertOwnedKey(app.app_id, key);
      report({ phase: "removing", done: deleted.length, total: order.length });
      try {
        await session.del(key);
      } catch (error) {
        throw new UninstallError("write-failed", { deleted: [...deleted], cause: error });
      }
      deleted.push(key);
    }

    report({ phase: "registry" });
    try {
      await session.removeRegistry(app.app_id);
      return { removed: deleted.length, registry: "removed" };
    } catch {
      // Files are already gone; the entry is retried by the next run. The cause is not shown: the copy says what to do.
      return { removed: deleted.length, registry: "failed" };
    }
  } finally {
    // A dispose failure leaves nothing to undo: the session holds no files and the run is over.
    await session?.dispose().catch(() => undefined);
  }
}
