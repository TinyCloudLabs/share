/**
 * The real ports for opening an installed app: OpenKey, the Web SDK and the node.
 *
 * Nothing here is imported by the page until the person clicks Continue; the SDK,
 * OpenKey and the shared sign-in helper load then (dynamic imports), so the page
 * itself loads no SDK and makes no request beyond this origin's own files.
 *
 * Two sign-ins, both the shared `signInWithManifest` (src/share/openkey-session.ts),
 * which this module does not change, each stating its own scope so the helper
 * refuses a manifest outside it before OpenKey opens:
 *   1. READ: the runner's own identity and one `get` grant on `<app_id>/app/`
 *      (skipPrefix), to read the saved manifest, code and install record. It is
 *      ended before the next sign-in; OpenKey stays connected.
 *   2. RUN: exactly the manifest `verifyStoredApp` returned (the person's copy,
 *      capped against the catalog), one hour, nothing persisted. Its scope is
 *      derived from the CATALOG's manifest (stored-app.ts), so the helper checks
 *      the resolved request against the catalog independently of the cap check.
 *
 * NO SIGNER ESCALATION. A wallet-mode client can sign for more than its session
 * covers: asked for something outside its ReCap it can ask its signer. The web client
 * here has OpenKey as its signer, so once the runtime sign-in is done every signature
 * request is refused (`runner-signing-closed`, in the approval guard both the
 * provider and the SDK's sign callback go through), and the services handed to the
 * bridge invoke with the session key only. A call outside the session's ReCap goes to
 * the node and is refused there: the node, not this page, is the boundary. The same
 * adapter over a signer-less node-sdk client is exercised against a real node in
 * test/e2e-prod/runner-node-boundary.mjs.
 */
import type { Manifest, TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig, type SharePublicConfig } from "../email-share/config.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import type { ApprovalGuard, ManifestSignIn, OpenKeyShareSession, WalletApprovalFailure } from "../share/openkey-session.js";
import type { ManifestScope } from "../share/manifest-policy.js";
import { createAppData } from "./app-data.ts";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE } from "./install-plan.ts";
import { isSignInLabel } from "../share/sign-in-label.js";
import { RunError, type InstalledHints, type PreparedApp, type PutResult, type ReadSession, type RunFailure, type RunHooks, type RunPorts, type RuntimeSession } from "./run.ts";
import { RUNTIME_SESSION_MS, type ManifestSdk } from "./grants.ts";
import { BundleRefusal, fetchVerifiedBundle, type VerifiedBundle } from "./bundle.ts";
import { loadManifest } from "./manifest.ts";

/** The session is treated as over this long before the SDK's own expiry, so a call is not sent into a dying session. */
const EXPIRY_MARGIN_MS = 60_000;
const APP_NAME_MAX_CHARS = 64;
/** Files and bytes read from `<app_id>/app/` at most; more than that is refused as unverifiable. */
export const MAX_STORED_FILES = 64;
export const MAX_STORED_BYTES = 8 * 1024 * 1024;

/**
 * The name OpenKey shows. DISPLAY ONLY (the app id and the grants never come from it): the catalog's name goes in only
 * if the shared sign-in accepts it as a label, otherwise a fixed one stands in; the whole line is cut to 64 characters.
 */
export function runnerAppName(prefix: string, name: string): string {
  const named = isSignInLabel(name) ? name : "Tiny app";
  const cut = [...`${prefix}${named}`].slice(0, APP_NAME_MAX_CHARS).join("").trimEnd();
  return isSignInLabel(cut) ? cut : `${prefix}Tiny app`;
}

/**
 * Identity the read sign-in uses: the runner's own, so the person's apps list does not gain a record named after the
 * app being opened and the record Share's library keeps under `xyz.tinycloud.share` is never overwritten.
 */
export const RUNNER_APP_ID = "xyz.tinycloud.share.runner";

/** One permission on one folder of the app's kv space: skipPrefix, so the folder itself is the grant. */
function kvPermission(path: string, actions: Array<"get" | "list" | "put">, description: string): NonNullable<Manifest["permissions"]>[number] {
  return { service: "tinycloud.kv", path, actions, skipPrefix: true, description };
}

/**
 * The read sign-in's manifest: `get` and `list` on `<app_id>/app/` in the applications space, and nothing else. With `install`
 * (the saved copy is not yet verified on this device), also create-only `put` on `<app_id>/app/` and `<app_id>/knowledge/`, so
 * missing files are saved within this same approval.
 */
export function readerManifest(appId: string, appName: string, install = false): Manifest {
  const read = install
    ? kvPermission(`${appId}/app/`, ["get", "list", "put"], `Read and save ${appName}'s files (its code, manifest and install record) so they can be checked before it is opened.`)
    : kvPermission(`${appId}/app/`, ["get", "list"], `Read ${appName}'s saved files (its code, manifest and install record) so they can be checked before it is opened.`);
  return {
    manifest_version: 1,
    app_id: RUNNER_APP_ID,
    name: "TinyCloud Share",
    description: `Open ${appName}.`,
    space: INSTALL_SPACE,
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    expiry: "15m",
    permissions: install ? [read, kvPermission(`${appId}/knowledge/`, ["put"], `Save ${appName}'s notes folder if it is missing.`)] : [read],
  };
}

/**
 * What the read sign-in may ask for: `get` and `list` on the one saved app, and with `install` create-only `put` on its folder and
 * notes. Nothing else.
 */
export function readerScope(appId: string, install = false): ManifestScope {
  const prefixes = [{ space: INSTALL_SPACE, prefix: `${appId}/app/` }, ...(install ? [{ space: INSTALL_SPACE, prefix: `${appId}/knowledge/` }] : [])];
  return { allowedSpaces: [INSTALL_SPACE], allowedServices: ["kv"], allowedActions: install ? ["get", "list", "put"] : ["get", "list"], allowedPathPrefixes: prefixes };
}

/** Signing guard: one approval at a time (the install flow's pattern), and a lock that ends signing for good. */
function approvalGuard(hooks: RunHooks): { guard: ApprovalGuard; lock(): void; observed(): RunFailure | undefined } {
  let locked = false;
  let failure: RunFailure | undefined;
  return {
    guard: async (wait) => {
      if (locked) throw new Error("runner-signing-closed");
      try {
        return await withWalletApproval({ setApproval: (open) => hooks.approval(open) }, () => wait());
      } catch (error) {
        if (error instanceof Error && error.message === "revoke-approval-abandoned") failure ??= "timeout";
        else if (error instanceof Error && error.message === "revoke-another-approval") failure ??= "busy";
        throw error;
      }
    },
    lock: () => { locked = true; },
    observed: () => failure,
  };
}

/** The parts of the SDK's key-value service the reader uses. */
interface ReaderKv {
  list(options: { prefix: string }): Promise<{ ok: true; data: { keys: string[]; truncated?: boolean } } | { ok: false; error: { code?: string } }>;
  /** A short-lived URL for one object (a `get` invocation): fetched below as a STREAM, so the read can stop at the cap. */
  createSignedReadUrl(key: string, options: { expiresInSeconds: number }): Promise<{ ok: true; data: { url: string } } | { ok: false; error: { code?: string } }>;
}

/** The part of the SDK's key-value service the install write uses. */
interface WriterKv {
  put(key: string, value: Uint8Array, options: { contentType: string; ifNoneMatch: "*" }): Promise<{ ok: true } | { ok: false; error: { code?: string } }>;
}

/** Create-only write: created, or already there and left as it is. Any other failure is a failed open, never a silent skip. */
export async function putCreateOnly(kv: WriterKv, key: string, bytes: Uint8Array, contentType: string): Promise<PutResult> {
  const written = await kv.put(key, bytes, { contentType, ifNoneMatch: "*" });
  if (written.ok) return "created";
  if (written.error.code === "KV_PRECONDITION_FAILED") return "exists";
  throw new RunError("failed", { detail: `save ${key}: ${written.error.code ?? "error"}` });
}

/** The part of `fetch` the reader uses (the page's own `fetch`, or a fake in tests). */
export type ReaderFetch = (url: string, init: { signal: AbortSignal; credentials: "omit"; redirect: "error" }) => Promise<Response>;

/**
 * Every file under `prefix`, keyed by path relative to it. A listing or total that is too large is `incomplete`, never silently cut.
 * The node's metadata does not give a file's size (a HEAD answers 0 length, and a browser may not see the header at all), and
 * `kv.get` buffers the whole value, so a 1 GB file could not be refused after the fact: each file is fetched as a STREAM from a signed
 * read URL and the read stops (the stream is cancelled) at the first byte past the cap.
 */
export async function readSavedFiles(kv: ReaderKv, prefix: string, fetcher: ReaderFetch = (url, init) => fetch(url, init)): Promise<ReadSession["files"]> {
  const listed = await kv.list({ prefix });
  if (!listed.ok) throw new RunError("failed", { detail: `list ${prefix}: ${listed.error.code ?? "error"}` });
  const paths = listed.data.keys.filter((key) => key.startsWith(prefix)).map((key) => key.slice(prefix.length)).filter((path) => path !== "");
  const entries = new Map<string, Uint8Array>();
  let incomplete = listed.data.truncated === true || paths.length > MAX_STORED_FILES;
  let total = 0;
  for (const path of paths.slice(0, MAX_STORED_FILES)) {
    const signed = await kv.createSignedReadUrl(`${prefix}${path}`, { expiresInSeconds: 60 });
    if (!signed.ok) {
      // Listed a moment ago and now gone: the set cannot be vouched for.
      if (/NOT_FOUND/.test(signed.error.code ?? "")) { incomplete = true; continue; }
      throw new RunError("failed", { detail: `read ${prefix}${path}: ${signed.error.code ?? "error"}` });
    }
    const controller = new AbortController();
    let response: Response;
    try {
      response = await fetcher(signed.data.url, { signal: controller.signal, credentials: "omit", redirect: "error" });
    } catch (cause) {
      throw new RunError("failed", { cause, detail: `read ${prefix}${path}: the download failed` });
    }
    if (response.status === 404) { incomplete = true; continue; }
    if (!response.ok) throw new RunError("failed", { detail: `read ${prefix}${path}: ${response.status}` });
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_STORED_BYTES - total) { controller.abort(); incomplete = true; break; }
    const reader = response.body?.getReader();
    if (reader === undefined) throw new RunError("failed", { detail: `read ${prefix}${path}: no stream` });
    const chunks: Uint8Array[] = [];
    let received = 0;
    let over = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      received += value.byteLength;
      if (total + received > MAX_STORED_BYTES) { over = true; await reader.cancel().catch(() => undefined); controller.abort(); break; }
      chunks.push(value);
    }
    if (over) { incomplete = true; break; }
    const bytes = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    total += received;
    entries.set(path, bytes);
  }
  return { entries, incomplete };
}

/** The OpenKey connection a read session hands to the runtime sign-in, and how to end the whole sign-in. */
const OPENKEY_SESSIONS = new WeakMap<ReadSession, ManifestSignIn>();

/** Device-local record of the digest last verified per app. It only chooses the read's grants; it is never proof that files are present. */
const HINT_PREFIX = "tinycloud-share.app-installed:";
function localHints(): InstalledHints {
  // localStorage can be missing or blocked (private modes, node tests): every open then takes the write-capable read, which is safe.
  const storage = (): Storage | undefined => { try { return globalThis.localStorage; } catch { return undefined; } };
  return {
    get: (appId) => { try { return storage()?.getItem(HINT_PREFIX + appId) ?? undefined; } catch { return undefined; } },
    set: (appId, digest) => { try { storage()?.setItem(HINT_PREFIX + appId, digest); } catch { /* not recorded: the next open checks again */ } },
    clear: (appId) => { try { storage()?.removeItem(HINT_PREFIX + appId); } catch { /* as above */ } },
  };
}

export function createRunPorts(): RunPorts {
  return {
    async prepare(entry): Promise<PreparedApp> {
      // Before any approval: every catalog file is fetched and checked against its pin, and the manifest is loaded and checked.
      const bundle = await fetchVerifiedBundle(entry).catch((error: unknown) => {
        if (error instanceof BundleRefusal && error.reason !== "unavailable") throw new RunError("catalog-unavailable", { cause: error, detail: "The catalog copy of this app did not match the catalog." });
        throw new RunError("failed", { cause: error, detail: "The app's files could not be downloaded. Check the connection and try again." });
      });
      const manifest = await loadManifest(entry);
      if (!manifest.ok && manifest.reason === "mismatch") throw new RunError("catalog-unavailable", { detail: "The catalog copy of this app's manifest did not match the catalog." });
      if (!manifest.ok) throw new RunError("failed", { detail: "The app's manifest could not be downloaded. Check the connection and try again." });
      return { bundle, manifest };
    },

    hints: localHints(),

    async sdk(): Promise<ManifestSdk> {
      // Lazy so the page itself loads no SDK until the person asks to open an app.
      return import("@tinycloud/sdk-core");
    },

    async readStored(entry, hooks, options): Promise<ReadSession> {
      // Dynamic on purpose: the SDK, OpenKey and the shared sign-in load only on the click.
      const openkey = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      const approvals = approvalGuard(hooks);
      let client: TinyCloudWeb | undefined;
      let signedIn: ManifestSignIn;
      try {
        signedIn = await openkey.signInWithManifest({
          manifest: readerManifest(entry.app_id, entry.name, options.install),
          ...readerScope(entry.app_id, options.install),
          config,
          hostSpaces: [INSTALL_SPACE],
          guardApproval: approvals.guard,
          onClient: (created) => { client = created; },
          appName: runnerAppName("TinyCloud Share: open ", entry.name),
          sessionPrefix: "tinycloud-share-runner-read",
          expiry: INSTALL_EXPIRY_MS,
        });
      } catch (error) {
        const reason: WalletApprovalFailure | RunFailure | undefined = approvals.observed() ?? (client === undefined ? undefined : openkey.takeWalletApprovalFailure(client));
        throw new RunError(reason ?? "failed", { cause: error });
      }
      const { tinycloud, spaces } = signedIn;
      const space = spaces[INSTALL_SPACE];
      if (space === undefined) { await signedIn.dispose(); throw new RunError("failed", { detail: "the applications space is not hosted" }); }
      approvals.lock();
      const kv = tinycloud.kvForSpace(space);
      let files: ReadSession["files"];
      try {
        files = await readSavedFiles(kv, `${entry.app_id}/app/`);
      } catch (error) {
        await signedIn.dispose();
        throw error instanceof RunError ? error : new RunError("failed", { cause: error });
      }
      let ended = false;
      const readSession: ReadSession = {
        files,
        ...(options.install ? { put: (key: string, bytes: Uint8Array, contentType: string) => putCreateOnly(kv, key, bytes, contentType) } : {}),
        end: async ({ keepOpenKey }) => {
          if (ended) return;
          ended = true;
          // The client's session key goes either way; closing OpenKey's own windows only when nothing follows.
          if (keepOpenKey) { try { await tinycloud.signOut(); } catch { /* it lives only in this tab */ } } else await signedIn.dispose();
        },
      };
      OPENKEY_SESSIONS.set(readSession, signedIn);
      return readSession;
    },

    async openRuntime(app, previous, hooks): Promise<RuntimeSession> {
      const openkey = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      const carried = OPENKEY_SESSIONS.get(previous);
      // The read session is over; OpenKey stays connected so this is one more approval, not a second connect.
      await previous.end({ keepOpenKey: true });
      const startedAt = Date.now();
      const approvals = approvalGuard(hooks);
      let client: TinyCloudWeb | undefined;
      let signedIn: ManifestSignIn;
      try {
        signedIn = await openkey.signInWithManifest({
          manifest: app.signing,
          ...app.scope,
          config,
          hostSpaces: [INSTALL_SPACE],
          guardApproval: approvals.guard,
          onClient: (created) => { client = created; },
          appName: runnerAppName("TinyCloud Share: ", app.entry.name),
          sessionPrefix: "tinycloud-share-runner",
          expiry: RUNTIME_SESSION_MS,
          ...(carried === undefined ? {} : { session: carried.session }),
        });
      } catch (error) {
        const reason: WalletApprovalFailure | RunFailure | undefined = approvals.observed() ?? (client === undefined ? undefined : openkey.takeWalletApprovalFailure(client));
        await carried?.dispose();
        throw new RunError(reason ?? "failed", { cause: error });
      }
      const { tinycloud, spaces } = signedIn;
      // From here the page signs nothing more: a call outside the session's ReCap is the node's to refuse.
      approvals.lock();
      const space = spaces[INSTALL_SPACE];
      if (space === undefined) { await signedIn.dispose(); await carried?.dispose(); throw new RunError("failed", { detail: "the applications space is not hosted" }); }
      const data = createAppData(tinycloud.kvForSpace(space), tinycloud.sqlForSpace(space));
      let ending: Promise<void> | undefined;
      return {
        data,
        expiresAt: startedAt + RUNTIME_SESSION_MS - EXPIRY_MARGIN_MS,
        // The runtime sign-in was handed the reader's OpenKey connection, so the helper leaves it open: close it with the reader's.
        end: () => (ending ??= (async () => { await signedIn.dispose(); await carried?.dispose(); })()),
      };
    },
  };
}
