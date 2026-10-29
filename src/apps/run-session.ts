/**
 * The real ports for opening an installed app: the Web SDK, OpenKey and the node.
 *
 * Existing app grants use a narrow same-session read of install.json, then authorize
 * only the saved version's resources. New installs sign the current version once.
 * App opens do not create or host spaces; OpenKey onboarding owns that setup.
 *
 * The signature guard is closed after the installed version's grant is resolved.
 */
import type { CatalogEntry } from "./catalog.ts";
import type { Manifest, PermissionEntry, TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig } from "../email-share/config.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import type { ApprovalGuard, ManifestSignIn } from "../share/openkey-session.js";
import { createAppData } from "./app-data.ts";
import { INSTALL_EXPIRY, INSTALL_EXPIRY_MS, INSTALL_SPACE, installRecordKey } from "./install-plan.ts";
import { isSignInLabel } from "../share/sign-in-label.js";
import { RunError, type PreparedApp, type PutResult, type RunFailure, type RunHooks, type RunPorts, type RunSession, type SignInPlan } from "./run.ts";
import { RUNTIME_SESSION_MS, type ManifestSdk } from "./grants.ts";
import { BundleRefusal, INSTALL_RECORD_PATH, fetchVerifiedBundle } from "./bundle.ts";
import { loadManifest } from "./manifest.ts";
import { parseInstallRecord, type StoredFiles } from "./stored-app.ts";
import { showRuntimePermissionDialog } from "./permission-dialog.ts";
import { restoreRuntimeGrants, saveRuntimeGrants } from "./runtime-grants.ts";


/** The session is treated as over this long before the SDK's own expiry, so a call is not sent into a dying session. */
const EXPIRY_MARGIN_MS = 60_000;
const APP_NAME_MAX_CHARS = 64;
/** Files and bytes read from `<app_id>/app/` at most; more than that is refused as unverifiable. */
export const MAX_STORED_FILES = 64;
export const MAX_STORED_BYTES = 8 * 1024 * 1024;

function installSafePermissionDialog(tinycloud: TinyCloudWeb, preparePermissionRequest: (permissions: PermissionEntry[]) => Promise<void>): void {
  // @tinycloud/web-sdk 3.7.0-beta.1 exposes only this private renderer seam; keep the exact version pinned in package.json.
  const previous = Reflect.get(tinycloud, "_testHooks");
  const hooks = typeof previous === "object" && previous !== null ? previous : {};
  const showModal = async (options: Parameters<typeof showRuntimePermissionDialog>[0]) => {
    const result = await showRuntimePermissionDialog(options);
    if (result.approved) await preparePermissionRequest(options.additional);
    return result;
  };
  if (!Reflect.set(tinycloud, "_testHooks", { ...hooks, showModal })) {
    throw new Error("runner-permission-dialog-unavailable");
  }
}

function uncoveredPermissions(tinycloud: Pick<TinyCloudWeb, "hasPermissions">, permissions: PermissionEntry[]): PermissionEntry[] {
  const uncovered: PermissionEntry[] = [];
  for (const permission of permissions) {
    const actions = permission.actions.filter((action) => !tinycloud.hasPermissions([{ ...permission, actions: [action] }]));
    if (actions.length > 0) uncovered.push({ ...permission, actions });
  }
  return uncovered;
}
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
 * The SDK's session storage key prefix for one app: the app id under a 128-bit hash, so the prefix
 * stays a valid label (app ids hold dots, which the sign-in's label guard refuses) and one app's
 * saved session can never stand in for another's. The address inside the stored record binds the
 * session to its owner; the prefix binds it to this app on this origin.
 */
export async function runnerSessionPrefix(appId: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(appId));
  const hex = [...new Uint8Array(digest).slice(0, 16)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `tinycloud-share-runner-${hex}`;
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
  list(options: { prefix: string }): Promise<{ ok: true; data: { keys: string[]; truncated?: boolean } } | { ok: false; error: { code?: string; message?: string; meta?: { status?: unknown } } }>;
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
export async function readSavedFiles(kv: ReaderKv, prefix: string, fetcher: ReaderFetch = (url, init) => fetch(url, init)): Promise<StoredFiles> {
  const listed = await kv.list({ prefix });
  if (!listed.ok) throw new RunError("failed", { detail: `list ${prefix}: ${listed.error.code ?? "error"}`, cause: listed.error });
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

const installLookupScope = (entry: CatalogEntry) => ({
  allowedSpaces: [INSTALL_SPACE],
  allowedServices: ["kv"],
  allowedActions: ["get", "list"],
  allowedPathPrefixes: [{ space: INSTALL_SPACE, prefix: installRecordKey(entry.app_id) }],
});

function installLookupManifest(entry: CatalogEntry): Manifest {
  const key = installRecordKey(entry.app_id);
  return {
    manifest_version: 1,
    app_id: entry.app_id,
    name: entry.name,
    space: INSTALL_SPACE,
    defaults: false,
    includePublicSpace: false,
    expiry: INSTALL_EXPIRY,
    permissions: [{ service: "tinycloud.kv", path: key, actions: ["get", "list"], skipPrefix: true, description: "Check the saved app version before opening it." }],
  };
}

export async function readInstallRecordDigest(kv: ReaderKv, appId: string): Promise<string | null> {
  const key = installRecordKey(appId);
  const prefix = `${appId}/app/`;
  const files = await readSavedFiles({
    list: async () => {
      const listed = await kv.list({ prefix: key });
      if (!listed.ok) return listed;
      return { ok: true, data: { keys: listed.data.keys.filter((candidate) => candidate === key), ...(listed.data.truncated === undefined ? {} : { truncated: listed.data.truncated }) } };
    },
    createSignedReadUrl: (path, options) => kv.createSignedReadUrl(path, options),
  }, prefix);
  if (files.incomplete) throw new RunError("damaged", { detail: "install.json could not be read completely" });
  const bytes = files.entries.get(INSTALL_RECORD_PATH);
  if (bytes === undefined) return null;
  const install = parseInstallRecord(bytes);
  if (install === null) throw new RunError("damaged", { detail: "install.json is not a valid install record" });
  return install.digest;
}
export async function readInstalledDigest(entry: CatalogEntry, hooks: RunHooks): Promise<string | null> {
  const openkey = await import("../share/openkey-session.js");
  const config = await loadSharePublicConfig();
  const approvals = approvalGuard(hooks);
  let client: TinyCloudWeb | undefined;
  let signedIn: ManifestSignIn;
  try {
    signedIn = await openkey.signInWithManifest({
      manifest: installLookupManifest(entry),
      ...installLookupScope(entry),
      config,
      includeAccountRegistryPermissions: false,
      hostSpaces: [INSTALL_SPACE],
      guardApproval: approvals.guard,
      onClient: (created) => { client = created; },
      appName: runnerAppName("TinyCloud Share: check version ", entry.name),
      expiry: INSTALL_EXPIRY_MS,
    });
  } catch (error) {
    const reason = approvals.observed() ?? (client === undefined ? undefined : openkey.takeWalletApprovalFailure(client));
    throw new RunError(reason ?? "failed", { cause: error });
  }
  try {
    const space = signedIn.spaces[INSTALL_SPACE];
    if (space === undefined) throw new RunError("failed", { detail: "the applications space is not hosted" });
    return await readInstallRecordDigest(signedIn.tinycloud.kvForSpace(space), entry.app_id);
  } catch (error) {
    throw error instanceof RunError ? error : new RunError("failed", { cause: error });
  } finally {
    await signedIn.dispose().catch(() => undefined);
  }
}

export function createRunPorts(): RunPorts {
  return {
    async hasPersistedSession(appId): Promise<boolean> {
      const { BrowserSessionStorage } = await import("@tinycloud/web-sdk");
      const keyPrefix = await runnerSessionPrefix(appId);
      return new BrowserSessionStorage({ keyPrefix }).activeAddress() !== undefined;
    },
    async prepare(entry): Promise<PreparedApp> {
      // Before the app's permissions are signed, every catalog file is fetched and checked against its pin, and the manifest is loaded and checked.
      const bundle = await fetchVerifiedBundle(entry).catch((error: unknown) => {
        if (error instanceof BundleRefusal && error.reason !== "unavailable") throw new RunError("catalog-unavailable", { cause: error, detail: "The catalog copy of this app did not match the catalog." });
        throw new RunError("failed", { cause: error, detail: "The app's files could not be downloaded. Check the connection and try again." });
      });
      const manifest = await loadManifest(entry);
      if (!manifest.ok && manifest.reason === "mismatch") throw new RunError("catalog-unavailable", { detail: "The catalog copy of this app's manifest did not match the catalog." });
      if (!manifest.ok) throw new RunError("failed", { detail: "The app's manifest could not be downloaded. Check the connection and try again." });
      return { bundle, manifest };
    },
    loadCatalogManifest(entry) { return loadManifest(entry); },


    async sdk(): Promise<ManifestSdk> {
      // Lazy so the page itself loads no SDK until the person asks to open an app.
      return import("@tinycloud/sdk-core");
    },

    async signIn(entry, plan: SignInPlan, hooks: RunHooks): Promise<RunSession> {
      // Dynamic on purpose: OpenKey and the shared sign-in load only when the sign-in starts.
      const openkey = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      const approvals = approvalGuard(hooks);
      let client: TinyCloudWeb | undefined;
      const sessionPrefix = await runnerSessionPrefix(entry.app_id);
      const openSession = async (): Promise<ManifestSignIn> => {
        try {
          return await openkey.signInWithManifest({
            manifest: plan.manifest,
            ...plan.scope,
            config,
            includeAccountRegistryPermissions: false,
            autoCreateSpace: false,

            guardApproval: approvals.guard,
            onClient: (created) => { client = created; },
            appName: runnerAppName("TinyCloud Share: ", entry.name),
            // The session is persisted under this app's own prefix: a reload while it still lives
            // (same owner, same origin, permissions still covered) restores it without a new
            // approval, and it can never stand in for another app's or another account's session.
            restoreBeforeOpenKey: true,
            sessionPrefix,
            persistSession: true,
            expiry: RUNTIME_SESSION_MS,
          });
        } catch (error) {
          const reason = approvals.observed() ?? (client === undefined ? undefined : openkey.takeWalletApprovalFailure(client));
          const detail = error instanceof Error && error.message.length > 0 ? error.message : undefined;
          throw new RunError(reason ?? "failed", { cause: error, ...(detail === undefined ? {} : { detail }) });
        }
      };
      const signedIn = await openSession();
      const { tinycloud, detach, dispose } = signedIn;
      const space = tinycloud.space(INSTALL_SPACE);
      const kv = space.kv;
      // The persisted grant is deliberately minimal on reopen; resolve install.json
      // first, then request only uncovered permissions for the saved version.
      const runtimeGrantKey = `${sessionPrefix}-runtime-grants`;
      let authorized = false;
      const authorize = async (selectedEntry: CatalogEntry, selectedPlan: SignInPlan, sdk: ManifestSdk): Promise<void> => {
        if (authorized) throw new RunError("failed", { detail: "the app grant was already resolved" });
        if (selectedPlan.manifest.app_id !== selectedEntry.app_id) throw new RunError("failed", { detail: "the app grant names a different app" });
        try {
          await restoreRuntimeGrants(tinycloud, runtimeGrantKey, selectedEntry.app_id, selectedEntry.bundle.digest);
          const permissions = sdk.resolveManifest(selectedPlan.manifest).resources
            .filter((resource) => resource.space === INSTALL_SPACE && (resource.service === "tinycloud.kv" || resource.service === "tinycloud.sql"))
            .map((resource) => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] }));
          const uncovered = uncoveredPermissions(tinycloud, permissions);
          if (uncovered.length > 0) {
            installSafePermissionDialog(tinycloud, signedIn.preparePermissionRequest);
            const result = await tinycloud.requestPermissions(uncovered, { expiryMs: RUNTIME_SESSION_MS });
            if (!result.approved) throw new RunError("cancelled", { detail: "permission-declined" });
            const delegations = result.delegations ?? tinycloud.getRuntimePermissionDelegations(uncovered);
            const ownerAddress = tinycloud.address();
            if (ownerAddress !== undefined) await saveRuntimeGrants(runtimeGrantKey, selectedEntry.app_id, selectedEntry.bundle.digest, ownerAddress, delegations);
          }
          authorized = true;
        } finally {
          approvals.lock();
        }
      };
      let files: StoredFiles;
      try {
        files = await readSavedFiles(kv, `${entry.app_id}/app/`);
      } catch (error) {
        approvals.lock();
        await dispose();
        throw error instanceof RunError ? error : new RunError("failed", { cause: error });
      }
      let ending: Promise<void> | undefined;
      const end: () => Promise<void> = () => {
        ending ??= dispose();
        return ending;
      };
      let detaching: Promise<void> | undefined;
      const detachRuntime = (): Promise<void> => {
        detaching ??= detach();
        return detaching;
      };
      return {
        files,
        authorize,
        put: (key, bytes, contentType): Promise<PutResult> => putCreateOnly(kv, key, bytes, contentType),
        runtime: {
          data: createAppData(kv, tinycloud.sqlForSpace(space.id)),
          expiresAt: signedIn.sessionExpiresAt - EXPIRY_MARGIN_MS,
          end,
          detach: detachRuntime,
        },
      };
    },
  };
}
