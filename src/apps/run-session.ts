/**
 * The real ports for opening an installed app: the Web SDK, OpenKey and the node.
 *
 * The SDK, OpenKey and the shared sign-in helper load only when the person opens an app
 * (dynamic imports).
 *
 * One sign-in per open (`signIn`, which calls the shared `signInWithManifest` in
 * src/share/openkey-session.ts). The session is persisted under the app's own storage
 * prefix, so a later open inside its lifetime restores it — same owner, same origin,
 * permissions still covered — with no new approval. The requested manifest is the union built in grants.ts:
 * the catalog's runtime grants, plus `get`, `list` and create-only `put` on `<app_id>/app/`,
 * and create-only `put` on `<app_id>/knowledge/`. The same session reads the saved copy,
 * saves what is missing and runs the app.
 *
 * Signing is closed once the sign-in completes: the approval guard refuses any further
 * signature request (`runner-signing-closed`).
 */
import type { TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig } from "../email-share/config.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import type { ApprovalGuard, ManifestSignIn } from "../share/openkey-session.js";
import { createAppData } from "./app-data.ts";
import { INSTALL_SPACE } from "./install-plan.ts";
import { isSignInLabel } from "../share/sign-in-label.js";
import { RunError, type PreparedApp, type PutResult, type RunFailure, type RunHooks, type RunPorts, type RunSession, type SignInPlan } from "./run.ts";
import { RUNTIME_SESSION_MS, type ManifestSdk } from "./grants.ts";
import { BundleRefusal, fetchVerifiedBundle } from "./bundle.ts";
import { loadManifest } from "./manifest.ts";
import type { StoredFiles } from "./stored-app.ts";

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
export async function readSavedFiles(kv: ReaderKv, prefix: string, fetcher: ReaderFetch = (url, init) => fetch(url, init)): Promise<StoredFiles> {
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
      let signedIn: ManifestSignIn;
      try {
        signedIn = await openkey.signInWithManifest({
          manifest: plan.manifest,
          ...plan.scope,
          config,
          hostSpaces: [INSTALL_SPACE],
          guardApproval: approvals.guard,
          onClient: (created) => { client = created; },
          appName: runnerAppName("TinyCloud Share: ", entry.name),
          // The session is persisted under this app's own prefix: a reload while it still lives
          // (same owner, same origin, permissions still covered) restores it without a new
          // approval, and it can never stand in for another app's or another account's session.
          sessionPrefix: await runnerSessionPrefix(entry.app_id),
          persistSession: true,
          expiry: RUNTIME_SESSION_MS,
        });
      } catch (error) {
        const reason = approvals.observed() ?? (client === undefined ? undefined : openkey.takeWalletApprovalFailure(client));
        throw new RunError(reason ?? "failed", { cause: error });
      }
      const { tinycloud, spaces, detach, dispose } = signedIn;
      const space = spaces[INSTALL_SPACE];
      if (space === undefined) {
        await dispose();
        throw new RunError("failed", { detail: "the applications space is not hosted" });
      }
      // Signing ends here, for good: the saves and the app run on this session without a signature request.
      approvals.lock();
      const kv = tinycloud.kvForSpace(space);
      let files: StoredFiles;
      try {
        files = await readSavedFiles(kv, `${entry.app_id}/app/`);
      } catch (error) {
        await dispose();
        throw error instanceof RunError ? error : new RunError("failed", { cause: error });
      }
      let ending: Promise<void> | undefined;
      const end = (): Promise<void> => {
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
        put: (key, bytes, contentType): Promise<PutResult> => putCreateOnly(kv, key, bytes, contentType),
        runtime: {
          data: createAppData(tinycloud.kvForSpace(space), tinycloud.sqlForSpace(space)),
          expiresAt: signedIn.sessionExpiresAt - EXPIRY_MARGIN_MS,
          end,
          detach: detachRuntime,
        },
      };
    },
  };
}
