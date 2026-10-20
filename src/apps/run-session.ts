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
import { isBytes } from "./bridge.ts";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE } from "./install-plan.ts";
import { isSignInLabel } from "../share/sign-in-label.js";
import { RunError, type ReadSession, type RunFailure, type RunHooks, type RunPorts, type RuntimeSession } from "./run.ts";
import { RUNTIME_SESSION_MS, type ManifestSdk } from "./grants.ts";

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

/** The read sign-in's manifest: `get` and `list` on `<app_id>/app/` in the applications space, and nothing else. */
export function readerManifest(appId: string, appName: string): Manifest {
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
    permissions: [{ service: "tinycloud.kv", path: `${appId}/app/`, actions: ["get", "list"], skipPrefix: true, description: `Read ${appName}'s saved files (its code, manifest and install record) so they can be checked before it is opened.` }],
  };
}

/** What the read sign-in may ask for: `get` and `list` on the one saved app, and nothing else. */
export function readerScope(appId: string): ManifestScope {
  return { allowedSpaces: [INSTALL_SPACE], allowedServices: ["kv"], allowedActions: ["get", "list"], allowedPathPrefixes: [{ space: INSTALL_SPACE, prefix: `${appId}/app/` }] };
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
  get(key: string, options: { binary: true }): Promise<{ ok: true; data: { data: unknown } } | { ok: false; error: { code?: string } }>;
}

/** Every file under `prefix`, keyed by path relative to it. A listing or total that is too large is `incomplete`, never silently cut. */
export async function readSavedFiles(kv: ReaderKv, prefix: string): Promise<ReadSession["files"]> {
  const listed = await kv.list({ prefix });
  if (!listed.ok) throw new RunError("failed", { detail: `list ${prefix}: ${listed.error.code ?? "error"}` });
  const paths = listed.data.keys.filter((key) => key.startsWith(prefix)).map((key) => key.slice(prefix.length)).filter((path) => path !== "");
  const entries = new Map<string, Uint8Array>();
  let incomplete = listed.data.truncated === true || paths.length > MAX_STORED_FILES;
  let total = 0;
  for (const path of paths.slice(0, MAX_STORED_FILES)) {
    const result = await kv.get(`${prefix}${path}`, { binary: true });
    if (!result.ok) {
      // Listed a moment ago and now gone or unreadable: the set cannot be vouched for.
      if (/NOT_FOUND/.test(result.error.code ?? "")) { incomplete = true; continue; }
      throw new RunError("failed", { detail: `read ${prefix}${path}: ${result.error.code ?? "error"}` });
    }
    const data: unknown = result.data.data;
    const bytes = isBytes(data) ? data : typeof data === "string" ? new TextEncoder().encode(data) : undefined;
    if (bytes === undefined) throw new RunError("failed", { detail: `read ${prefix}${path}: not bytes` });
    total += bytes.byteLength;
    if (total > MAX_STORED_BYTES) { incomplete = true; break; }
    entries.set(path, bytes);
  }
  return { entries, incomplete };
}

/** The OpenKey connection a read session hands to the runtime sign-in, and how to end the whole sign-in. */
const OPENKEY_SESSIONS = new WeakMap<ReadSession, ManifestSignIn>();

export function createRunPorts(): RunPorts {
  return {
    async sdk(): Promise<ManifestSdk> {
      // Lazy so the page itself loads no SDK until the person asks to open an app.
      return import("@tinycloud/sdk-core");
    },

    async readStored(entry, hooks): Promise<ReadSession> {
      // Dynamic on purpose: the SDK, OpenKey and the shared sign-in load only on the click.
      const openkey = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      const approvals = approvalGuard(hooks);
      let client: TinyCloudWeb | undefined;
      let signedIn: ManifestSignIn;
      try {
        signedIn = await openkey.signInWithManifest({
          manifest: readerManifest(entry.app_id, entry.name),
          ...readerScope(entry.app_id),
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
