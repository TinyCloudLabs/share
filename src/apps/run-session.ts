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
import { INSTALL_RECORD_PATH } from "./bundle.ts";
import { RunError, type ReadSession, type RunFailure, type RunHooks, type RunPorts, type RuntimeSession } from "./run.ts";
import { RUNTIME_SESSION_MS, type ManifestSdk } from "./grants.ts";

/** The session is treated as over this long before the SDK's own expiry, so a call is not sent into a dying session. */
const EXPIRY_MARGIN_MS = 60_000;
const APP_NAME_MAX = 80;

/**
 * Identity the read sign-in uses: the runner's own, so the person's apps list does not gain a record named after the
 * app being opened and the record Share's library keeps under `xyz.tinycloud.share` is never overwritten.
 */
export const RUNNER_APP_ID = "xyz.tinycloud.share.runner";

/** The read sign-in's manifest: `get` on `<app_id>/app/` in the applications space, and nothing else. */
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
    permissions: [{ service: "tinycloud.kv", path: `${appId}/app/`, actions: ["get"], skipPrefix: true, description: `Read ${appName}'s saved files (its code, manifest and install record) so it can be opened.` }],
  };
}

/** What the read sign-in may ask for: `get` on the one saved app, and nothing else. */
export function readerScope(appId: string): ManifestScope {
  return { allowedSpaces: [INSTALL_SPACE], allowedServices: ["kv"], allowedActions: ["get"], allowedPathPrefixes: [{ space: INSTALL_SPACE, prefix: `${appId}/app/` }] };
}

/** The keys read in step 1, in `StoredBytes` order. */
export const storedKeys = (appId: string): { manifest: string; install: string; source: string } => ({
  manifest: `${appId}/app/manifest.json`,
  install: `${appId}/app/${INSTALL_RECORD_PATH}`,
  source: `${appId}/app/app.jsx`,
});

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
          appName: `TinyCloud Share: open ${entry.name}`.slice(0, APP_NAME_MAX),
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
      const keys = storedKeys(entry.app_id);
      const read = async (key: string): Promise<Uint8Array | undefined> => {
        const result = await kv.get(key, { binary: true });
        if (!result.ok) {
          if (result.error.code === "KV_NOT_FOUND" || /NOT_FOUND/.test(result.error.code ?? "")) return undefined;
          throw new RunError("failed", { detail: `read ${key}: ${result.error.code ?? "error"}` });
        }
        const data: unknown = result.data.data;
        if (data instanceof Uint8Array) return data;
        if (typeof data === "string") return new TextEncoder().encode(data);
        throw new RunError("failed", { detail: `read ${key}: not bytes` });
      };
      let files: ReadSession["files"];
      try {
        files = { manifest: await read(keys.manifest), install: await read(keys.install), source: await read(keys.source) };
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
          appName: `TinyCloud Share: ${app.name}`.slice(0, APP_NAME_MAX),
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
      if (space === undefined) { await signedIn.dispose(); throw new RunError("failed", { detail: "the applications space is not hosted" }); }
      const data = createAppData(tinycloud.kvForSpace(space), tinycloud.sqlForSpace(space));
      return {
        data,
        expiresAt: startedAt + RUNTIME_SESSION_MS - EXPIRY_MARGIN_MS,
        end: () => signedIn.dispose(),
      };
    },
  };
}
