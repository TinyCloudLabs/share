/**
 * The real ports for the install flow: OpenKey, the Web SDK and the node.
 *
 * Nothing here is imported by the apps page itself. `createInstallPorts` is
 * called on the Install click, and the SDK, OpenKey and the shared sign-in
 * helper load only then (dynamic imports), so the catalog page stays free of
 * them until a person asks to install something.
 *
 * The sign-in is the shared `signInWithManifest` (src/share/openkey-session.ts).
 * The installer states its own scope (`installerScope`), so the helper refuses
 * a manifest that asks for more than the two put-only folders before OpenKey
 * opens; it waits for the SDK's apps-list sync, and the session is disposed
 * when the install ends, whatever the outcome.
 */
import type { Manifest, TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig, type SharePublicConfig } from "../email-share/config.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import type { ApprovalGuard, ManifestSignIn, WalletApprovalFailure } from "../share/openkey-session.js";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE, expectedInstallerResources, installerScope, resourceMismatch, type RequestedResource } from "./install-plan.ts";
import { InstallError, type InstallFailure, type InstallPorts, type InstallSession, type PutResult } from "./install.ts";

/** The helper waits for the SDK's apps-list sync; this is only the bounded fallback if the list still lacks the app. */
const LISTED_POLL_MS = 1_000;
const LISTED_ATTEMPTS = 5;
const APP_NAME_MAX = 80;

function guardFailure(error: unknown): InstallFailure | undefined {
  if (!(error instanceof Error)) return undefined;
  if (error.message === "revoke-approval-abandoned") return "timeout";
  if (error.message === "revoke-another-approval") return "busy";
  return undefined;
}

/**
 * The SDK's own reading of `manifest`, checked against what the sheet showed,
 * right before OpenKey opens. A mismatch (a different SDK version resolving the
 * manifest differently) stops the install: the sheet must never describe less
 * than the sign-in asks for.
 */
async function assertRequestMatchesSheet(manifest: Manifest): Promise<void> {
  // Dynamic for the same reason as the sign-in helper below (the page must not load the SDK before a click).
  const { composeManifestRequest } = await import("@tinycloud/sdk-core");
  const composed = composeManifestRequest([manifest], { includeAccountRegistryPermissions: true });
  if (composed.delegationTargets.length > 0) throw new Error("install-request-delegates");
  const mismatch = resourceMismatch(expectedInstallerResources(manifest), composed.resources.map((resource): RequestedResource => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] })));
  if (mismatch !== null) throw new Error("install-request-differs-from-sheet");
}

export function createInstallPorts(): InstallPorts {
  return {
    async openSession(manifest, hooks) {
      // Dynamic on purpose: the SDK, OpenKey and the shared sign-in load only on the Install click, never with the catalog page.
      const session = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      await assertRequestMatchesSheet(manifest);

      let client: TinyCloudWeb | undefined;
      let observed: InstallFailure | undefined;
      // One approval at a time, for at most the 60-second window; the sheet shows the hint while it is open.
      const guardApproval: ApprovalGuard = async (wait) => {
        try {
          return await withWalletApproval({ setApproval: (open) => hooks.approval(open) }, () => wait());
        } catch (error) {
          observed ??= guardFailure(error);
          throw error;
        }
      };
      let signedIn: ManifestSignIn;
      try {
        signedIn = await session.signInWithManifest({
          manifest,
          ...installerScope(manifest.app_id),
          config,
          hostSpaces: [INSTALL_SPACE],
          guardApproval,
          onClient: (created) => { client = created; },
          appName: `TinyCloud Share: install ${manifest.name}`.slice(0, APP_NAME_MAX),
          sessionPrefix: "tinycloud-share-install",
          expiry: INSTALL_EXPIRY_MS,
          waitForAccountRegistrySync: true,
        });
      } catch (error) {
        const failure: WalletApprovalFailure | InstallFailure | undefined = observed ?? (client === undefined ? undefined : session.takeWalletApprovalFailure(client));
        // A manifest outside the installer's scope is a bug in this code, never something to retry.
        throw new InstallError(failure ?? "failed", { cause: error });
      }
      const { tinycloud, spaces } = signedIn;
      const spaceId = spaces[INSTALL_SPACE];
      if (spaceId === undefined) {
        await signedIn.dispose();
        throw new InstallError("failed", { cause: new Error("install-space-not-hosted") });
      }
      const kv = tinycloud.kvForSpace(spaceId);

      return {
        async put(key: string, bytes: Uint8Array, contentType: string): Promise<PutResult> {
          const written = await kv.put(key, bytes, { contentType, ifNoneMatch: "*" });
          if (written.ok) return "created";
          if (written.error.code === "KV_PRECONDITION_FAILED") return "exists";
          throw new Error(`install-write-failed:${written.error.code}`);
        },
        async confirmListed(installer: Manifest): Promise<boolean> {
          const listed = async (): Promise<boolean> => (await tinycloud.account.applications.get(installer.app_id)).ok;
          // The helper already waited for the SDK's sync, so this is normally one read. If the list still lacks the app, register it once and look a few times.
          if (await listed()) return true;
          await tinycloud.account.applications.register(installer);
          for (let attempt = 0; attempt < LISTED_ATTEMPTS; attempt += 1) {
            if (await listed()) return true;
            await new Promise((resolve) => setTimeout(resolve, LISTED_POLL_MS));
          }
          return false;
        },
        async dispose(): Promise<void> {
          await signedIn.dispose();
        },
      } satisfies InstallSession;
    },
  };
}
