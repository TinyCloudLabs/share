/**
 * The real ports for the install flow: OpenKey, the Web SDK and the node.
 *
 * Nothing here is imported by the apps page itself. `createInstallPorts` is
 * called on the Install click, and the SDK, OpenKey and the shared sign-in
 * helper load only then (dynamic imports), so the catalog page stays free of
 * them until a person asks to install something.
 *
 * The sign-in is the shared `signInWithManifest` (src/share/openkey-session.ts),
 * which this module does not change. `InstallerSignInOptions` below is the
 * interface the install needs from it; the options the helper does not honour
 * yet are marked, and everything this module needs from them is also done here
 * (the apps-list confirmation) or is harmless when absent (`dispose`).
 */
import type { Manifest, TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig, type SharePublicConfig } from "../email-share/config.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import type { ApprovalGuard, ManifestSignIn, OpenKeyShareSession, WalletApprovalFailure } from "../share/openkey-session.js";
import { INSTALL_SPACE, expectedInstallerResources, resourceMismatch, type RequestedResource } from "./install-plan.ts";
import { InstallError, type InstallFailure, type InstallPorts, type InstallSession, type PutResult } from "./install.ts";

/** What the install asks of the shared sign-in helper. */
interface InstallerSignInOptions {
  readonly manifest: Manifest;
  readonly config: SharePublicConfig;
  readonly hostSpaces: readonly string[];
  readonly guardApproval: ApprovalGuard;
  readonly onClient: (tinycloud: TinyCloudWeb) => void;
  readonly session?: OpenKeyShareSession;
  /** Pending S6 fix round: wait for the SDK's sign-in registry sync before returning. */
  readonly waitForAccountRegistrySync?: boolean;
}

/** `ManifestSignIn`, plus the teardown the S6 fix round adds. */
interface InstallerSignIn extends ManifestSignIn {
  /** Closes any OpenKey window and clears the session. Absent until that round lands. */
  readonly dispose?: () => Promise<void> | void;
}

/** How long to wait for the apps list to show the app before registering it explicitly, then for it to show up. */
const LISTED_POLL_MS = 1_000;
const LISTED_ATTEMPTS = 15;

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
      // The helper's current signature; the options in InstallerSignInOptions it does not know yet are ignored until the S6 fix round lands.
      const signIn = session.signInWithManifest as unknown as (options: InstallerSignInOptions) => Promise<InstallerSignIn>;
      let signedIn: InstallerSignIn;
      try {
        signedIn = await signIn({ manifest, config, hostSpaces: [INSTALL_SPACE], guardApproval, onClient: (created) => { client = created; }, waitForAccountRegistrySync: true });
      } catch (error) {
        const failure: WalletApprovalFailure | InstallFailure | undefined = observed ?? (client === undefined ? undefined : session.takeWalletApprovalFailure(client));
        throw new InstallError(failure ?? "failed", { cause: error });
      }
      const { tinycloud, spaces } = signedIn;
      const spaceId = spaces[INSTALL_SPACE];
      if (spaceId === undefined) {
        await Promise.resolve(signedIn.dispose?.()).catch(() => undefined);
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
          // The SDK records the app in the background right after sign-in; give it a moment, then say so ourselves once.
          for (let attempt = 0; attempt < LISTED_ATTEMPTS; attempt += 1) {
            if (await listed()) return true;
            if (attempt === 4) await tinycloud.account.applications.register(installer);
            await new Promise((resolve) => setTimeout(resolve, LISTED_POLL_MS));
          }
          return listed();
        },
        async dispose(): Promise<void> {
          await signedIn.dispose?.();
        },
      } satisfies InstallSession;
    },
  };
}
