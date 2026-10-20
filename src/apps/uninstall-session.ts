/**
 * The real ports for the uninstall flow: OpenKey, the Web SDK and the node.
 *
 * Loaded only on the Uninstall confirm. The SDK, OpenKey and the shared sign-in
 * are dynamic imports on purpose: the apps page must not load them before a
 * click (the same constraint install-session.ts documents).
 *
 * The sign-in is the shared `signInWithManifest`, with the uninstall's own
 * identity and scope (`uninstallScope`). It does not sync the apps list
 * (`includeAccountRegistryPermissions: false`), so the uninstall never writes an
 * apps-list record for its own identity. The account space is hosted
 * explicitly, because the registry removal needs it.
 *
 * A key that is already missing counts as deleted (`KV_NOT_FOUND`), so a retry
 * after an interrupted run finishes the job.
 */
import type { Manifest, TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig } from "../email-share/config.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import type { ApprovalGuard, ManifestSignIn } from "../share/openkey-session.js";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE, resourceMismatch, type RequestedResource } from "./install-plan.ts";
import { ACCOUNT_SPACE, LIST_PAGE_LIMIT, UninstallError, expectedUninstallResources, uninstallAppName, uninstallManifest, uninstallScope, type UninstallFailure } from "./uninstall-plan.ts";
import type { ListPage, UninstallPorts, UninstallSession } from "./uninstall.ts";

/** The error code a key-value service returns for a key that is not there. */
const MISSING = "KV_NOT_FOUND";

function guardFailure(error: unknown): UninstallFailure | undefined {
  if (!(error instanceof Error)) return undefined;
  if (error.message === "revoke-approval-abandoned") return "timeout";
  if (error.message === "revoke-another-approval") return "busy";
  return undefined;
}

function errorCode(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string") return error.code;
  return undefined;
}

/**
 * The SDK's reading of the uninstall manifest, checked against the confirm
 * sheet right before OpenKey opens. The sheet must never describe less than the
 * sign-in asks for, so a mismatch stops the uninstall.
 */
async function assertUninstallRequestMatchesSheet(manifest: Manifest, appId: string): Promise<void> {
  const { composeManifestRequest } = await import("@tinycloud/sdk-core");
  const composed = composeManifestRequest([manifest], { includeAccountRegistryPermissions: false });
  if (composed.delegationTargets.length > 0) throw new Error("uninstall-request-delegates");
  const actual = composed.resources.map((resource): RequestedResource => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] }));
  if (resourceMismatch(expectedUninstallResources(appId), actual) !== null) throw new Error("uninstall-request-differs-from-sheet");
}

export function createUninstallPorts(): UninstallPorts {
  return {
    async openSession(app, hooks) {
      const session = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      const manifest = uninstallManifest(app);
      await assertUninstallRequestMatchesSheet(manifest, app.app_id);

      let client: TinyCloudWeb | undefined;
      let observed: UninstallFailure | undefined;
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
          ...uninstallScope(app.app_id),
          config,
          hostSpaces: [INSTALL_SPACE, ACCOUNT_SPACE],
          includeAccountRegistryPermissions: false,
          guardApproval,
          onClient: (created) => { client = created; },
          appName: uninstallAppName(app.name),
          sessionPrefix: "tinycloud-share-uninstall",
          expiry: INSTALL_EXPIRY_MS,
        });
      } catch (error) {
        const failure = observed ?? (client === undefined ? undefined : session.takeWalletApprovalFailure(client));
        throw new UninstallError(failure ?? "failed", { cause: error });
      }
      const { tinycloud, spaces } = signedIn;
      const spaceId = spaces[INSTALL_SPACE];
      const accountId = spaces[ACCOUNT_SPACE];
      if (spaceId === undefined || accountId === undefined) {
        await signedIn.dispose();
        throw new UninstallError("failed", { cause: new Error("uninstall-space-not-hosted") });
      }
      const kv = tinycloud.kvForSpace(spaceId);

      return {
        async list(prefix: string, cursor?: string): Promise<ListPage> {
          const listed = await kv.list({ prefix, limit: LIST_PAGE_LIMIT, ...(cursor === undefined ? {} : { cursor }) });
          if (!listed.ok) throw new Error(`uninstall-list-failed:${listed.error.code}`);
          return { keys: [...listed.data.keys], truncated: listed.data.truncated === true, ...(listed.data.nextCursor === undefined ? {} : { nextCursor: listed.data.nextCursor }) };
        },
        async del(key: string): Promise<void> {
          const removed = await kv.delete(key);
          if (removed.ok || removed.error.code === MISSING) return;
          throw new Error(`uninstall-delete-failed:${removed.error.code}`);
        },
        async removeRegistry(appId: string): Promise<void> {
          // `applications.remove` deletes `applications/<appId>` in the account space; a missing entry is success.
          const removed = await tinycloud.account.applications.remove(appId);
          if (removed.ok || errorCode(removed.error) === MISSING) return;
          throw new Error(`uninstall-registry-failed:${errorCode(removed.error) ?? "unknown"}`);
        },
        async dispose(): Promise<void> {
          await signedIn.dispose();
        },
      } satisfies UninstallSession;
    },
  };
}
