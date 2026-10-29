/**
 * The real ports for Repair: OpenKey, the Web SDK and the node. Loaded only when the person clicks Repair in the
 * repair panel (dynamic imports), like the open flow's. The sign-in is the shared `signInWithManifest` with Repair's own
 * scope (`repairScope`), so the helper refuses a manifest that asks for more than `put`/`del`/`list` on the one
 * app's `app/` folder before OpenKey opens.
 */
import type { TinyCloudWeb } from "@tinycloud/web-sdk";

import { loadSharePublicConfig } from "../email-share/config.js";
import type { ApprovalGuard, ManifestSignIn, WalletApprovalFailure } from "../share/openkey-session.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import { INSTALL_EXPIRY_MS, INSTALL_SPACE } from "./install-plan.ts";
import { RepairError, type RepairFailure, type RepairPorts, type RepairSession, repairScope } from "./repair.ts";
import { runnerAppName } from "./run-session.ts";

export function createRepairPorts(): RepairPorts {
  return {
    async openSession(manifest, hooks): Promise<RepairSession> {
      // Dynamic on purpose: the SDK, OpenKey and the shared sign-in load only on the click.
      const openkey = await import("../share/openkey-session.js");
      const config = await loadSharePublicConfig();
      let client: TinyCloudWeb | undefined;
      let observed: RepairFailure | undefined;
      const guardApproval: ApprovalGuard = async (wait) => {
        try {
          return await withWalletApproval({ setApproval: (open) => hooks.approval(open) }, () => wait());
        } catch (error) {
          if (error instanceof Error && error.message === "revoke-approval-abandoned") observed ??= "timeout";
          else if (error instanceof Error && error.message === "revoke-another-approval") observed ??= "busy";
          throw error;
        }
      };
      let signedIn: ManifestSignIn;
      try {
        signedIn = await openkey.signInWithManifest({
          manifest,
          ...repairScope(manifest.app_id),
          config,
          hostSpaces: [INSTALL_SPACE],
          guardApproval,
          onClient: (created) => { client = created; },
          appName: runnerAppName("TinyCloud Share: repair ", manifest.name),
          sessionPrefix: "tinycloud-share-repair",
          expiry: INSTALL_EXPIRY_MS,
        });
      } catch (error) {
        const failure: WalletApprovalFailure | RepairFailure | undefined = observed ?? (client === undefined ? undefined : openkey.takeWalletApprovalFailure(client));
        throw new RepairError(failure ?? "failed", { cause: error });
      }
      const { tinycloud, spaces } = signedIn;
      const space = spaces[INSTALL_SPACE];
      if (space === undefined) { await signedIn.dispose(); throw new RepairError("failed", { cause: new Error("repair-space-not-hosted") }); }
      const kv = tinycloud.kvForSpace(space);
      return {
        async put(key, bytes, contentType) {
          const written = await kv.put(key, bytes, { contentType });
          if (!written.ok) throw new Error(`repair-write-failed:${written.error.code}`);
        },
        async list(prefix) {
          const listed = await kv.list({ prefix });
          if (!listed.ok) throw new Error(`repair-list-failed:${listed.error.code}`);
          if (listed.data.truncated === true) throw new Error("repair-list-truncated");
          return listed.data.keys;
        },
        async del(key) {
          const deleted = await kv.delete(key);
          if (!deleted.ok) throw new Error(`repair-delete-failed:${deleted.error.code}`);
        },
        dispose: () => signedIn.dispose(),
      };
    },
  };
}
