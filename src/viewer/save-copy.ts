/**
 * "Save a copy to my TinyCloud", the viewer's only account step.
 *
 * Opening a share is account-free. Nothing here runs, and OpenKey is not even
 * loaded, until the person clicks Save: this module only builds the function
 * the click calls. That function signs in with OpenKey (with the manifest for
 * `files-for-you/v1/` and nothing else), hosts the person's own space, and
 * writes the bytes the viewer already holds. The session stays in memory and is
 * dropped with the call; no key, token or session is stored or logged.
 */
import type { SharePublicConfig } from "../email-share/config.js";
import type { ApprovalGuard, ShareTinyCloud, WalletApprovalFailure } from "../share/openkey-session.js";
import type { SavedCopyInput } from "../share/saved-copy.js";
import { withWalletApproval } from "../share/revoke-flight.js";

export type { SavedCopyInput } from "../share/saved-copy.js";

/** What the bar learns while a save runs. */
export interface SaveProgress {
  /** True while an OpenKey approval is open, false when it closes. */
  approval(open: boolean): void;
}

export interface SaveResult {
  /** `files-for-you/v1/<name>`. */
  readonly path: string;
}

/** Called by the bar's Save click, never before. */
export type SaveToTinyCloud = (copy: SavedCopyInput, progress: SaveProgress) => Promise<SaveResult>;

export const SAVE_APPROVAL_HINT = "Approve in the OpenKey window to save a copy";

export type SaveFailureReason = WalletApprovalFailure | "busy" | "failed";

export class SaveCopyError extends Error {
  readonly reason: SaveFailureReason;
  constructor(reason: SaveFailureReason, options?: { readonly cause?: unknown }) {
    super(`save-copy-${reason}`, options);
    this.name = "SaveCopyError";
    this.reason = reason;
  }
}

/** A person's own choice, an unanswered window or a second request is not a fault: a quiet note, not an alert. */
export function saveFailureMessage(error: unknown): { readonly message: string; readonly neutral: boolean } {
  const reason: SaveFailureReason = error instanceof SaveCopyError ? error.reason : "failed";
  switch (reason) {
    case "cancelled": return { message: "Sign-in cancelled. Nothing was saved.", neutral: true };
    case "timeout": return { message: "OpenKey didn't answer in time. Nothing was saved. Try again.", neutral: true };
    case "busy": return { message: "Another OpenKey request is waiting. Finish or cancel it, then try again.", neutral: true };
    case "wrong-account": return { message: "That approval came from a different account than the one signed in. Nothing was saved.", neutral: false };
    default: return { message: "We couldn't save a copy. Nothing was saved. Try again.", neutral: false };
  }
}

function guardReason(error: unknown): SaveFailureReason | undefined {
  if (!(error instanceof Error)) return undefined;
  if (error.message === "revoke-approval-abandoned") return "timeout";
  if (error.message === "revoke-another-approval") return "busy";
  return undefined;
}

/**
 * The function the viewer's Save action calls. Only `config` is captured here;
 * OpenKey and the Web SDK load on the click.
 */
export function createSaveToTinyCloud(config: SharePublicConfig): SaveToTinyCloud {
  return async (copy, progress) => {
    let client: ShareTinyCloud | undefined;
    let observed: SaveFailureReason | undefined;
    let takeFailure: ((tinycloud: ShareTinyCloud) => WalletApprovalFailure | undefined) | undefined;
    // One approval at a time, for at most the 60-second window; the bar shows the hint while it is open.
    const guardApproval: ApprovalGuard = async (wait) => {
      try {
        return await withWalletApproval({ setApproval: (open) => progress.approval(open) }, () => wait());
      } catch (error) {
        observed ??= guardReason(error);
        throw error;
      }
    };
    try {
      // Dynamic on purpose: the receiver must not load OpenKey or the account SDK (let alone call them) before the click, and the viewer bundle must not carry them.
      const session = await import("../share/openkey-session.js");
      const { writeSavedCopy } = await import("../share/saved-copy.js");
      takeFailure = session.takeWalletApprovalFailure;
      const { tinycloud, spaces } = await session.signInWithManifest({
        manifest: session.saveCopyManifest(),
        config,
        hostSpaces: [session.FILES_FOR_YOU_SPACE],
        guardApproval,
        onClient: (created) => { client = created; },
      });
      const spaceId = spaces[session.FILES_FOR_YOU_SPACE];
      if (spaceId === undefined) throw new Error("save-copy-space-not-hosted");
      return { path: (await writeSavedCopy(tinycloud.kvForSpace(spaceId), copy)).path };
    } catch (error) {
      if (error instanceof SaveCopyError) throw error;
      // The SDK folds a plain `{ code }` rejection from OpenKey into "[object Object]", so ask what the approval itself said.
      const reason = observed ?? (client === undefined ? undefined : takeFailure?.(client)) ?? "failed";
      throw new SaveCopyError(reason, { cause: error });
    }
  };
}
