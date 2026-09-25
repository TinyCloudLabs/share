import type { SharePublicConfig } from "../email-share/config.js";
import {
  renderRecipientClaim,
  renderRecipientClaimProgress,
  renderRecipientClaimRecovery,
  type RecipientClaimRecovery,
  type RecipientClaimView,
} from "../email-share/view.js";
import { createShareReceiverClient } from "../share/receiver.js";

/** Signed invitation facts the host may show next to the mailbox check. */
export interface AccountlessInvitationSummary {
  readonly filename?: string;
  readonly expiresAt?: string;
  readonly actions?: readonly string[];
}

/**
 * Maps a stopped credential acquisition to a recovery the recipient can act
 * on. Anything else (a substituted or invalid invitation, a policy denial)
 * propagates to the caller's generic failure screen.
 */
export function claimRecoveryFor(error: unknown): RecipientClaimRecovery | undefined {
  if (typeof error !== "object" || error === null || (error as { name?: unknown }).name !== "CredentialError") return undefined;
  const { code, details } = error as { code?: unknown; details?: { state?: unknown } };
  if (code === "CANCELED") return { title: "Verification canceled", detail: "Nothing was opened. Send a new code when you’re ready.", action: "Send a new code" };
  if (code === "REQUEST_EXPIRED") return { title: "That code expired", detail: "Codes work for a few minutes and only once. Send a new code to try again.", action: "Send a new code" };
  if (code === "VERIFICATION_FAILED" && details?.state === "proof_attempts_exhausted") return { title: "Too many incorrect codes", detail: "For your security, that code no longer works. Send a new code to try again.", action: "Send a new code" };
  if (code === "OFFLINE" || code === "ISSUER_UNREADY") return { title: "Email verification is unavailable", detail: "Nothing was opened. Check your connection, then try again.", action: "Try again" };
  return undefined;
}

/**
 * The Share app owns presentation, while the web SDK owns the receiver
 * ceremony.  Keeping that seam here prevents the viewer from reimplementing
 * credential custody, policy admission, delegation import, or invocation.
 */
export async function receiveWithSdk(input: {
  readonly root: HTMLElement;
  readonly shareUrl: string;
  readonly config: SharePublicConfig;
  readonly invitation?: AccountlessInvitationSummary;
  readonly onComplete: (content: { readonly bytes: Uint8Array }) => Promise<void>;
}): Promise<void> {
  let view: RecipientClaimView | undefined;
  // The SDK mounts its credential view here only when `get` needs a
  // credential, by which time the claim screen below holds this element.
  const mount = input.root.ownerDocument.createElement("div");
  mount.className = "claim-credential";
  const tinycloud = await createShareReceiverClient(input.config);
  const received = await tinycloud.share.receive(input.shareUrl, {
    identity: "auto",
    interaction: { kind: "inline", mountTarget: mount },
    onProgress: (event) => {
      if (view !== undefined && event.state === "credential-acquisition" && event.status === "completed") {
        renderRecipientClaimProgress(view, "Opening the file through the owner’s TinyCloud node…");
      }
    },
  });
  // `receive` returns only after the invitation signature, the owner's Node
  // binding, and the recipient's policy commitment have been verified.
  view = renderRecipientClaim(input.root, { recipientEmail: received.recipient.email, ...input.invitation });
  const claim = view;
  for (;;) {
    mount.replaceChildren();
    claim.verify.replaceChildren(mount);
    try {
      await input.onComplete(await received.get());
      return;
    } catch (error) {
      const recovery = claimRecoveryFor(error);
      if (recovery === undefined) throw error;
      // Retrying starts a new acquisition, so OpenCredentials emails a new code.
      await new Promise<void>((resolve) => renderRecipientClaimRecovery(claim, recovery, resolve));
    }
  }
}
