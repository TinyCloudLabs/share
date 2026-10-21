import type { ShareReceivedContent } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";
import {
  renderRecipientClaim,
  renderRecipientClaimProgress,
  renderRecipientClaimRecovery,
  renderRecipientCodeRequest,
  renderRecipientCodeRequested,
  renderRecipientUnavailable,
  waitPhrase,
  type RecipientClaimRecovery,
  type RecipientClaimView,
} from "../email-share/view.js";
import { checkShareAvailability, type ShareAvailabilityTarget } from "../email-share/share-status.js";
import { createShareReceiverClient } from "../share/receiver.js";

/** Minimum time between two code emails the recipient can trigger. */
const RESEND_COOLDOWN_MS = 30_000;

/** Wait used when the issuer rate-limits without saying how long. */
const RATE_LIMIT_FALLBACK_MS = 60 * 60_000;

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
  const failure = credentialFailure(error);
  if (failure === undefined) return undefined;
  const { code } = failure;
  const details = detailsOf(failure.details);
  if (code === "CANCELED") return { title: "Verification canceled", detail: "Nothing was opened. Send a new code when you’re ready.", action: "Send a new code" };
  if (code === "REQUEST_EXPIRED") return { title: "That code expired", detail: "Codes work for a few minutes and only once. Send a new code to try again.", action: "Send a new code" };
  if (code === "VERIFICATION_FAILED" && details?.state === "proof_attempts_exhausted") return { title: "Too many incorrect codes", detail: "For your security, that code no longer works. Send a new code to try again.", action: "Send a new code" };
  const limited = rateLimitedIssuer(failure);
  if (limited !== undefined) {
    const retryAfterMs = issuerRetryAfterMs(limited);
    const when = retryAfterMs === undefined ? "about an hour" : waitPhrase(retryAfterMs);
    return { title: "Too many codes requested", detail: `Too many verification codes were requested recently. Nothing was opened. Try again in ${when}.`, action: "Try again" };
  }
  if (code === "OFFLINE" || code === "ISSUER_UNREADY") return { title: "Email verification is unavailable", detail: "Nothing was opened. Check your connection, then try again.", action: "Try again" };
  return undefined;
}

/** A CredentialError's code and details, or undefined for any other value. */
function credentialFailure(error: unknown): { code: unknown; details: unknown } | undefined {
  if (typeof error !== "object" || error === null || !("name" in error) || error.name !== "CredentialError") return undefined;
  return { code: "code" in error ? error.code : undefined, details: "details" in error ? error.details : undefined };
}

/** The `state` and `retryAfterMs` fields of a CredentialError's details, when present. */
function detailsOf(details: unknown): { state?: unknown; retryAfterMs?: unknown } | undefined {
  if (typeof details !== "object" || details === null) return undefined;
  return { state: "state" in details ? details.state : undefined, retryAfterMs: "retryAfterMs" in details ? details.retryAfterMs : undefined };
}

/** The issuer's rate-limit refusal, when that is what stopped the acquisition. */
function rateLimitedIssuer(failure: { code: unknown; details: unknown }): { retryAfterMs?: unknown } | undefined {
  const details = detailsOf(failure.details);
  return failure.code === "ISSUER_UNREADY" && details?.state === "rate_limited" ? details : undefined;
}

/** The Retry-After the issuer sent, in ms; undefined when it sent none. */
function issuerRetryAfterMs(details: { retryAfterMs?: unknown }): number | undefined {
  return typeof details.retryAfterMs === "number" && details.retryAfterMs > 0 ? details.retryAfterMs : undefined;
}

/** How long the recipient waits, from when a refusal arrived, before a new code may be requested. */
export function resendWaitMs(error: unknown): number {
  const failure = credentialFailure(error);
  const limited = failure === undefined ? undefined : rateLimitedIssuer(failure);
  if (limited === undefined) return RESEND_COOLDOWN_MS;
  return issuerRetryAfterMs(limited) ?? RATE_LIMIT_FALLBACK_MS;
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
  /** The received bytes and their descriptor (name, media type, digest), as the SDK verified them. */
  readonly onComplete: (content: ShareReceivedContent) => Promise<void>;
  /** Where to ask whether the share can still open. Omitted: no pre-check. */
  readonly availability?: ShareAvailabilityTarget | undefined;
}): Promise<void> {
  // A revoked or expired share can never open, so no key is made and no code is
  // requested for it. Any doubt (offline, unknown root) lets the normal flow run.
  const closed = async (): Promise<boolean> => {
    const state = input.availability === undefined ? "available" : await checkShareAvailability(input.availability);
    if (state === "available") return false;
    renderRecipientUnavailable(input.root, state);
    return true;
  };
  if (await closed()) return;
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
        renderRecipientClaimProgress(view, "Opening the file through the owner’s TinyCloud node…", event.mailbox);
      }
    },
  });
  // `receive` returns only after the invitation signature, the owner's Node
  // binding, and the recipient's policy commitment have been verified.
  const memoryOnly = received.identity.kind === "receiver" && received.identity.custody === "memory";
  view = renderRecipientClaim(input.root, { recipient: received.recipient, ...input.invitation, memoryOnly });
  const claim = view;
  const recipient = received.recipient;
  // An exact-email acquisition mails its code as soon as it starts, and link
  // scanners run page scripts, so it starts only from the recipient's click.
  // A domain invitation already waits for the recipient to type an address.
  // The share is checked again after the click: the page may have waited open.
  if (recipient.kind === "exactEmail") {
    await new Promise<void>((resolve) => renderRecipientCodeRequest(claim, recipient.email, resolve));
    if (await closed()) return;
  }
  for (;;) {
    mount.replaceChildren();
    if (recipient.kind === "exactEmail") renderRecipientCodeRequested(claim, recipient.email, mount);
    else claim.verify.replaceChildren(mount);
    try {
      await input.onComplete(await received.get());
      return;
    } catch (error) {
      const recovery = claimRecoveryFor(error);
      if (recovery === undefined) throw error;
      // Retrying starts a new acquisition, so OpenCredentials emails a new code.
      // The issuer's Retry-After clock starts after this request was sent, so the wait runs from arrival. Arrival is never earlier than the issuer's answer, so retry is never enabled early.
      const arrivedAt = Date.now();
      await new Promise<void>((resolve) => renderRecipientClaimRecovery(claim, recovery, resolve, arrivedAt + resendWaitMs(error)));
    }
    if (await closed()) return;
  }
}
