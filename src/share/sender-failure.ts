/** Sender-facing failure vocabulary. Raw error details never reach UI or telemetry. */
export type SenderFailureKind =
  | "session"
  | "content"
  | "account"
  | "source"
  | "rejected"
  | "permission"
  | "internal"
  | "save"
  | "delivery"
  | "storage"
  | "filename"
  | "folder"
  | "actions"
  | "upload"
  | "libraryCopy"
  | "libraryOpen"
  | "offline"
  | "emptyFile"
  | "fileTooLarge"
  | "recipientDomain"
  | "recipientEmail"
  | "recipientUnavailable"
  | "expiry"
  | "deliveryRecipient"
  | "deliveryDomain"
  | "plaintext"
  | "acknowledgment"
  | "linkOnlyActions"
  | "linkOnlyFolder"
  | "folderUnsupported"
  | "signIn"
  | "spaceNotReady";

export const SENDER_FAILURE: Record<SenderFailureKind, string> = {
  session: "Your session expired. Reload and sign in again.",
  content: "Pick the file you want to share.",
  account: "Your account isn't set up for sharing yet. Contact support.",
  source: "You don't have access to that file any more. Pick another one.",
  rejected: "We couldn't create that link. Try again, or pick a different file.",
  permission: "You can't grant more access than you have on that file.",
  internal: "Something went wrong creating this link. Nothing was shared. Try again.",
  save: "We couldn't save this link. Nothing was shared. Try again.",
  delivery: "Add the email address this should be sent to.",
  storage: "Your TinyCloud storage isn't ready yet. Reload and try again.",
  filename: "That file name can't be shared. Rename it and try again.",
  folder: "Pick the folder from your library to share it.",
  actions: "Choose at least one thing they can do.",
  upload: "Upload didn't go through. Nothing was shared — try again.",
  libraryCopy: "We couldn't copy that from your library. Try again.",
  libraryOpen: "We couldn't open that folder in your library. Try again.",
  offline: "Couldn't reach TinyCloud. Check your connection and try again.",
  emptyFile: "Choose a non-empty document.",
  fileTooLarge: "Choose a document no larger than 100 MB.",
  recipientDomain: "Enter a domain like example.com (use the xn-- form for international domains).",
  recipientEmail: "Enter one exact email address.",
  recipientUnavailable: "That recipient option isn't available yet. Choose one person or anyone with the link.",
  expiry: "Choose when the link should expire.",
  deliveryRecipient: "The delivery address must match the person you're sharing with.",
  deliveryDomain: "Every address to email must be at the shared domain exactly.",
  plaintext: "Shares must stay encrypted.",
  acknowledgment: "Tick the box to confirm you understand.",
  linkOnlyActions: "Link-only shares are view-only. Share with a specific person or domain to allow editing.",
  linkOnlyFolder: "To share multiple files or a folder, choose a specific person or company domain. Anyone-with-link shares support one file at a time.",
  folderUnsupported: "Folder sharing is temporarily unavailable. Choose one file to share.",
  signIn: "Sign-in could not be completed. Try again.",
  spaceNotReady: "Your TinyCloud storage isn't ready for this yet. This is a known problem we're fixing. Please try again later. If it keeps failing, contact support with code SPACE_NOT_READY.",
};

export function fail(kind: SenderFailureKind, detail: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error(detail), { kind, ...extra });
}

export function senderFailureKind(error: unknown): SenderFailureKind {
  const tagged = typeof error === "object" && error !== null ? (error as { readonly kind?: unknown }).kind : undefined;
  if (typeof tagged === "string" && Object.hasOwn(SENDER_FAILURE, tagged)) return tagged as SenderFailureKind;
  // Composer-model uses TypeError for local form validation, so unlike the
  // recipient lane we only treat recognizable transport TypeErrors as offline.
  if (typeof navigator === "object" && navigator !== null && navigator.onLine === false) return "offline";
  if (error instanceof TypeError && /failed to fetch|networkerror|load failed|network request failed/i.test(error.message)) return "offline";
  return "internal";
}

export function senderFailureMessage(error: unknown): string {
  const kind = senderFailureKind(error);
  // The one interpolation is the sender's own typed address, so they can find
  // it in a long pasted list.
  const subject = kind === "deliveryDomain" ? (error as { readonly subject?: unknown }).subject : undefined;
  if (typeof subject !== "string") return SENDER_FAILURE[kind];
  const shown = subject.length > 80 ? `${subject.slice(0, 79)}…` : subject;
  return `“${shown}” isn't an address at the shared domain. List only addresses at that domain, separated by commas or new lines.`;
}

/**
 * TC-335. Same classification, different default. The sign-in wall renders
 * whatever rejects between "Continue with OpenKey" and the first library
 * paint — `openkey-session.ts`'s own throws, the OpenKey SDK, and the entire
 * Web SDK bootstrap. Only the first of those is tagged, so the untagged
 * remainder must not land on `internal`, whose copy ("Nothing was shared")
 * describes a share that does not exist yet.
 */
export function authFailureMessage(error: unknown): string {
  const kind = senderFailureKind(error);
  return SENDER_FAILURE[kind === "internal" ? "signIn" : kind];
}

/**
 * HTTP status of a failed node call, or undefined. Reads only the numeric
 * status the SDKs attach (`status`, or the `HTTP 403` / `: 403 - ` text they
 * put in a message, also under `.error`); never returns any other text.
 */
export function httpStatusOf(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  if ("status" in error && typeof error.status === "number") return error.status;
  if ("error" in error) { const nested = httpStatusOf(error.error); if (nested !== undefined) return nested; }
  if ("message" in error && typeof error.message === "string") {
    const match = /\bHTTP (\d{3})\b|: (\d{3}) - /.exec(error.message);
    const code = match?.[1] ?? match?.[2];
    if (code !== undefined) return Number(code);
  }
  return undefined;
}

/**
 * TC-721. Why a Revoke failed, in plain words. Only a status code is ever
 * quoted: raw error text can carry a response body, which never reaches the page.
 */
export function revokeFailureMessage(error: unknown): string {
  const text = error instanceof Error ? error.message : "";
  // A cancelled approval is the sender's own choice, not a failure.
  if (text === "revoke-approval-cancelled") return "Revoke cancelled. The share is still active.";
  const reason = ((): string => {
    const status = httpStatusOf(error);
    if (text === "revoke-unbound-policy-root") return "This share was made with a different account or TinyCloud node than this session. Sign in with the account that created it.";
    if (text === "revoke-earlier-sign-in") return "This share was created in an earlier sign-in, and Share can't revoke it from this one yet. The share is still active.";
    if (text === "revoke-approval-timeout") return "The approval wasn't completed in time. The share is still active. Try again and approve in the OpenKey window.";
    if (text === "revoke-approval-expired") return "The approval took longer than 60 seconds. The share is still active. Try again and approve within a minute.";
    if (text === "revoke-approval-wrong-account") return "The approval came from a different account than the one signed in. The share is still active. Approve with the signed-in account.";
    if (text === "share-not-found") return "This saved share is no longer in your library. Reload the page.";
    if (text === "revoke-unsupported") return "This saved link has no revocation authority.";
    if (status === 401 || status === 403) return `TinyCloud refused the request (HTTP ${status}). The share is still active.`;
    if (status === 404) return "TinyCloud could not find this share (HTTP 404). Reload your library to check its status.";
    if (status === 409) return "TinyCloud reports a conflict (HTTP 409). Reload your library to check its status.";
    if (status !== undefined && (status === 429 || status >= 500)) return `TinyCloud is having trouble right now (HTTP ${status}). The share is still active. Try again in a moment.`;
    if (status !== undefined) return `TinyCloud rejected the request (HTTP ${status}). The share is still active.`;
    if (senderFailureKind(error) === "offline") return SENDER_FAILURE.offline;
    return "Something unexpected went wrong. The share is still active. Try again.";
  })();
  return `Could not revoke: ${reason}`;
}
