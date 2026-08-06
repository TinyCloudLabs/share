import { LinkOnlyShareError } from "./link-only.js";

/** Sender-facing failure vocabulary. Raw error details only reach console.debug. */
export type SenderFailureKind =
  | "session"
  | "content"
  | "format"
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
  | "signInService";

export const SENDER_FAILURE: Record<SenderFailureKind, string> = {
  session: "Your session expired. Reload and sign in again.",
  content: "Pick the file you want to share.",
  format: "This share can't be made self-contained. Use the short link instead.",
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
  recipientDomain: "Enter a valid ASCII email domain.",
  recipientEmail: "Enter one exact email address.",
  recipientUnavailable: "That recipient option isn't available yet. Choose one person or anyone with the link.",
  expiry: "Choose when the link should expire.",
  deliveryRecipient: "The delivery address must match the person you're sharing with.",
  deliveryDomain: "The delivery address must belong to the shared domain.",
  plaintext: "Shares must stay encrypted.",
  acknowledgment: "Tick the box to confirm you understand.",
  linkOnlyActions: "Link-only shares are view-only. Share with a specific person to allow editing.",
  linkOnlyFolder: "To share multiple files or a folder, choose a specific person or company domain. Anyone-with-link shares support one file at a time.",
  folderUnsupported: "Folder sharing is temporarily unavailable. Choose one file to share.",
  signIn: "Sign-in could not be completed. Try again.",
  signInService: "TinyCloud is temporarily unavailable. Try signing in again shortly.",
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
  // Link-only's authored messages are already swept human copy and are more
  // specific than its four-value kind enum. New messages must stay free of protocol vocabulary.
  if (error instanceof LinkOnlyShareError) return error.message;
  return SENDER_FAILURE[senderFailureKind(error)];
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
