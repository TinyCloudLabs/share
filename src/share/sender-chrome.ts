import { confirmDialog } from "./confirm-dialog.js";
import { forgetOpenKeySignedInHere, openKeySignedInHere } from "./library-session.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";

/**
 * TC-1583. The signed-in bar above every sender screen: who is signed in, and a
 * way out. Share saves its session on this device so a reload resumes it, so
 * what Sign out ends is that saved session, and OpenKey's sign-in when this tab
 * holds one. Nothing the account owns changes: shares stay active and nothing
 * is revoked or deleted.
 */

export const SIGN_OUT_TITLE = "Sign out of Share?";
export const SIGN_OUT_BODY = "This signs you out of Share on this device. Your shares stay active; nothing is revoked or deleted.";
export const SIGN_OUT_NEXT = "To come back you'll sign in with OpenKey again.";
/** This tab held an OpenKey sign-in and OpenKey confirmed it ended it. */
export const SIGNED_OUT_NOTICE = "Signed out. Share's session and your OpenKey sign-in in this tab were cleared.";
/** This tab held no OpenKey sign-in (a resumed tab, usually): there was nothing of OpenKey's to end here. */
export const SIGNED_OUT_SHARE_ONLY_NOTICE = "Signed out of Share. To sign out of OpenKey too, use openkey.so.";
/** This tab held an OpenKey sign-in, and OpenKey did not confirm it ended it. */
export const SIGNED_OUT_PARTIAL_NOTICE = "Signed out of Share, and its session was cleared. OpenKey didn't confirm that it ended its own sign-in, so sign out there too if this is a shared device. Your shares are unchanged.";
/** OpenKey's widget answers a sign-out in about a second; this only bounds a window that never answers. */
export const OPENKEY_SIGN_OUT_WAIT_MS = 8_000;

/** What a sign-out ended besides Share's session. */
export type SignOutOutcome = "openkey-ended" | "openkey-unconfirmed" | "share-only";

export interface SenderChromeOptions {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  /** The session is gone: show the sign-in screen with this notice. */
  readonly onSignedOut: (notice: string) => void;
}

/**
 * Ends this tab's session: the TinyCloud client's session key first (local, no
 * network the page waits on), then, only when this tab holds an OpenKey sign-in
 * (`openKeySignedInHere`), OpenKey's own sign-in through its confirm window.
 * `openkey-ended` when OpenKey confirmed it; `openkey-unconfirmed` when it could
 * not (no window, no answer in time, or it said it could not verify);
 * `share-only` when the tab held none, so OpenKey is not asked. The local
 * session is cleared either way.
 */
export async function endSenderSession(options: Pick<SenderChromeOptions, "session" | "tinycloud">, waitMs: number = OPENKEY_SIGN_OUT_WAIT_MS): Promise<SignOutOutcome> {
  try { await options.tinycloud.signOut(); } catch { /* The SDK clears the saved session in its own `finally`, even when ending the session throws. */ }
  if (!openKeySignedInHere()) return "share-only";
  let timer: ReturnType<typeof setTimeout> | undefined;
  const silent = new Promise<false>((resolve) => { timer = setTimeout(() => { options.session.openkey.disconnect(); resolve(false); }, waitMs); });
  try {
    const revoked = await Promise.race([options.session.openkey.signOut().then((answer) => answer.revoked === true), silent]);
    if (!revoked) return "openkey-unconfirmed";
    forgetOpenKeySignedInHere();
    return "openkey-ended";
  } catch {
    return "openkey-unconfirmed";
  } finally {
    clearTimeout(timer);
  }
}

const SIGNED_OUT_NOTICES: Readonly<Record<SignOutOutcome, string>> = {
  "openkey-ended": SIGNED_OUT_NOTICE,
  "openkey-unconfirmed": SIGNED_OUT_PARTIAL_NOTICE,
  "share-only": SIGNED_OUT_SHARE_ONLY_NOTICE,
};

export function mountSenderChrome(parent: HTMLElement, options: SenderChromeOptions): HTMLElement {
  const doc = parent.ownerDocument;
  // A named landmark, so the account and Sign out are reachable from the landmark list and are not content outside every region.
  const bar = doc.createElement("nav"); bar.className = "sender-chrome tc-toolbar"; bar.setAttribute("aria-label", "Account");
  const address = options.session.address;
  const account = doc.createElement("span"); account.className = "sender-account tc-badge tc-badge--mono";
  account.textContent = address.length > 12 ? `${address.slice(0, 6)}…${address.slice(-4)}` : address;
  account.title = "Signed in with OpenKey";
  const signOut = doc.createElement("button"); signOut.type = "button";
  signOut.className = "button button-secondary tc-button tc-button--compact sender-signout"; signOut.textContent = "Sign out";
  const live = doc.createElement("p"); live.className = "sr-only"; live.setAttribute("role", "status"); live.setAttribute("aria-live", "polite");
  bar.append(account, signOut, live);
  signOut.addEventListener("click", () => {
    if (signOut.disabled) return;
    void confirmDialog(parent, {
      title: SIGN_OUT_TITLE, paragraphs: [SIGN_OUT_BODY, SIGN_OUT_NEXT], confirmLabel: "Sign out", opener: signOut,
      onConfirm: () => {
        signOut.disabled = true; signOut.textContent = "Signing out…"; live.textContent = "Signing out…";
        void endSenderSession(options).then((outcome) => options.onSignedOut(SIGNED_OUT_NOTICES[outcome]));
      },
    });
  });
  parent.prepend(bar);
  return bar;
}
