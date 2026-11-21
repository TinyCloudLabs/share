import { confirmDialog } from "./confirm-dialog.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";

/**
 * TC-1583. The signed-in bar above every sender screen: who is signed in, and a
 * way out. Share saves its session on this device so a reload resumes it, so
 * what Sign out ends is that saved session and OpenKey's sign-in, which stops any
 * renewal lease OpenKey holds for it. Nothing the account owns changes: shares
 * stay active and nothing is revoked or deleted.
 */

export const SIGN_OUT_TITLE = "Sign out of Share?";
export const SIGN_OUT_BODY = "This signs you out of Share in this browser, and Share's access stops renewing. Your shares stay active and nothing is deleted.";
export const SIGN_OUT_NEXT = "To come back you'll sign in with OpenKey again.";
/** OpenKey confirmed that it ended its sign-in, and with it any renewal lease. */
export const SIGNED_OUT_NOTICE = "Signed out of Share in this browser. Share's access won't renew.";
/** OpenKey did not confirm that it ended its sign-in (so a renewal may still be on). */
export const SIGNED_OUT_PARTIAL_NOTICE = "You're signed out of Share in this browser, but OpenKey may still be renewing its access. To stop that, choose Stop renewal under Renewing permissions in OpenKey settings.";
/** OpenKey's widget answers a sign-out in about a second; this only bounds a window that never answers. */
export const OPENKEY_SIGN_OUT_WAIT_MS = 5_000;

/** What a sign-out ended besides Share's session. `share-only` is Courier's embedded session, which holds no OpenKey sign-in. */
export type SignOutOutcome = "openkey-ended" | "openkey-unconfirmed" | "share-only";

export interface SenderChromeOptions {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  /** The session is gone: show the sign-in screen with this notice. */
  readonly onSignedOut: (notice: string) => void;
}

/**
 * Ends this tab's session: the TinyCloud client's session key first (local, no
 * network the page waits on), then OpenKey's own sign-in through its confirm
 * window, in every tab: a tab restored from the saved session (or through a
 * renewal lease) signed nothing in with OpenKey, but OpenKey's sign-out is what
 * stops the leases recorded under its session. `openkey-ended` only when OpenKey
 * confirmed it (`revoked === true`); `openkey-unconfirmed` when it could not (no
 * window, no answer in time, or it said it could not verify). The local session
 * is cleared either way.
 */
export async function endSenderSession(
  options: Pick<SenderChromeOptions, "session" | "tinycloud">,
  { waitMs = OPENKEY_SIGN_OUT_WAIT_MS }: { readonly waitMs?: number } = {},
): Promise<Exclude<SignOutOutcome, "share-only">> {
  try { await options.tinycloud.signOut(); } catch { /* The SDK clears the saved session in its own `finally`, even when ending the session throws. */ }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const silent = new Promise<false>((resolve) => { timer = setTimeout(() => { options.session.openkey.disconnect(); resolve(false); }, waitMs); });
  try {
    const revoked = await Promise.race([options.session.openkey.signOut().then((answer) => answer.revoked === true), silent]);
    return revoked ? "openkey-ended" : "openkey-unconfirmed";
  } catch {
    return "openkey-unconfirmed";
  } finally {
    clearTimeout(timer);
  }
}

const SIGNED_OUT_NOTICES: Readonly<Record<Exclude<SignOutOutcome, "share-only">, string>> = {
  "openkey-ended": SIGNED_OUT_NOTICE,
  "openkey-unconfirmed": SIGNED_OUT_PARTIAL_NOTICE,
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
