/**
 * The first-view notice for artifacts that run the sender's code (HTML and JSX).
 *
 * It lives in the VIEWER document, before the sandbox frame in the DOM, and
 * nothing the artifact does can reach it:
 * - the frame is an iframe, so `position: fixed`, full-viewport elements, z-index
 *   and `pointer-events` inside it only affect the frame's own box (artifact-notice.css
 *   also isolates and clips that box and stacks the notice above it);
 * - it is dismissed only by activating its own "Got it" button. No frame message is
 *   wired to dismissal, and no frame-triggered path moves focus onto that button: a
 *   frame can ask for the notice to be revealed (`restore-controls`, which the viewer
 *   rate-limits), and `reveal()` then shows it and, only if focus was in the frame
 *   (or nowhere), focuses the notice itself (tabindex -1, not actionable). Activating
 *   "Got it" therefore always takes the person's own Tab or click, so a keystroke
 *   meant for the artifact cannot dismiss it;
 * - it comes first in tab order, so keyboard users meet it before the frame.
 *
 * The claim is deliberately plain. CSP stops content and script requests, but
 * prerender (an HTTP GET with author-chosen query data), preconnect, navigation
 * attempts, dns-prefetch and WebRTC can still reach out, so a hostile author can
 * learn the viewer's IP, the time, and that the page was opened: see
 * docs/jsx-artifact-sharing.md.
 */
import "./artifact-tokens.css";
import "./artifact-notice.css";
import { hashedShareKey } from "./share-key-hash.js";

export const ARTIFACT_NOTICE_TEXT = "This page runs the sender's code. The sender can tell that you opened it.";
export const ARTIFACT_NOTICE_CLASS = "viewer-artifact-notice";
/** The detail under the headline: what CSP stops, and what a page can still do. Open on first view. */
export const ARTIFACT_NOTICE_DETAIL = "The viewer stops this page from loading anything or making requests. A page can still reach out another way: prerender sends an HTTP GET to an address the sender chooses (with data they choose, and that site's cookies), and preconnect, navigation attempts, DNS prefetch and WebRTC open connections. The sender can learn your IP address, the time, and that the page was opened.";

const STORAGE_PREFIX = "tc.artifact-notice.v1:";

export interface ArtifactNotice {
  readonly element: HTMLElement;
  /**
   * Shows the notice again. Never hides anything and never focuses an actionable
   * control: focus moves to the notice itself, and only when it was in the frame
   * or nowhere (so a frame cannot pull focus away from a control the person is using).
   */
  reveal(): void;
}

export interface ArtifactNoticeOptions {
  /** Dismissal is remembered per share, per browser, under a hashed key. Without one it lasts for this view. */
  readonly shareId?: string;
  readonly storage?: Pick<Storage, "getItem" | "setItem"> | undefined;
}

function browserStorage(view: Window | null): Pick<Storage, "getItem" | "setItem"> | undefined {
  try { return view?.localStorage; } catch { return undefined; }
}

export function createArtifactNotice(doc: Document, options: ArtifactNoticeOptions = {}): ArtifactNotice {
  const storage = options.storage ?? browserStorage(doc.defaultView);
  // The digest is async; until it resolves the notice is open, the safe direction.
  const key = options.shareId === undefined ? undefined : hashedShareKey(STORAGE_PREFIX, options.shareId).catch(() => undefined);

  const element = doc.createElement("div");
  element.className = ARTIFACT_NOTICE_CLASS;
  // Dark values of the tokens follow the OS under this attribute (artifact-tokens.css).
  element.dataset["theme"] = "system";
  element.setAttribute("role", "note");
  // Focusable by script only (never in tab order): where a frame-triggered reveal puts focus.
  element.tabIndex = -1;
  const text = doc.createElement("p");
  text.className = "viewer-artifact-notice-text";
  text.textContent = ARTIFACT_NOTICE_TEXT;
  const dismiss = doc.createElement("button");
  dismiss.type = "button";
  dismiss.className = "viewer-artifact-notice-dismiss";
  dismiss.textContent = "Got it";
  const recall = doc.createElement("button");
  recall.type = "button";
  recall.className = "viewer-artifact-notice-recall";
  recall.textContent = "About this page";
  recall.setAttribute("aria-expanded", "false");
  // The headline stays short; this is the plain account behind it, open on first view and
  // one click away afterwards. It sits in the viewer document, beside the headline.
  const more = doc.createElement("details");
  more.className = "viewer-artifact-notice-detail";
  // Open on first view on a screen with room for it. On a phone it is one tap away under the
  // headline, which already says the sender can tell the page was opened: the open detail alone
  // would be a third of the screen.
  more.open = doc.defaultView?.matchMedia?.("(min-width: 40.0625rem)").matches ?? true;
  const moreSummary = doc.createElement("summary");
  moreSummary.textContent = "What the sender can learn";
  const moreText = doc.createElement("p");
  moreText.textContent = ARTIFACT_NOTICE_DETAIL;
  more.append(moreSummary, moreText);
  element.append(text, dismiss, more, recall);

  const show = (open: boolean): void => {
    text.hidden = !open;
    dismiss.hidden = !open;
    more.hidden = !open;
    recall.hidden = open;
    recall.setAttribute("aria-expanded", String(open));
    element.dataset["state"] = open ? "open" : "collapsed";
  };
  show(true);
  let touched = false;
  void key?.then((resolved) => {
    try { if (!touched && resolved !== undefined && storage?.getItem(resolved) === "1") show(false); } catch { /* stays open */ }
  });

  // Dismissed only by a click or key activation on this button, in this document.
  // No frame message is wired to it.
  dismiss.addEventListener("click", () => {
    touched = true;
    show(false);
    recall.focus();
    void key?.then((resolved) => {
      try { if (resolved !== undefined) storage?.setItem(resolved, "1"); } catch { /* the notice stays reachable either way */ }
    });
  });
  recall.addEventListener("click", () => {
    touched = true;
    show(true);
    dismiss.focus();
  });

  return {
    element,
    reveal(): void {
      touched = true;
      show(true);
      const active = doc.activeElement;
      // Focus in the frame (or nowhere) is where the recall shortcut was typed: bring the
      // person to the notice. Never to a button, and never away from a chrome control.
      if (active === null || active === doc.body || active.tagName === "IFRAME") element.focus();
    },
  };
}
