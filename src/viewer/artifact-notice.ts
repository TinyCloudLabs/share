/**
 * The first-view notice for artifacts that run the sender's code (HTML and JSX).
 *
 * It lives in the VIEWER document, before the sandbox frame in the DOM, and
 * nothing the artifact does can reach it:
 * - the frame is an iframe, so `position: fixed`, full-viewport elements, z-index
 *   and `pointer-events` inside it only affect the frame's own box (artifact-notice.css
 *   also isolates and clips that box and stacks the notice above it);
 * - it is dismissed only by a click on its own button, never by a message
 *   from a frame; the one frame message that touches it, `restore-controls`, can
 *   only reveal it and move focus to it, never hide it;
 * - it comes first in tab order, so keyboard users meet it before the frame.
 *
 * The claim is deliberately plain. CSP stops every content request but not
 * connection-level signals (preconnect, navigation attempts, prerender,
 * dns-prefetch, WebRTC), so a hostile author can learn the viewer's IP and the
 * time of opening: see docs/jsx-artifact-sharing.md.
 */
import "./artifact-notice.css";

export const ARTIFACT_NOTICE_TEXT = "This page runs the sender's code. The sender can tell that you opened it.";
export const ARTIFACT_NOTICE_CLASS = "viewer-artifact-notice";

export interface ArtifactNotice {
  readonly element: HTMLElement;
  /** Shows the notice again and moves focus to it. Never hides anything. */
  reveal(): void;
}

export interface ArtifactNoticeOptions {
  /** Dismissal is remembered per share, per browser. Without one it lasts for this view. */
  readonly shareId?: string;
  readonly storage?: Pick<Storage, "getItem" | "setItem"> | undefined;
}

function storageKey(shareId: string): string {
  return `tc.artifact-notice.dismissed:${shareId}`;
}

function browserStorage(view: Window | null): Pick<Storage, "getItem" | "setItem"> | undefined {
  try { return view?.localStorage; } catch { return undefined; }
}

export function createArtifactNotice(doc: Document, options: ArtifactNoticeOptions = {}): ArtifactNotice {
  const storage = options.storage ?? browserStorage(doc.defaultView);
  const key = options.shareId === undefined ? undefined : storageKey(options.shareId);
  const remembered = (): boolean => {
    try { return key !== undefined && storage?.getItem(key) === "1"; } catch { return false; }
  };

  const element = doc.createElement("div");
  element.className = ARTIFACT_NOTICE_CLASS;
  element.setAttribute("role", "note");
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
  element.append(text, dismiss, recall);

  const show = (open: boolean): void => {
    text.hidden = !open;
    dismiss.hidden = !open;
    recall.hidden = open;
    recall.setAttribute("aria-expanded", String(open));
    element.dataset["state"] = open ? "open" : "collapsed";
  };
  show(!remembered());

  // Dismissed only by a click on this button, in this document. No frame message is
  // wired to it: the sandbox controller's `restore-controls` handler calls reveal().
  dismiss.addEventListener("click", () => {
    try { if (key !== undefined) storage?.setItem(key, "1"); } catch { /* the notice stays reachable either way */ }
    show(false);
    recall.focus();
  });
  recall.addEventListener("click", () => {
    show(true);
    dismiss.focus();
  });

  return {
    element,
    reveal(): void {
      show(true);
      dismiss.focus();
    },
  };
}
