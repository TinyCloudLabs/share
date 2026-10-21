/**
 * TC-1583. The hint shown while the page waits on an OpenKey approval.
 *
 * It says what to do ("Approve in the OpenKey window…"), offers Cancel (which
 * closes the open OpenKey window; trying the action again opens a new one), and
 * says what is going on if the window is slow or never answers. It lives only
 * while the approval is open: `dispose()` removes it, and every caller disposes
 * on every way out (approved, refused, cancelled, timed out, screen replaced),
 * so it cannot sit next to a "Share revoked." or "Your link is ready" line.
 */
import { OPENKEY_ORIGIN } from "./openkey-origin.js";

/** After this long without an answer the hint adds where the window may be. */
export const APPROVAL_SLOW_AFTER_MS = 15_000;
/** After this long the hint says the wait has gone on too long. Matches the wallet request's own 60 s life. */
export const APPROVAL_TIMEOUT_AFTER_MS = 60_000;

export const APPROVAL_SLOW_COPY = "Can't see the OpenKey window? It may be behind this tab or blocked as a pop-up. Cancel and try again.";

/**
 * Calls `onModal` when OpenKey's in-page window reports ready. The SDK keeps that window in a closed shadow root, so the
 * page cannot read whether it is open. The window's frame posts `openkey:ready` to this window from the exact OpenKey
 * origin. A top-level popup (the SDK's CSP fallback) posts the same message from a window that is its own `top`, so it
 * does not count: the help line still shows for a popup that may be behind this tab. Returns the stop function.
 */
export function watchOpenKeyModal(view: Window, onModal: () => void): () => void {
  const onMessage = (event: MessageEvent): void => {
    if (event.origin !== OPENKEY_ORIGIN || event.data?.type !== "openkey:ready") return;
    const source = event.source as WindowProxy | null;
    if (source === null || source.top === source) return;
    onModal();
  };
  view.addEventListener("message", onMessage);
  return () => view.removeEventListener("message", onMessage);
}

export interface ApprovalHintOptions {
  /** The first line, e.g. "Approve in the OpenKey window to revoke". */
  readonly text: string;
  /** Class of the first line (the screens style and test it by name). */
  readonly lineClass: string;
  /** Said when the wait has gone on too long. */
  readonly timeoutCopy: string;
  /** Closes the open OpenKey window. Without it the hint has no Cancel. */
  readonly onCancel?: () => void;
  readonly slowAfterMs?: number;
  readonly timeoutAfterMs?: number;
}

export interface ApprovalHint {
  readonly element: HTMLElement;
  dispose(): void;
}

export function showApprovalHint(parent: HTMLElement, options: ApprovalHintOptions): ApprovalHint {
  const doc = parent.ownerDocument;
  const view = doc.defaultView ?? window;
  const element = doc.createElement("div"); element.className = "sender-approval";
  const line = doc.createElement("p"); line.className = options.lineClass; line.textContent = options.text;
  const more = doc.createElement("p"); more.className = "sender-approval-more"; more.hidden = true;
  element.append(line, more);
  let cancel: HTMLButtonElement | undefined;
  if (options.onCancel !== undefined) {
    const onCancel = options.onCancel;
    cancel = doc.createElement("button"); cancel.type = "button";
    cancel.className = "button button-secondary tc-button tc-button--compact sender-approval-cancel"; cancel.textContent = "Cancel";
    cancel.addEventListener("click", () => { if (cancel === undefined) return; cancel.disabled = true; cancel.textContent = "Cancelling…"; onCancel(); });
    element.append(cancel);
  }
  // While the OpenKey window is up the wait is working: the help line stays away, and comes off if the window arrives late.
  let modalShown = false;
  const stopModalWatch = watchOpenKeyModal(view, () => {
    modalShown = true;
    if (more.textContent === APPROVAL_SLOW_COPY) { more.textContent = ""; more.hidden = true; }
  });
  const slow = view.setTimeout(() => { if (!modalShown) { more.textContent = APPROVAL_SLOW_COPY; more.hidden = false; } }, options.slowAfterMs ?? APPROVAL_SLOW_AFTER_MS);
  const timeout = view.setTimeout(() => { more.textContent = options.timeoutCopy; more.hidden = false; }, options.timeoutAfterMs ?? APPROVAL_TIMEOUT_AFTER_MS);
  parent.append(element);
  return {
    element,
    dispose: () => { view.clearTimeout(slow); view.clearTimeout(timeout); stopModalWatch(); element.remove(); },
  };
}
