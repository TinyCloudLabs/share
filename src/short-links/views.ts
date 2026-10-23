import { focusViewerRoot } from "../viewer/focus.js";
import { COURIER_VIEW_LINE, OPEN_CONFIRM_BUTTON, OPEN_CONFIRM_DETAIL, OPEN_CONFIRM_TITLE } from "./strings.js";

function element<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/**
 * The click that starts a link: nothing is fetched or opened before it, so a scanner that follows
 * links and runs scripts does not use the link up. Resolves when the person presses the button.
 */
export function renderOpenConfirm(root: HTMLElement): Promise<void> {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message link-confirm");
  const button = element(doc, "button", "tc-button tc-button--primary link-confirm-action", OPEN_CONFIRM_BUTTON);
  button.type = "button";
  main.append(element(doc, "h1", "recipient-title", OPEN_CONFIRM_TITLE), element(doc, "p", "recipient-detail", OPEN_CONFIRM_DETAIL), button);
  root.append(main);
  focusViewerRoot(root);
  button.focus();
  return new Promise((resolve) => {
    button.addEventListener("click", () => {
      button.disabled = true;
      resolve();
    }, { once: true });
  });
}

/**
 * The single place a verified invitation is shown. Any signed issuer can make one, so nothing from
 * the invitation is rendered here: the page shows one fixed line.
 */
export function renderCourierRecord(root: HTMLElement): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message courier-record");
  main.append(element(doc, "p", "courier-record-line", COURIER_VIEW_LINE));
  root.append(main);
  focusViewerRoot(root);
}
