import { canonicalize } from "@tinycloud/share-envelope";
import { focusViewerRoot } from "../viewer/focus.js";
import { OPEN_CONFIRM_BUTTON, OPEN_CONFIRM_DETAIL, OPEN_CONFIRM_TITLE } from "./strings.js";

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
 * The single place a verified courier invitation is shown. Its wording is not settled, so this prints
 * the verified fields as they are and adds no text of its own. Values are inserted as text only.
 */
export function renderCourierRecord(root: HTMLElement, plaintext: Readonly<Record<string, unknown>>): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message courier-record");
  const list = element(doc, "dl", "courier-record-fields");
  for (const [name, value] of Object.entries(plaintext)) {
    if (name === "issuer") continue;
    list.append(element(doc, "dt", "courier-record-name", name), element(doc, "dd", "courier-record-value", typeof value === "string" ? value : canonicalize(value)));
  }
  main.append(list);
  root.append(main);
  focusViewerRoot(root);
}
