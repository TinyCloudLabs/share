import type { ResolveResult } from "./resolve.js";
import { focusViewerRoot } from "./focus.js";

export interface RecipientDidAuthorizationViewOptions {
  readonly expectedDid: string;
  readonly resume: () => Promise<ResolveResult>;
}

function el<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** Explicit, user-started OpenKey/session-holder continuation for DID shares. */
export function mountRecipientDidAuthorization(root: HTMLElement, options: RecipientDidAuthorizationViewOptions): void {
  const doc = root.ownerDocument;
  const main = el(doc, "main", "recipient-shell recipient-message recipient-did-shell");
  const status = el(doc, "div", "recipient-status-live");
  status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  const button = el(doc, "button", "recipient-primary-action", "Continue with OpenKey") as HTMLButtonElement;
  button.type = "button";
  const detail = el(doc, "p", "recipient-detail", "This share is addressed to your OpenKey device. Continue to confirm the current session; nothing is opened until the signed challenge is accepted.");
  main.append(el(doc, "p", "recipient-brand", "TinyCloud sharing"), el(doc, "h1", "recipient-title", "Confirm this OpenKey device"), detail, status, button);
  root.replaceChildren(main);
  focusViewerRoot(root);
  button.addEventListener("click", () => {
    button.disabled = true;
    status.textContent = "Opening OpenKey…";
    void options.resume().then((result) => {
      if (result.state === "recipient-did-authorization-required") {
        button.disabled = false;
        status.textContent = "This OpenKey device is not the one named by the sender.";
        return;
      }
      status.textContent = "OpenKey confirmed. Opening the share…";
    }).catch((error) => {
      console.debug("tinycloud share: recipient device authorization failed", error);
      button.disabled = false;
      status.setAttribute("role", "alert");
      status.textContent = "We couldn't confirm this OpenKey device. Try again or ask the sender for a new link.";
    });
  });
}
