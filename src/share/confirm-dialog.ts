/**
 * In-page confirmation. Never `window.confirm`: a native dialog is dismissed
 * without a trace by automation, embedded webviews and a browser's "block
 * further dialogs", and the handler then returned before showing anything.
 *
 * Resolves true only on the explicit confirm press; Esc, Cancel and the
 * backdrop resolve false. `onConfirm` runs synchronously inside the press,
 * before the dialog closes, so the action starts from the click itself.
 */
export interface ConfirmDialogOptions {
  readonly title: string;
  /** What the action is about (a file name), shown under the title. */
  readonly subject?: string;
  readonly paragraphs: readonly string[];
  readonly confirmLabel: string;
  readonly danger?: boolean;
  /** Takes focus back when the dialog closes. */
  readonly opener: HTMLElement;
  readonly onConfirm: () => void;
}

export function confirmDialog(root: HTMLElement, options: ConfirmDialogOptions): Promise<boolean> {
  const doc = root.ownerDocument;
  const make = <K extends keyof HTMLElementTagNameMap>(tag: K, className: string, text?: string): HTMLElementTagNameMap[K] => {
    const element = doc.createElement(tag); element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  };
  return new Promise((resolve) => {
    const dialog = make("dialog", "sender-confirm-dialog");
    const titleId = `sender-confirm-title-${Math.random().toString(36).slice(2, 8)}`;
    dialog.setAttribute("aria-labelledby", titleId); dialog.setAttribute("role", "alertdialog");
    const heading = make("h2", "sender-confirm-title", options.title); heading.id = titleId;
    dialog.append(heading);
    if (options.subject !== undefined) dialog.append(make("p", "sender-confirm-subject", options.subject));
    for (const paragraph of options.paragraphs) dialog.append(make("p", "sender-status-detail", paragraph));
    const actions = make("div", "sender-confirm-actions");
    const cancel = make("button", "button button-secondary tc-button", "Cancel"); cancel.type = "button";
    const confirm = make("button", `button ${options.danger === true ? "button-danger" : "button-primary tc-button--primary"} tc-button sender-confirm-revoke`, options.confirmLabel); confirm.type = "button";
    actions.append(cancel, confirm); dialog.append(actions);
    const finish = (result: boolean): void => { if (result) options.onConfirm(); dialog.remove(); if (options.opener.isConnected) options.opener.focus(); resolve(result); };
    cancel.addEventListener("click", () => finish(false));
    confirm.addEventListener("click", () => finish(true));
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); finish(false); });
    dialog.addEventListener("click", (event) => { if (event.target === dialog) finish(false); });
    root.append(dialog);
    // Engines without <dialog> modal support still show it, open in place.
    if (typeof dialog.showModal === "function") dialog.showModal(); else dialog.setAttribute("open", "");
    cancel.focus();
  });
}
