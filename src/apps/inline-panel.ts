/**
 * The inline panel an install or a repair reports in, under the app's card.
 *
 * Why it is not the sheet: the OpenKey window is an overlay the SDK appends to `document.body` (fixed, z-index
 * 999999). A modal `<dialog>` is in the browser's top layer, which no z-index rises above, so a sheet that stays modal
 * while the window is open covers it: clicks land on the dialog and its backdrop. The sheet therefore closes when
 * Continue is pressed, and the progress, the approval hint, a Cancel and the result are shown here, in the page, which
 * is not inert while the window is up.
 *
 * The panel is a live region (`role=status`). It takes focus when it appears so the person (and a screen reader) is
 * where the progress is; Escape cancels while it is running.
 */

export type PanelTone = "info" | "success" | "neutral" | "danger";

export interface PanelAction {
  readonly label: string;
  readonly primary?: boolean;
  /** A link instead of a button (Open). */
  readonly href?: string;
  readonly disabled?: boolean;
  readonly onClick?: () => void;
}

function node<K extends keyof HTMLElementTagNameMap>(tag: K, className: string | null, children: (Node | string)[] = [], attributes: Record<string, string> = {}): HTMLElementTagNameMap[K] {
  const created = document.createElement(tag);
  if (className !== null) created.className = className;
  for (const [name, value] of Object.entries(attributes)) created.setAttribute(name, value);
  for (const child of children) created.append(typeof child === "string" ? document.createTextNode(child) : child);
  return created;
}

export class InlinePanel {
  readonly root: HTMLElement;
  private readonly status: HTMLElement;
  private readonly actions: HTMLElement;
  /** Called on Escape while focus is in the panel. Set by the owner while a run can be cancelled, cleared after. */
  onEscape: (() => void) | undefined;

  constructor(label: string) {
    this.status = node("div", "apps-install-status", [], { role: "status", "aria-live": "polite" });
    this.actions = node("div", "apps-install-actions", []);
    this.root = node("div", "apps-install-panel", [this.status, this.actions], { tabindex: "-1", "aria-label": label });
    this.root.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && this.onEscape !== undefined) { event.stopPropagation(); this.onEscape(); }
    });
  }

  /** Shows one line (plus any extra content) and the actions for it. */
  say(message: string, tone: PanelTone, options: { readonly extra?: readonly HTMLElement[]; readonly actions?: readonly PanelAction[] } = {}): void {
    const className = tone === "danger" ? "danger" : tone === "success" ? "success" : "info";
    this.status.replaceChildren(node("p", `tc-status tc-status--${className} apps-install-line`, [message], tone === "danger" ? { role: "alert" } : {}), ...(options.extra ?? []));
    this.actions.replaceChildren(...(options.actions ?? []).map((action): HTMLElement => {
      const cls = `tc-button${action.primary === true ? " tc-button--primary" : ""} apps-button`;
      if (action.href !== undefined) return node("a", cls, [action.label], { href: action.href });
      const button = node("button", cls, [action.label], { type: "button" });
      button.disabled = action.disabled === true;
      if (action.onClick !== undefined) button.addEventListener("click", action.onClick);
      return button;
    }));
  }

  /** Moves focus to the panel (and brings it into view). */
  focus(): void {
    this.root.focus({ preventScroll: true });
    this.root.scrollIntoView?.({ block: "nearest" });
  }

  remove(): void {
    this.root.remove();
  }
}
