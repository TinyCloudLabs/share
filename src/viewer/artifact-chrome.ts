import { hashedShareKey } from "./share-key-hash.js";

const STORAGE_PREFIX = "tinycloud:artifact-chrome:v1:";
const FEEDBACK_MS = 2_000;
const TOAST_MS = 4_000;
const TOAST_ALERT_MS = 8_000;

export interface ArtifactChrome {
  destroy(): void;
}

export type ArtifactChromeIcon = "link" | "copy" | "download" | "share";

export interface ArtifactChromeAction {
  readonly label: string;
  readonly icon: ArtifactChromeIcon;
  /** Extra class on the button (stable hook for tests and gates). */
  readonly className?: string;
  /** Shown instead of `label` for a moment after the action succeeds. */
  readonly doneLabel?: string;
  /** Shown (and announced) next to the bar when the action succeeds. */
  readonly doneMessage?: string;
  /** Shown (and announced as an alert) when the action rejects. */
  readonly failMessage?: string;
  /** Rejecting shows `failMessage`; resolving shows `doneMessage`. */
  readonly run?: () => Promise<void> | void;
  /** One line of help, as a tooltip and as the button's accessible description. */
  readonly hint?: string;
  /** A disabled action explains itself through this text. */
  readonly disabledReason?: string;
}

export interface ArtifactChromeOptions {
  /** Stable per share; only its SHA-256 is stored, to remember "hidden". */
  readonly shareId: string;
  readonly title: string;
  /** Provenance text, e.g. "Sender unverified". */
  readonly provenance?: string;
  /** Expiry badge; `datetime` is an ISO timestamp. */
  readonly expiry?: { readonly text: string; readonly datetime: string };
  readonly actions: readonly ArtifactChromeAction[];
  /** Element the bar (first child) and the recall pill are added to. Defaults to the body. */
  readonly mount?: HTMLElement;
  readonly storage?: Storage;
}

function storageKey(shareId: string): Promise<string> {
  return hashedShareKey(STORAGE_PREFIX, shareId);
}

const SVG_NS = "http://www.w3.org/2000/svg";
const ICON_PATHS: Readonly<Record<ArtifactChromeIcon, readonly string[]>> = {
  link: ["M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.43", "M14 11a5 5 0 0 0-7.07 0L4.1 13.83a5 5 0 0 0 7.07 7.07l1.33-1.33"],
  copy: ["M9 9h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1V10a1 1 0 0 1 1-1z", "M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"],
  download: ["M12 3v12", "m7 10 5 5 5-5", "M5 21h14"],
  share: ["M4 12v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7", "M16 6l-4-4-4 4", "M12 2v13"],
};

function icon(doc: Document, name: ArtifactChromeIcon): SVGSVGElement {
  const svg = doc.createElementNS(SVG_NS, "svg");
  for (const [key, value] of Object.entries({ class: "artifact-chrome-icon", viewBox: "0 0 24 24", width: "16", height: "16", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" })) svg.setAttribute(key, value);
  for (const d of ICON_PATHS[name]) {
    const path = doc.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

function brandMark(doc: Document): HTMLSpanElement {
  const mark = doc.createElement("span");
  mark.className = "brand-mark";
  mark.setAttribute("aria-hidden", "true");
  for (let index = 0; index < 9; index += 1) mark.append(doc.createElement("span"));
  return mark;
}

function el<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function actionButton(doc: Document, className: string, iconName: ArtifactChromeIcon | undefined, label: string): { readonly button: HTMLButtonElement; readonly text: HTMLSpanElement } {
  const button = el(doc, "button", className);
  button.type = "button";
  if (iconName !== undefined) button.append(icon(doc, iconName));
  const text = el(doc, "span", "artifact-chrome-label", label);
  button.append(text);
  return { button, text };
}

/**
 * The viewer bar: title, provenance, expiry and the share actions, hideable to
 * a persistent pill. Hidden state is remembered per share in this browser; the
 * pill and Alt+Shift+C always bring it back.
 */
export async function mountArtifactChrome(doc: Document, options: ArtifactChromeOptions): Promise<ArtifactChrome> {
  const view = doc.defaultView;
  if (view === null) throw new Error("artifact chrome requires a window");
  let storage = options.storage;
  if (storage === undefined) {
    try { storage = view.localStorage; } catch { storage = undefined; }
  }
  const key = await storageKey(options.shareId);
  let hidden = false;
  try { hidden = storage?.getItem(key) === "hidden"; } catch { storage = undefined; }
  const mount = options.mount ?? doc.body;

  const bar = el(doc, "div", "artifact-chrome tc-toolbar");
  bar.setAttribute("role", "region");
  bar.setAttribute("aria-label", "TinyCloud sharing controls");
  const identity = el(doc, "div", "artifact-chrome-identity");
  const title = el(doc, "span", "artifact-chrome-title", options.title);
  title.title = options.title;
  identity.append(brandMark(doc), title);
  const meta = el(doc, "div", "artifact-chrome-meta");
  if (options.provenance !== undefined) meta.append(el(doc, "span", "artifact-chrome-provenance", options.provenance));
  if (options.expiry !== undefined) {
    const expiry = el(doc, "time", "tc-badge artifact-chrome-expiry", `Expires ${options.expiry.text}`);
    expiry.dateTime = options.expiry.datetime;
    meta.append(expiry);
  }
  const actions = el(doc, "div", "artifact-chrome-actions");

  // Two live regions. The visually hidden one announces hiding and showing the
  // bar. The toast is VISIBLE and also announced: it is where a sighted user
  // learns that Copy worked or was refused (labels are icon-only on narrow screens).
  const status = el(doc, "span", "artifact-chrome-status");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const toast = el(doc, "p", "artifact-chrome-toast");
  toast.setAttribute("role", "status");
  toast.setAttribute("aria-live", "polite");
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  const say = (value: string, alert = false): void => {
    if (toastTimer !== undefined) clearTimeout(toastTimer);
    toast.setAttribute("role", alert ? "alert" : "status");
    toast.dataset["tone"] = alert ? "danger" : "info";
    toast.textContent = value;
    toastTimer = setTimeout(() => { toast.textContent = ""; toastTimer = undefined; }, alert ? TOAST_ALERT_MS : TOAST_MS);
  };

  const timers = new Set<ReturnType<typeof setTimeout>>();
  const buttons: HTMLButtonElement[] = [];
  for (const action of options.actions) {
    const { button, text } = actionButton(doc, `tc-button tc-button--compact artifact-chrome-button${action.className === undefined ? "" : ` ${action.className}`}`, action.icon, action.label);
    if (action.disabledReason !== undefined) {
      const reason = el(doc, "span", "artifact-chrome-reason", action.disabledReason);
      reason.id = `artifact-chrome-reason-${buttons.length}`;
      button.disabled = true;
      button.setAttribute("aria-describedby", reason.id);
      button.title = action.disabledReason;
      actions.append(button, reason);
      buttons.push(button);
      continue;
    }
    if (action.hint !== undefined) {
      const hint = el(doc, "span", "artifact-chrome-reason", action.hint);
      hint.id = `artifact-chrome-hint-${buttons.length}`;
      button.setAttribute("aria-describedby", hint.id);
      button.title = action.hint;
      actions.append(hint);
    }
    let attempt = 0;
    button.addEventListener("click", () => {
      const current = ++attempt;
      void (async () => {
        try {
          await action.run?.();
          if (current !== attempt) return;
          if (action.doneLabel !== undefined) {
            text.textContent = action.doneLabel;
            const timer = setTimeout(() => { timers.delete(timer); if (current === attempt) text.textContent = action.label; }, FEEDBACK_MS);
            timers.add(timer);
          }
          if (action.doneMessage !== undefined) say(action.doneMessage);
        } catch {
          if (current === attempt) say(action.failMessage ?? `${action.label} failed. Try again.`, true);
        }
      })();
    });
    actions.append(button);
    buttons.push(button);
  }
  const hide = actionButton(doc, "tc-button tc-button--compact artifact-chrome-button artifact-chrome-hide", undefined, "Hide");
  hide.button.setAttribute("aria-keyshortcuts", "Alt+Shift+C");
  actions.append(hide.button);

  bar.append(identity, meta, actions);

  const pill = el(doc, "button", "tc-button artifact-chrome-pill");
  pill.type = "button";
  pill.append(brandMark(doc), el(doc, "span", "artifact-chrome-pill-label", "TinyCloud"));
  pill.setAttribute("aria-label", "Show TinyCloud controls");
  pill.setAttribute("aria-keyshortcuts", "Alt+Shift+C");

  const render = (): void => {
    bar.hidden = hidden;
    pill.hidden = !hidden;
    mount.dataset["chrome"] = hidden ? "hidden" : "shown";
  };
  render();
  // The pill takes the bar's place in reading and Tab order.
  mount.prepend(bar, pill);
  mount.append(toast, status);

  const setHidden = (value: boolean, focus: boolean): void => {
    hidden = value;
    try { if (hidden) storage?.setItem(key, "hidden"); else storage?.removeItem(key); } catch { storage = undefined; }
    render();
    status.textContent = hidden ? "TinyCloud controls hidden. Press Alt+Shift+C to show them." : "TinyCloud controls shown.";
    if (focus) (hidden ? pill : (buttons[0] ?? hide.button)).focus();
  };
  hide.button.addEventListener("click", () => setHidden(true, true));
  pill.addEventListener("click", () => setHidden(false, true));

  const onKeyDown = (event: KeyboardEvent): void => {
    if (!(event.altKey && event.shiftKey && event.key.toLowerCase() === "c")) return;
    event.preventDefault();
    setHidden(!hidden, true);
  };
  view.addEventListener("keydown", onKeyDown);

  return {
    destroy(): void {
      view.removeEventListener("keydown", onKeyDown);
      for (const timer of timers) clearTimeout(timer);
      if (toastTimer !== undefined) clearTimeout(toastTimer);
      bar.remove();
      pill.remove();
      toast.remove();
      status.remove();
      delete mount.dataset["chrome"];
    },
  };
}
