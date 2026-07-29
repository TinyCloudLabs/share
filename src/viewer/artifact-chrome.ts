import { copyWithFallback } from "../share/link-only.js";

const STORAGE_PREFIX = "tinycloud:artifact-chrome:v1:";

export interface ArtifactChrome {
  destroy(): void;
}

export interface ArtifactChromeOptions {
  readonly shareId: string;
  readonly shareUrl?: string;
  readonly storage?: Storage;
  readonly navigator?: Pick<Navigator, "clipboard"> & { share?: (data: ShareData) => Promise<void> };
}

async function storageKey(shareId: string): Promise<string> {
  const bytes = new TextEncoder().encode(shareId);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `${STORAGE_PREFIX}${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function button(doc: Document, className: string, text: string, label?: string): HTMLButtonElement {
  const node = doc.createElement("button");
  node.type = "button";
  node.className = className;
  node.textContent = text;
  if (label !== undefined) node.setAttribute("aria-label", label);
  return node;
}

export async function mountArtifactChrome(doc: Document, options: ArtifactChromeOptions): Promise<ArtifactChrome> {
  const view = doc.defaultView;
  if (view === null) throw new Error("artifact chrome requires a window");
  let storage = options.storage;
  if (storage === undefined) {
    try { storage = view.localStorage; } catch { storage = undefined; }
  }
  const navigatorObject = options.navigator ?? view.navigator;
  const key = await storageKey(options.shareId);
  let permanentlyHidden = false;
  try { permanentlyHidden = storage?.getItem(key) === "hidden"; } catch { storage = undefined; }

  const root = doc.createElement("aside");
  root.className = "artifact-chrome";
  root.setAttribute("aria-label", "TinyCloud sharing controls");
  const panel = doc.createElement("div");
  panel.className = "artifact-chrome-panel";
  const message = doc.createElement("p");
  message.className = "artifact-chrome-label";
  message.textContent = "Shared with TinyCloud";
  const collapse = button(doc, "artifact-chrome-button", "Collapse");
  const reshare = button(doc, "artifact-chrome-button", "Share");
  reshare.disabled = options.shareUrl === undefined;
  const hide = button(doc, "artifact-chrome-button artifact-chrome-hide", "Hide permanently");
  const status = doc.createElement("span");
  status.className = "artifact-chrome-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const collapsed = button(doc, "artifact-chrome-cloud", "☁", "Open TinyCloud sharing controls");
  collapsed.hidden = true;
  collapse.setAttribute("aria-expanded", "true");
  collapsed.setAttribute("aria-expanded", "false");
  panel.append(message, collapse, reshare, hide);
  root.append(panel, collapsed, status);
  if (permanentlyHidden) root.hidden = true;
  doc.body.append(root);

  const announce = (value: string, alert = false): void => {
    status.setAttribute("role", alert ? "alert" : "status");
    status.textContent = value;
  };
  const expand = (): void => {
    panel.hidden = false;
    collapsed.hidden = true;
    root.dataset.state = "expanded";
    collapse.setAttribute("aria-expanded", "true");
    collapsed.setAttribute("aria-expanded", "false");
    announce("TinyCloud controls expanded.");
    collapse.focus();
  };
  const collapsePanel = (): void => {
    panel.hidden = true;
    collapsed.hidden = false;
    root.dataset.state = "collapsed";
    collapse.setAttribute("aria-expanded", "false");
    collapsed.setAttribute("aria-expanded", "false");
    announce("TinyCloud controls collapsed.");
    collapsed.focus();
  };
  collapse.addEventListener("click", collapsePanel);
  collapsed.addEventListener("click", expand);
  hide.addEventListener("click", () => {
    try { storage?.setItem(key, "hidden"); } catch { storage = undefined; }
    permanentlyHidden = true;
    root.hidden = true;
  });
  reshare.addEventListener("click", () => {
    const shareUrl = options.shareUrl;
    if (shareUrl === undefined) return;
    void (async () => {
      try {
        if (typeof navigatorObject.share === "function") {
          await navigatorObject.share({ title: "Shared with TinyCloud", url: shareUrl });
          announce("Share menu opened.");
          return;
        }
        await copyWithFallback(shareUrl);
        announce("Link copied.");
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") {
          announce("");
          return;
        }
        try {
          await copyWithFallback(shareUrl);
          announce("Link copied.");
        } catch {
          announce("Sharing failed. Allow clipboard access and try again.", true);
        }
      }
    })();
  });
  const onKeyDown = (event: KeyboardEvent): void => {
    if (!(event.altKey && event.shiftKey && event.key.toLowerCase() === "c")) return;
    event.preventDefault();
    if (permanentlyHidden) {
      permanentlyHidden = false;
      try { storage?.removeItem(key); } catch { storage = undefined; }
      root.hidden = false;
      panel.hidden = false;
      collapsed.hidden = true;
      root.dataset.state = "expanded";
      collapse.setAttribute("aria-expanded", "true");
      collapsed.setAttribute("aria-expanded", "false");
      announce("TinyCloud controls restored.");
      collapse.focus();
      return;
    }
    if (root.hidden) return;
    if (panel.hidden) expand(); else collapsePanel();
  };
  view.addEventListener("keydown", onKeyDown);

  return {
    destroy(): void {
      view.removeEventListener("keydown", onKeyDown);
      root.remove();
    },
  };
}
