/**
 * Parent side of the JSX sandbox (frame design and threat model: jsx-frame.ts).
 *
 * Creates the bridge iframe with `sandbox="allow-scripts"` and nothing else,
 * `allow=""`, `referrerpolicy="no-referrer"`, and a 128-bit nonce in the URL
 * fragment. The only thing that ever crosses into it is the render message
 * built by buildRenderRequest. Replies are accepted only when
 * `event.source === iframe.contentWindow`, `event.origin === "null"`, and
 * parseFrameMessage accepts them (v:1, nonce, type allowlist, own keys only);
 * everything else is dropped without a reply. Error text is kept as data: the
 * caller shows it with `textContent`.
 */
import {
  JSX_RESTORE_CONTROLS_INTERVAL_MS,
  JSX_SANDBOX_PATH,
  JSX_START_TIMEOUT_MS,
  JSX_MAX_SOURCE_CHARS,
  buildRenderRequest,
  parseCapabilityMessage,
  parseFrameMessage,
  type JsxCapabilityMessage,
  type JsxFramePhase,
  type JsxRenderRequest,
  type JsxTheme,
} from "./jsx-frame.js";
import { userContentUrl } from "./user-content-origin.js";

export const JSX_SANDBOX_IFRAME_CLASS = "viewer-artifact-frame";

/** A failure the frame reported, or "start" when it never reported anything. */
export class JsxRenderError extends Error {
  readonly phase: JsxFramePhase | "start" | "limit";
  readonly line: number | undefined;
  readonly moduleName: string | undefined;
  constructor(phase: JsxRenderError["phase"], message: string, line?: number, moduleName?: string) {
    super(message);
    this.name = "JsxRenderError";
    this.phase = phase;
    this.line = line;
    this.moduleName = moduleName;
  }
}

export interface JsxSandbox {
  readonly iframe: HTMLIFrameElement;
  /** Resolves when the artifact has committed its first render; rejects with JsxRenderError. */
  render(source: string, modules: Readonly<Record<string, string>>, theme?: JsxTheme): Promise<void>;
  destroy(): void;
}

/**
 * Extension point for viewer capabilities (a later slice): receives a `cap/*`
 * request from this sandbox's own frame after source, origin, version and nonce
 * checks. Without a handler (the default) every `cap/*` message is dropped
 * silently, exactly like any other unknown message.
 */
export type JsxCapabilityHandler = (request: JsxCapabilityMessage) => void;

export interface JsxSandboxOptions {
  readonly onCapability?: JsxCapabilityHandler;
  /** A failure after the first render settled (a runtime error, or navigation). */
  readonly onFailure?: (error: JsxRenderError) => void;
  /** The frame forwarded the Alt+Shift+C recall shortcut. */
  readonly onRestoreControls?: () => void;
  readonly mount?: HTMLElement;
  readonly className?: string;
  readonly title?: string;
  readonly startTimeoutMs?: number;
}

function nonce128(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function createJsxSandbox(doc: Document, options: JsxSandboxOptions = {}): JsxSandbox {
  const view = doc.defaultView;
  if (view === null) throw new Error("jsx sandbox requires a window");
  const nonce = nonce128();
  const iframe = doc.createElement("iframe");
  iframe.className = options.className ?? JSX_SANDBOX_IFRAME_CLASS;
  // ONLY allow-scripts: the frame's origin stays opaque. Never add allow-same-origin.
  iframe.setAttribute("sandbox", "allow-scripts");
  iframe.setAttribute("allow", "");
  iframe.setAttribute("src", userContentUrl(`${JSX_SANDBOX_PATH}#${nonce}`));
  iframe.setAttribute("title", options.title ?? "Shared JSX artifact");
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.hidden = true;
  (options.mount ?? doc.body ?? doc.documentElement).append(iframe);

  let bridgeReady = false;
  let destroyed = false;
  let rendered = false;
  let settled = false;
  let pending: { resolve: () => void; reject: (error: Error) => void; timeout: ReturnType<typeof setTimeout> } | undefined;
  let queued: JsxRenderRequest | undefined;
  let started = false;
  let lastRestore = 0;

  const post = (request: JsxRenderRequest): void => iframe.contentWindow?.postMessage(request, "*");
  const settle = (error?: JsxRenderError): void => {
    if (pending === undefined) return;
    clearTimeout(pending.timeout);
    const job = pending;
    pending = undefined;
    settled = true;
    if (error === undefined) job.resolve(); else job.reject(error);
  };

  const onMessage = (event: MessageEvent): void => {
    if (destroyed || event.source !== iframe.contentWindow || event.origin !== "null") return;
    // The one place the reserved capability namespace is decided.
    const capability = parseCapabilityMessage(event.data, nonce);
    if (capability !== undefined) { options.onCapability?.(capability); return; }
    const message = parseFrameMessage(event.data, nonce);
    if (message === undefined) return;
    switch (message.type) {
      case "bridge-ready":
        bridgeReady = true;
        if (queued !== undefined) { post(queued); queued = undefined; }
        return;
      case "ready":
        started = true;
        settle();
        return;
      case "restore-controls": {
        // A request from the frame, not a user action: at most one a second, and only once
        // its page has started. The handler decides what revealing means (artifact-notice.ts).
        const now = Date.now();
        if (!started || now - lastRestore < JSX_RESTORE_CONTROLS_INTERVAL_MS) return;
        lastRestore = now;
        options.onRestoreControls?.();
        return;
      }
      case "error": {
        const error = new JsxRenderError(message.phase, message.message, message.line, message.module);
        if (pending !== undefined) settle(error);
        else if (settled) options.onFailure?.(error);
        return;
      }
    }
  };
  view.addEventListener("message", onMessage);

  return {
    iframe,
    render(source, modules, theme = "system"): Promise<void> {
      if (destroyed) return Promise.reject(new Error("jsx sandbox is destroyed"));
      if (rendered) return Promise.reject(new Error("jsx sandbox renders once"));
      if (source.length > JSX_MAX_SOURCE_CHARS) return Promise.reject(new JsxRenderError("limit", "This file is too large to run here."));
      rendered = true;
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => settle(new JsxRenderError("start", "The artifact didn't start.")), options.startTimeoutMs ?? JSX_START_TIMEOUT_MS);
        pending = { resolve, reject, timeout };
        const request = buildRenderRequest(nonce, source, modules, theme);
        if (bridgeReady) post(request); else queued = request;
      });
    },
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      view.removeEventListener("message", onMessage);
      iframe.remove();
      if (pending !== undefined) {
        clearTimeout(pending.timeout);
        pending.reject(new Error("jsx sandbox destroyed"));
        pending = undefined;
      }
      queued = undefined;
    },
  };
}
