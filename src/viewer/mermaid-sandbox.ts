/**
 * Parent side of the mermaid opaque-origin sandbox (viewer spec §3.2-3.3;
 * the stage-4 HARD PREREQUISITE render.ts's stage-3 TODO demanded).
 *
 * Creates a hidden iframe embedding MERMAID_SANDBOX_PATH with
 * `sandbox="allow-scripts"` and NOTHING else — no `allow-same-origin`, so
 * the frame runs in an OPAQUE origin: it cannot touch this document, its
 * DOM, cookies, storage, or make credentialed same-origin requests, and its
 * own CSP (see mermaid-frame.ts) forbids all network. The ONLY thing that
 * ever crosses into the frame is `{type:"render", id, nonce, source}` where
 * `source` is diagram text — never the fragment key, session key, envelope,
 * or any other document content. Replies are validated by `event.source`
 * (must be OUR frame's window), by `event.origin` (must be "null" — exactly
 * what an opaque-origin frame posts as; anything else is not our sandboxed
 * frame), by the per-frame CSPRNG handshake NONCE every message both ways
 * must carry (established at frame creation via the frame URL fragment),
 * and by shape; the returned SVG string is still UNTRUSTED — render.ts
 * sanitizes it again and bounds its node count before it touches the
 * document.
 *
 * `destroy()` tears the whole frame down — which, unlike stage 3's
 * Promise.race abandonment, actually KILLS a hung/hostile render (the
 * mermaid DoS answer the stage-3 TODO called out).
 */
import { MERMAID_SANDBOX_PATH, type MermaidRenderRequest } from "./mermaid-frame.js";

export const MERMAID_SANDBOX_IFRAME_CLASS = "mermaid-sandbox";

export interface MermaidSandbox {
  /** Render diagram source → serialized SVG (UNSANITIZED — caller sanitizes). */
  render(source: string): Promise<string>;
  /** Tear down the frame; rejects every pending render. */
  destroy(): void;
}

interface PendingRender {
  resolve(svg: string): void;
  reject(error: Error): void;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** Per-frame CSPRNG handshake nonce (128 bits, hex — see module header). */
function generateFrameNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function createMermaidSandbox(doc: Document): MermaidSandbox {
  const view = doc.defaultView;
  if (view === null) {
    throw new Error("mermaid sandbox requires a window-attached document");
  }

  // Handshake nonce, handed to the frame in the URL FRAGMENT (never sent to
  // the server, readable inside the opaque-origin document). Every message
  // both ways must carry it; a message without it is ignored.
  const nonce = generateFrameNonce();

  const iframe = doc.createElement("iframe");
  // ONLY allow-scripts: the frame's origin stays opaque. Never add
  // allow-same-origin here — that would collapse the entire boundary.
  iframe.setAttribute("sandbox", "allow-scripts");
  iframe.setAttribute("src", `${MERMAID_SANDBOX_PATH}#${nonce}`);
  iframe.className = MERMAID_SANDBOX_IFRAME_CLASS;
  iframe.setAttribute("aria-hidden", "true");
  iframe.setAttribute("tabindex", "-1");
  iframe.setAttribute("title", "mermaid rendering sandbox");
  // Offscreen, not display:none — mermaid needs layout to measure text.
  iframe.style.position = "absolute";
  iframe.style.left = "-10000px";
  iframe.style.top = "0";
  iframe.style.width = "800px";
  iframe.style.height = "600px";
  iframe.style.border = "0";
  (doc.body ?? doc.documentElement).append(iframe);

  let ready = false;
  let destroyed = false;
  let counter = 0;
  const queued: MermaidRenderRequest[] = [];
  const pending = new Map<string, PendingRender>();

  function post(request: MermaidRenderRequest): void {
    // targetOrigin must be "*": an opaque-origin frame matches no concrete
    // origin. Safe because the payload is diagram text only (see module doc).
    iframe.contentWindow?.postMessage(request, "*");
  }

  const onMessage = (event: MessageEvent): void => {
    // The load-bearing checks: only OUR frame's window may answer …
    if (destroyed || event.source !== iframe.contentWindow) return;
    // … and it must be posting from an OPAQUE origin (serialized "null") —
    // any concrete origin means it is not our sandboxed frame …
    if (event.origin !== "null") return;
    const data: unknown = event.data;
    if (!isRecord(data)) return;
    // … and every message must carry the per-frame handshake nonce.
    if (data["nonce"] !== nonce) return;
    if (data["type"] === "ready") {
      ready = true;
      const flush = queued.splice(0);
      for (const request of flush) post(request);
      return;
    }
    if (data["type"] !== "result" || typeof data["id"] !== "string") return;
    const job = pending.get(data["id"]);
    if (job === undefined) return;
    pending.delete(data["id"]);
    if (data["ok"] === true && typeof data["svg"] === "string") {
      job.resolve(data["svg"]);
    } else {
      job.reject(
        new Error(
          typeof data["error"] === "string"
            ? `mermaid sandbox render failed: ${data["error"]}`
            : "mermaid sandbox render failed",
        ),
      );
    }
  };
  view.addEventListener("message", onMessage);

  return {
    render(source: string): Promise<string> {
      if (destroyed) {
        return Promise.reject(new Error("mermaid sandbox is destroyed"));
      }
      const id = `diagram-${counter++}`;
      return new Promise<string>((resolve, reject) => {
        pending.set(id, { resolve, reject });
        const request: MermaidRenderRequest = { type: "render", id, nonce, source };
        if (ready) post(request);
        else queued.push(request);
      });
    },
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      view.removeEventListener("message", onMessage);
      iframe.remove();
      const error = new Error("mermaid sandbox destroyed");
      for (const job of pending.values()) job.reject(error);
      pending.clear();
      queued.length = 0;
    },
  };
}
