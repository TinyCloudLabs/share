import type { PreparedArtifact } from "../artifact/bundle.js";
import { ARTIFACT_SANDBOX_PATH, type ArtifactRenderRequest } from "./artifact-frame.js";

export const ARTIFACT_SANDBOX_IFRAME_CLASS = "viewer-artifact-frame";

interface PendingRender {
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly timeout: ReturnType<typeof setTimeout>;
}

export interface ArtifactSandbox {
  readonly iframe: HTMLIFrameElement;
  render(artifact: PreparedArtifact): Promise<void>;
  destroy(): void;
}

export interface ArtifactSandboxOptions {
  readonly onFailure?: () => void;
}

function nonce128(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function createArtifactSandbox(doc: Document, options: ArtifactSandboxOptions = {}): ArtifactSandbox {
  const view = doc.defaultView;
  if (view === null) throw new Error("artifact sandbox requires a window");
  const nonce = nonce128();
  const iframe = doc.createElement("iframe");
  iframe.className = ARTIFACT_SANDBOX_IFRAME_CLASS;
  iframe.setAttribute("sandbox", "allow-scripts");
  iframe.setAttribute("src", `${ARTIFACT_SANDBOX_PATH}#${nonce}`);
  iframe.setAttribute("title", "Shared HTML artifact");
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.hidden = true;
  (doc.body ?? doc.documentElement).append(iframe);

  let ready = false;
  let destroyed = false;
  let counter = 0;
  const queue: ArtifactRenderRequest[] = [];
  const pending = new Map<string, PendingRender>();
  const post = (request: ArtifactRenderRequest): void => iframe.contentWindow?.postMessage(request, "*");
  const onMessage = (event: MessageEvent): void => {
    if (destroyed || event.source !== iframe.contentWindow || event.origin !== "null" || !isRecord(event.data) || event.data["nonce"] !== nonce) return;
    if (event.data["type"] === "ready") {
      ready = true;
      for (const request of queue.splice(0)) post(request);
      return;
    }
    if (event.data["type"] !== "result" || typeof event.data["id"] !== "string") return;
    const job = pending.get(event.data["id"]);
    if (job === undefined) {
      if (event.data["ok"] !== true) options.onFailure?.();
      return;
    }
    pending.delete(event.data["id"]);
    clearTimeout(job.timeout);
    if (event.data["ok"] === true) job.resolve();
    else job.reject(new Error("artifact sandbox render failed"));
  };
  view.addEventListener("message", onMessage);

  return {
    iframe,
    render(artifact): Promise<void> {
      if (destroyed) return Promise.reject(new Error("artifact sandbox is destroyed"));
      const id = `artifact-${counter++}`;
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error("artifact sandbox render timed out"));
        }, 15_000);
        pending.set(id, { resolve, reject, timeout });
        const request: ArtifactRenderRequest = { type: "render", id, nonce, entry: artifact.entry, pages: artifact.pages };
        if (ready) post(request); else queue.push(request);
      });
    },
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      view.removeEventListener("message", onMessage);
      iframe.remove();
      for (const job of pending.values()) {
        clearTimeout(job.timeout);
        job.reject(new Error("artifact sandbox destroyed"));
      }
      pending.clear();
      queue.length = 0;
    },
  };
}
