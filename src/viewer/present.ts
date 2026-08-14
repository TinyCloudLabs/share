/**
 * Present a resolve result: state chrome (ui.ts) + — for a verified share
 * that carried content — the decrypted file text through the full hostile
 * content pipeline (render.ts, mermaid behind the opaque-origin sandbox).
 * ONE glue function shared by the real entry (main.ts) and the e2e suite,
 * so the tested path IS the shipped path.
 */
import {
  ContentTooLargeError,
  renderMarkdownInto,
  type RenderMarkdownOptions,
} from "./render.js";
import type { ResolveResult } from "./resolve.js";
import { renderViewerState, type ViewerStateOptions } from "./ui.js";
import { renderSafeContent } from "./content.js";
import { copyWithFallback } from "../share/link-only.js";

function downloadName(result: Extract<ResolveResult, { readonly state: "ok" }>): string {
  const metadata = (result.envelope as unknown as { readonly metadata?: { readonly filename?: unknown } }).metadata;
  if (typeof metadata?.filename === "string" && metadata.filename.length > 0) return safeFilename(metadata.filename);
  const candidate =
    result.envelope.display.filename ??
    (result.envelope.version === 1 ? result.envelope.target.resource.path : result.envelope.resource.path).split("/").at(-1) ??
    "shared-document.txt";
  return safeFilename(candidate);
}

function safeFilename(candidate: string): string {
  const safe = candidate
    .split(/[\\/]/)
    .at(-1)
    ?.replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  return safe === undefined || safe.length === 0 ? "shared-document.txt" : safe;
}

function signedMediaType(result: Extract<ResolveResult, { readonly state: "ok" }>): string {
  const metadata = (result.envelope as unknown as { readonly metadata?: { readonly mediaType?: unknown } }).metadata;
  return typeof metadata?.mediaType === "string" && metadata.mediaType.length > 0 ? metadata.mediaType : result.content === undefined ? "application/octet-stream" : "text/plain;charset=utf-8";
}

function appendDownloadAction(
  root: HTMLElement,
  result: Extract<ResolveResult, { readonly state: "ok" }>,
): void {
  if (result.content === undefined && result.contentBytes === undefined) return;
  const footer = root.querySelector<HTMLElement>(".viewer-footer");
  const hint = footer?.querySelector<HTMLElement>(".viewer-agent-hint");
  if (footer === null || footer === undefined || hint === null || hint === undefined) return;
  const button = root.ownerDocument.createElement("button");
  button.type = "button";
  button.className = "viewer-download";
  button.textContent = "Download original";
  button.addEventListener("click", () => {
    const blobBytes = result.contentBytes ?? new TextEncoder().encode(result.content ?? "");
    const blob = new Blob([new Uint8Array(blobBytes).buffer as ArrayBuffer], {
      type: signedMediaType(result),
    });
    const href = URL.createObjectURL(blob);
    const link = root.ownerDocument.createElement("a");
    link.href = href;
    link.download = downloadName(result);
    link.hidden = true;
    root.ownerDocument.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
  });
  footer.insertBefore(button, hint);
}

function appendMarkdownCopyAction(root: HTMLElement, container: HTMLElement, source: string): void {
  const doc = root.ownerDocument;
  const tools = doc.createElement("div");
  tools.className = "viewer-document-tools";
  const button = doc.createElement("button");
  button.type = "button";
  button.className = "viewer-copy-text";
  button.textContent = "Copy text";
  const status = doc.createElement("span");
  status.className = "viewer-copy-text-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  let statusTimer: ReturnType<typeof setTimeout> | undefined;
  button.addEventListener("click", () => {
    if (statusTimer !== undefined) {
      clearTimeout(statusTimer);
      statusTimer = undefined;
    }
    void copyWithFallback(source).then(() => {
      button.textContent = "Copy text";
      status.setAttribute("role", "status");
      status.textContent = "Markdown copied.";
      statusTimer = setTimeout(() => {
        status.textContent = "";
        statusTimer = undefined;
      }, 3_000);
    }).catch(() => {
      button.textContent = "Copy text";
      status.setAttribute("role", "alert");
      status.textContent = "Copy failed. Allow clipboard access and try again.";
    });
  });
  tools.append(button, status);
  container.before(tools);
}

function decodeMarkdown(bytes: Uint8Array): string | undefined {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return undefined; }
}

/**
 * Add the explicit post-render account import action. The callback is the only
 * place allowed to start OpenKey; callers therefore cannot accidentally put
 * account sign-in in front of the receiver ceremony.
 */
export function appendSaveToTinyCloudAction(
  root: HTMLElement,
  save: () => Promise<void>,
): void {
  const footer = root.querySelector<HTMLElement>(".viewer-footer");
  const hint = footer?.querySelector<HTMLElement>(".viewer-agent-hint");
  if (footer === null || footer === undefined || hint === null || hint === undefined
    || footer.querySelector(".viewer-save-to-tinycloud") !== null) return;
  const doc = root.ownerDocument;
  const button = doc.createElement("button");
  button.type = "button";
  button.className = "viewer-save-to-tinycloud";
  button.textContent = "Save a private copy";
  const status = doc.createElement("span");
  status.className = "viewer-save-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  button.addEventListener("click", () => {
    button.disabled = true;
    status.setAttribute("role", "status");
    status.textContent = "Opening OpenKey…";
    void save().then(() => {
      button.textContent = "Saved to Files for you";
      status.textContent = "A private copy is now in your TinyCloud.";
    }).catch(() => {
      button.disabled = false;
      status.setAttribute("role", "alert");
      status.textContent = "We couldn't save a copy. Try again.";
    });
  });
  footer.insertBefore(button, hint);
  footer.insertBefore(status, hint);
}

export interface PresentShareOptions extends RenderMarkdownOptions, ViewerStateOptions {
  /** Offered only after verified bytes have rendered successfully. */
  readonly saveToTinyCloud?: () => Promise<void>;
}

/**
 * Returns the content container when the share verified ("ok"), null for
 * every other state (fail closed: no content sink exists unless every
 * verification step passed — ui.ts invariant).
 */
export async function presentShare(
  root: HTMLElement,
  result: ResolveResult,
  options: PresentShareOptions = {},
): Promise<HTMLElement | null> {
  const container = renderViewerState(root, result, options);
  if (container === null || result.state !== "ok" || (result.content === undefined && result.contentBytes === undefined)) {
    return container;
  }
  // display.mode is a NARROWING-ONLY hint (viewer spec §1): "source" may
  // downgrade the presentation; anything else renders as a document.
  const mode = result.envelope.display.mode === "source" ? "source" : "document";
  try {
    let markdownSource: string | undefined;
    if (result.contentBytes !== undefined) {
      const kind = await renderSafeContent(container, result.contentBytes, {
        mediaType: signedMediaType(result),
        filename: downloadName(result),
        byteLength: result.contentBytes.byteLength,
      }, options);
      if (kind === "markdown") markdownSource = decodeMarkdown(result.contentBytes);
    } else {
      markdownSource = result.content as string;
      await renderMarkdownInto(container, markdownSource, mode, options);
    }
    if (markdownSource !== undefined) appendMarkdownCopyAction(root, container, markdownSource);
    appendDownloadAction(root, result);
    if (options.saveToTinyCloud !== undefined) {
      appendSaveToTinyCloudAction(root, options.saveToTinyCloud);
    }
  } catch (error) {
    // renderMarkdownInto throws before touching the DOM (oversize source,
    // node-count breach); leave a message, never partial content. Fail closed.
    container.replaceChildren();
    const notice = root.ownerDocument.createElement("p");
    notice.className = "viewer-render-error";
    notice.textContent =
      error instanceof ContentTooLargeError
        ? "This document is too large to show here. Download it to read it."
        : "We couldn't display this document. Download it to open it.";
    container.append(notice);
  }
  return container;
}
