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
import { renderViewerState } from "./ui.js";
import { renderSafeContent } from "./content.js";

function downloadName(result: Extract<ResolveResult, { readonly state: "ok" }>): string {
  const metadata = (result.envelope as unknown as { readonly metadata?: { readonly filename?: unknown } }).metadata;
  if (typeof metadata?.filename === "string" && metadata.filename.length > 0) return safeFilename(metadata.filename);
  const candidate =
    result.envelope.display.filename ??
    result.envelope.target.resource.path.split("/").at(-1) ??
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

/**
 * Returns the content container when the share verified ("ok"), null for
 * every other state (fail closed: no content sink exists unless every
 * verification step passed — ui.ts invariant).
 */
export async function presentShare(
  root: HTMLElement,
  result: ResolveResult,
  options: RenderMarkdownOptions = {},
): Promise<HTMLElement | null> {
  const container = renderViewerState(root, result);
  if (container === null || result.state !== "ok" || (result.content === undefined && result.contentBytes === undefined)) {
    return container;
  }
  // display.mode is a NARROWING-ONLY hint (viewer spec §1): "source" may
  // downgrade the presentation; anything else renders as a document.
  const mode = result.envelope.display.mode === "source" ? "source" : "document";
  try {
    if (result.contentBytes !== undefined) {
      await renderSafeContent(container, result.contentBytes, {
        mediaType: signedMediaType(result),
        filename: downloadName(result),
        byteLength: result.contentBytes.byteLength,
      }, options);
    } else {
      await renderMarkdownInto(container, result.content as string, mode, options);
    }
    appendDownloadAction(root, result);
  } catch (error) {
    // renderMarkdownInto throws before touching the DOM (oversize source,
    // node-count breach); leave a message, never partial content. Fail closed.
    container.replaceChildren();
    const notice = root.ownerDocument.createElement("p");
    notice.className = "viewer-render-error";
    notice.textContent =
      error instanceof ContentTooLargeError
        ? "This document is too large to display safely, so nothing is shown."
        : "This document couldn't be rendered safely, so nothing is shown.";
    container.append(notice);
  }
  return container;
}
