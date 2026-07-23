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

function downloadName(result: Extract<ResolveResult, { readonly state: "ok" }>): string {
  const candidate =
    result.envelope.display.filename ??
    result.envelope.target.resource.path.split("/").at(-1) ??
    "shared-document.txt";
  const safe = candidate
    .split(/[\\/]/)
    .at(-1)
    ?.replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  return safe === undefined || safe.length === 0 ? "shared-document.txt" : safe;
}

function appendDownloadAction(
  root: HTMLElement,
  result: Extract<ResolveResult, { readonly state: "ok" }>,
): void {
  if (result.content === undefined) return;
  const footer = root.querySelector<HTMLElement>(".viewer-footer");
  const hint = footer?.querySelector<HTMLElement>(".viewer-agent-hint");
  if (footer === null || footer === undefined || hint === null || hint === undefined) return;
  const button = root.ownerDocument.createElement("button");
  button.type = "button";
  button.className = "viewer-download";
  button.textContent = "Download original";
  button.addEventListener("click", () => {
    const blob = new Blob([result.content ?? ""], {
      type: "text/plain;charset=utf-8",
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
  if (container === null || result.state !== "ok" || result.content === undefined) {
    return container;
  }
  // display.mode is a NARROWING-ONLY hint (viewer spec §1): "source" may
  // downgrade the presentation; anything else renders as a document.
  const mode = result.envelope.display.mode === "source" ? "source" : "document";
  try {
    await renderMarkdownInto(container, result.content, mode, options);
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
