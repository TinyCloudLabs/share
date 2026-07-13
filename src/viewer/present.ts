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
