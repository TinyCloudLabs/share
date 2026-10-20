/**
 * The SCRIPTLESS preview frame (viewer spec §3.3: "the final document is
 * placed in a scriptless sandboxed preview iframe") — the LAST boundary of
 * the hostile-content pipeline, defense-in-depth ON TOP of every sanitizer
 * (raw-HTML-off markdown, rehype-sanitize, DOMPurify, remote-resource
 * stripping, the opaque-origin mermaid sandbox + SVG re-sanitization).
 *
 * DESIGN CHOICE — truly scriptless srcdoc frame (option "a"), NOT a minimal
 * allow-scripts bootstrap frame (option "b"):
 *
 *   The final sanitized document is delivered DECLARATIVELY via the iframe's
 *   `srcdoc` attribute into a frame whose sandbox attribute grants NOTHING
 *   (`sandbox=""`): no `allow-scripts`, no `allow-same-origin`. That means
 *   - the frame's origin is OPAQUE — it holds none of the viewer origin's
 *     powers (no DOM access to the parent, no storage, no credentialed
 *     fetches), and
 *   - script execution is disabled AT THE PARSER LEVEL by the sandbox flag
 *     itself: even a <script> that somehow survived every sanitizer, or an
 *     event-handler attribute, or a javascript: URL, is inert DATA here.
 *     This guarantee does not depend on CSP at all.
 *   A bootstrap frame (option "b") would have handed the hostile document a
 *   script-capable realm plus an open postMessage channel; here NO message
 *   channel into the frame exists — there is nothing that could ever receive
 *   the fragment key, content key, envelope, delegation, or CIDs even by
 *   bug. The frame's ENTIRE input is the one sanitized HTML string embedded
 *   in the srcdoc document below.
 *
 * CSP IMPLICATIONS of srcdoc (why this differs from mermaid-frame.ts):
 *   srcdoc documents INHERIT the embedder's CSP. The mermaid sandbox NEEDS
 *   inline scripts, which the viewer's `script-src 'self'` would block —
 *   hence its separately-SERVED document with its own policy. The preview
 *   frame needs NO script, so inheriting the viewer's strict CSP
 *   (viewer.html: default-src 'none'; script-src 'self'; img-src 'self'
 *   data: blob:; …) is acceptable and even desirable — but it makes the
 *   PARENT policy load-bearing for this frame, which is documented at the
 *   CSP in viewer.html. On top of the inherited policy, the srcdoc document
 *   pins its own meta CSP (PREVIEW_FRAME_CSP below — both policies enforce,
 *   the effective policy is the intersection): default-src 'none' with NO
 *   script-src directive (so script-src falls back to 'none'), images only
 *   from data:/blob: (remote images were already stripped by the pipeline;
 *   this backstops them), inline styles only (needed for the frame's own
 *   base stylesheet; CSS cannot execute script). Mermaid diagrams need no
 *   stylesheet here: the sandbox resolves their theme into SVG presentation
 *   attributes and the SVG sanitizer forbids <style> (render.ts).
 *
 * Residual behaviors, considered and accepted:
 *   - The frame cannot self-report its content height (no script), so the
 *     parent styles it as a fixed-height scrolling region (viewer.css).
 *   - A safe (sanitizer-allowed https) link clicked inside the frame
 *     navigates the FRAME, not the top-level viewer — and the navigated
 *     document keeps the sandbox flags (still no script, still opaque).
 *     Hostile content can no longer navigate the privileged document at all.
 */
import tokensCss from "@tinycloud/styles/tokens.css?raw";
import baseCss from "@tinycloud/styles/base.css?raw";
import patternsCss from "@tinycloud/styles/patterns.css?raw";

import { toTrustedHtml } from "./trusted-html.js";

export const PREVIEW_FRAME_CLASS = "viewer-preview-frame";

/**
 * The srcdoc document's own CSP (additive to the inherited viewer CSP —
 * see module doc). Deliberately NO script-src directive: it falls back to
 * default-src 'none'. Script inertness itself comes from sandbox="", not
 * from this policy. VIEWER PRIVACY: a Markdown document makes no request and
 * no connection to any host, so its author cannot tell who opened it or when:
 * images are data:/blob: only; fonts, media, connections, frames and scripts
 * have no source at all (`default-src 'none'`); styles are inline (the tokens
 * and prose CSS come from the strings inlined below, and the fonts are the
 * system stack, never fetched).
 */
export const PREVIEW_FRAME_CSP =
  "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'";

/**
 * Stylesheet inlined into the frame document (the parent's viewer.css cannot
 * reach across the frame boundary): the shared TinyCloud tokens, base and
 * patterns (which carry `.tc-prose`) as raw strings, then the layout and the
 * few viewer-only rules. Fixed content — must never interpolate untrusted input.
 */
const PREVIEW_STYLES = `${tokensCss}
${baseCss}
${patternsCss}
body { margin: 0; }
.viewer-doc { box-sizing: border-box; max-width: calc(var(--tc-prose-max) + 2 * var(--tc-space-6)); margin: 0 auto; padding: var(--tc-space-6) var(--tc-space-6) var(--tc-space-7); }
@media (max-width: 40rem) { .viewer-doc { padding: var(--tc-space-5) var(--tc-space-4) var(--tc-space-6); } }
.tc-prose { font-size: var(--tc-text-md); max-width: none; }
@media (min-width: 48rem) { .tc-prose { font-size: var(--tc-text-lg); } }
/* An image the viewer refused to fetch: the reader sees what was blocked and
   why, and the URL as plain text (never a link, never loaded). */
.viewer-blocked-image { display: inline-flex; flex-direction: column; gap: var(--tc-space-1); max-width: 100%; margin-block: var(--tc-space-1); padding: var(--tc-space-2) var(--tc-space-3); color: var(--tc-color-text); background: var(--tc-color-surface-subtle); border: 1px dotted var(--tc-color-text-muted); border-radius: var(--tc-radius-md); font-size: var(--tc-text-sm); line-height: var(--tc-leading-ui); }
.viewer-blocked-image code { padding: 0; background: none; border: 0; overflow-wrap: anywhere; }
/* Diagrams use Mermaid's light "neutral" theme, whose edges and free-standing
   labels are dark grey: keep them on a light card in both colour schemes.
   The card wraps the SVG so its padding never eats into the diagram's own
   width; only a diagram wider than the page is scaled down, and not below
   the half-size min-width the sandbox sets — past that the card scrolls. */
.viewer-mermaid {
  box-sizing: border-box;
  /* A diagram may be wider than the reading column (centred on it) so wide
     ones stay legible; past the viewport or 72rem the card scrolls. */
  position: relative;
  left: 50%;
  transform: translateX(-50%);
  width: max-content;
  max-width: min(calc(100vw - 2 * var(--tc-space-4)), 72rem);
  margin: var(--tc-space-4) 0;
  padding: var(--tc-space-3);
  overflow-x: auto;
  background: var(--tc-palette-white);
  border: 1px solid var(--tc-color-border);
  border-radius: var(--tc-radius-md);
}
.viewer-mermaid svg { display: block; max-width: 100%; height: auto; }
/* Print shows only this frame's viewport: the frame has no script, so it
   cannot report its content height for the parent to grow it, and a printed
   card cannot scroll. In print the diagrams share 60vh of that viewport:
   each is scaled as a whole to the page width and to its share of the
   budget, so the drawings together leave room for the surrounding text.
   --mermaid-diagram-count is set by buildPreviewDocument. A document whose
   text alone outgrows the viewport is still cut off when printed. */
@media print {
  .viewer-mermaid svg {
    width: auto;
    min-width: 0 !important;
    max-height: calc(60vh / var(--mermaid-diagram-count, 1));
  }
}
`;

/**
 * Build the complete srcdoc document around the sanitized content HTML.
 * The content string has been through the FULL pipeline already; it is
 * embedded in body context as-is. Even if it somehow carried markup that
 * breaks document structure, nothing in this frame can execute (sandbox=""),
 * so the failure mode is cosmetic, never privileged. `diagramCount` (the
 * rendered Mermaid diagrams in it) splits the print height budget; it is a
 * number the viewer counted, never document text.
 */
export function buildPreviewDocument(sanitizedHtml: string, diagramCount: number): string {
  const count = Math.max(1, Math.trunc(diagramCount));
  return `<!doctype html>
<html lang="en" data-theme="system">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${PREVIEW_FRAME_CSP}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shared document</title>
<style>${PREVIEW_STYLES}:root { --mermaid-diagram-count: ${count}; }</style>
</head>
<body><main class="viewer-doc"><article class="tc-prose">${sanitizedHtml}</article></main></body>
</html>
`;
}

/**
 * Create the scriptless preview iframe for a fully-sanitized document.
 * `sanitizedHtml` is the ONLY content that crosses into the frame — callers
 * must never pass anything derived from the fragment key, content key,
 * envelope, delegation, or CIDs. `diagramCount` is how many rendered Mermaid
 * diagrams the document holds (print sizing).
 */
export function createPreviewFrame(
  doc: Document,
  sanitizedHtml: string,
  diagramCount: number,
): HTMLIFrameElement {
  const iframe = doc.createElement("iframe");
  // Grant NOTHING: empty sandbox = opaque origin AND parser-level script
  // blocking. Never add allow-scripts or allow-same-origin here — either
  // token would collapse the last boundary of the pipeline.
  iframe.setAttribute("sandbox", "");
  iframe.className = PREVIEW_FRAME_CLASS;
  iframe.setAttribute("title", "shared document (isolated preview)");
  iframe.setAttribute("referrerpolicy", "no-referrer");
  // srcdoc is a TrustedHTML sink under the viewer's
  // `require-trusted-types-for 'script'` — wrap the (already-sanitized)
  // document with the named policy, same as every innerHTML assignment.
  iframe.srcdoc = toTrustedHtml(buildPreviewDocument(sanitizedHtml, diagramCount));
  return iframe;
}
