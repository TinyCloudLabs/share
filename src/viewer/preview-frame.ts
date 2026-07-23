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
 *   this backstops them), inline styles only (needed for mermaid theme CSS
 *   and the frame's own base stylesheet; CSS cannot execute script).
 *
 * Residual behaviors, considered and accepted:
 *   - The frame cannot self-report its content height (no script), so the
 *     parent styles it as a fixed-height scrolling region (viewer.css).
 *   - A safe (sanitizer-allowed https) link clicked inside the frame
 *     navigates the FRAME, not the top-level viewer — and the navigated
 *     document keeps the sandbox flags (still no script, still opaque).
 *     Hostile content can no longer navigate the privileged document at all.
 */
import { toTrustedHtml } from "./trusted-html.js";

export const PREVIEW_FRAME_CLASS = "viewer-preview-frame";

/**
 * The srcdoc document's own CSP (additive to the inherited viewer CSP —
 * see module doc). Deliberately NO script-src directive: it falls back to
 * default-src 'none'. Script inertness itself comes from sandbox="", not
 * from this policy.
 */
export const PREVIEW_FRAME_CSP =
  "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'";

/**
 * Base stylesheet inlined into the frame document (the parent's viewer.css
 * cannot reach across the frame boundary). Mirrors the .viewer-content
 * typography. Fixed content — must never interpolate untrusted input.
 */
const PREVIEW_STYLES = `
:root { color-scheme: light; }
body {
  margin: 0;
  padding: 1.25rem;
  color: #000000;
  background: transparent;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 16px;
  line-height: 1.55;
}
pre {
  background: #f3f3f3;
  border: 1px solid #000000;
  border-radius: 0;
  padding: 1rem;
  overflow-x: auto;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.86em; }
table { border-collapse: collapse; }
th, td { border: 1px solid #000000; padding: 0.45rem 0.65rem; }
img { max-width: 100%; }
.viewer-mermaid { margin: 1rem 0; overflow-x: auto; }
.viewer-mermaid svg { max-width: 100%; height: auto; }
`;

/**
 * Build the complete srcdoc document around the sanitized content HTML.
 * The content string has been through the FULL pipeline already; it is
 * embedded in body context as-is. Even if it somehow carried markup that
 * breaks document structure, nothing in this frame can execute (sandbox=""),
 * so the failure mode is cosmetic, never privileged.
 */
export function buildPreviewDocument(sanitizedHtml: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${PREVIEW_FRAME_CSP}">
<meta name="referrer" content="no-referrer">
<style>${PREVIEW_STYLES}</style>
</head>
<body>${sanitizedHtml}</body>
</html>
`;
}

/**
 * Create the scriptless preview iframe for a fully-sanitized document.
 * `sanitizedHtml` is the ONLY thing that crosses into the frame — callers
 * must never pass anything derived from the fragment key, content key,
 * envelope, delegation, or CIDs.
 */
export function createPreviewFrame(
  doc: Document,
  sanitizedHtml: string,
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
  iframe.srcdoc = toTrustedHtml(buildPreviewDocument(sanitizedHtml));
  return iframe;
}
