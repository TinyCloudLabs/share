/**
 * The mermaid sandbox FRAME document (viewer spec §3.2): builder + protocol
 * constants shared by the parent-side module (mermaid-sandbox.ts), the Vite
 * plugin that serves/emits the document (vite.config.ts), and the tests that
 * pin the CSP and protocol.
 *
 * Why a real served document instead of `srcdoc`: local-scheme documents
 * (srcdoc/blob:/about:blank) INHERIT the embedder's CSP — and the viewer's
 * strict `script-src 'self'` would then block the sandbox's inline scripts.
 * A network-delivered document gets its own policy, so the sandbox page is
 * served from the app origin at MERMAID_SANDBOX_PATH and embedded with
 * `sandbox="allow-scripts"` (NO `allow-same-origin`), which makes its origin
 * OPAQUE: it cannot reach the parent document, its DOM, its storage, or its
 * origin-scoped anything — all it can do is run scripts and postMessage.
 *
 * The frame's own CSP is the spec §3.2 policy verbatim: no network at all
 * (`default-src 'none'`), inline script/style only (everything is inlined at
 * build time — no CDN, per the zero-CDN-executables rule), images only from
 * data:/blob:. The mermaid library is INLINED into the document body.
 *
 * Protocol (narrow by design): parent → frame `{type:"render", id, nonce,
 * source}` where `source` is the diagram TEXT and nothing else — never keys,
 * never the envelope, never other document content; frame → parent
 * `{type:"ready", nonce}` once, then `{type:"result", id, nonce, ok,
 * svg|error}` per render. The frame posts to `window.parent` with
 * targetOrigin "*" (it cannot know the parent origin from inside an opaque
 * origin, and the SVG result is not a secret).
 *
 * ---- Embedding hardening (both directions of the boundary) --------------
 *
 * The opaque origin is imposed by OUR parent iframe's sandbox attribute — a
 * hostile page could instead embed this served document WITHOUT a sandbox
 * and drive it under the real share-site origin. Three independent locks:
 *
 * 1. SELF-DEFENSE: on load the bridge checks `self.origin === "null"` (the
 *    exact serialization a sandboxed, opaque-origin document gets). Any
 *    other origin means the document is NOT sandboxed → the bridge refuses
 *    to initialize mermaid or process a single message.
 * 2. FRAME-ANCESTORS: the document must be SERVED with the HTTP headers in
 *    MERMAID_SANDBOX_HTTP_HEADERS (frame-ancestors cannot ride in a <meta>
 *    CSP) so third-party pages cannot frame it at all. The Vite plugin sets
 *    them in dev/preview; production static hosting MUST send the same
 *    headers (public/_headers carries the Cloudflare Pages rule).
 * 3. HANDSHAKE NONCE: the parent generates a CSPRNG nonce per frame and
 *    passes it in the frame URL'S FRAGMENT at creation. EVERY message in
 *    BOTH directions must carry it. The frame additionally requires
 *    `event.source === window.parent`; the parent requires `event.source`
 *    to be its own frame's window AND `event.origin === "null"` (what an
 *    opaque-origin frame posts as).
 */

/** App-origin path the sandbox document is served from (dev + build). */
export const MERMAID_SANDBOX_PATH = "/mermaid-sandbox.html";

/** Spec §3.2 CSP for the sandbox frame, verbatim. */
export const MERMAID_SANDBOX_CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:";

/**
 * HTTP headers the sandbox document MUST be served with — dev/preview
 * (vite.config.ts middleware) and production alike. `frame-ancestors 'self'`
 * (plus the legacy X-Frame-Options equivalent) refuses every third-party
 * embedding of the document; only our own origin may frame it. These are
 * HTTP-header-only directives: a <meta> CSP cannot express frame-ancestors,
 * so a static production host MUST be configured to send them (see
 * public/_headers for the Cloudflare Pages rule the build ships).
 */
export const MERMAID_SANDBOX_HTTP_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ["content-security-policy", "frame-ancestors 'self'"],
  ["x-frame-options", "SAMEORIGIN"],
];

/** Message shapes crossing the boundary — keep these EXACTLY this narrow. */
export interface MermaidRenderRequest {
  readonly type: "render";
  readonly id: string;
  /** Per-frame handshake nonce — required on EVERY message, both ways. */
  readonly nonce: string;
  /** Diagram source text. The ONLY payload that ever enters the frame. */
  readonly source: string;
}
export type MermaidFrameReply =
  | { readonly type: "ready"; readonly nonce: string }
  | {
      readonly type: "result";
      readonly id: string;
      readonly nonce: string;
      readonly ok: true;
      readonly svg: string;
    }
  | {
      readonly type: "result";
      readonly id: string;
      readonly nonce: string;
      readonly ok: false;
      readonly error: string;
    };

/**
 * The bridge script that runs INSIDE the sandbox. Plain ES5-ish inline
 * script: refuse to operate outside an opaque-origin sandbox, require the
 * handshake nonce from the frame URL fragment, initialize mermaid strict
 * (strict mode runs *inside* the sandbox, not instead of it — §3.2), answer
 * nonce-carrying render requests from the parent, announce readiness.
 * Exported (not just inlined) so tests can EXECUTE it against a mock
 * environment and prove the guards, not merely string-match them.
 */
export const MERMAID_BRIDGE_SCRIPT = `"use strict";
(function () {
  // SELF-DEFENSE: this document only ever runs inside our parent iframe
  // with sandbox="allow-scripts" (no allow-same-origin), which makes its
  // origin OPAQUE — serialized as exactly "null". Any other origin means a
  // page embedded it WITHOUT the sandbox (scripts would run under the real
  // share-site origin): refuse to do ANYTHING.
  if (self.origin !== "null") {
    try {
      window.parent.postMessage(
        { type: "result", id: "", nonce: "", ok: false, error: "mermaid sandbox refused: document is not in an opaque-origin sandbox" },
        "*"
      );
    } catch (_refusalError) {}
    return;
  }
  // Handshake nonce, placed in the frame URL fragment by the embedding
  // parent at creation. No nonce → no bridge.
  var nonce = String(window.location.hash || "").replace(/^#/, "");
  if (nonce.length === 0) return;
  mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "neutral" });
  var renderCount = 0;
  window.addEventListener("message", function (event) {
    if (event.source !== window.parent) return;
    var data = event.data;
    if (typeof data !== "object" || data === null) return;
    if (data.nonce !== nonce) return;
    if (data.type !== "render" || typeof data.id !== "string" || typeof data.source !== "string") return;
    var id = data.id;
    mermaid
      .render("mermaid-sandbox-" + renderCount++, data.source)
      .then(function (out) {
        window.parent.postMessage({ type: "result", id: id, nonce: nonce, ok: true, svg: out.svg }, "*");
      })
      .catch(function (err) {
        window.parent.postMessage(
          { type: "result", id: id, nonce: nonce, ok: false, error: String((err && err.message) || err) },
          "*"
        );
      });
  });
  window.parent.postMessage({ type: "ready", nonce: nonce }, "*");
})();`;

/**
 * Build the complete sandbox HTML document with the (version-pinned,
 * self-hosted) mermaid library inlined. `</script` sequences inside the
 * library text are escaped to `<\/script` so the inline block cannot be
 * terminated early by string contents.
 */
export function buildMermaidSandboxHtml(mermaidLibraryJs: string): string {
  const inlinedLibrary = mermaidLibraryJs.replace(/<\/script/gi, "<\\/script");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${MERMAID_SANDBOX_CSP}">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<title>mermaid sandbox</title>
</head>
<body>
<script>${inlinedLibrary}</script>
<script>${MERMAID_BRIDGE_SCRIPT}</script>
</body>
</html>
`;
}
