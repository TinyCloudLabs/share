/**
 * Hostile-content rendering pipeline (viewer spec §3, stage-3 subset).
 *
 * Sender content is UNTRUSTED INPUT rendered inside the privileged document
 * (the one that held the fragment key). The pipeline, layer by layer:
 *
 *   markdown
 *     → remark-parse + remark-gfm            (AST; no HTML execution ever)
 *     → remark-rehype, raw HTML DISABLED     (embedded HTML nodes are
 *       dropped — `allowDangerousHtml` stays at its `false` default)
 *     → rehype-sanitize (schema below)       (GitHub-style allowlist:
 *       headings/lists/tables/code/emphasis; javascript:-style URL schemes
 *       and event handlers are not representable in the output; img src is
 *       restricted to data:/relative — remote images are stripped HERE, not
 *       just by the outer CSP, per spec §3 "remote images off by default")
 *     → rehype-stringify
 *     → DOMPurify (html profile + hooks)     (defense in depth on the final
 *       string, per §2 "+ DOMPurify as defense-in-depth"; hooks strip any
 *       surviving remote resource refs and url()-bearing styles)
 *     → Trusted Types policy → innerHTML     (the sanitized string is
 *       wrapped by the named policy below where Trusted Types exist)
 *
 * Mermaid blocks (```mermaid) are then upgraded through the STAGE-4
 * OPAQUE-ORIGIN SANDBOX (viewer spec §3.2-3.3 — the stage-3 boxed TODO here,
 * now RESOLVED): diagram SOURCE TEXT only is posted into an iframe with
 * `sandbox="allow-scripts"` (no `allow-same-origin` — opaque origin) whose
 * own CSP forbids all network (`default-src 'none'; script-src
 * 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:`), where a
 * bundled, version-pinned mermaid runs with securityLevel:"strict". The
 * frame never receives the fragment key, session key, envelope, or any other
 * document content — see mermaid-sandbox.ts / mermaid-frame.ts. The SVG that
 * comes back over the narrow postMessage protocol is UNTRUSTED: it is
 * sanitized AGAIN here (DOMPurify svg profile, script/foreignObject
 * forbidden, remote refs and url()-styles stripped) and its element count is
 * bounded (MAX_SVG_NODES). Any failure — render error, node-count breach, or
 * a timeout (which DESTROYS the frame: real cancellation, the stage-3
 * abandon-only gap) — leaves the sanitized source visible as plain code;
 * fail closed.
 *
 * FINAL BOUNDARY (spec §3.3, closing the last stage-4 gap): the assembled
 * document — sanitized markdown HTML with the sanitized mermaid SVGs
 * substituted in — is staged on a DETACHED element (never attached to the
 * privileged document, which holds the fragment key and content key),
 * bounded by a TOTAL node-count cap (MAX_PREVIEW_NODES; breach throws
 * ContentTooLargeError → the caller shows a "content too large" state), and
 * then shipped as ONE sanitized HTML string into the SCRIPTLESS preview
 * iframe (preview-frame.ts: sandbox="" — opaque origin AND parser-level
 * script blocking, own strict CSP, no message channel). The privileged
 * document keeps only the chrome; the content the user reads lives entirely
 * inside that frame.
 */
import DOMPurify from "dompurify";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import rehypeStringify from "rehype-stringify";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import { unified } from "unified";

import { createPreviewFrame } from "./preview-frame.js";
import { setSanitizedInnerHtml, TRUSTED_TYPES_POLICY_NAME } from "./trusted-html.js";

/** Re-exported so existing importers/tests keep one entry point. */
export { TRUSTED_TYPES_POLICY_NAME };

/**
 * DoS containment (spec §3.4): bound source size and diagram count.
 * MAX_MARKDOWN_BYTES is measured in ENCODED UTF-8 bytes (TextEncoder), not
 * UTF-16 code units — a string of multibyte characters cannot smuggle in
 * 3-4x the byte budget.
 */
export const MAX_MARKDOWN_BYTES = 1 * 1024 * 1024;
export const MAX_MERMAID_BLOCKS = 12;
export const MAX_MERMAID_SOURCE_CHARS = 20_000;
/**
 * Per-diagram render budget. A timeout DESTROYS the sandbox frame (real
 * cancellation — a hung render dies with its frame) and every remaining
 * diagram in the document stays as sanitized source; fail closed.
 */
export const MERMAID_RENDER_TIMEOUT_MS = 5_000;
/**
 * DoS containment (spec §3.4): maximum element count of a single sanitized
 * diagram SVG. Counted on the final sanitized markup in a DETACHED host
 * before it joins the assembled document; a breach leaves the source visible
 * instead. Generous for legitimate diagrams (hundreds of nodes), hostile to
 * element bombs.
 */
export const MAX_SVG_NODES = 5_000;
/**
 * DoS containment (spec §3.4): maximum TOTAL element count of the final
 * assembled document (markdown HTML + substituted mermaid SVGs), measured on
 * the detached staging element before anything ships to the preview frame —
 * the whole-document bound the per-diagram MAX_SVG_NODES cap doesn't give
 * (12 diagrams × 5k nodes alone could reach 60k). A breach throws
 * ContentTooLargeError and NOTHING renders; fail closed. Generous for
 * legitimate documents (tens of thousands of elements), hostile to node
 * bombs assembled from many small pieces.
 */
export const MAX_PREVIEW_NODES = 50_000;

/** Timeout marker so callers can distinguish "hung" from "failed". */
export class TimeoutError extends Error {}

/** Node-count-cap marker so callers can show a "content too large" state. */
export class ContentTooLargeError extends Error {}

/** What renderMarkdownInto needs from the mermaid sandbox (mermaid-sandbox.ts). */
export interface MermaidSandboxLike {
  render(source: string): Promise<string>;
  destroy(): void;
}
export type MermaidSandboxFactory = (doc: Document) => MermaidSandboxLike;

export interface RenderMarkdownOptions {
  /** Sandbox factory override (tests inject a shimmed frame). */
  mermaidSandbox?: MermaidSandboxFactory;
  /** Per-diagram timeout override (tests only). */
  mermaidTimeoutMs?: number;
  /** Total node-count budget override (tests only). */
  previewNodeBudget?: number;
}

// ------------------------------------------------- remote-resource stripping

/**
 * Is this attribute value a REMOTE resource reference? Anything carrying a
 * scheme other than `data:image/`, or a protocol-relative `//host` form.
 * Relative/same-document references (no scheme) are not remote. Control and
 * whitespace characters are stripped before matching, mirroring how HTML
 * URL parsing tolerates them (spec §3: remote images off by default —
 * privacy must not depend solely on the outer CSP's img-src).
 */
function isRemoteResourceRef(value: string): boolean {
  const compact = value.replace(/[\u0000-\u0020]/g, "").toLowerCase();
  if (compact.startsWith("//")) return true;
  const scheme = /^([a-z][a-z0-9+.-]*):/.exec(compact);
  if (scheme === null) return false;
  return !compact.startsWith("data:image/");
}

/** Elements whose src/href FETCH a resource (vs. navigate on click). */
const RESOURCE_LOADING_TAGS = new Set([
  "img",
  "image",
  "feimage",
  "use",
  "source",
  "video",
  "audio",
  "track",
  "input",
]);
const RESOURCE_REF_ATTRS = new Set(["src", "srcset", "href", "xlink:href"]);

/**
 * Does CSS text reach for an external (or any url()-loaded) resource?
 * CSS escape sequences are decoded first so `u\72 l(` can't slip past.
 * Fail closed: url()/image-set()/@import of ANY form is rejected — inline
 * mermaid theme CSS needs none of them.
 */
function cssContainsExternalRef(css: string): boolean {
  const decoded = css
    .replace(/\\([0-9a-fA-F]{1,6})[ \t\n\r\f]?/g, (_match, hex: string) =>
      String.fromCodePoint(Number.parseInt(hex, 16)),
    )
    .replace(/\\(.)/g, "$1");
  return /url[ \t\n\r\f]*\(|image-set[ \t\n\r\f]*\(|@import/i.test(decoded);
}

/**
 * DOMPurify hooks (module-scoped: DOMPurify hooks are global to the
 * instance, and one policy — no remote resource loads from sanitized
 * content — applies to both the html and svg passes):
 *  - strip src/srcset/href/xlink:href on resource-loading elements unless
 *    the value is relative/same-document or a data:image/ URI;
 *  - strip style attributes whose CSS reaches for url()/@import;
 *  - empty <style> elements (svg profile; mermaid themes) that do the same.
 */
DOMPurify.addHook("uponSanitizeAttribute", (node, data) => {
  const attrName = data.attrName.toLowerCase();
  if (attrName === "style" && cssContainsExternalRef(data.attrValue)) {
    data.keepAttr = false;
    return;
  }
  if (
    RESOURCE_REF_ATTRS.has(attrName) &&
    RESOURCE_LOADING_TAGS.has(node.tagName?.toLowerCase() ?? "") &&
    isRemoteResourceRef(data.attrValue)
  ) {
    data.keepAttr = false;
  }
});
DOMPurify.addHook("uponSanitizeElement", (node, data) => {
  if (data.tagName === "style" && cssContainsExternalRef(node.textContent ?? "")) {
    node.textContent = "";
  }
});

/**
 * rehype-sanitize schema: GitHub defaultSchema, with img src restricted to
 * `data:` (relative refs, which carry no protocol, also pass) — the FIRST
 * layer that drops remote images; the DOMPurify hook above is the second.
 * defaultSchema keeps `className` values matching /^language-./ on <code>,
 * which is how mermaid blocks are found later.
 */
const sanitizeSchema = {
  ...defaultSchema,
  protocols: {
    ...defaultSchema.protocols,
    src: ["data"],
  },
};

/**
 * The markdown processor. `remarkRehype` keeps its default
 * `allowDangerousHtml: false`, so raw HTML embedded in markdown never
 * reaches the output tree at all; rehype-sanitize's schema then allowlists
 * what remains.
 */
const processor = unified()
  .use(remarkParse)
  .use(remarkGfm)
  .use(remarkRehype)
  .use(rehypeSanitize, sanitizeSchema)
  .use(rehypeStringify);

/** Markdown → sanitized HTML string (sanitizer + DOMPurify, both applied). */
export async function markdownToSanitizedHtml(markdown: string): Promise<string> {
  const encodedBytes = new TextEncoder().encode(markdown).length;
  if (encodedBytes > MAX_MARKDOWN_BYTES) {
    throw new RangeError(
      `document too large to render: ${encodedBytes} bytes > ${MAX_MARKDOWN_BYTES}`,
    );
  }
  const html = String(await processor.process(markdown));
  // Defense in depth: the rehype allowlist already ran; DOMPurify re-parses
  // the final serialization so a sanitizer bypass must beat BOTH layers.
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "form", "math", "svg"],
    FORBID_ATTR: ["style", "srcset"],
  });
}

/**
 * Sanitize an SVG string produced by mermaid before it touches the document
 * (§3.3 "sanitized again against an SVG allowlist"). <style> stays allowed —
 * mermaid themes need it and CSS cannot execute script — but script,
 * foreignObject (an HTML escape hatch), and event handlers are stripped,
 * and the module hooks above strip remote image/feImage/use refs and any
 * url()-bearing style.
 */
export function sanitizeSvg(svg: string): string {
  return DOMPurify.sanitize(svg, {
    USE_PROFILES: { svg: true, svgFilters: true },
    FORBID_TAGS: ["script", "foreignObject", "iframe", "audio", "video"],
  });
}

/**
 * Reject with a TimeoutError if `promise` hasn't settled within `ms`. The
 * race itself only ABANDONS the work — cancellation is the caller's job (the
 * mermaid path destroys the sandbox frame when it sees a TimeoutError).
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new TimeoutError(`${label} timed out after ${ms}ms`)),
          ms,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Render markdown into `container`. This is THE content entry point: stage 4
 * feeds decrypted share-content bytes through it (present.ts), and the test
 * suites feed it hostile payloads. `display.mode === "source"` (a
 * narrowing-only hint, viewer spec §1) renders the raw text in a <pre>
 * instead of as a document — textContent assignment parses nothing and is
 * inert, so source mode needs no frame.
 *
 * Document mode (spec §3.3): the sanitized HTML is staged on a DETACHED
 * element in the privileged document's realm — never attached to its DOM —
 * where the mermaid blocks are upgraded and the TOTAL node count is bounded.
 * Only then is the assembled document serialized and shipped into the
 * scriptless preview iframe (preview-frame.ts), which is the single child
 * the container ever receives. Nothing but that one sanitized HTML string
 * crosses the boundary. Throws (container untouched — fail closed):
 *  - RangeError            when the markdown exceeds MAX_MARKDOWN_BYTES;
 *  - ContentTooLargeError  when the assembled document exceeds the node
 *                          budget (MAX_PREVIEW_NODES).
 */
export async function renderMarkdownInto(
  container: HTMLElement,
  markdown: string,
  mode: "document" | "source" = "document",
  options: RenderMarkdownOptions = {},
): Promise<void> {
  if (mode === "source") {
    container.replaceChildren();
    const pre = container.ownerDocument.createElement("pre");
    pre.className = "viewer-source";
    pre.textContent = markdown; // textContent: no parsing, no execution
    container.append(pre);
    return;
  }
  const doc = container.ownerDocument;
  const staging = doc.createElement("div"); // DETACHED — never joins the DOM
  setSanitizedInnerHtml(staging, await markdownToSanitizedHtml(markdown));
  await upgradeMermaidBlocks(staging, options);

  const budget = options.previewNodeBudget ?? MAX_PREVIEW_NODES;
  const nodeCount = staging.querySelectorAll("*").length;
  if (nodeCount > budget) {
    throw new ContentTooLargeError(
      `rendered document too large to display: ${nodeCount} nodes > ${budget}`,
    );
  }
  container.replaceChildren(createPreviewFrame(doc, staging.innerHTML));
}

/**
 * Replace ```mermaid code blocks with sandbox-rendered, re-sanitized,
 * node-count-bounded SVG (spec §3.2-3.3). The sandbox module is imported
 * lazily so documents without diagrams pay nothing. Fail-closed ladder:
 *  - sandbox unavailable            → all sources stay as sanitized code;
 *  - a render errors                → that block stays, the rest proceed;
 *  - a render TIMES OUT             → the frame is DESTROYED (kills the hung
 *    render) and all remaining blocks stay as sanitized source;
 *  - sanitized SVG exceeds MAX_SVG_NODES → that block stays as source.
 * The sanitized-SVG node count is measured on a DETACHED host element; only
 * hosts that pass the bound ever join the (itself detached) staging tree,
 * whose TOTAL node count renderMarkdownInto bounds again before anything
 * ships to the preview frame.
 */
async function upgradeMermaidBlocks(
  container: HTMLElement,
  options: RenderMarkdownOptions,
): Promise<void> {
  const blocks = Array.from(
    container.querySelectorAll<HTMLElement>("pre > code.language-mermaid"),
  ).slice(0, MAX_MERMAID_BLOCKS);
  if (blocks.length === 0) return;
  const timeoutMs = options.mermaidTimeoutMs ?? MERMAID_RENDER_TIMEOUT_MS;

  let sandbox: MermaidSandboxLike;
  try {
    const factory =
      options.mermaidSandbox ??
      (await import("./mermaid-sandbox.js")).createMermaidSandbox;
    sandbox = factory(container.ownerDocument);
  } catch {
    return; // sandbox unavailable → sources stay as sanitized code blocks
  }

  try {
    for (const code of blocks) {
      // Diagram SOURCE TEXT only crosses into the sandbox — never document
      // HTML, never keys or session state (mermaid-sandbox.ts module doc).
      const source = code.textContent ?? "";
      if (source.length > MAX_MERMAID_SOURCE_CHARS) continue;
      try {
        const svg = await withTimeout(
          sandbox.render(source),
          timeoutMs,
          "mermaid render",
        );
        const clean = sanitizeSvg(svg);
        // Node-count bound, measured DETACHED: the host joins the document
        // only if the sanitized markup is within budget.
        const host = container.ownerDocument.createElement("div");
        host.className = "viewer-mermaid";
        setSanitizedInnerHtml(host, clean);
        if (host.querySelectorAll("*").length > MAX_SVG_NODES) continue;
        code.parentElement?.replaceWith(host);
      } catch (error) {
        if (error instanceof TimeoutError) {
          // The frame may be wedged — kill it and stop upgrading. Remaining
          // diagrams stay as sanitized source; fail closed.
          sandbox.destroy();
          return;
        }
        // Per-block render failure: leave the sanitized source visible.
      }
    }
  } finally {
    sandbox.destroy();
  }
}
