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
 * Mermaid blocks (```mermaid) are then upgraded: diagram SOURCE TEXT only is
 * handed to a bundled, version-pinned mermaid with securityLevel:"strict",
 * and the returned SVG is sanitized AGAIN (DOMPurify svg profile, script/
 * foreignObject forbidden, remote refs and url()-styles stripped) before
 * being placed in an isolated element. Any failure — including a render
 * that exceeds the timeout — leaves the sanitized source visible as plain
 * code; fail closed.
 *
 * ============================================================================
 * TODO(stage-4 HARD PREREQUISITE — viewer spec §3.2-3.3): opaque-origin
 * sandbox iframe for mermaid (and the final document preview).
 *
 * Before stage 4 renders REAL FILE BYTES fetched from the node, mermaid MUST
 * be moved out of this privileged document into an opaque-origin iframe
 * (`sandbox="allow-scripts"` WITHOUT `allow-same-origin`, CSP
 * `default-src 'none'`) returning SVG over a narrow postMessage protocol,
 * and the final document must render in a scriptless sandboxed preview
 * iframe. This is NOT optional hardening: mermaid has a repeated XSS
 * advisory history, in-document double-sanitization is a mitigation for the
 * stage-3 placeholder only, and a sandbox is also the only real answer to
 * mermaid DoS (a synchronous main-thread hang cannot be aborted from this
 * document — the timeout below abandons, it cannot kill). Do not ship
 * stage-4 node-read content through this pipeline without the sandbox.
 * Do not remove this TODO until the sandbox exists.
 * ============================================================================
 */
import DOMPurify from "dompurify";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import rehypeStringify from "rehype-stringify";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import { unified } from "unified";

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
 * Per-diagram render budget. NOTE: Promise.race can only ABANDON an async
 * render — a synchronous main-thread hang is uninterruptible from here.
 * True cancellation (and a node-count bound) arrives with the stage-4
 * opaque-origin sandbox iframe (see the HARD PREREQUISITE TODO above),
 * where the whole frame can be torn down.
 */
export const MERMAID_RENDER_TIMEOUT_MS = 5_000;

// --------------------------------------------------------------- Trusted Types

/**
 * Named Trusted Types policy (viewer spec §2 "Strict CSP + Trusted Types").
 * The policy wraps strings that have ALREADY been through the full
 * sanitization pipeline — sanitize first, then wrap; the policy itself adds
 * no sanitization and must never be handed raw input. Its name is pinned in
 * the viewer CSP (`trusted-types` directive in viewer.html). Feature-
 * detected so the pipeline still works where Trusted Types are unsupported.
 */
export const TRUSTED_TYPES_POLICY_NAME = "share-viewer-html";

interface SanitizedHtmlPolicy {
  createHTML(input: string): unknown;
}
interface TrustedTypesFactory {
  createPolicy(
    name: string,
    rules: { createHTML(input: string): string },
  ): SanitizedHtmlPolicy;
}

let sanitizedHtmlPolicy: SanitizedHtmlPolicy | null | undefined;

function trustedHtmlPolicy(): SanitizedHtmlPolicy | null {
  if (sanitizedHtmlPolicy === undefined) {
    const trustedTypes = (globalThis as { trustedTypes?: TrustedTypesFactory })
      .trustedTypes;
    sanitizedHtmlPolicy =
      trustedTypes !== undefined
        ? trustedTypes.createPolicy(TRUSTED_TYPES_POLICY_NAME, {
            createHTML: (input) => input,
          })
        : null;
  }
  return sanitizedHtmlPolicy;
}

/**
 * THE innerHTML sink for the viewer: every innerHTML assignment routes
 * through here, and only already-sanitized strings may be passed. Under
 * Trusted Types enforcement the assignment carries the named policy's
 * TrustedHTML; elsewhere it degrades to the plain (sanitized) string.
 */
function setSanitizedInnerHtml(element: HTMLElement, sanitizedHtml: string): void {
  const policy = trustedHtmlPolicy();
  element.innerHTML =
    policy !== null ? (policy.createHTML(sanitizedHtml) as string) : sanitizedHtml;
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
 * Abandon `promise` if it hasn't settled within `ms`. NOTE this cannot
 * cancel the underlying work (see MERMAID_RENDER_TIMEOUT_MS) — it only
 * unblocks the pipeline and lets the caller fail closed.
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
          () => reject(new Error(`${label} timed out after ${ms}ms`)),
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
 * feeds node-read file bytes through this same function (BEHIND the sandbox
 * iframe demanded by the TODO above); stage-3 tests feed it hostile
 * payloads. `display.mode === "source"` (a narrowing-only hint, viewer spec
 * §1) renders the raw text in a <pre> instead of as a document.
 */
export async function renderMarkdownInto(
  container: HTMLElement,
  markdown: string,
  mode: "document" | "source" = "document",
): Promise<void> {
  if (mode === "source") {
    container.replaceChildren();
    const pre = container.ownerDocument.createElement("pre");
    pre.className = "viewer-source";
    pre.textContent = markdown; // textContent: no parsing, no execution
    container.append(pre);
    return;
  }
  setSanitizedInnerHtml(container, await markdownToSanitizedHtml(markdown));
  await upgradeMermaidBlocks(container);
}

/**
 * Replace ```mermaid code blocks with rendered, re-sanitized SVG. Mermaid is
 * imported lazily (bundled by Vite — never a CDN script tag) so documents
 * without diagrams pay nothing. Every per-block failure — including a
 * timed-out render — falls back to the already-sanitized source text.
 */
async function upgradeMermaidBlocks(container: HTMLElement): Promise<void> {
  const blocks = Array.from(
    container.querySelectorAll<HTMLElement>("pre > code.language-mermaid"),
  ).slice(0, MAX_MERMAID_BLOCKS);
  if (blocks.length === 0) return;

  let mermaid: typeof import("mermaid").default;
  try {
    mermaid = (await import("mermaid")).default;
    mermaid.initialize({
      startOnLoad: false,
      // Strict mode INSIDE our sanitization, not instead of it (§3.2).
      securityLevel: "strict",
      theme: "neutral",
    });
  } catch {
    return; // mermaid unavailable → sources stay as sanitized code blocks
  }

  for (const [index, code] of blocks.entries()) {
    // Diagram SOURCE TEXT only crosses into mermaid — never document HTML,
    // never keys or session state.
    const source = code.textContent ?? "";
    if (source.length > MAX_MERMAID_SOURCE_CHARS) continue;
    try {
      const { svg } = await withTimeout(
        mermaid.render(`share-viewer-mermaid-${index}`, source),
        MERMAID_RENDER_TIMEOUT_MS,
        "mermaid render",
      );
      const clean = sanitizeSvg(svg);
      const host = container.ownerDocument.createElement("div");
      host.className = "viewer-mermaid";
      setSanitizedInnerHtml(host, clean);
      code.parentElement?.replaceWith(host);
    } catch {
      // Fail closed: leave the sanitized source visible as plain code.
    }
  }
}
