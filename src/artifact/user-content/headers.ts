/**
 * Build-time header text for the two deployments of the sandbox documents:
 *
 * - same-origin (default): `public/_headers` as committed, served by the Share
 *   Pages project; `renderViewerHeaders` returns it unchanged for an empty origin.
 * - user-content origin: the viewer's headers lose the sandbox routes and name
 *   the origin in `frame-src`/`connect-src`; the user-content project serves the
 *   sandbox documents and library files under `renderUserContentHeaders`.
 *
 * Pure string functions (no Node APIs) so tests and both build paths share them.
 */
import { JSX_RUNTIME_URL_PREFIX } from "../jsx-runtime/files.js";
import { ARTIFACT_SANDBOX_CSP, ARTIFACT_SANDBOX_PATH } from "../../viewer/artifact-frame.js";
import { JSX_SANDBOX_CSP, JSX_SANDBOX_PATH } from "../../viewer/jsx-frame.js";
import { SANDBOX_PERMISSIONS_POLICY } from "../../viewer/sandbox-permissions.js";
import { MERMAID_SANDBOX_CSP, MERMAID_SANDBOX_PATH } from "../../viewer/mermaid-frame.js";

export const DEFAULT_VIEWER_ORIGIN = "https://share.tinycloud.xyz";


export interface SandboxDocument {
  readonly path: string;
  /** The meta-tag policy; the HTTP policy is this plus a frame-ancestors directive. */
  readonly csp: string;
  /** Replaces the site-wide Permissions-Policy for this document when set. */
  readonly permissionsPolicy?: string;
}

export const SANDBOX_DOCUMENTS: readonly SandboxDocument[] = [
  { path: JSX_SANDBOX_PATH, csp: JSX_SANDBOX_CSP, permissionsPolicy: SANDBOX_PERMISSIONS_POLICY },
  { path: ARTIFACT_SANDBOX_PATH, csp: ARTIFACT_SANDBOX_CSP, permissionsPolicy: SANDBOX_PERMISSIONS_POLICY },
  { path: MERMAID_SANDBOX_PATH, csp: MERMAID_SANDBOX_CSP },
];

const extensionless = (path: string): string => path.replace(/\.html$/, "");

/** Both route forms Cloudflare Pages serves for a document. */
function sandboxRoutes(): string[] {
  return SANDBOX_DOCUMENTS.flatMap((doc) => [extensionless(doc.path), doc.path]);
}

/** Adds `origin` to `frame-src` and `connect-src`, leaving every other directive alone. */
export function withUserContentOrigin(csp: string, origin: string): string {
  if (origin === "") return csp;
  return csp.split("; ").map((directive) => {
    const [name, ...values] = directive.split(" ");
    if (name !== "frame-src" && name !== "connect-src") return directive;
    if (values.includes(origin)) return directive;
    // Right after 'self' when present, so the order reads self, origin, then the rest.
    const at = values.indexOf("'self'");
    values.splice(at < 0 ? 0 : at + 1, 0, origin);
    return `${name} ${values.join(" ")}`;
  }).join("; ");
}

/**
 * `public/_headers` for the viewer deployment. With a user-content origin the
 * sandbox routes are dropped (the viewer origin serves no user-content
 * documents) and the site-wide policy names the origin.
 */
export function renderViewerHeaders(template: string, origin: string): string {
  if (origin === "") return template;
  const dropped = new Set(sandboxRoutes());
  const sections = template.split(/\n{2,}/).filter((section) => !dropped.has(section.split("\n", 1)[0]?.trim() ?? ""));
  const rewritten = sections.map((section) => section.replace(/^(\s+Content-Security-Policy: )(.*)$/m, (_line, prefix: string, csp: string) => `${prefix}${withUserContentOrigin(csp, origin)}`));
  return `${rewritten.join("\n\n").trimEnd()}\n`;
}

/** The manifest is published at the root, beside the hashed files' directory. */
export const USER_CONTENT_MANIFEST_PATH = "/manifest.json";

/**
 * The complete header file of the user-content Pages project (placeholder
 * headers kept: no-cache, COOP, Permissions-Policy, no referrer, nosniff, and
 * no cookies, ever).
 *
 * Pages adds `Access-Control-Allow-Origin: *` by default, so the site-wide block
 * detaches it and only the library files and the manifest name the viewer origin.
 * Sandbox documents replace the site-wide CSP (detached with `!`) by their own;
 * there is no X-Frame-Options (it cannot name a cross-origin parent).
 */
export function renderUserContentHeaders(viewerOrigin: string): string {
  const frameAncestors = `frame-ancestors ${viewerOrigin}`;
  const sections: string[] = [
    [
      "/*",
      "  ! Access-Control-Allow-Origin",
      "  Cache-Control: no-cache",
      `  Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
      "  Cross-Origin-Opener-Policy: same-origin",
      "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
      "  Referrer-Policy: no-referrer",
      "  X-Content-Type-Options: nosniff",
    ].join("\n"),
  ];
  for (const route of sandboxRoutes()) {
    const doc = SANDBOX_DOCUMENTS.find((candidate) => route === candidate.path || route === extensionless(candidate.path));
    if (doc === undefined) throw new Error(`no sandbox document for ${route}`);
    sections.push([
      route,
      "  ! Content-Security-Policy",
      ...(doc.permissionsPolicy === undefined ? [] : ["  ! Permissions-Policy"]),
      `  Content-Security-Policy: ${doc.csp}; ${frameAncestors}`,
      ...(doc.permissionsPolicy === undefined ? [] : [`  Permissions-Policy: ${doc.permissionsPolicy}`]),
    ].join("\n"));
  }
  sections.push([
    `${JSX_RUNTIME_URL_PREFIX}*`,
    "  ! Cache-Control",
    "  Cache-Control: public, max-age=31536000, immutable",
    `  Access-Control-Allow-Origin: ${viewerOrigin}`,
    "  Vary: Origin",
  ].join("\n"));
  sections.push([
    USER_CONTENT_MANIFEST_PATH,
    `  Access-Control-Allow-Origin: ${viewerOrigin}`,
    "  Vary: Origin",
  ].join("\n"));
  return `${sections.join("\n\n")}\n`;
}
