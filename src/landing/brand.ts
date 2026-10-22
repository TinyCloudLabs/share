/**
 * Single source for the product name, domain and agent prompt shown on the
 * landing page. Renaming the product or domain is an edit to this file only.
 *
 * `index.html` holds `{{PRODUCT}}`, `{{PRODUCT_WORDMARK}}`, `{{DOMAIN}}`, `{{AGENT_PROMPT}}`,
 * `{{AGENT_LINKS}}` and `{{HEADLINE_LABEL}}` placeholders; `renderLandingTemplate` substitutes them at build/dev time
 * (see the `landing-template` plugin in vite.config.ts), so the page is fully
 * static and works without JavaScript.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SHARE_TARGETS } from "./share-targets.js";

export const PRODUCT = "TinyCloud Sharing";
export const DOMAIN = "share.tinycloud.xyz";
export const AGENT_SKILL_URL = "https://agents.tinycloud.xyz/share";
export const AGENT_PROMPT = `Share this with TinyCloud, and ask me who should be able to open it: ${AGENT_SKILL_URL}`;

/**
 * The "Open your agent" icon row (agent-links.html). Each link opens that agent with the prompt
 * (or, for Hermes, the skill URL) filled in; the URL-encoded values contain no HTML-special
 * characters, so they go into the href attributes as-is.
 */
const AGENT_LINKS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "agent-links.html"), "utf8")
  .replaceAll("{{AGENT_PROMPT_QUERY}}", encodeURIComponent(AGENT_PROMPT))
  .replaceAll("{{AGENT_SKILL_QUERY}}", encodeURIComponent(AGENT_SKILL_URL))
  .trimEnd();

/**
 * The hero headline's accessible name. The visible headline types one recipient at a time, so
 * screen readers get the whole sentence once instead (the animated part is aria-hidden).
 */
export const HEADLINE_LABEL = `Share what your agent makes with ${SHARE_TARGETS.slice(0, -1).join(", ")} or ${SHARE_TARGETS.at(-1)}.`;

/**
 * Token values are HTML-escaped on render, except the AGENT_LINKS markup. PRODUCT_WORDMARK is the
 * header wordmark markup: the first word as the brand, the rest wrapped in <b>.
 */
function wordmarkHtml(product: string): string {
  const [brand = "", ...rest] = product.split(" ");
  return rest.length === 0 ? escapeHtml(brand) : `${escapeHtml(brand)} <b>${escapeHtml(rest.join(" "))}</b>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

const TOKENS: Readonly<Record<string, string>> = {
  PRODUCT: escapeHtml(PRODUCT),
  PRODUCT_WORDMARK: wordmarkHtml(PRODUCT),
  DOMAIN: escapeHtml(DOMAIN),
  AGENT_PROMPT: escapeHtml(AGENT_PROMPT),
  AGENT_LINKS,
  HEADLINE_LABEL: escapeHtml(HEADLINE_LABEL),
};

/** Replace every `{{TOKEN}}` with its rendered value; unknown tokens throw. */
export function renderLandingTemplate(html: string): string {
  return html.replace(/\{\{([A-Z_]+)\}\}/g, (_match, name: string) => {
    const value = TOKENS[name];
    if (value === undefined) throw new Error(`Unknown landing template token: ${name}`);
    return value;
  });
}
