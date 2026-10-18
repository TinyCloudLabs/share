/**
 * Single source for the product name, domain and agent prompt shown on the
 * landing page. Renaming the product or domain is an edit to this file only.
 *
 * `index.html` holds `{{PRODUCT}}`, `{{PRODUCT_WORDMARK}}`, `{{DOMAIN}}` and
 * `{{AGENT_PROMPT}}` placeholders; `renderLandingTemplate` substitutes them at build/dev time
 * (see the `landing-template` plugin in vite.config.ts), so the page is fully
 * static and works without JavaScript.
 */
export const PRODUCT = "TinyCloud Sharing";
export const DOMAIN = "share.tinycloud.xyz";
export const AGENT_PROMPT =
  "Share this with TinyCloud, and ask me who should be able to open it: https://agents.tinycloud.xyz/share";

/**
 * Token values are HTML-escaped on render. PRODUCT_WORDMARK is the header
 * wordmark markup: the first word as the brand, the rest wrapped in <b>.
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
};

/** Replace every `{{TOKEN}}` with its rendered value; unknown tokens throw. */
export function renderLandingTemplate(html: string): string {
  return html.replace(/\{\{([A-Z_]+)\}\}/g, (_match, name: string) => {
    const value = TOKENS[name];
    if (value === undefined) throw new Error(`Unknown landing template token: ${name}`);
    return value;
  });
}
