/**
 * Single source for the product name, domain and agent prompt shown on the
 * landing page. Renaming the product or domain is an edit to this file only.
 *
 * `index.html` holds `{{PRODUCT}}`, `{{DOMAIN}}` and `{{AGENT_PROMPT}}`
 * placeholders; `renderLandingTemplate` substitutes them at build/dev time
 * (see the `landing-template` plugin in vite.config.ts), so the page is fully
 * static and works without JavaScript.
 */
export const PRODUCT = "TinyCloud Sharing";
export const DOMAIN = "share.tinycloud.xyz";
export const AGENT_PROMPT =
  "Share this with TinyCloud, and ask me who should be able to open it: https://agents.tinycloud.xyz/share";

const TOKENS: Readonly<Record<string, string>> = {
  PRODUCT,
  DOMAIN,
  AGENT_PROMPT,
};

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/** Replace every `{{TOKEN}}` with its HTML-escaped value; unknown tokens throw. */
export function renderLandingTemplate(html: string): string {
  return html.replace(/\{\{([A-Z_]+)\}\}/g, (_match, name: string) => {
    const value = TOKENS[name];
    if (value === undefined) throw new Error(`Unknown landing template token: ${name}`);
    return escapeHtml(value);
  });
}
