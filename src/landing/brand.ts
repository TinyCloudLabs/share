/**
 * Single source for the product name, domain and agent prompt shown on the
 * landing page. Renaming the product or domain is an edit to this file only.
 *
 * `index.html` holds `{{PRODUCT}}`, `{{PRODUCT_WORDMARK}}`, `{{DOMAIN}}`, `{{AGENT_PROMPT}}`,
 * `{{AGENT_LINKS}}`, `{{PRIVACY_CLAUSE}}`, `{{SHARE_TARGET_FIRST}}` and `{{SHARE_TARGET_LONGEST}}` placeholders; `renderLandingTemplate` substitutes them at build/dev time
 * (see the `landing-template` plugin in vite.config.ts), so the page is fully
 * static and works without JavaScript.
 */
import { longestShareTarget, SHARE_TARGETS } from "./share-targets.js";

export const PRODUCT = "TinyCloud Sharing";
export const DOMAIN = "share.tinycloud.xyz";
export const SKILL_URL = "https://agents.tinycloud.xyz/share";
export const AGENT_PROMPT = `Read ${SKILL_URL} and follow it.`;

/** Hero privacy sentence tail. The preview-only alternative lives in preview-variant.ts, outside production builds. */
export const PRIVACY_CLAUSE = "a link to share with whoever you choose, and only them";

interface AgentTarget {
  id: string;
  name: string;
  /** Badge letter(s) shown instead of a vendor logo. */
  badge: string;
  href: (prompt: string, skillUrl: string) => string;
  toast: string;
  /** Hidden on touch devices, where the link has no app to open. */
  desktopOnly?: boolean;
}

const opening = (name: string): string => `Opening ${name}. The prompt is copied too.`;
const sendIt = (name: string): string => `Copied. If ${name} did not open, send it the prompt.`;
const enc = encodeURIComponent;

/** Deep links that open an agent with the prompt filled in. Order is the order on the page. */
export const AGENT_TARGETS: readonly AgentTarget[] = [
  { id: "chatgpt", name: "ChatGPT", badge: "Ch", href: (p) => `https://chatgpt.com/?q=${enc(p)}`, toast: opening("ChatGPT") },
  { id: "claude", name: "Claude", badge: "Cl", href: (p) => `https://claude.ai/new?q=${enc(p)}`, toast: opening("Claude") },
  { id: "grok", name: "Grok", badge: "Gr", href: (p) => `https://grok.com/?q=${enc(p)}`, toast: opening("Grok") },
  { id: "gemini", name: "Gemini", badge: "Ge", href: (p) => `https://gemini.google.com/app?q=${enc(p)}`, toast: "Copied. Paste it into Gemini." },
  { id: "perplexity", name: "Perplexity", badge: "Pe", href: (p) => `https://www.perplexity.ai/search?q=${enc(p)}`, toast: opening("Perplexity") },
  { id: "cursor", name: "Cursor", badge: "Cu", href: (p) => `https://cursor.com/link/prompt?text=${enc(p)}`, toast: opening("Cursor"), desktopOnly: true },
  { id: "openclaw", name: "OpenClaw", badge: "Oc", href: (p) => `openclaw://agent?message=${enc(p)}`, toast: sendIt("OpenClaw") },
  { id: "hermes", name: "Hermes", badge: "He", href: (_p, skill) => `hermes://skill/install?identifier=${enc(skill)}`, toast: sendIt("Hermes") },
];

function agentLinksHtml(): string {
  return AGENT_TARGETS.map(
    (agent) =>
      `<a class="agent-link" data-agent="${agent.id}" data-toast="${escapeHtml(agent.toast)}"${agent.desktopOnly ? ' data-only="desktop"' : ""} href="${escapeHtml(agent.href(AGENT_PROMPT, SKILL_URL))}" target="_blank" rel="noopener" aria-label="Open in ${agent.name}"><span class="agent-badge" aria-hidden="true">${agent.badge}</span>${agent.name}</a>`,
  ).join("\n            ");
}

/**
 * Token values are HTML-escaped on render. PRODUCT_WORDMARK and AGENT_LINKS are
 * markup built from escaped parts; PRODUCT_WORDMARK is the header wordmark: the
 * first word as the brand, the rest wrapped in <b>.
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
  AGENT_LINKS: agentLinksHtml(),
  PRIVACY_CLAUSE: escapeHtml(PRIVACY_CLAUSE),
  SHARE_TARGET_FIRST: escapeHtml(SHARE_TARGETS[0] ?? ""),
  SHARE_TARGET_LONGEST: escapeHtml(longestShareTarget()),
};

/** Replace every `{{TOKEN}}` with its rendered value; unknown tokens throw. */
export function renderLandingTemplate(html: string): string {
  return html.replace(/\{\{([A-Z_]+)\}\}/g, (_match, name: string) => {
    const value = TOKENS[name];
    if (value === undefined) throw new Error(`Unknown landing template token: ${name}`);
    return value;
  });
}
