/**
 * The invitation message.
 *
 * Deliberately a pure function of already-verified, already-bounded inputs:
 * nothing here reads configuration, storage or the network, so the rendering
 * can be tested exactly, and no unverified string can reach a recipient's
 * inbox. Every interpolated value is HTML-escaped; the only link targets are
 * the public, fragment-free Share URL the Node signed and the service-owned
 * abuse-report URL.
 */

export interface InvitationEmailInput {
  /** The exact public Policy/v3 invitation URL authorized by the owner Node. */
  readonly magicUrl: string;
  readonly documentName: string;
  /** RFC 3339, shown to the recipient verbatim. */
  readonly expiresAt: string;
  readonly reportAbuseUrl: string;
}

export interface RenderedEmail {
  readonly subject: string;
  readonly html: string;
  readonly text: string;
}

const TRUST_LABEL = "Verified TinyCloud sender";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderInvitationEmail(input: InvitationEmailInput): RenderedEmail {
  const subject = `${input.documentName} was shared with you`;
  const html =
    "<!doctype html><html><body>" +
    `<p>${escapeHtml(TRUST_LABEL)} shared &ldquo;${escapeHtml(input.documentName)}&rdquo; with you.</p>` +
    `<p><a href="${escapeHtml(input.magicUrl)}" rel="noopener noreferrer">Open document</a></p>` +
    `<p>This link expires at ${escapeHtml(input.expiresAt)}.</p>` +
    `<p><a href="${escapeHtml(input.reportAbuseUrl)}" rel="noopener noreferrer">Report this email</a></p>` +
    "</body></html>";
  const text =
    `${TRUST_LABEL} shared "${input.documentName}" with you.\n\n` +
    `Open document: ${input.magicUrl}\n\n` +
    `This link expires at ${input.expiresAt}.\n\n` +
    `Report this email: ${input.reportAbuseUrl}\n`;
  return { subject, html, text };
}
