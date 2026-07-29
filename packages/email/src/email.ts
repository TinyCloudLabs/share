/**
 * The invitation message.
 *
 * Deliberately a pure function of already-verified, already-bounded inputs:
 * nothing here reads configuration, storage or the network, so the rendering
 * can be tested exactly, and no unverified string can reach a recipient's
 * inbox. Every interpolated value is HTML-escaped; the only link targets are
 * the share URL the Node signed and the service-owned abuse-report URL.
 *
 * The claim ceremony is NOT here. Today `magicUrl` is the share URL verbatim.
 * When the ceremony lands, it supplies a delivery URL with `&i=<invitation>`
 * and `&c=<claim secret>` appended to the fragment plus an `otp`, and only
 * this function's inputs change — the shape below already has the slot.
 */

export type SenderTrust = "verified" | "unverified";

export interface InvitationEmailInput {
  /** The exact URL to put behind the button. Treated as a secret: it carries the decryption key in its fragment. */
  readonly magicUrl: string;
  readonly documentName: string;
  readonly senderTrust: SenderTrust;
  /** RFC 3339, shown to the recipient verbatim. */
  readonly expiresAt: string;
  readonly reportAbuseUrl: string;
  /** Reserved for the claim ceremony. Omitted today. */
  readonly otp?: string;
}

export interface RenderedEmail {
  readonly subject: string;
  readonly html: string;
  readonly text: string;
}

const TRUST_LABEL: Record<SenderTrust, string> = {
  verified: "Verified TinyCloud sender",
  unverified: "Unverified sender — confirm the sender before opening",
};

const OTP_WARNING =
  "Never send this code to anyone, including someone claiming to be TinyCloud support.";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderInvitationEmail(input: InvitationEmailInput): RenderedEmail {
  const trust = TRUST_LABEL[input.senderTrust];
  const subject = `${input.documentName} was shared with you`;
  const otpHtml =
    input.otp === undefined
      ? ""
      : `<p>Or enter this code: <strong>${escapeHtml(input.otp)}</strong></p><p>${escapeHtml(OTP_WARNING)}</p>`;
  const html =
    "<!doctype html><html><body>" +
    `<p>${escapeHtml(trust)} shared &ldquo;${escapeHtml(input.documentName)}&rdquo; with you.</p>` +
    `<p><a href="${escapeHtml(input.magicUrl)}" rel="noopener noreferrer">Open document</a></p>` +
    otpHtml +
    `<p>This link expires at ${escapeHtml(input.expiresAt)}.</p>` +
    `<p><a href="${escapeHtml(input.reportAbuseUrl)}" rel="noopener noreferrer">Report this email</a></p>` +
    "</body></html>";
  const otpText = input.otp === undefined ? "" : `Or enter this code: ${input.otp}\n\n${OTP_WARNING}\n\n`;
  const text =
    `${trust} shared "${input.documentName}" with you.\n\n` +
    `Open document: ${input.magicUrl}\n\n` +
    otpText +
    `This link expires at ${input.expiresAt}.\n\n` +
    `Report this email: ${input.reportAbuseUrl}\n`;
  return { subject, html, text };
}
