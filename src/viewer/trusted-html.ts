/**
 * Named Trusted Types policy (viewer spec §2 "Strict CSP + Trusted Types"),
 * shared by BOTH sanitized-HTML sinks in the viewer:
 *
 *   - render.ts's detached staging element (innerHTML), and
 *   - preview-frame.ts's scriptless preview iframe (srcdoc — also a
 *     TrustedHTML-guarded sink under `require-trusted-types-for 'script'`).
 *
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
 * Wrap an ALREADY-SANITIZED HTML string for assignment to a TrustedHTML
 * sink (innerHTML, iframe.srcdoc). Under Trusted Types enforcement the
 * value carries the named policy's TrustedHTML; elsewhere it degrades to
 * the plain (sanitized) string.
 */
export function toTrustedHtml(sanitizedHtml: string): string {
  const policy = trustedHtmlPolicy();
  return policy !== null
    ? (policy.createHTML(sanitizedHtml) as string)
    : sanitizedHtml;
}

/**
 * THE innerHTML sink for the viewer: every innerHTML assignment routes
 * through here, and only already-sanitized strings may be passed.
 */
export function setSanitizedInnerHtml(
  element: HTMLElement,
  sanitizedHtml: string,
): void {
  element.innerHTML = toTrustedHtml(sanitizedHtml);
}
