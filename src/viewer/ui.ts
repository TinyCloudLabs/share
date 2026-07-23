/**
 * Viewer UI states — copy from sharing-ux-blueprint.md §5 "Flow 2a …
 * Wireframe — viewer" (NOT the viewer spec's §5, which is folder-listing
 * semantics); stage-3 bearer subset.
 *
 * All chrome is built with createElement/textContent — envelope-derived
 * strings (senderName, filename, paths) are ATTACKER-CONTROLLED and must
 * never travel through innerHTML. The only TrustedHTML sinks in the viewer
 * are render.ts's sanitized outputs (detached staging innerHTML) and the
 * scriptless preview frame's srcdoc (preview-frame.ts), all routed through
 * trusted-html.ts.
 *
 * Fail-closed invariant: the document content container exists ONLY in the
 * "ok" state. Every other state renders a message and nothing else, so no
 * verification failure can ever be followed by content.
 */
import type { ShareEnvelope } from "@tinycloud/share-envelope";

import type { ResolveResult, UnsupportedReason } from "./resolve.js";

function el<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  className: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function filenameOf(envelope: ShareEnvelope): string {
  const fromDisplay = envelope.display.filename;
  if (fromDisplay !== undefined && fromDisplay.length > 0) return fromDisplay;
  const path = envelope.target.resource.path;
  return path.split("/").pop() ?? path;
}

function formatExpiry(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function renderResolving(root: HTMLElement): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "div", "viewer-state viewer-resolving");
  box.append(
    el(doc, "h1", "viewer-state-title", "Verifying share link…"),
    el(
      doc,
      "p",
      "viewer-state-detail",
      "Fetching the envelope, checking its fingerprint, and decrypting locally. The key in this link never leaves your browser.",
    ),
  );
  root.append(box);
}

function renderErrorState(root: HTMLElement, title: string, detail: string): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "div", "viewer-state viewer-error");
  box.append(
    el(doc, "h1", "viewer-state-title", title),
    el(doc, "p", "viewer-state-detail", detail),
  );
  root.append(box);
}

export interface EmailClaimViewActions {
  readonly onOpen: () => void;
  readonly onRetry: () => void;
  readonly onUseOtp: () => void;
  readonly onOtp: (code: string) => void;
  readonly onResend: () => void;
  readonly onForget: () => void;
}

export function renderEmailClaimUnavailable(root: HTMLElement): void {
  renderErrorState(root, "Email invitations aren't connected", "This share was verified locally, but this deployment has not enabled its exact-email claim adapter. No credential or storage request was made.");
}

export function renderEmailClaimState(root: HTMLElement, state: import("../email-share/claim.js").ClaimState, actions: EmailClaimViewActions): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "section", "viewer-state viewer-claim");
  box.setAttribute("aria-labelledby", "claim-title");
  box.setAttribute("role", "status");
  box.setAttribute("aria-live", "polite");
  box.setAttribute("aria-atomic", "true");
  const title = el(doc, "h1", "viewer-state-title", state.state === "claimed" ? "Credential ready" : state.state === "forgotten" ? "Browser key forgotten" : state.state === "otp" ? "Enter the email code" : state.state === "activation" ? "Confirming invitation…" : state.state === "challenge" ? "Checking invitation…" : state.state === "redeeming" ? "Verifying email proof…" : state.state === "session" ? "Authorizing one read…" : state.state === "reading" ? "Reading document…" : state.state === "resending" ? "Requesting a new code…" : state.state === "used" ? "Invitation already used" : state.state === "expired" ? "Invitation expired" : state.state === "revoked" ? "Invitation unavailable" : state.state === "denied" ? "Invitation not authorized" : state.state === "error" ? "We couldn't finish the invitation" : "Open this shared document");
  title.id = "claim-title";
  const detailText = state.state === "claimed" ? "Your browser now holds a non-extractable key for this share. The node will authorize one read using that key." : state.state === "forgotten" ? "The holder key and claim material were removed from this browser. No document bytes remain available here; ask the sender for a fresh invitation to start again." : state.state === "otp" ? (state.message ?? "The link scanner-safe step is complete. Enter the six-digit code from the invitation email.") : state.state === "used" || state.state === "expired" || state.state === "revoked" || state.state === "denied" ? state.message : state.state === "error" ? (state.code === "unsupported-browser" ? "This browser cannot create the non-extractable key required for a private claim. Try a current browser with WebCrypto support." : state.code === "offline" ? "You appear to be offline. Reconnect, then retry; no document bytes were requested." : state.code === "capability-unavailable" ? "This deployment has not enabled its trusted claim services. No credential or document request was made." : state.retryable ? "The service is temporarily unavailable. Reconnect, then retry; no document bytes were requested." : "Ask the sender for a fresh invitation.") : state.state === "reading" || state.state === "session" ? "The browser is checking the signed Node response before showing any document bytes." : "The envelope and exact policy are verified locally. Selecting Open document is the required confirmation; simply visiting this link is inert.";
  const detail = el(doc, "p", "viewer-state-detail", detailText);
  box.append(title, detail);
  if (state.state === "ready" || state.state === "verifying") { const button = el(doc, "button", "viewer-primary-action", "Open document"); button.type = "button"; button.addEventListener("click", actions.onOpen); box.append(button); }
  if (state.state === "ready" || state.state === "verifying") { const otp = el(doc, "button", "viewer-secondary-action", "Use email code instead"); otp.type = "button"; otp.setAttribute("aria-label", "Use the six-digit email code instead of the link"); otp.addEventListener("click", actions.onUseOtp); box.append(otp); }
  if (state.state === "error" && state.retryable) { const retry = el(doc, "button", "viewer-primary-action", "Retry"); retry.type = "button"; retry.addEventListener("click", actions.onRetry); box.append(retry); }
  if (state.state === "otp") {
    const form = el(doc, "form", "viewer-otp-form") as HTMLFormElement; const label = el(doc, "label", "viewer-otp-label", "Six-digit code"); const input = el(doc, "input", "viewer-otp-input") as HTMLInputElement; input.id = "viewer-otp"; input.inputMode = "numeric"; input.autocomplete = "one-time-code"; input.pattern = "[0-9]{6}"; input.maxLength = 6; input.required = true; input.setAttribute("aria-describedby", "viewer-cooldown"); label.htmlFor = input.id; label.append(input); const submit = el(doc, "button", "viewer-primary-action", "Verify code"); submit.type = "submit"; form.append(label, submit); form.addEventListener("submit", (event) => { event.preventDefault(); actions.onOtp(input.value); }); box.append(form); const cooldown = state.retryAfterSeconds !== undefined && state.retryAfterSeconds > 0 ? `You can request another code in ${state.retryAfterSeconds} seconds.` : "You can request a new code if it does not arrive."; const cooldownNode = el(doc, "p", "viewer-cooldown", cooldown); cooldownNode.id = "viewer-cooldown"; cooldownNode.setAttribute("aria-live", "polite"); box.append(cooldownNode); const resend = el(doc, "button", "viewer-secondary-action", "Resend email"); resend.type = "button"; resend.disabled = (state.retryAfterSeconds ?? 0) > 0; resend.setAttribute("aria-disabled", String(resend.disabled)); resend.addEventListener("click", actions.onResend); box.append(resend);
  }
  if (state.state === "claimed" || state.state === "session" || state.state === "reading") { const forget = el(doc, "button", "viewer-secondary-action", "Forget this browser key"); forget.type = "button"; forget.setAttribute("aria-label", "Forget the private browser key for this share"); forget.addEventListener("click", actions.onForget); box.append(forget); }
  root.append(box);
}

const UNSUPPORTED_COPY: Record<UnsupportedReason, { title: string; detail: string }> = {
  "policy-target": {
    title: "This share isn't supported in this build yet",
    detail:
      "It's an addressed share (policy target): opening it requires proving who you are, and that claim ceremony lands in a later stage. Nothing about this share was verified — this build only checked that the link decrypts.",
  },
  "recipient-did-target": {
    title: "This share isn't supported in this build yet",
    detail:
      "It's addressed to a specific key (recipient DID): opening it requires signing in with that key, which lands in a later stage. Nothing about this share was verified — this build only checked that the link decrypts.",
  },
  "prefix-resource": {
    title: "Folder shares aren't supported in this build yet",
    detail:
      "This link shares a folder (prefix resource). The folder browser lands in a later stage; this build renders single-file bearer shares only.",
  },
};

/**
 * Render the verified bearer single-file share. Returns the content
 * container so the caller (present.ts) can feed the decrypted file text
 * through render.ts's sanitization pipeline.
 */
function renderOk(
  root: HTMLElement,
  envelope: ShareEnvelope,
  hasContent: boolean,
  senderVerified = false,
): HTMLElement {
  root.replaceChildren();
  const doc = root.ownerDocument;

  // Top bar: filename · shared by <name> (unverified) · read-only
  const bar = el(doc, "header", "viewer-bar");
  bar.append(el(doc, "span", "viewer-filename", `\u{1F4C4} ${filenameOf(envelope)}`));
  const sender = envelope.display.senderName;
  bar.append(
    el(
      doc,
      "span",
      "viewer-sender",
      sender !== undefined && sender.length > 0
        ? `shared by ${sender}${senderVerified ? " (verified)" : " (unverified)"}`
        : senderVerified ? "shared by a verified TinyCloud sender" : "shared via link (sender unverified)",
    ),
  );
  bar.append(el(doc, "span", "viewer-mode", "read-only"));
  root.append(bar);

  // Bearer honesty note (§2.1: bearer shares are self-asserted; trust is
  // possession of the link, not sender identity — so no checkmark, ever).
  root.append(
    el(
      doc,
      "p",
      senderVerified ? "viewer-addressed-note" : "viewer-bearer-note",
      senderVerified ? "This file was addressed to the verified recipient policy. The browser key and read request stay local to this tab." : "Anyone with this link can open it. The sender name above comes from the link itself and is not independently verified.",
    ),
  );

  // Content area. When the resolve step recovered file text (stage 4:
  // verified, CID-checked, decrypted `content`), the container starts EMPTY
  // and the caller (present.ts) streams the text through render.ts's
  // sanitization pipeline. For pointer-less envelopes there are no bytes to
  // show — render an honest placeholder from the signed display metadata.
  //
  // HONESTY CONTRACT for this copy: this build verified, client-side, that
  // the envelope is signed and intact and that its embedded delegation is
  // BOUND to this link's key and NAMES read access to the target. Whether
  // a delegation chain actually authorizes a node read is the node's
  // decision at fetch time (the policy/recipient-DID slices) — so the copy
  // says "carries … naming read access", never "grants read access".
  const content = el(doc, "main", "viewer-content");
  if (!hasContent) {
    const placeholder = el(doc, "div", "viewer-placeholder");
    placeholder.append(
      el(doc, "h2", "viewer-placeholder-title", "Share link checks passed"),
      el(
        doc,
        "p",
        "viewer-placeholder-detail",
        `This link is intact and carries a delegation bound to its embedded key, naming read access to ${envelope.target.resource.path} on ${envelope.target.origin}.`,
      ),
      el(
        doc,
        "p",
        "viewer-placeholder-detail",
        "It doesn't include an embedded file preview, though — it was created without a content attachment. Ask the sender for a fresh link.",
      ),
    );
    content.append(placeholder);
  }
  root.append(content);

  // Footer: expiry + the agent-path bridge hint (blueprint §5
  // "Wireframe — viewer").
  const footer = el(doc, "footer", "viewer-footer");
  footer.append(
    el(doc, "span", "viewer-expiry", `Expires ${formatExpiry(envelope.expiry)}`),
  );
  const hint = el(doc, "div", "viewer-agent-hint");
  hint.append(
    el(
      doc,
      "p",
      "viewer-agent-hint-text",
      "\u{1F4A1} Want your agent to work with this doc? Paste the link into your agent — it'll know what to do.",
    ),
  );
  footer.append(hint);
  root.append(footer);

  return content;
}

/**
 * Render any resolve result. Returns the content container in the "ok"
 * state, null otherwise — the null is load-bearing: no content sink exists
 * unless every verification step passed.
 */
export function renderViewerState(
  root: HTMLElement,
  result: ResolveResult,
): HTMLElement | null {
  switch (result.state) {
    case "ok":
      return renderOk(root, result.envelope, result.content !== undefined, result.senderVerified);
    case "policy-email-claim-required":
      renderErrorState(root, "This invitation needs a confirmation", "The share envelope and exact recipient policy are verified. Open the document from the invitation link to continue.");
      return null;
    case "invalid-link":
      renderErrorState(
        root,
        "This isn't a valid share link",
        "Share links look like /s/<cid>#k=… — check you copied the whole link, including everything after the #.",
      );
      return null;
    case "fetch-failed":
      renderErrorState(
        root,
        "Couldn't fetch this share",
        "The registry didn't return the envelope — it may have been deleted, expired, or the registry is unreachable. Ask the sender for a fresh link.",
      );
      return null;
    case "cid-mismatch":
      renderErrorState(
        root,
        "This share failed its integrity check",
        "The registry returned bytes whose fingerprint doesn't match this link's address (CID mismatch). Refusing to decrypt or show anything.",
      );
      return null;
    case "decrypt-failed":
      renderErrorState(
        root,
        "Couldn't unlock this share",
        "The key in the link didn't decrypt the envelope — it's wrong, incomplete, or missing. Check you copied the whole link, including everything after #k=.",
      );
      return null;
    case "envelope-invalid":
      renderErrorState(
        root,
        "This share can't be read",
        "The envelope decrypted but isn't a valid share envelope. Refusing to show anything.",
      );
      return null;
    case "signature-invalid":
      renderErrorState(
        root,
        "This share failed verification",
        "The envelope's signature doesn't check out — it may have been tampered with. Refusing to show anything.",
      );
      return null;
    case "capability-invalid":
      renderErrorState(
        root,
        "This share's authorization doesn't add up",
        "The delegation inside this link can't be used by the link's own key, or doesn't cover the shared file. The link is malformed or was assembled incorrectly. Refusing to show anything.",
      );
      return null;
    case "expired":
      renderErrorState(
        root,
        "This share has expired",
        `It expired on ${formatExpiry(result.envelope.expiry)}. Ask the sender for a fresh link.`,
      );
      return null;
    case "content-fetch-failed":
      renderErrorState(
        root,
        "Couldn't fetch the shared file",
        "The share link verified, but the registry didn't return the file's encrypted bytes — they may have been deleted or expired, or the registry is unreachable. Ask the sender for a fresh link.",
      );
      return null;
    case "content-integrity-failed":
      renderErrorState(
        root,
        "The shared file failed its integrity check",
        "The registry returned bytes for this file that don't match the fingerprint signed into the share, or they couldn't be decrypted. Refusing to show anything.",
      );
      return null;
    case "unsupported": {
      const copy = UNSUPPORTED_COPY[result.reason];
      renderErrorState(root, copy.title, copy.detail);
      return null;
    }
  }
}
