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
import type { RecipientDidEnvelopeV2, ShareEnvelope } from "@tinycloud/share-envelope";

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

function filenameOf(envelope: ViewerEnvelope): string {
  const fromDisplay = envelope.display.filename;
  if (fromDisplay !== undefined && fromDisplay.length > 0) return fromDisplay;
  const path = envelope.target.resource.path;
  return path.split("/").pop() ?? path;
}

type ViewerEnvelope = ShareEnvelope | RecipientDidEnvelopeV2;

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
  box.setAttribute("role", "status");
  box.setAttribute("aria-live", "polite");
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

export function renderRecipientIdentityLoading(root: HTMLElement): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "div", "viewer-state viewer-resolving");
  box.setAttribute("role", "status");
  box.setAttribute("aria-live", "polite");
  box.append(
    el(doc, "h1", "viewer-state-title", "Checking your account…"),
    el(
      doc,
      "p",
      "viewer-state-detail",
      "Rechecking the verified destination before opening secure account selection.",
    ),
  );
  root.append(box);
}

function renderErrorState(root: HTMLElement, title: string, detail: string): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "div", "viewer-state viewer-error");
  box.setAttribute("role", "alert");
  box.append(
    el(doc, "h1", "viewer-state-title", title),
    el(doc, "p", "viewer-state-detail", detail),
  );
  root.append(box);
}

function renderRecipientActionState(
  root: HTMLElement,
  envelope: RecipientDidEnvelopeV2,
  title: string,
  detail: string,
  label: string,
  onSelectAccount: (() => void) | undefined,
): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "section", "viewer-state viewer-recipient-action");
  box.setAttribute("aria-labelledby", "recipient-action-title");
  const heading = el(doc, "h1", "viewer-state-title", title);
  heading.id = "recipient-action-title";
  const description = el(doc, "p", "viewer-state-detail", detail);
  const facts = el(doc, "dl", "viewer-share-facts");
  const appendFact = (label: string, value: string): void => {
    facts.append(
      el(doc, "dt", "viewer-share-fact-label", label),
      el(doc, "dd", "viewer-share-fact-value", value),
    );
  };
  appendFact("File", filenameOf(envelope));
  appendFact(
    "From",
    envelope.display.senderName !== undefined && envelope.display.senderName.length > 0
      ? `${envelope.display.senderName} (verified sender)`
      : "Verified TinyCloud sender",
  );
  appendFact(
    "For",
    envelope.display.recipientHint !== undefined && envelope.display.recipientHint.length > 0
      ? envelope.display.recipientHint
      : "The account selected by the sender",
  );
  appendFact("Access", "Read-only");
  appendFact("Expires", formatExpiry(envelope.expiry));
  const button = el(doc, "button", "viewer-primary-action", label);
  button.type = "button";
  button.disabled = onSelectAccount === undefined;
  if (onSelectAccount !== undefined) button.addEventListener("click", onSelectAccount);
  box.append(heading, description, facts, button);
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
  envelope: ViewerEnvelope,
  hasContent: boolean,
  senderVerified: boolean,
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
        : senderVerified ? "shared by a verified TinyCloud account" : "shared via link (sender unverified)",
    ),
  );
  bar.append(el(doc, "span", "viewer-mode", "read-only"));
  root.append(bar);

  // Bearer honesty note (§2.1: bearer shares are self-asserted; trust is
  // possession of the link, not sender identity — so no checkmark, ever).
  root.append(el(
    doc,
    "p",
    senderVerified ? "viewer-addressed-note" : "viewer-bearer-note",
    senderVerified
      ? "This file was addressed to your account. Its sender and read-only access were verified before sign-in."
      : "Anyone with this link can open it. The sender name above comes from the link itself and is not independently verified.",
  ));

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
  actions: { onSelectRecipientAccount?: () => void } = {},
): HTMLElement | null {
  switch (result.state) {
    case "ok":
      return renderOk(root, result.envelope, result.content !== undefined, result.senderVerified);
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
    case "recipient-adapter-unavailable":
      renderErrorState(
        root,
        "Addressed shares aren't available in this build",
        "This link is for one specific account, but this viewer doesn't include the required account and TinyCloud connection yet. No sign-in or storage service was contacted.",
      );
      return null;
    case "recipient-verification-failed":
      renderErrorState(
        root,
        "This share failed verification",
        "The sender, destination, or read permission couldn't be verified. No account or storage service was contacted.",
      );
      return null;
    case "recipient-identity-required":
      renderRecipientActionState(
        root,
        result.envelope,
        "Open this shared file",
        "The sender and read-only access check out. Choose the account this file was addressed to.",
        "Choose account",
        actions.onSelectRecipientAccount,
      );
      return null;
    case "recipient-wrong-account":
      renderRecipientActionState(
        root,
        result.envelope,
        "This file is for a different account",
        "Nothing was requested from the sender's storage. Switch to the account named by the sender, or ask them to share it with this account.",
        "Switch account",
        actions.onSelectRecipientAccount,
      );
      return null;
    case "recipient-identity-cancelled":
      renderRecipientActionState(
        root,
        result.envelope,
        "Account selection was cancelled",
        "The file is still unopened. You can try again when you're ready.",
        "Try again",
        actions.onSelectRecipientAccount,
      );
      return null;
    case "recipient-node-unauthorized":
      renderErrorState(
        root,
        "Access is no longer available",
        "The sender's storage refused this read. The share may have expired or been revoked; ask the sender for a fresh link.",
      );
      return null;
    case "recipient-node-not-found":
      renderErrorState(
        root,
        "The shared file wasn't found",
        "The verified location no longer contains this file. Ask the sender to share it again.",
      );
      return null;
    case "recipient-node-unavailable":
      renderErrorState(
        root,
        "Couldn't reach the sender's storage",
        "Your account matched, but the verified storage service is unavailable. Check your connection and try this link again.",
      );
      return null;
    case "recipient-content-invalid":
      renderErrorState(
        root,
        "This file can't be displayed safely",
        "The sender's storage returned content that isn't valid text, so nothing is shown.",
      );
      return null;
    case "recipient-continuation-expired":
      renderErrorState(
        root,
        "This verification timed out",
        "For your security, account selection must start soon after the link is checked. Open the original share link again to retry. No account or storage service was contacted.",
      );
      return null;
    case "recipient-expired":
      renderErrorState(
        root,
        "This share has expired",
        `It expired on ${formatExpiry(result.envelope.expiry)}. Ask the sender for a fresh link. No account or storage service was contacted.`,
      );
      return null;
    case "unsupported": {
      const copy = UNSUPPORTED_COPY[result.reason];
      renderErrorState(root, copy.title, copy.detail);
      return null;
    }
  }
}
