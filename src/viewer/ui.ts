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
import type { ShareEnvelope, ShareEnvelopeV2, ShareEnvelopeV3 } from "@tinycloud/share-envelope";

import type { ResolveResult, UnsupportedReason } from "./resolve.js";
import { focusViewerRoot } from "./focus.js";
import { copyWithFallback } from "../share/link-only.js";

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

type PresentableEnvelope = ShareEnvelope | ShareEnvelopeV2 | ShareEnvelopeV3;

function filenameOf(envelope: PresentableEnvelope): string {
  const fromDisplay = envelope.display.filename;
  if (fromDisplay !== undefined && fromDisplay.length > 0) return fromDisplay;
  const path = envelope.version === 1 ? envelope.target.resource.path : envelope.resource.path;
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

/**
 * Every error state is a whole-page swap, so it must announce itself and take
 * focus: `role="alert"` makes assistive tech read it without waiting for
 * focus, and focusViewerRoot gives the keyboard user somewhere to be.
 * viewer.css already styles `.viewer-state[role="alert"]`.
 */
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
  focusViewerRoot(root);
}

const UNSUPPORTED_COPY: Record<UnsupportedReason, { title: string; detail: string }> = {
  "policy-target": {
    title: "We can't open this link",
    detail:
      "We couldn't read who this was shared with, so nothing was opened. Ask the sender for a fresh link.",
  },
  "recipient-did-target": {
    title: "We can't open this link",
    detail:
      "Sign-in-with-a-key shares aren't supported yet. Ask the sender to share it by email instead.",
  },
  "prefix-resource": {
    title: "Folder sharing isn't available yet",
    detail:
      "Ask the sender to share the files individually.",
  },
};

/**
 * Render the verified bearer single-file share. Returns the content
 * container so the caller (present.ts) can feed the decrypted file text
 * through render.ts's sanitization pipeline.
 */
function renderOk(
  root: HTMLElement,
  envelope: PresentableEnvelope,
  hasContent: boolean,
  access: "bearer" | "policy",
  senderVerified = false,
  shareUrl?: string,
): HTMLElement {
  root.replaceChildren();
  const doc = root.ownerDocument;

  // Compact provenance: filename, sender trust, and access mode. This stays
  // visually subordinate to the document the recipient came here to read.
  const bar = el(doc, "header", "viewer-bar");
  bar.append(el(doc, "span", "viewer-filename", filenameOf(envelope)));
  const sender = envelope.display.senderName;
  bar.append(
    el(
      doc,
      "span",
      "viewer-sender",
      sender !== undefined && sender.length > 0
        ? `${sender} · ${senderVerified ? "verified sender" : "sender unverified"}`
        : senderVerified ? "Verified sender" : "Sender unverified",
    ),
  );
  bar.append(el(doc, "span", "viewer-mode", "Read-only"));
  root.append(bar);

  // Bearer honesty note (§2.1: bearer shares are self-asserted; trust is
  // possession of the link, not sender identity — so no checkmark, ever).
  root.append(
    el(
      doc,
      "p",
      access === "policy" ? "viewer-addressed-note" : "viewer-bearer-note",
      access === "policy" ? "Access checked for the approved recipient." : "Anyone with the link can open it.",
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
  // a chain actually authorizes a node read is the node's decision at fetch
  // time — so the copy says the LINK is valid, never that access is granted.
  // The recipient is not told the sender's internal path or node origin.
  const content = el(doc, "main", "viewer-content");
  if (!hasContent) {
    const placeholder = el(doc, "div", "viewer-placeholder");
    placeholder.append(
      el(doc, "h2", "viewer-placeholder-title", "Link verified"),
      el(
        doc,
        "p",
        "viewer-placeholder-detail",
        "This link is valid, but it doesn't include the file itself.",
      ),
      el(
        doc,
        "p",
        "viewer-placeholder-detail",
        "Ask the sender to share it again.",
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
  // The opened view keeps a visible Copy link (user amendment 2026-07-24).
  // Reloading /s/<cid> without the scrubbed `#k=` fails, so the recipient
  // needs a safe way to keep the working link. The complete URL lives only in
  // this closure: never as text, an href, or any other DOM attribute.
  if (shareUrl !== undefined) {
    const copyStatus = el(doc, "span", "viewer-copy-status", "");
    copyStatus.id = "viewer-copy-status";
    copyStatus.setAttribute("role", "status");
    copyStatus.setAttribute("aria-live", "polite");
    // The warning §6.2 asks for: the key fragment is scrubbed from the address
    // bar on purpose, so the URL on screen will NOT reopen this document.
    const hint = el(doc, "span", "viewer-copy-hint", "The address bar no longer holds this link — copy it if you need to open this again.");
    hint.id = "viewer-copy-hint";
    const copy = el(doc, "button", "viewer-copy-link", "Copy link");
    copy.type = "button";
    copy.setAttribute("aria-describedby", `${hint.id} ${copyStatus.id}`);
    copy.addEventListener("click", () => {
      void copyWithFallback(shareUrl)
        .then(() => { copyStatus.removeAttribute("role"); copyStatus.textContent = "Link copied."; })
        .catch(() => { copyStatus.setAttribute("role", "alert"); copyStatus.textContent = "Copy failed. Allow clipboard access and try again."; });
    });
    footer.append(copy, hint, copyStatus);
  }
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
  focusViewerRoot(root);

  return content;
}

/**
 * Render any resolve result. Returns the content container in the "ok"
 * state, null otherwise — the null is load-bearing: no content sink exists
 * unless every verification step passed.
 */
export interface ViewerStateOptions {
  /**
   * Complete launch URL, held in memory only, for the opened view's Copy link
   * action. Never rendered.
   */
  readonly shareUrl?: string;
}

export function renderViewerState(
  root: HTMLElement,
  result: ResolveResult,
  options: ViewerStateOptions = {},
): HTMLElement | null {
  switch (result.state) {
    case "ok":
      return renderOk(root, result.envelope, result.content !== undefined, result.access ?? "bearer", result.senderVerified, options.shareUrl);
    case "policy-email-claim-required":
      renderErrorState(root, "Confirm your email to open this", "Open this document from the link in the invitation email the sender asked us to send.");
      return null;
    case "policy-v2-claim-required":
      renderErrorState(root, "Confirm your email to open this", "The sender shared this with you. Confirming takes about 30 seconds.");
      return null;
    case "recipient-did-authorization-required":
      renderErrorState(root, "Confirm this OpenKey device", "Continue with OpenKey to confirm the current session before opening this share.");
      return null;
    case "invalid-link":
      renderErrorState(
        root,
        "This link is incomplete",
        "Part of the link is missing. Copy the whole thing from the message you received — it needs everything after the #.",
      );
      return null;
    case "fetch-failed":
      renderErrorState(
        root,
        "This share isn't available",
        "This share isn't available any more — it may have expired or been removed. Ask the sender to share it again.",
      );
      return null;
    case "cid-mismatch":
      renderErrorState(
        root,
        "This share failed its integrity check",
        "This share doesn't match its link. We won't open it. Ask the sender for a fresh link.",
      );
      return null;
    case "decrypt-failed":
      renderErrorState(
        root,
        "Couldn't unlock this share",
        "We couldn't unlock this. Copy the whole link from the message you received and try again.",
      );
      return null;
    case "envelope-invalid":
      renderErrorState(
        root,
        "This share can't be read",
        "We couldn't read this share. Ask the sender for a fresh link.",
      );
      return null;
    case "signature-invalid":
      renderErrorState(
        root,
        "This share failed verification",
        "This share failed its security check — it may have been altered. We won't open it.",
      );
      return null;
    case "capability-invalid":
      renderErrorState(
        root,
        "We can't open this link",
        "This link isn't put together correctly. Ask the sender for a fresh one.",
      );
      return null;
    case "expired":
      renderErrorState(
        root,
        "This share has expired",
        `It expired on ${formatExpiry(result.expiresAt)}. Ask the sender for a fresh link.`,
      );
      return null;
    case "content-fetch-failed":
      renderErrorState(
        root,
        "The file isn't available",
        "The file isn't available any more. Ask the sender to share it again.",
      );
      return null;
    case "content-integrity-failed":
      renderErrorState(
        root,
        "The shared file failed its integrity check",
        "This file doesn't match what was shared. We won't open it.",
      );
      return null;
    case "unsupported": {
      const copy = UNSUPPORTED_COPY[result.reason];
      renderErrorState(root, copy.title, copy.detail);
      return null;
    }
  }
}
