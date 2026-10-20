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
import { canonicalShareFilename } from "../filename-policy.js";

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
  if (fromDisplay !== undefined && fromDisplay.length > 0) return canonicalShareFilename(fromDisplay);
  const path = envelope.version === 1 ? envelope.target.resource.path : envelope.resource.path;
  return canonicalShareFilename(path.split("/").pop() ?? path);
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

interface StateCopy {
  /** Short state label shown in the chip above the title. */
  readonly label?: string;
  readonly tone?: "danger" | "warning" | "info";
}

/**
 * Every error state is a whole-page swap, so it must announce itself and take
 * focus: `role="alert"` makes assistive tech read it without waiting for
 * focus, and focusViewerRoot gives the keyboard user somewhere to be. The
 * card carries its state as text (the chip), never colour alone.
 */
function renderErrorState(root: HTMLElement, title: string, detail: string, copy: StateCopy = {}): HTMLElement {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const box = el(doc, "div", "viewer-state tc-panel");
  box.setAttribute("role", "alert");
  const tone = copy.tone ?? "danger";
  box.dataset["tone"] = tone;
  if (copy.label !== undefined) box.append(el(doc, "p", `tc-status tc-status--${tone} viewer-state-chip`, copy.label));
  box.append(
    el(doc, "h1", "viewer-state-title", title),
    el(doc, "p", "viewer-state-detail", detail),
  );
  root.append(box);
  focusViewerRoot(root);
  return box;
}

export type ShareUnavailableReason = "revoked" | "expired" | "unavailable";

/**
 * A bearer link that did not open. These are the only reasons that get their
 * own screen; each is honest about what happened and none of them leaves any
 * content in the DOM (there is no content sink outside renderOk).
 */
export function renderShareUnavailable(root: HTMLElement, reason: ShareUnavailableReason, expiresAt?: string, retry?: () => void): void {
  root.ownerDocument.body.classList.remove("viewer-fullpage");
  if (reason === "revoked") {
    renderErrorState(root, "This share was revoked by its sender", "The link no longer opens anything. If you still need the file, ask the sender for a new link.", { label: "Revoked", tone: "danger" });
    return;
  }
  if (reason === "expired") {
    renderErrorState(root, expiresAt === undefined ? "This share has expired" : `This share expired on ${formatExpiry(expiresAt)}`, "Shares stop working at the time the sender chose. Ask the sender for a fresh link.", { label: "Expired", tone: "warning" });
    return;
  }
  const box = renderErrorState(root, "TinyCloud is temporarily unavailable", "Nothing was opened. This is usually brief. Try again in a moment.", { label: "Unavailable", tone: "info" });
  if (retry === undefined) return;
  const button = el(root.ownerDocument, "button", "tc-button tc-button--primary viewer-state-action", "Try again");
  button.type = "button";
  button.addEventListener("click", retry);
  box.append(button);
}

const UNSUPPORTED_COPY: Record<UnsupportedReason, { title: string; detail: string }> = {
  "policy-target": {
    title: "We can't open this link",
    detail:
      "We couldn't read who this was shared with, so nothing was opened. Ask the sender for a fresh link.",
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
function renderOk(root: HTMLElement, hasContent: boolean): HTMLElement {
  root.replaceChildren();
  const doc = root.ownerDocument;

  // Content area. When the resolve step recovered file text (stage 4:
  // verified, CID-checked, decrypted `content`), the container starts EMPTY
  // and the caller (present.ts) streams the text through render.ts's
  // sanitization pipeline. For pointer-less envelopes there are no bytes to
  // show — render an honest placeholder from the signed display metadata.
  // The bar (title, provenance, expiry, actions) is mounted by present.ts.
  //
  // HONESTY CONTRACT for this copy: this build verified, client-side, that
  // the envelope is signed and intact and that its embedded delegation is
  // BOUND to this link's key and NAMES read access to the target. Whether
  // a chain actually authorizes a node read is the node's decision at fetch
  // time — so the copy says the LINK is valid, never that access is granted.
  // The recipient is not told the sender's internal path or node origin.
  const content = el(doc, "main", "viewer-content");
  if (!hasContent) {
    const placeholder = el(doc, "div", "viewer-placeholder tc-panel");
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
  focusViewerRoot(root);
  return content;
}

/** What the bar shows about a verified share: name, who vouches for it, and when it ends. */
export function describeShare(envelope: PresentableEnvelope, senderVerified: boolean): { readonly title: string; readonly provenance: string; readonly expiry: { readonly text: string; readonly datetime: string } } {
  const sender = envelope.display.senderName;
  const provenance = sender !== undefined && sender.length > 0
    ? `${sender} · ${senderVerified ? "verified sender" : "sender unverified"}`
    : senderVerified ? "Verified sender" : "Sender unverified";
  const expiry = Date.parse(envelope.expiry);
  return {
    title: filenameOf(envelope),
    provenance,
    expiry: { text: formatExpiry(envelope.expiry), datetime: Number.isNaN(expiry) ? envelope.expiry : new Date(expiry).toISOString() },
  };
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
  root.ownerDocument.body.classList.toggle("viewer-fullpage", result.state === "ok");
  switch (result.state) {
    case "ok":
      return renderOk(root, result.content !== undefined);
    case "policy-authorization-required":
      renderErrorState(root, "Confirm your identity to open this", "The sender shared this with you. Confirming takes about 30 seconds.");
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
    case "expired":
      renderErrorState(
        root,
        "This share has expired",
        `It expired on ${formatExpiry(result.expiresAt)}. Ask the sender for a fresh link.`,
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
