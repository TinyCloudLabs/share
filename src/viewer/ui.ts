/**
 * Viewer UI states — copy from sharing-ux-blueprint.md §5 "Flow 2a …
 * Wireframe — viewer" (NOT the viewer spec's §5, which is folder-listing
 * semantics); stage-3 bearer subset.
 *
 * All chrome is built with createElement/textContent — envelope-derived
 * strings (senderName, filename, paths) are ATTACKER-CONTROLLED and must
 * never travel through innerHTML. The only innerHTML sinks in the viewer
 * are the two sanitized outputs in render.ts.
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
 * container so the caller (stage 4's node read; tests today) can feed file
 * bytes through render.ts's sanitization pipeline.
 */
function renderOk(root: HTMLElement, envelope: ShareEnvelope): HTMLElement {
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
        ? `shared by ${sender} (unverified)`
        : "shared via link (sender unverified)",
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
      "viewer-bearer-note",
      "Anyone with this link can open it. The sender name above comes from the link itself and is not independently verified.",
    ),
  );

  // Content area. Stage 3 has no node-read client, so the envelope alone
  // cannot yield file bytes — render a placeholder from the signed display
  // metadata. Stage 4 replaces the placeholder by streaming the fetched
  // file through renderMarkdownInto(content, …).
  //
  // HONESTY CONTRACT for this copy: this build verified, client-side, that
  // the envelope is signed and intact and that its embedded delegation is
  // BOUND to this link's key and NAMES read access to the target. Whether
  // the delegation chain actually authorizes the read is the node's
  // decision at fetch time (stage 4) — so the copy says "carries … naming
  // read access", never "grants read access".
  const content = el(doc, "main", "viewer-content");
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
      "Content preview is coming in stage 4: the file is fetched from the node with the embedded session key, and the node independently verifies the delegation chain before serving it. This build checks and displays the share link itself.",
    ),
  );
  content.append(placeholder);
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
      return renderOk(root, result.envelope);
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
    case "unsupported": {
      const copy = UNSUPPORTED_COPY[result.reason];
      renderErrorState(root, copy.title, copy.detail);
      return null;
    }
  }
}
