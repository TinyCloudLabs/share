/**
 * Present a resolve result: state chrome (ui.ts) + — for a verified share
 * that carried content — the decrypted file text through the full hostile
 * content pipeline (render.ts, mermaid behind the opaque-origin sandbox).
 * ONE glue function shared by the real entry (main.ts) and the e2e suite,
 * so the tested path IS the shipped path.
 */
import {
  ContentTooLargeError,
  renderMarkdownInto,
  type RenderMarkdownOptions,
} from "./render.js";
import type { ResolveResult } from "./resolve.js";
import { describeShare, renderViewerState, type ViewerStateOptions } from "./ui.js";
import { classifyContent, renderSafeContent, type SafeContentKind } from "./content.js";
import { mountArtifactChrome, type ArtifactChrome, type ArtifactChromeAction } from "./artifact-chrome.js";
import { copyWithFallback } from "../share/clipboard.js";
import { canonicalShareFilename } from "../filename-policy.js";
import { downloadMediaType, safeDownloadName } from "./download-name.js";

function downloadName(result: Extract<ResolveResult, { readonly state: "ok" }>): string {
  const metadata = (result.envelope as unknown as { readonly metadata?: { readonly filename?: unknown } }).metadata;
  if (typeof metadata?.filename === "string" && metadata.filename.length > 0) return canonicalShareFilename(metadata.filename);
  const candidate =
    result.envelope.display.filename ??
    (result.envelope.version === 1 ? result.envelope.target.resource.path : result.envelope.resource.path).split("/").at(-1) ??
    "shared-document.txt";
  return canonicalShareFilename(candidate);
}

function signedMediaType(result: Extract<ResolveResult, { readonly state: "ok" }>): string {
  const metadata = (result.envelope as unknown as { readonly metadata?: { readonly mediaType?: unknown } }).metadata;
  return typeof metadata?.mediaType === "string" && metadata.mediaType.length > 0 ? metadata.mediaType : result.content === undefined ? "application/octet-stream" : "text/plain;charset=utf-8";
}

function decodeMarkdown(bytes: Uint8Array): string | undefined {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return undefined; }
}

/**
 * Add the explicit post-render account import action. The callback is the only
 * place allowed to start OpenKey; callers therefore cannot accidentally put
 * account sign-in in front of the receiver ceremony.
 */
export function appendSaveToTinyCloudAction(
  root: HTMLElement,
  save: () => Promise<void>,
): void {
  const footer = root.querySelector<HTMLElement>(".viewer-footer");
  const hint = footer?.querySelector<HTMLElement>(".viewer-agent-hint");
  if (footer === null || footer === undefined || hint === null || hint === undefined
    || footer.querySelector(".viewer-save-to-tinycloud") !== null) return;
  const doc = root.ownerDocument;
  const button = doc.createElement("button");
  button.type = "button";
  button.className = "viewer-save-to-tinycloud";
  button.textContent = "Save a private copy";
  const status = doc.createElement("span");
  status.className = "viewer-save-status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  button.addEventListener("click", () => {
    button.disabled = true;
    status.setAttribute("role", "status");
    status.textContent = "Opening OpenKey…";
    void save().then(() => {
      button.textContent = "Saved to Files for you";
      status.textContent = "A private copy is now in your TinyCloud.";
    }).catch(() => {
      button.disabled = false;
      status.setAttribute("role", "alert");
      status.textContent = "We couldn't save a copy. Try again.";
    });
  });
  footer.insertBefore(button, hint);
  footer.insertBefore(status, hint);
}

export interface PresentShareOptions extends RenderMarkdownOptions, ViewerStateOptions {
  /** Offered only after verified bytes have rendered successfully. */
  readonly saveToTinyCloud?: () => Promise<void>;
}

type OkResult = Extract<ResolveResult, { readonly state: "ok" }>;

const activeChrome = new WeakMap<HTMLElement, ArtifactChrome>();

/** The bar's actions. Copy link needs the in-memory launch URL; Download needs verified bytes. */
function barActions(result: OkResult, shareUrl: string | undefined, markdown: () => string | undefined, kind: SafeContentKind): ArtifactChromeAction[] {
  const actions: ArtifactChromeAction[] = [];
  if (shareUrl !== undefined) {
    actions.push({
      label: "Copy link",
      icon: "link",
      doneLabel: "Copied",
      doneMessage: "Link copied",
      failMessage: "Couldn't copy the link. Allow clipboard access and try again.",
      // The private part of the link is gone from the address bar and is never stored.
      hint: "Keep this link: this page can't reopen the file by itself",
      run: () => copyWithFallback(shareUrl),
    });
  }
  if (markdown() !== undefined) {
    actions.push({
      label: "Copy text",
      icon: "copy",
      doneLabel: "Copied",
      doneMessage: "Text copied",
      failMessage: "Couldn't copy the text. Allow clipboard access and try again.",
      run: () => copyWithFallback(markdown() ?? ""),
    });
  }
  if (result.content !== undefined || result.contentBytes !== undefined) {
    // An unsafe signed filename gets no download control (filename policy). A safe
    // one is saved under an extension the viewer knows for this kind of content.
    let filename: string | undefined;
    try { filename = safeDownloadName(downloadName(result), kind, signedMediaType(result)); } catch { filename = undefined; }
    if (filename !== undefined) {
      const name = filename;
      actions.push({
        label: "Download",
        icon: "download",
        className: "viewer-download",
        failMessage: "Couldn't start the download.",
        run: () => {
          const blobBytes = result.contentBytes ?? new TextEncoder().encode(result.content ?? "");
          const blob = new Blob([new Uint8Array(blobBytes).buffer as ArrayBuffer], { type: downloadMediaType(kind) });
          const href = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = href;
          link.download = name;
          link.hidden = true;
          document.body.append(link);
          link.click();
          link.remove();
          URL.revokeObjectURL(href);
        },
      });
    }
  }
  actions.push({ label: "Share on", icon: "share", disabledReason: "The owner hasn't allowed passing this on yet" });
  return actions;
}

/**
 * Returns the content container when the share verified ("ok"), null for
 * every other state (fail closed: no content sink exists unless every
 * verification step passed — ui.ts invariant).
 */
export async function presentShare(
  root: HTMLElement,
  result: ResolveResult,
  options: PresentShareOptions = {},
): Promise<HTMLElement | null> {
  activeChrome.get(root)?.destroy();
  activeChrome.delete(root);
  const container = renderViewerState(root, result, options);
  if (container === null || result.state !== "ok") return container;

  // display.mode is a NARROWING-ONLY hint (viewer spec §1): "source" may
  // downgrade the presentation; anything else renders as a document.
  const mode = result.envelope.display.mode === "source" ? "source" : "document";
  const hasContent = result.content !== undefined || result.contentBytes !== undefined;
  let kind: SafeContentKind | undefined;
  if (result.contentBytes !== undefined) {
    try {
      kind = classifyContent({ mediaType: signedMediaType(result), filename: downloadName(result), byteLength: result.contentBytes.byteLength });
    } catch { kind = undefined; }
  } else if (result.content !== undefined) {
    kind = "markdown";
  }
  const markdownBytes = kind === "markdown" ? result.contentBytes : undefined;
  const markdownText = (): string | undefined => result.content ?? (markdownBytes === undefined ? undefined : decodeMarkdown(markdownBytes));

  // The verified bytes stay downloadable whatever happens to the preview
  // (oversize, render error, sandbox timeout or unavailable), so the bar is
  // mounted before, and independently of, the render.
  const described = describeShare(result.envelope, result.senderVerified);
  activeChrome.set(root, await mountArtifactChrome(root.ownerDocument, {
    shareId: result.envelope.shareId,
    title: described.title,
    provenance: described.provenance,
    expiry: described.expiry,
    actions: barActions(result, options.shareUrl, markdownText, kind ?? "file"),
    mount: root,
  }));
  if (!hasContent) return container;

  try {
    let renderedKind: SafeContentKind;
    if (result.contentBytes !== undefined) {
      renderedKind = await renderSafeContent(container, result.contentBytes, {
        mediaType: signedMediaType(result),
        filename: downloadName(result),
        byteLength: result.contentBytes.byteLength,
      }, { ...options, ...(result.access === undefined ? {} : { linkAccess: result.access }), shareId: result.envelope.shareId });
    } else {
      await renderMarkdownInto(container, result.content as string, mode, options);
      renderedKind = mode === "source" ? "text" : "markdown";
    }
    // Documents and pages own the whole area under the bar; everything else
    // (text, images, download notes) sits in a padded, scrolling column.
    container.classList.toggle("viewer-content--frame", renderedKind === "markdown" || renderedKind === "html" || renderedKind === "jsx");
    if (options.saveToTinyCloud !== undefined) {
      appendSaveToTinyCloudAction(root, options.saveToTinyCloud);
    }
  } catch (error) {
    // renderMarkdownInto throws before touching the DOM (oversize source,
    // node-count breach); leave a message, never partial content. Fail closed.
    container.replaceChildren();
    container.classList.remove("viewer-content--frame");
    const notice = root.ownerDocument.createElement("p");
    notice.className = "viewer-render-error";
    notice.textContent =
      error instanceof ContentTooLargeError
        ? "This document is too large to show here. Download it to read it."
        : "We couldn't display this document. Download it to open it.";
    container.append(notice);
  }
  return container;
}
