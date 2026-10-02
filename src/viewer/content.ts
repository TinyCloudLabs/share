import { renderMarkdownInto, type RenderMarkdownOptions } from "./render.js";
import { createArtifactSandbox } from "./artifact-sandbox.js";
import { canonicalShareFilename } from "../filename-policy.js";

export type SafeContentKind = "markdown" | "text" | "image" | "html" | "file" | "download";

export const HTML_FRAME_CLASS = "viewer-html-frame";

export interface ContentDescriptor {
  readonly mediaType: string;
  readonly filename: string;
  readonly byteLength: number;
}

export interface SafeContentOptions extends RenderMarkdownOptions {
  /**
   * Link type that delivered the bytes; the only provenance HTML execution
   * may depend on (never a media type or filename). Only "bearer" renders
   * HTML: on addressed links the viewer's renderer process holds the
   * recipient's session key and email credential, which a sender's script
   * could target through side channels. Absent means no HTML execution.
   */
  readonly linkAccess?: "bearer" | "policy";
}

/** The browser must never decode or render bytes above the preview budget. */
export const MAX_SAFE_CONTENT_BYTES = 1 * 1024 * 1024;

const activeCleanup = new WeakMap<HTMLElement, () => void>();

function clearPreviousContent(container: HTMLElement): void {
  activeCleanup.get(container)?.();
  activeCleanup.delete(container);
  container.replaceChildren();
}

function formatBytes(size: number): string {
  if (size >= 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  if (size >= 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${size} bytes`;
}

function utf8(bytes: Uint8Array): string | undefined {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return undefined; }
}

export function classifyContent(descriptor: ContentDescriptor): SafeContentKind {
  const mediaType = descriptor.mediaType.split(";", 1)[0]?.toLowerCase() ?? "";
  // Signed `text/html` (addressed links) or an unsigned bearer key ending in
  // `.html`/`.htm` is a page. Whether it may run is decided by the link type
  // in renderSafeContent; it never reaches a viewer-origin sink.
  if (mediaType === "text/html" || (mediaType === "application/octet-stream" && /\.html?$/i.test(descriptor.filename))) return "html";
  if (mediaType === "image/svg+xml" || mediaType === "application/javascript") return "download";
  if (mediaType === "text/markdown" || /\.(?:md|markdown)$/i.test(descriptor.filename)) return "markdown";
  if (mediaType.startsWith("text/") || /\.(?:txt|csv|log|json|yaml|yml)$/i.test(descriptor.filename)) return "text";
  if (mediaType.startsWith("image/") && mediaType !== "image/svg+xml") return "image";
  return "file";
}

export async function renderSafeContent(container: HTMLElement, bytes: Uint8Array, descriptor: ContentDescriptor, options: SafeContentOptions = {}): Promise<SafeContentKind> {
  const actualDescriptor = { ...descriptor, filename: canonicalShareFilename(descriptor.filename), byteLength: bytes.byteLength };
  const kind = bytes.byteLength > MAX_SAFE_CONTENT_BYTES ? "download" : classifyContent(actualDescriptor);
  const doc = container.ownerDocument;
  if (kind === "markdown") {
    const source = utf8(bytes);
    if (source === undefined) {
      return renderDownloadContent(container, bytes, { ...actualDescriptor, mediaType: "application/octet-stream", filename: "shared-file.bin" }, "download");
    }
    clearPreviousContent(container);
    await renderMarkdownInto(container, source, "document", options);
    return kind;
  }
  if (kind === "text") {
    const source = utf8(bytes);
    if (source === undefined) {
      return renderDownloadContent(container, bytes, { ...actualDescriptor, mediaType: "application/octet-stream", filename: "shared-file.bin" }, "download");
    }
    clearPreviousContent(container);
    const pre = doc.createElement("pre"); pre.className = "viewer-source"; pre.textContent = source; container.append(pre); return kind;
  }
  if (kind === "html") {
    if (options.linkAccess !== "bearer") {
      return renderDownloadContent(container, bytes, actualDescriptor, "download", "Preview isn't available for this link type yet. Download it to open it.");
    }
    const source = utf8(bytes);
    if (source === undefined) {
      return renderDownloadContent(container, bytes, { ...actualDescriptor, mediaType: "application/octet-stream", filename: "shared-file.bin" }, "download");
    }
    clearPreviousContent(container);
    await renderHtmlPage(container, source, actualDescriptor.filename);
    return kind;
  }
  return renderDownloadContent(container, bytes, actualDescriptor, kind);
}

/**
 * The decrypted bytes travel to the sandbox only as a postMessage string that
 * becomes the child's `srcdoc`; the frame never fetches content. Rejects (and
 * leaves no frame behind) when the page does not load, so the caller's
 * fail-closed notice and the footer download remain the fallback.
 */
async function renderHtmlPage(container: HTMLElement, source: string, filename: string): Promise<void> {
  const doc = container.ownerDocument;
  const notice = doc.createElement("p");
  notice.className = "viewer-html-notice";
  notice.textContent = "This page comes from the sender and runs in an isolated frame. It can't read this link or your session, or make signed-in requests to this site. It can still reveal your IP address to the sender, for example through WebRTC.";
  container.append(notice);
  const sandbox = createArtifactSandbox(doc, {
    mount: container,
    className: HTML_FRAME_CLASS,
    title: `Shared page: ${filename}`,
    onFailure: () => {
      clearPreviousContent(container);
      const closed = doc.createElement("p");
      closed.className = "viewer-render-error";
      closed.textContent = "This page tried to open another page, so it was closed. Download it to open it.";
      container.append(closed);
    },
  });
  sandbox.iframe.hidden = false;
  activeCleanup.set(container, () => sandbox.destroy());
  try {
    await sandbox.renderDocument(source);
  } catch (error) {
    clearPreviousContent(container);
    throw error;
  }
}

function renderDownloadContent(container: HTMLElement, bytes: Uint8Array, descriptor: ContentDescriptor, kind: SafeContentKind = "file", detailText = kind === "download" ? "This file can't be previewed here. Download it to open it." : "Download it to open it."): SafeContentKind {
  clearPreviousContent(container);
  const doc = container.ownerDocument;
  const blob = new Blob([new Uint8Array(bytes).buffer], { type: descriptor.mediaType });
  const href = URL.createObjectURL(blob);
  let revoked = false;
  const revoke = (): void => { if (!revoked) { revoked = true; URL.revokeObjectURL(href); activeCleanup.delete(container); } };
  activeCleanup.set(container, revoke);
  if (kind === "image") {
    const image = doc.createElement("img"); image.className = "viewer-safe-image"; image.alt = descriptor.filename; image.src = href; image.addEventListener("load", revoke, { once: true }); image.addEventListener("error", revoke, { once: true }); container.append(image); return kind;
  }
  const note = doc.createElement("div"); note.className = "viewer-file-note"; const title = doc.createElement("h2"); title.textContent = `${descriptor.filename} — ${formatBytes(descriptor.byteLength)}`; const detail = doc.createElement("p"); detail.textContent = detailText; const link = doc.createElement("a"); link.href = href; link.download = descriptor.filename; link.textContent = "Download file"; link.addEventListener("click", revoke, { once: true }); note.append(title, detail, link); container.append(note); return kind;
}
