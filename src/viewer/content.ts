import { renderMarkdownInto, type RenderMarkdownOptions } from "./render.js";

export type SafeContentKind = "markdown" | "text" | "image" | "file" | "download";

export interface ContentDescriptor {
  readonly mediaType: string;
  readonly filename: string;
  readonly byteLength: number;
}

/** The browser must never decode or render bytes above the preview budget. */
export const MAX_SAFE_CONTENT_BYTES = 1 * 1024 * 1024;

const activeCleanup = new WeakMap<HTMLElement, () => void>();

function clearPreviousContent(container: HTMLElement): void {
  activeCleanup.get(container)?.();
  activeCleanup.delete(container);
  container.replaceChildren();
}

function utf8(bytes: Uint8Array): string | undefined {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return undefined; }
}

export function classifyContent(descriptor: ContentDescriptor): SafeContentKind {
  const mediaType = descriptor.mediaType.split(";", 1)[0]?.toLowerCase() ?? "";
  if (mediaType === "text/html" || mediaType === "image/svg+xml" || mediaType === "application/javascript") return "download";
  if (mediaType === "text/markdown" || /\.(?:md|markdown)$/i.test(descriptor.filename)) return "markdown";
  if (mediaType.startsWith("text/") || /\.(?:txt|csv|log|json|yaml|yml)$/i.test(descriptor.filename)) return "text";
  if (mediaType.startsWith("image/") && mediaType !== "image/svg+xml") return "image";
  return "file";
}

export async function renderSafeContent(container: HTMLElement, bytes: Uint8Array, descriptor: ContentDescriptor, options: RenderMarkdownOptions = {}): Promise<SafeContentKind> {
  const actualDescriptor = { ...descriptor, byteLength: bytes.byteLength };
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
  return renderDownloadContent(container, bytes, actualDescriptor, kind);
}

function renderDownloadContent(container: HTMLElement, bytes: Uint8Array, descriptor: ContentDescriptor, kind: SafeContentKind = "file"): SafeContentKind {
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
  const note = doc.createElement("div"); note.className = "viewer-file-note"; const title = doc.createElement("h2"); title.textContent = kind === "download" ? "Preview disabled for safety" : "File ready"; const detail = doc.createElement("p"); detail.textContent = `${descriptor.filename} · ${descriptor.byteLength.toLocaleString()} bytes`; const link = doc.createElement("a"); link.href = href; link.download = descriptor.filename.replace(/[\\/\u0000-\u001f\u007f]/g, "") || "shared-file"; link.textContent = "Download file"; link.addEventListener("click", revoke, { once: true }); note.append(title, detail, link); container.append(note); return kind;
}
