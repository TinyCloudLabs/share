import { canonicalShareFilename } from "../filename-policy.js";
import type { SafeContentKind } from "./content.js";

/**
 * The name a downloaded copy is saved under. The share's own filename is
 * attacker-controlled data, so after the share filename policy (no path, control
 * or bidi characters) the saved name must also not claim a type the viewer
 * never showed: `report.md.exe` is saved as `report.md.exe.md`.
 */
const MAX_NAME_CODE_POINTS = 120;

/** Final extensions that can run or install when opened. Never kept, whatever the kind. */
const EXECUTABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  "exe", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs", "js", "jar", "sh", "app", "dmg", "lnk", "hta", "apk",
]);

/** Extensions the viewer itself renders or knows, per kind of content, and the one appended otherwise. */
const KIND_EXTENSIONS: Readonly<Record<SafeContentKind, { readonly allowed: readonly string[]; readonly canonical: string }>> = {
  markdown: { allowed: ["md", "markdown"], canonical: "md" },
  html: { allowed: ["html", "htm"], canonical: "html" },
  text: { allowed: ["txt", "csv", "log", "json", "yaml", "yml"], canonical: "txt" },
  image: { allowed: ["png", "jpg", "jpeg", "gif", "webp", "avif"], canonical: "png" },
  file: { allowed: ["bin", "pdf", "png", "jpg", "jpeg", "gif", "webp", "avif", "txt", "csv", "json", "md", "markdown", "html", "htm"], canonical: "bin" },
  download: { allowed: ["bin", "pdf", "png", "jpg", "jpeg", "gif", "webp", "avif", "txt", "csv", "json", "md", "markdown", "html", "htm"], canonical: "bin" },
};
const IMAGE_BY_SUBTYPE: Readonly<Record<string, string>> = { png: "png", jpeg: "jpg", gif: "gif", webp: "webp", avif: "avif" };

/** The Blob type a downloaded copy gets: forced from the kind, never a sender-chosen one. */
export function downloadMediaType(kind: SafeContentKind): string {
  if (kind === "markdown") return "text/markdown;charset=utf-8";
  if (kind === "text") return "text/plain;charset=utf-8";
  // Never text/html: a Blob typed as a page must not be openable as one.
  return "application/octet-stream";
}

/** Throws (like `canonicalShareFilename`) when the share's name is unsafe: such a share gets no download. */
export function safeDownloadName(name: string, kind: SafeContentKind, signedMediaType = ""): string {
  // A missing name is not an unsafe one: save it under a neutral name.
  const shown = name === "" ? "" : canonicalShareFilename(name);
  // No hidden files, trailing dots or spaces, or runs of dots.
  const tidy = shown.replace(/\.{2,}/g, ".").replace(/^[.\s]+|[.\s]+$/g, "");
  const spec = KIND_EXTENSIONS[kind];
  const subtype = /^image\/([a-z0-9.+-]+)/i.exec(signedMediaType)?.[1]?.toLowerCase() ?? "";
  const canonical = kind === "image" ? IMAGE_BY_SUBTYPE[subtype] ?? spec.canonical : spec.canonical;
  if (tidy.length === 0) return `artifact.${canonical}`;

  const dot = tidy.lastIndexOf(".");
  const finalExtension = dot > 0 ? tidy.slice(dot + 1).toLowerCase() : "";
  const keep = finalExtension.length > 0 && spec.allowed.includes(finalExtension) && !EXECUTABLE_EXTENSIONS.has(finalExtension);
  const stem = keep ? tidy.slice(0, dot) : tidy;
  const extension = keep ? tidy.slice(dot + 1) : canonical;

  // Truncate the stem, never the extension, and never in the middle of a character.
  const room = Math.max(1, MAX_NAME_CODE_POINTS - extension.length - 1);
  const points = Array.from(stem);
  const kept = points.length > room ? points.slice(0, room).join("").replace(/[.\s]+$/, "") : stem;
  return `${kept.length === 0 ? "artifact" : kept}.${extension}`;
}
