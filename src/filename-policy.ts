/**
 * Characters that can hide or visually reorder a filename are not safe at a
 * signed resource or presentation boundary. Reject every Unicode control,
 * format, and surrogate code point, plus the line/paragraph separators that
 * JavaScript does not classify as Cc. This includes the bidi embedding and
 * isolation ranges U+202A-U+202E and U+2066-U+2069.
 */
const UNSAFE_FILENAME_CODE_POINT = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;

export function hasUnsafeFilenameCodePoint(value: string): boolean {
  return UNSAFE_FILENAME_CODE_POINT.test(value);
}

/** A single display/download filename, never a path. */
export function canonicalShareFilename(value: string): string {
  const canonical = value.normalize("NFC");
  if (
    canonical.length === 0
    || canonical === "."
    || canonical === ".."
    || canonical.includes("/")
    || canonical.includes("\\")
    || hasUnsafeFilenameCodePoint(canonical)
  ) {
    throw new TypeError("share filename is unsafe");
  }
  return canonical;
}
