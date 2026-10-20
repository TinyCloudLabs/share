/**
 * The names the shared sign-in puts in front of a person (`appName` in OpenKey's window and the sign-in statement,
 * `sessionPrefix`): what they may contain. A tiny module of its own so a caller that builds a name from untrusted
 * data (an app catalog) can ask `isSignInLabel` first and fall back to a fixed name, without loading OpenKey.
 */

/** A sign-in option outside what the helper allows (an expiry over an hour, a domain that is not a host name). */
export class SignInOptionError extends Error {
  constructor(option: string, detail: string) {
    super(`sign-in-option-${option}: ${detail}`);
    this.name = "SignInOptionError";
  }
}

/** Longest app name, session prefix or domain label the helper accepts, in characters. */
const MAX_LABEL_CHARS = 64;
/**
 * Characters a name may not contain, whatever they look like: control, format (zero-width, joiners, soft hyphen, word
 * joiner, bidi controls, tag characters), surrogate, private-use and unassigned code points, every space and
 * separator other than a plain U+0020, the fillers that render as blanks (Hangul and Mongolian), variation selectors,
 * and the combining grapheme joiner.
 */
const INVISIBLE_OR_SPACE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}\u3164\uffa0\u115f\u1160\u17b4\u17b5\u180e\u034f\ufe00-\ufe0f\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/u;
/** Look-alikes of the characters that make a link, folded to the real ones before the link check (NFKC folds the full-width forms; these it leaves alone). */
const LINK_LOOKALIKES: ReadonlyArray<readonly [RegExp, string]> = [
  [/[\u2215\u2044\u29f8\u2571\u2afd]/g, "/"],
  [/[\u2216\u29f5\u29f9\ufe68]/g, "\\"],
  [/[\ua789\u2236\u0589\ufe13]/g, ":"],
  [/[\u3002\u0589\u06d4\u0701\u0702\u1803\u2e3c]/g, "."],
];
const SCHEME_TOKEN = /(?:^|\s)[a-z][a-z0-9+.-]*:(?!\s|$)/i;
const RISKY_SCHEME = /\b(?:javascript|vbscript|data|mailto|tel|sms|file|blob|ftp|https?|wss?)\s*:/i;
/** A dotted name whose last label is letters (`evil.com`, `a.b.example`); a version such as `1.2` or `v2.0.1` has no letter label. */
const HOST_LIKE = /[\p{L}\p{N}_-]+\.\p{L}{2,}(?![\p{L}\p{N}_-])/iu;
const PATH_LIKE = /[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)+\//iu;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const IPV6 = /\[[0-9a-f:.]+\]|(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{1,4}|::/i;

/** True when `value` reads as a link or an address, once look-alike slashes, colons, dots and full-width forms are folded to the real ones. */
function looksLikeLink(value: string): boolean {
  let folded = value.normalize("NFKC");
  for (const [pattern, replacement] of LINK_LOOKALIKES) folded = folded.replace(pattern, replacement);
  return SCHEME_TOKEN.test(folded) || RISKY_SCHEME.test(folded) || folded.includes("//") || folded.includes("\\") || folded.includes("@")
    || HOST_LIKE.test(folded) || PATH_LIKE.test(folded) || IPV4.test(folded) || IPV6.test(folded);
}

/**
 * A name that goes into the sign-in statement or OpenKey's window: one short printable line, written the one way, that
 * does not read as a link. Nothing is trimmed or collapsed: a name that needs it is refused.
 */
export function checkLabel(option: string, value: string): void {
  if ([...value].length === 0 || [...value].length > MAX_LABEL_CHARS) throw new SignInOptionError(option, `1 to ${MAX_LABEL_CHARS} characters`);
  if (value.normalize("NFC") !== value) throw new SignInOptionError(option, "must be written in normalised (NFC) form");
  if (INVISIBLE_OR_SPACE.test(value.replaceAll(" ", ""))) throw new SignInOptionError(option, "no control, invisible, direction or special space characters");
  if (value.startsWith(" ") || value.endsWith(" ") || value.includes("  ")) throw new SignInOptionError(option, "no leading, trailing or repeated spaces");
  if (looksLikeLink(value)) throw new SignInOptionError(option, "must not look like a link or an address");
}


/** True when `value` is acceptable as an `appName` (see `checkLabel`). */
export function isSignInLabel(value: string): boolean {
  try { checkLabel("appName", value); return true; } catch { return false; }
}
