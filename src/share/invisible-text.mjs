/**
 * What counts as invisible text: the ONE definition the sign-in labels, the Details sheet's manifest check and the
 * catalog check all use. A plain .mjs file (with a .d.mts beside it) so the build-time scripts can import it as well as the page.
 */

/**
 * Characters a displayed name may not contain, whatever they look like: control (U+0085 included), format (zero-width,
 * joiners, soft hyphen, word joiner, bidi controls, tag characters), surrogate, private-use and unassigned code points,
 * every space and separator other than a plain U+0020, the fillers that render as blanks (Hangul and Mongolian),
 * variation selectors, and the combining grapheme joiner.
 */
export const INVISIBLE_OR_SPACE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}\u0085\u3164\uffa0\u115f\u1160\u17b4\u17b5\u180e\u034f\ufe00-\ufe0f\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/u;

/** True when `value` holds any invisible character or any space other than a plain U+0020. */
export function hasInvisibleOrSpecialSpace(value) {
  return INVISIBLE_OR_SPACE.test(value.replaceAll(" ", ""));
}

/** True for text a person can see and read: something besides plain spaces, and nothing invisible or oddly spaced. */
export function isVisibleText(value) {
  return typeof value === "string" && value.replaceAll(" ", "") !== "" && !hasInvisibleOrSpecialSpace(value);
}
