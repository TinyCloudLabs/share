/**
 * Strict request parsing (contract, strictness rule (d)): a JSON object with the same key twice, at any depth,
 * is refused. Keys are compared after unescaping, so `"a"` and `"\u0061"` are the same key. Keys are compared
 * as UTF-16 strings with no normalisation, as property names are.
 *
 * The scan is one pass over the text with an explicit stack: O(n) time, and O(n) space for the keys of the
 * objects that are open at once (each key is stored once). It does not validate the JSON; `JSON.parse` does
 * that, and a text that is not JSON is refused there.
 */

interface Frame {
  /** The keys of an open object; null for an array. */
  readonly keys: Set<string> | null;
  /** In an object: the next string is a key (after `{` and after `,`). */
  expectKey: boolean;
}

/** The index just past the string that opens at `start` (a `"`), or -1 when it never closes. */
function endOfString(text: string, start: number): number {
  for (let i = start + 1; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    if (ch === 0x5c) {
      i += 1;
    } else if (ch === 0x22) {
      return i + 1;
    }
  }
  return -1;
}

/** The characters of the string literal `text.slice(start, end)`, unescaped; null when an escape is not valid. */
function unescape(text: string, start: number, end: number): string | null {
  const literal = text.slice(start, end);
  if (!literal.includes("\\")) {
    return literal.slice(1, -1);
  }
  try {
    return JSON.parse(literal) as string;
  } catch {
    return null;
  }
}

/** True when some object in `text` repeats a key. */
export function hasDuplicateKey(text: string): boolean {
  const stack: Frame[] = [];
  let i = 0;
  while (i < text.length) {
    const ch = text.charCodeAt(i);
    const top = stack[stack.length - 1];
    if (ch === 0x22) {
      const end = endOfString(text, i);
      if (end < 0) {
        return false;
      }
      if (top?.keys && top.expectKey) {
        const key = unescape(text, i, end);
        if (key === null) {
          return false;
        }
        if (top.keys.has(key)) {
          return true;
        }
        top.keys.add(key);
        top.expectKey = false;
      }
      i = end;
      continue;
    }
    if (ch === 0x7b) {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === 0x5b) {
      stack.push({ keys: null, expectKey: false });
    } else if (ch === 0x7d || ch === 0x5d) {
      stack.pop();
    } else if (ch === 0x2c && top?.keys) {
      top.expectKey = true;
    }
    i += 1;
  }
  return false;
}
