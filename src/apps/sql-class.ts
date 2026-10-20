/**
 * Classifies the SQL an installed app sends through the runner's bridge.
 *
 * tinycloud-node authorises SQL by the ABILITY a delegation carries (read /
 * write / schema), not by which call the client used: on v1.20.6 and v1.21.0 a
 * `DROP TABLE` sent to the query endpoint with a write-capable delegation
 * executes, and TC-1581 (sql/write permits DDL) is not fixed on the node this
 * runner talks to. So the runner page classifies every statement itself, before
 * the manifest is consulted, and refuses what it cannot classify.
 *
 *   "read"    exactly ONE statement: SELECT, VALUES, a read-only WITH ... SELECT,
 *             or EXPLAIN [QUERY PLAN] of one of those
 *   "write"   exactly ONE INSERT / UPDATE / DELETE / REPLACE (also WITH ... INSERT|UPDATE|DELETE)
 *   "schema"  exactly ONE CREATE / DROP / ALTER / REINDEX
 *   null      anything else: empty or unterminated text, more than one statement
 *             (a `;` outside literals and comments, except one trailing), PRAGMA,
 *             ATTACH, DETACH, VACUUM, load_extension anywhere (also as a quoted
 *             function name), WITH ... with a schema or maintenance word, a first
 *             word that is none of the above, a NUL byte, or any non-ASCII
 *             character outside a literal, identifier quote or comment.
 *
 * `sql.query` accepts only "read"; `sql.execute` accepts "write" and "schema".
 * (A CREATE TRIGGER body holds `;`, so it counts as several statements and is
 * refused: an app creates triggers with a different design, not through here.)
 *
 * Reference: classifySql in the kit's examples/sample-healthlog/dev/shim.mjs. This
 * version also (a) unquotes identifiers before looking for load_extension, so
 * `"load_extension"(...)` and `[load_extension](...)` are refused, (b) refuses the
 * characters SQLite does not treat as whitespace but JavaScript does (U+00A0,
 * U+2028, ...) instead of letting the two parsers disagree about where a word or
 * statement ends, and (c) treats the maintenance words as refused wherever they
 * appear, not only first.
 */

export type SqlClass = "read" | "write" | "schema";

/** Longest statement the classifier looks at (the bridge's message cap is far larger). */
export const MAX_SQL_CHARS = 200_000;

interface Scanned {
  /** The text with comments replaced by a space and string / quoted-identifier bodies emptied. */
  readonly code: string;
  /** Bodies of quoted identifiers (`"a"`, `` `a` ``, `[a]`), unescaped. */
  readonly identifiers: readonly string[];
}

/** SQLite's whitespace: nothing else separates tokens. */
const SQLITE_SPACE = new Set([" ", "\t", "\n", "\f", "\r"]);

/** Comments become a space, literals are emptied; null when a literal or block comment is unterminated or the text has a NUL. */
function scan(text: string): Scanned | null {
  let code = "";
  const identifiers: string[] = [];
  for (let i = 0; i < text.length; ) {
    const c = text.charAt(i);
    const n = text.charAt(i + 1);
    if (c === "\0") return null;
    if (c === "-" && n === "-") {
      const end = text.indexOf("\n", i);
      i = end === -1 ? text.length : end + 1;
      code += " ";
    } else if (c === "/" && n === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end === -1) return null;
      i = end + 2;
      code += " ";
    } else if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      let body = "";
      for (;;) {
        if (j >= text.length) return null;
        if (text.charAt(j) === c) {
          if (text.charAt(j + 1) === c) { body += c; j += 2; } else break; // a doubled quote is an escaped quote
        } else { body += text.charAt(j); j += 1; }
      }
      if (c !== "'") identifiers.push(body);
      code += `${c}${c}`;
      i = j + 1;
    } else if (c === "[") {
      const end = text.indexOf("]", i + 1);
      if (end === -1) return null;
      identifiers.push(text.slice(i + 1, end));
      code += '""';
      i = end + 1;
    } else {
      code += c;
      i += 1;
    }
  }
  return { code, identifiers };
}

/** True when `code` holds a character SQLite and JavaScript could read differently. */
function hasAmbiguousCharacter(code: string): boolean {
  for (let i = 0; i < code.length; i += 1) {
    const point = code.charCodeAt(i);
    if (point > 0x7e) return true;
    if (point < 0x20 && !SQLITE_SPACE.has(code.charAt(i))) return true;
    if (point === 0x7f) return true;
  }
  return false;
}

/** Words that are never allowed in a statement the bridge runs, wherever they appear. */
const REFUSED_WORDS: readonly string[] = ["LOAD_EXTENSION", "PRAGMA", "ATTACH", "DETACH", "VACUUM"];
const DDL_WORDS: readonly string[] = ["CREATE", "DROP", "ALTER", "REINDEX"];

export function classifySql(text: unknown): SqlClass | null {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_SQL_CHARS) return null;
  const scanned = scan(text);
  if (scanned === null || hasAmbiguousCharacter(scanned.code)) return null;
  // One statement: drop a single trailing `;`, then no other `;` may remain.
  const body = scanned.code.replace(/;[ \t\n\f\r]*$/, "").replace(/^[ \t\n\f\r]+|[ \t\n\f\r]+$/g, "");
  if (body === "" || body.includes(";") || !/^[A-Za-z]/.test(body)) return null;
  const words = (body.match(/[A-Za-z_][A-Za-z0-9_$]*/g) ?? []).map((word) => word.toUpperCase());
  const quoted = scanned.identifiers.map((name) => name.trim().toUpperCase());
  if (REFUSED_WORDS.some((word) => words.includes(word) || quoted.includes(word))) return null;
  const first = words[0];
  const has = (...candidates: string[]): boolean => candidates.some((word) => words.includes(word));
  // REPLACE( is the string function; a bare REPLACE is the statement.
  const replaceStatement = /\bREPLACE\b(?!\s*\()/i.test(body);

  if (first === "SELECT" || first === "VALUES") return "read";
  if (first === "EXPLAIN") {
    const rest = body.replace(/^EXPLAIN[ \t\n\f\r]+(QUERY[ \t\n\f\r]+PLAN[ \t\n\f\r]+)?/i, "");
    return rest !== body && classifySql(rest) === "read" ? "read" : null;
  }
  if (first === "WITH") {
    if (has(...DDL_WORDS)) return null;
    return has("INSERT", "UPDATE", "DELETE") || replaceStatement ? "write" : "read";
  }
  if (first === "INSERT" || first === "UPDATE" || first === "DELETE" || (first === "REPLACE" && replaceStatement)) return "write";
  if (first !== undefined && DDL_WORDS.includes(first)) return "schema";
  return null; // BEGIN, COMMIT, SAVEPOINT, ANALYZE, ... and anything unknown
}
