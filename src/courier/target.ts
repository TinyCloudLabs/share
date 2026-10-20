/**
 * What a stored request's `target` must be for the view to let it be decided: exactly what js-sdk `packages/courier`
 * (`guard/target.ts` `canonicalTarget` and `text.ts` `TARGET_SHAPES`) accepts as STORED. `courier request` writes the
 * canonical spelling; a hand-written variant (`o/r#0139`, an upper-case repo, `secrets:A  bB`) is not what the CLI's
 * guard would match, so the CLI refuses it and the view must too. Shared vectors: test/vectors/courier-request-fields.json.
 */

export const VERBS = ["merge", "deploy", "publish", "spend", "other"] as const;
export type Verb = (typeof VERBS)[number];

const REPO = "[A-Za-z0-9_.-]+";
const SEG = "[A-Za-z0-9_.@/+-]+";
// `[a-z0-9~][a-z0-9._~-]*` per npm; scoped `@scope/name`.
const NPM_NAME = "(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*";
const VERSION = "[0-9A-Za-z][0-9A-Za-z.+_-]*";

/** What each verb's stored target must look like (the CLI's `TARGET_SHAPES`, applied on top of the printable-ASCII rule). */
const TARGET_SHAPES: Readonly<Record<Verb, RegExp>> = {
  merge: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(#[0-9]+|@[A-Za-z0-9_.@/+*-]+)$/,
  publish: /^(npm:|release:|changeset:|script:)\S.*$/,
  deploy: /^(wrangler:|pages:|phala:|script:)\S.*$/,
  other: /^[a-z][a-z0-9-]{0,30}:\S(.*\S)?$/,
  spend: /^spend:\S(.*\S)?$/,
};

/** A PR number as the digits written, leading zeros stripped, never through a float; 1 to 9 digits. */
function prNumber(digits: string): string | undefined {
  const stripped = digits.replace(/^0+/, "");
  return stripped === "" || stripped.length > 9 ? undefined : stripped;
}

/** The one spelling of `raw` for `verb`, or undefined when it is not a recognised target. Mirrors the CLI's `canonicalTarget`. */
export function canonicalTarget(verb: Verb, raw: string): string | undefined {
  const t = raw.trim();
  if (t === "" || t.length > 200 || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\n]/.test(t)) return undefined;
  let m: RegExpExecArray | null;
  if (verb === "merge") {
    m = new RegExp(`^https?://github\\.com/(${REPO})/(${REPO})/pull/(\\d+)(?:[/?#].*)?$`, "i").exec(t);
    if (m) { const number = prNumber(m[3]!); return number === undefined ? undefined : `${m[1]}/${m[2]}#${number}`.toLowerCase(); }
    m = new RegExp(`^(${REPO})/(${REPO})#(\\d+)$`).exec(t);
    if (m) { const number = prNumber(m[3]!); return number === undefined ? undefined : `${m[1]}/${m[2]}#${number}`.toLowerCase(); }
    m = new RegExp(`^(${REPO})/(${REPO})@(${SEG}|\\*)$`).exec(t);
    return m ? `${m[1]}/${m[2]}`.toLowerCase() + `@${m[3]}` : undefined;
  }
  if (verb === "publish") {
    m = new RegExp(`^npm:(${NPM_NAME})@(${VERSION})$`).exec(t);
    if (m) return `npm:${m[1]}@${m[2]}`;
    m = new RegExp(`^release:(${REPO})/(${REPO})@(${SEG})$`).exec(t);
    if (m) return `release:${m[1]}/${m[2]}`.toLowerCase() + `@${m[3]}`;
    m = new RegExp(`^changeset:(${NPM_NAME})$`).exec(t);
    if (m) return `changeset:${m[1]}`;
    m = /^script:([^:\s]+):([^:\s]+)$/.exec(t);
    return m ? `script:${m[1]}:${m[2]}` : undefined;
  }
  if (verb === "deploy") {
    m = /^wrangler:([A-Za-z0-9_.-]+)(?::([A-Za-z0-9_.-]+))?$/.exec(t);
    if (m) return `wrangler:${m[1]}${m[2] ? `:${m[2]}` : ""}`;
    m = /^(pages|phala):([A-Za-z0-9_.-]+)$/.exec(t);
    if (m) return `${m[1]}:${m[2]}`;
    m = /^script:([^:\s]+):([^:\s]+)$/.exec(t);
    return m ? `script:${m[1]}:${m[2]}` : undefined;
  }
  if (verb === "other") {
    m = new RegExp(`^workflow:(${REPO})/(${REPO}):(${SEG})$`).exec(t);
    if (m) return `workflow:${m[1]}/${m[2]}`.toLowerCase() + `:${m[3]}`;
    m = /^secrets:(\S(?:.*\S)?)$/.exec(t);
    if (m) return `secrets:${m[1]!.replace(/\s+/g, " ")}`;
    m = /^[a-z][a-z0-9-]{0,30}:\S(?:.*\S)?$/.exec(t);
    return m ? t : undefined;
  }
  m = /^spend:\S(?:.*\S)?$/.exec(t);
  return m ? t : undefined;
}

/** True when `target` (already known to be printable ASCII, trimmed, one line) is acceptable as stored for `verb`. */
export function targetIsCanonical(verb: Verb, target: string): boolean {
  return TARGET_SHAPES[verb].test(target) && canonicalTarget(verb, target) === target;
}
