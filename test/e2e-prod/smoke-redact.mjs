// Redaction and the approval-button name guard for the /courier live smoke (TC-2310).
// Pure functions, so they can be unit tested without a browser.

/** The OpenKey approval's primary action: its labels while ready, and while signing. */
export const APPROVE_NAME = /^(Approve( exact bytes)?|Signing…)$/;

// Origins whose URL paths are kept (with queries and fragments removed); any other origin keeps only its host.
const APP_HOSTS = new Set(["share.tinycloud.xyz", "openkey.so", "api.openkey.so", "node.tinycloud.xyz", "tee.node.tinycloud.xyz", "registry.tinycloud.xyz"]);

/** A path segment that looks like an identifier, token or code rather than a route word (route words: lowercase and hyphens, short). */
const tokenLike = (segment) =>
  !/^[A-Z_]+$/.test(segment) && (
    segment.length >= 32
    || (segment.length >= 20 && /^[a-z0-9]+$/.test(segment))
    || (segment.length >= 8 && /\d/.test(segment) && /[A-Za-z]/.test(segment))
    || (segment.length >= 6 && /[a-z]/.test(segment) && /[A-Z]/.test(segment) && (/\d/.test(segment) || segment.length >= 16)));

/** A long run of token characters: an all-caps error code stays; a path keeps its route words; anything else is an id. */
function longRun(match) {
  if (/^[A-Z_]+$/.test(match)) return match;
  if (!match.includes("/") || /[+=]/.test(match)) return "<id>";
  return match.split("/").map((segment) => (tokenLike(segment) ? "<id>" : segment)).join("/");
}

/** Backstop for any text that reaches the report: no tokens, codes, links' secrets, emails or addresses. */
export const scrub = (value) => String(value)
  .replace(/\beyJ[\w-]*\.[\w-]*\.?[\w-]*/g, "<jwt>")
  .replace(/\bhttps?:\/\/([^\s"'/?#]+)([^\s"'?#]*)[^\s"']*/g, (_, host, path) =>
    (APP_HOSTS.has(host.toLowerCase()) ? `https://${host}${path}` : `https://${host}/<redacted>`))
  .replace(/#\S*/g, "#<fragment>")
  .replace(/[\w.+-]+(@|%40)[\w-]+\.[\w.]+/gi, "<email>")
  .replace(/0x[0-9a-fA-F]{40}/g, "0x<address>")
  .replace(/did(:|%3A)(key|pkh)[\w:.%-]{8,}/gi, "did:$2:<id>")
  .replace(/[A-Za-z0-9_\-+/=]{20,}/g, longRun)
  .replace(/(^|\/)([^/\s"]+)(?=\/|$|\s|")/g, (whole, lead, segment) => (tokenLike(segment) ? `${lead}<id>` : whole))
  .replace(/\b\d{6,}\b/g, "<digits>");

/** An error code worth keeping: a word-like identifier, not something that could be a one-time code. */
const codeLike = (value) =>
  /^([A-Z][A-Z0-9]*(_[A-Z0-9]+)*|[a-z][a-z0-9]*([_.-][a-z0-9]+)*)$/.test(value)
  && (!/\d/.test(value) || /[_.-]/.test(value))
  && value.length <= 64;

const MAX_DEPTH = 6;
/**
 * A refused response, for the report: only allowlisted keys survive (code, message, error, status,
 * statusText, and error.code / error.message); every other value, and anything deeper than
 * MAX_DEPTH, becomes "<redacted>". Strings are scrubbed; a code that doesn't look like an error code
 * is redacted too.
 */
export function refusal(text) {
  let body;
  try { body = JSON.parse(text); } catch { return { body: scrub(String(text ?? "")).slice(0, 300) }; }
  const keep = (key, value, depth) => {
    if (depth > MAX_DEPTH) return "<redacted>";
    if (key === "status" && typeof value === "number") return value;
    if (key === "code") return typeof value === "string" && codeLike(value) ? value : "<redacted>";
    if (typeof value === "string") return scrub(value).slice(0, 200);
    if (key === "error" && value !== null && typeof value === "object" && !Array.isArray(value)) {
      return Object.fromEntries(Object.entries(value).map(([inner, item]) => [inner, ["code", "message"].includes(inner) ? keep(inner, item, depth + 1) : "<redacted>"]));
    }
    return "<redacted>";
  };
  const ALLOWED = new Set(["code", "message", "error", "status", "statusText"]);
  const shaped = body !== null && typeof body === "object" && !Array.isArray(body)
    ? Object.fromEntries(Object.entries(body).map(([key, value]) => [key, ALLOWED.has(key) ? keep(key, value, 1) : "<redacted>"]))
    : "<redacted>";
  const code = [shaped?.code, shaped?.error?.code, typeof shaped?.error === "string" ? shaped.error : undefined]
    .find((item) => typeof item === "string" && item !== "<redacted>" && codeLike(item));
  return { ...(code ? { code } : {}), body: JSON.stringify(shaped).slice(0, 300) };
}
