/** Keep live acceptance artifacts useful without persisting bearer material. */
const SENSITIVE_KEY = /(?:authorization|cookie|token|secret|private|jwk|password|otp|code|signature|share.?key|session.?key|^credential$)/i;

export function redactString(value) {
  return String(value)
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer <redacted>")
    .replace(/https:\/\/[^\s"'<>]*\/s\/[^\s"'<>]*/gi, "<redacted-share-url>")
    .replace(/\/s\/[A-Za-z0-9_-]+(?:#[^\s"'<>]*)?/gi, "/s/<redacted>")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "<redacted-email>")
    .replace(/\/inboxes\/[^/\s"']+/gi, "/inboxes/<redacted>")
    .replace(/([#?&](?:k|key|token|secret|code|otp)=[^&#\s]+)/gi, (_match, part) => `${part.slice(0, part.indexOf("=") + 1)}<redacted>`)
    .replace(/("(?:authorization|cookie|token|secret|private|jwk|password|otp|code|signature|d)"\s*:\s*)("[^"]*"|[^,}\s]+)/gi, "$1\"<redacted>\"")
    .replace(/\b\d{6}\b/g, "<redacted-otp>");
}

export function redactHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [
    name,
    /^(authorization|cookie|set-cookie|x-api-key)$/i.test(name) ? "<redacted>" : redactString(value),
  ]));
}

export function redactValue(value, key = "") {
  if (SENSITIVE_KEY.test(key)) return "<redacted>";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactValue(item, name)]));
  }
  return value;
}

export function redactJsonText(value) {
  try {
    return JSON.stringify(redactValue(JSON.parse(value)));
  } catch {
    return redactString(value);
  }
}
