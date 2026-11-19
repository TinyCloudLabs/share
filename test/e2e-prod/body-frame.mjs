// The sandbox a Courier message body's frame may have (TC-2310, Naomi's ruling on the /courier live
// smoke). Bodies render in Share's preview frame, which may open links in a new tab (50d96ed) and
// must never run script or share an origin: the attribute must be present, and every token must
// be one of the popup tokens. An empty sandbox (nothing granted) is fine.

const ALLOWED = new Set(["allow-popups", "allow-popups-to-escape-sandbox"]);

/**
 * Whether a frame's `sandbox` attribute value (null when absent) keeps a message body inert. Tokens
 * are split on ASCII whitespace and compared case-insensitively, as the browser does, so
 * `ALLOW-SCRIPTS` is allow-scripts; anything else that isn't a popup token (a comma list, a
 * non-breaking space) fails.
 */
export function bodySandboxOk(value) {
  if (typeof value !== "string") return false;
  return value.split(/[\t\n\f\r ]+/).filter((token) => token !== "").every((token) => ALLOWED.has(token.toLowerCase()));
}
