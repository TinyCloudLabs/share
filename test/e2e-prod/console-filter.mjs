// Console entries as the gates store them. Both gates build entries with consoleEntry and test them with these predicates,
// so the offline replay test (console-filter.test.mjs) exercises the code the live gates run.

// Chrome writes URLs inside quotes and parentheses; the stop set keeps the closing quote and paren out of the match.
export const redactUrls = (text) => text.replaceAll(/(?:https?|wss?):\/\/[^\s'"()]+/g, "<url>");

// Puppeteer reports level "warning" as type "warn"; the gates compare against "warn" and "error".
export const consoleType = (level) => (level === "warning" ? "warn" : level);

export const consoleEntry = (phase, type, text, location) => ({
  phase,
  type,
  text: redactUrls(text).slice(0, 240),
  at: `${location?.url ?? ""}:${location?.lineNumber ?? ""}`.replace(/^https:\/\/[^/]+/, "").slice(0, 120),
});

// The browser's postMessage warning after redactUrls. Chrome: "... provided ('https://share.tinycloud.xyz') does not match the recipient window's origin ('null')."
export const postMessageWarning = /^Failed to execute 'postMessage' on 'DOMWindow': The target origin provided \('<url>'\) does not match the recipient window's origin \('(?:<url>|null)'\)\.?$/;

// The hostile app's blocked-request messages after redactUrls.
export const hostileRefusals = [
  /^Connecting to '<url>' violates the following Content Security Policy directive: "[^"]*"\. The action has been blocked\.$/,
  /^Fetch API cannot load <url>\.? Refused to connect because it violates the document's Content Security Policy\.$/,
];

// Where the browser attributes a frame's refusal: its srcdoc child, the jsx-sandbox bridge document, or no url at all
// (Chrome omits the url for these frame refusals). The empty-url form is also how the runner page's own refusals appear,
// so the text filter alone cannot separate them; the runner gate's top-document violation check does that.
export const appFrameAt = (at) => at.startsWith("about:srcdoc:") || /\/jsx-sandbox\.html(?:[#?:]|$)/.test(at) || /^:\d+$/.test(at);

export const isHostileRefusal = (entry, appId) => (
  entry.phase === `open-${appId}` && entry.type === "error" && appFrameAt(entry.at) && hostileRefusals.some((pattern) => pattern.test(entry.text))
);
