// installBrowserTelemetry (integration.mjs) rewrites canonical Node/
// Credentials URLs to the harness's owned loopback Share origin so the
// browser's same-origin CSP is satisfied. When window.fetch receives a
// Request object (rather than a string/URL), the routed call must preserve
// every Request semantic — method, byte-exact body, headers, credentials,
// cache, mode, redirect, referrer, integrity, keepalive, and signal — because
// production SDK code issues Request-object fetches. This function is the
// sole routing implementation: it is unit tested directly here with Node's
// native fetch globals, and its source is also injected verbatim into the
// browser page via Function.prototype.toString() so there is exactly one
// implementation to keep in sync.
const REQUEST_OVERRIDE_KEYS = [
  "method",
  "body",
  "mode",
  "credentials",
  "cache",
  "redirect",
  "referrer",
  "referrerPolicy",
  "integrity",
  "keepalive",
  "signal",
];

export function routeTelemetryFetchArgs(input, init, context) {
  const nodeOrigin = context.nodeOrigin;
  const credentialsOrigin = context.credentialsOrigin;
  const currentOrigin = context.currentOrigin;
  const isRequestInput = typeof Request !== "undefined" && input instanceof Request;
  const originalUrl = isRequestInput ? input.url : typeof input === "string" ? input : String(input && input.href !== undefined ? input.href : input);
  const method = isRequestInput ? (init && init.method) || input.method : (init && init.method) || "GET";

  let routedUrl = originalUrl;
  if (originalUrl.indexOf(nodeOrigin) === 0 || originalUrl.indexOf(credentialsOrigin) === 0) {
    const parsed = new URL(originalUrl);
    const target = new URL(currentOrigin);
    parsed.protocol = target.protocol;
    parsed.host = target.host;
    routedUrl = parsed.toString();
  }
  const isSameOrigin = new URL(routedUrl, currentOrigin).origin === currentOrigin;

  if (isRequestInput) {
    const overrides = {};
    if (init) {
      for (const key of REQUEST_OVERRIDE_KEYS) {
        if (Object.prototype.hasOwnProperty.call(init, key)) overrides[key] = init[key];
      }
    }
    // Route to the new URL from the original Request first (preserves every
    // field, including the body stream), then apply any explicit non-header
    // init overrides exactly as native fetch(request, init) would.
    const routedRequest = Object.keys(overrides).length > 0
      ? new Request(new Request(routedUrl, input), overrides)
      : new Request(routedUrl, input);
    // Headers are merged (original preserved, explicit init overlaid), not
    // wholesale-replaced the way native fetch(request, init) treats headers.
    const mergedHeaders = new Headers(routedRequest.headers);
    if (init && init.headers) {
      const overlay = new Headers(init.headers);
      for (const entry of overlay.entries()) mergedHeaders.set(entry[0], entry[1]);
    }
    if (isSameOrigin) mergedHeaders.set("x-forwarded-proto", "https");
    for (const key of [...routedRequest.headers.keys()]) {
      if (!mergedHeaders.has(key)) routedRequest.headers.delete(key);
    }
    for (const entry of mergedHeaders.entries()) routedRequest.headers.set(entry[0], entry[1]);
    return { url: routedUrl, method: routedRequest.method, fetchArgs: [routedRequest] };
  }

  let requestInit = init;
  if (isSameOrigin) {
    const headers = new Headers(init && init.headers);
    headers.set("x-forwarded-proto", "https");
    requestInit = Object.assign({}, init || {}, { headers: headers });
  }
  return { url: routedUrl, method: method, fetchArgs: [routedUrl, requestInit] };
}
