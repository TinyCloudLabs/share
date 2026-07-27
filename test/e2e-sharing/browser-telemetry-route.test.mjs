import assert from "node:assert/strict";
import test from "node:test";
import { routeTelemetryFetchArgs } from "./browser-telemetry-route.mjs";

const NODE_ORIGIN = "https://node.tinycloud.xyz";
const CREDENTIALS_ORIGIN = "https://credentials.org";
const CURRENT_ORIGIN = "http://127.0.0.1:4173";

function context(overrides = {}) {
  return { nodeOrigin: NODE_ORIGIN, credentialsOrigin: CREDENTIALS_ORIGIN, currentOrigin: CURRENT_ORIGIN, ...overrides };
}

test("routes a Request(input) POST with a body to the local origin, preserving method/body/headers/credentials/signal and adding the harness header", async () => {
  const controller = new AbortController();
  const original = new Request(`${NODE_ORIGIN}/invoke`, {
    method: "POST",
    body: JSON.stringify({ hello: "world" }),
    headers: { "content-type": "application/json", "x-harmless-custom": "custom-value" },
    credentials: "include",
    signal: controller.signal,
  });

  const routed = routeTelemetryFetchArgs(original, undefined, context());

  assert.equal(routed.fetchArgs.length, 1, "a Request input must produce a single routed Request argument");
  const [routedRequest] = routed.fetchArgs;
  assert.ok(routedRequest instanceof Request);
  assert.equal(routedRequest.url, `${CURRENT_ORIGIN}/invoke`);
  assert.equal(routedRequest.method, "POST");
  assert.equal(await routedRequest.clone().text(), JSON.stringify({ hello: "world" }), "body must be byte-exact");
  assert.equal(routedRequest.headers.get("content-type"), "application/json");
  assert.equal(routedRequest.headers.get("x-harmless-custom"), "custom-value");
  assert.equal(routedRequest.headers.get("x-forwarded-proto"), "https", "same-origin routing must add the harness header");
  assert.equal(routedRequest.credentials, "include");
  assert.equal(routedRequest.signal.aborted, false);
  controller.abort();
  assert.equal(routedRequest.signal.aborted, true, "the routed Request's signal must still follow the original AbortController (native Request-reconstruction semantics link, rather than alias, the signal)");
  assert.equal(routed.method, "POST");
  assert.equal(routed.url, `${CURRENT_ORIGIN}/invoke`);
});

test("overlays explicit init on a routed Request exactly as native fetch(request, init) would, merging (not replacing) headers", async () => {
  const original = new Request(`${CREDENTIALS_ORIGIN}/v1/share-email/claims/abc`, {
    method: "POST",
    body: "original-body",
    headers: { "content-type": "text/plain", "x-harmless-custom": "original-value" },
    credentials: "same-origin",
  });

  const routed = routeTelemetryFetchArgs(original, { headers: { "x-harmless-custom": "override-value", "x-extra": "added" } }, context());

  const [routedRequest] = routed.fetchArgs;
  assert.equal(routedRequest.method, "POST", "method not present in explicit init must be inherited from the original Request");
  assert.equal(await routedRequest.clone().text(), "original-body", "body not present in explicit init must be inherited byte-exact");
  assert.equal(routedRequest.headers.get("content-type"), "text/plain", "headers absent from explicit init must be preserved from the original Request");
  assert.equal(routedRequest.headers.get("x-harmless-custom"), "override-value", "explicit init headers must overlay original headers");
  assert.equal(routedRequest.headers.get("x-extra"), "added");
  assert.equal(routedRequest.headers.get("x-forwarded-proto"), "https");
  assert.equal(routedRequest.credentials, "same-origin", "credentials absent from explicit init must be inherited");
});

test("explicit init can override non-header Request fields", async () => {
  const original = new Request(`${NODE_ORIGIN}/invoke`, { method: "POST", body: "original", credentials: "omit" });

  const routed = routeTelemetryFetchArgs(original, { method: "PUT", body: "overridden", credentials: "include" }, context());

  const [routedRequest] = routed.fetchArgs;
  assert.equal(routedRequest.method, "PUT");
  assert.equal(await routedRequest.clone().text(), "overridden");
  assert.equal(routedRequest.credentials, "include");
});

test("string input routing is unchanged: same-origin adds the harness header, other init fields pass through untouched", async () => {
  const routed = routeTelemetryFetchArgs(`${NODE_ORIGIN}/health/readiness`, { method: "GET" }, context());

  assert.deepEqual(routed.fetchArgs.length, 2);
  const [url, init] = routed.fetchArgs;
  assert.equal(url, `${CURRENT_ORIGIN}/health/readiness`);
  assert.equal(init.headers.get("x-forwarded-proto"), "https");
  assert.equal(init.method, "GET");
});

test("URL object input routing is unchanged", async () => {
  const routed = routeTelemetryFetchArgs(new URL(`${CREDENTIALS_ORIGIN}/readiness`), undefined, context());

  const [url, init] = routed.fetchArgs;
  assert.equal(url, `${CURRENT_ORIGIN}/readiness`);
  assert.equal(init.headers.get("x-forwarded-proto"), "https");
});

test("a non-canonical origin is never rewritten and never receives the harness header", async () => {
  const external = "https://example.com/not-canonical";
  const explicitInit = { method: "GET" };
  const routed = routeTelemetryFetchArgs(external, explicitInit, context());

  assert.equal(routed.url, external, "a URL outside nodeOrigin/credentialsOrigin must not be rewritten");
  const [url, init] = routed.fetchArgs;
  assert.equal(url, external);
  assert.equal(init, explicitInit, "init is passed through unchanged for a non-routed, non-same-origin request");
});

test("a non-canonical Request origin is never rewritten and preserves its own headers untouched", async () => {
  const original = new Request("https://example.com/not-canonical", { method: "POST", body: "payload", headers: { "x-harmless-custom": "value" } });

  const routed = routeTelemetryFetchArgs(original, undefined, context());

  assert.equal(routed.url, "https://example.com/not-canonical");
  const [routedRequest] = routed.fetchArgs;
  assert.equal(routedRequest.headers.get("x-forwarded-proto"), null);
  assert.equal(routedRequest.headers.get("x-harmless-custom"), "value");
  assert.equal(await routedRequest.clone().text(), "payload");
});
