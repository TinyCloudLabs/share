import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parseProductionHeaders, productionHeadersForPath } from "./production-headers.mjs";

const rules = parseProductionHeaders(readFileSync(new URL("../../public/_headers", import.meta.url), "utf8"));

test("production-origin viewer reproduces the deployed CSP and browser isolation headers", () => {
  const headers = productionHeadersForPath(rules, "/s/inline");
  assert.match(headers["content-security-policy"], /require-trusted-types-for 'script'/);
  assert.match(headers["content-security-policy"], /trusted-types share-viewer-html dompurify 'allow-duplicates'/);
  assert.match(headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.equal(headers["referrer-policy"], "no-referrer");
  assert.equal(headers["x-content-type-options"], "nosniff");
  assert.equal(headers["cache-control"], "no-store, no-transform");
});

test("production-origin sandbox routes detach the site policy and send only the frame policy", () => {
  const sandboxRules = rules.filter((rule) => rule.pattern === "/artifact-sandbox" || rule.pattern === "/artifact-sandbox.html");
  assert.equal(sandboxRules.length, 2);
  for (const rule of sandboxRules) {
    // Cloudflare Pages appends a second CSP unless the site-wide one is detached;
    // the site policy's frame-ancestors 'none' and script-src 'self' would
    // otherwise stop the sandbox from being framed or running its bridge.
    assert.deepEqual(rule.detach, ["content-security-policy"]);
    const headers = productionHeadersForPath(rules, rule.pattern);
    assert.match(headers["content-security-policy"], /^default-src 'none'; script-src 'unsafe-inline';/);
    assert.match(headers["content-security-policy"], /connect-src 'none'/);
    assert.match(headers["content-security-policy"], /frame-ancestors 'self'$/);
    assert.equal(headers["x-frame-options"], "SAMEORIGIN");
  }
});

test("asset cache policy overrides the global no-store policy", () => {
  assert.equal(productionHeadersForPath(rules, "/assets/app.js")["cache-control"], "public, max-age=31536000, immutable");
});
