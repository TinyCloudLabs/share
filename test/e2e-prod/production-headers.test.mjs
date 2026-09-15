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

test("production-origin sandbox routes reproduce their narrower frame headers", () => {
  for (const pathname of ["/artifact-sandbox", "/artifact-sandbox.html"]) {
    const headers = productionHeadersForPath(rules, pathname);
    assert.equal(headers["content-security-policy"], "default-src 'none'; frame-ancestors 'self'");
    assert.equal(headers["x-frame-options"], "SAMEORIGIN");
  }
});

test("asset cache policy overrides the global no-store policy", () => {
  assert.equal(productionHeadersForPath(rules, "/assets/app.js")["cache-control"], "public, max-age=31536000, immutable");
});
