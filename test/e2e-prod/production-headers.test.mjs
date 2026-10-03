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

// Cloudflare's pretty-URL redirect sends each .html path to the extensionless
// one, so both forms of every sandbox document need their own rule.
const SANDBOX_ROUTES = ["/artifact-sandbox", "/artifact-sandbox.html", "/mermaid-sandbox", "/mermaid-sandbox.html"];

test("production-origin sandbox routes detach the site policy and send only the frame policy", () => {
  for (const pathname of SANDBOX_ROUTES) {
    const rule = rules.find((candidate) => candidate.pattern === pathname);
    assert.ok(rule !== undefined, `${pathname} has its own _headers rule`);
    // Cloudflare Pages appends a second CSP unless the site-wide one is detached;
    // the site policy's frame-ancestors 'none' and script-src 'self' would
    // otherwise stop the sandbox from being framed or running its bridge.
    assert.deepEqual(rule.detach, ["content-security-policy"], `${pathname} detaches the site CSP`);
    const csp = productionHeadersForPath(rules, pathname)["content-security-policy"];
    assert.match(csp, /^default-src 'none'; /, `${pathname} denies by default`);
    assert.match(csp, /; script-src 'unsafe-inline'[^;]*;/, `${pathname} lets its inline bridge run`);
    assert.doesNotMatch(csp, /frame-ancestors 'none'|script-src 'self'/, `${pathname} carries no site-policy directive`);
    assert.match(csp, /; frame-ancestors 'self'$/, `${pathname} may be framed only by the viewer origin`);
    assert.equal(productionHeadersForPath(rules, pathname)["x-frame-options"], "SAMEORIGIN");
  }
});

test("asset cache policy overrides the global no-store policy", () => {
  assert.equal(productionHeadersForPath(rules, "/assets/app.js")["cache-control"], "public, max-age=31536000, immutable");
});
