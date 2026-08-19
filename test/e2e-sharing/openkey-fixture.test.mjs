import assert from "node:assert/strict";
import test from "node:test";
import { OPENKEY_TEST_SESSION_TOKEN, openKeyApiCors, openKeyWidgetHtml } from "./openkey-fixture.mjs";

test("OpenKey fixture returns a managed session with a delegated signing token", () => {
  const html = openKeyWidgetHtml("0x1111111111111111111111111111111111111111");
  assert.match(html, /openkey:auth:response/);
  assert.match(html, /keyType:\"MANAGED\"/);
  assert.match(html, new RegExp(OPENKEY_TEST_SESSION_TOKEN));
  assert.match(html, /openkey:sign:response/);
  assert.doesNotMatch(html, /use-external-wallet/);
});

test("OpenKey delegated signer CORS is restricted to Share and loopback", () => {
  assert.equal(openKeyApiCors("https://share.tinycloud.xyz")["access-control-allow-origin"], "https://share.tinycloud.xyz");
  assert.equal(openKeyApiCors("http://127.0.0.1:8787")["access-control-allow-origin"], "http://127.0.0.1:8787");
  assert.deepEqual(openKeyApiCors("https://evil.example"), {});
});
