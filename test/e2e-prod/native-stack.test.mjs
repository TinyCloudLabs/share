import assert from "node:assert/strict";
import test from "node:test";
import { resendFixtureJsonResponse } from "./native-stack.mjs";

test("Resend fixture responses declare their exact bounded UTF-8 length", () => {
  const response = resendFixtureJsonResponse({ id: "mail_é" }, { "cache-control": "no-store" });

  assert.equal(response.headers["content-type"], "application/json");
  assert.equal(response.headers["content-length"], String(Buffer.byteLength(response.body)));
  assert.equal(response.headers["cache-control"], "no-store");
  assert.deepEqual(JSON.parse(response.body), { id: "mail_é" });
});
