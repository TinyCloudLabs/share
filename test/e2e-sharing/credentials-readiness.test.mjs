import assert from "node:assert/strict";
import test from "node:test";
import { assertCredentialsReadinessBody, redactSecrets } from "./credentials-readiness.mjs";

const capabilityId = "tinycloud.share-email-claim";

test("assertCredentialsReadinessBody accepts the exact healthy+ready+capability-id shape", () => {
  assert.doesNotThrow(() => assertCredentialsReadinessBody(200, { healthy: true, capability: { id: capabilityId, status: "ready" } }, capabilityId));
});

test("assertCredentialsReadinessBody rejects a non-200 status", () => {
  assert.throws(() => assertCredentialsReadinessBody(503, { healthy: false }, capabilityId), /HTTP 503/);
});

test("assertCredentialsReadinessBody rejects healthy !== true", () => {
  assert.throws(() => assertCredentialsReadinessBody(200, { healthy: false }, capabilityId), /healthy=false/);
});

test("assertCredentialsReadinessBody rejects a capability status other than ready", () => {
  assert.throws(() => assertCredentialsReadinessBody(200, { healthy: true, capability: { id: capabilityId, status: "pending" } }, capabilityId), /"pending"/);
});

test("assertCredentialsReadinessBody rejects an unexpected capability id", () => {
  assert.throws(() => assertCredentialsReadinessBody(200, { healthy: true, capability: { id: "other", status: "ready" } }, capabilityId), /"other"/);
});

test("redactSecrets removes every occurrence of every provided secret", () => {
  const output = redactSecrets("key=re_supersecretvalue db=postgres://user:re_supersecretvalue@host/db", ["re_supersecretvalue"]);
  assert.equal(output.includes("re_supersecretvalue"), false);
  assert.equal(output.split("[redacted]").length - 1, 2);
});

test("redactSecrets ignores empty or non-string secrets", () => {
  assert.equal(redactSecrets("unchanged", ["", undefined, null]), "unchanged");
});
