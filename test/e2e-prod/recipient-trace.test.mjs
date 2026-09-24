import assert from "node:assert/strict";
import test from "node:test";

import { auditRecipientTrace } from "./recipient-trace.mjs";

const ownerNode = "https://owner-node.example";
const valid = [
  ["GET", "https://registry.tinycloud.xyz", "/v1/locations/did%3Akey%3Aowner"],
  ["POST", "https://witness.credentials.org", "/v1/acquisitions"],
  ["POST", ownerNode, "/policy/v3/challenges"],
  ["POST", ownerNode, "/policy/v3/delegations"],
  ["POST", ownerNode, "/delegate"],
  ["POST", ownerNode, "/invoke"],
  ["POST", ownerNode, "/invoke"],
].map(([method, origin, path]) => ({ method, origin, path }));

test("accepts acquisition, signed discovery, policy, delegation, KV, and decrypt on the reviewed origins", () => {
  const report = auditRecipientTrace(valid, ownerNode);
  assert.equal(report.nodeInvokeCount, 2);
  assert.deepEqual(Object.keys(report), ["verifiedOrigins", "verifiedRoutes", "nodeInvokeCount"]);
  assert.doesNotMatch(JSON.stringify(report), /@|#|otp|fragment|did%3Akey%3Aowner/i);
});

for (const [name, entry, message] of [
  ["credential acquisition on another origin", { method: "POST", origin: "https://credentials.example", path: "/v1/acquisitions" }, /pinned OpenCredentials|untrusted origin/],
  ["Policy/v3 on a second Node", { method: "POST", origin: "https://other-node.example", path: "/policy/v3/challenges" }, /owner Node identities/],
  ["generic invoke on a second Node", { method: "POST", origin: "https://other-node.example", path: "/invoke" }, /owner Node identities/],
  ["legacy Share data plane", { method: "GET", origin: ownerNode, path: "/share/v3/policy/claim" }, /prohibited Share registry/],
  ["Share registry blob retrieval", { method: "GET", origin: "https://registry.tinycloud.xyz", path: "/v1/blobs/bafy" }, /prohibited Share registry/],
  ["standalone policy origin", { method: "POST", origin: "https://policy.tinycloud.xyz", path: "/health" }, /prohibited Share registry/],
  ["OpenKey identity creation", { method: "POST", origin: "https://api.openkey.so", path: "/api/session" }, /OpenKey/],
]) {
  test(`rejects ${name}`, () => {
    assert.throws(() => auditRecipientTrace([...valid, entry], ownerNode), message);
  });
}
