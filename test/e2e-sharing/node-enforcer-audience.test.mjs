import assert from "node:assert/strict";
import test from "node:test";
import { nodeEnforcerAudienceFromTrustBundle } from "./node-enforcer-audience.mjs";

const CANONICAL_NODE_AUDIENCE = "did:web:node.tinycloud.xyz";
const MISMATCHED_EXPORTER_AUDIENCE = "did:web:tee.node.tinycloud.xyz";

function trustBundleJson(nodeAudience) {
  return JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1", nodeAudience });
}

test("node enforcer audience is read from the runtime trust bundle, never the exporter's deployment audience", () => {
  const nodePublic = { nodeAudience: MISMATCHED_EXPORTER_AUDIENCE };
  const nodeTrustBundleJson = trustBundleJson(CANONICAL_NODE_AUDIENCE);

  const enforcerDid = nodeEnforcerAudienceFromTrustBundle(nodeTrustBundleJson);

  assert.equal(enforcerDid, CANONICAL_NODE_AUDIENCE);
  assert.notEqual(enforcerDid, nodePublic.nodeAudience, "a mismatched exporter audience must never become SHARE_NODE_ENFORCER_DID");
});

test("node enforcer audience rejects a trust bundle missing nodeAudience", () => {
  assert.throws(() => nodeEnforcerAudienceFromTrustBundle(JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1" })), /non-empty nodeAudience/);
});

test("node enforcer audience rejects a non-string nodeAudience", () => {
  assert.throws(() => nodeEnforcerAudienceFromTrustBundle(JSON.stringify({ nodeAudience: 42 })), /non-empty nodeAudience/);
});

test("node enforcer audience rejects invalid JSON", () => {
  assert.throws(() => nodeEnforcerAudienceFromTrustBundle("not-json"), /valid JSON/);
});
