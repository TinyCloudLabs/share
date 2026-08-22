/** Real Rust Node delivery authorization consumed by the api.share verifier. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import process from "node:process";

import { canonicalize, computeCid, shareEnvelopeV3Schema, verifyEnvelopeV3, verifyEnvelopeV3SignatureOnly } from "@tinycloud/share-envelope";
import { parseDeliveryRequest, verifyDeliveryAuthorization } from "../../packages/email/src/protocol.ts";

const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE?.trim();
assert(nodeRoot, "TINYCLOUD_NODE_WORKTREE is required so the addressed E2E uses an explicit Rust Node checkout");
const result = spawnSync(
  "cargo",
  ["test", "-p", "tinycloud-node", "policy_v2_admits_v3_account_and_v4_accountless_receivers", "--", "--nocapture"],
  {
    cwd: resolve(nodeRoot),
    encoding: "utf8",
    env: { ...process.env, TC498_EMIT_DELIVERY_RECEIPT: "1" },
    maxBuffer: 32 * 1024 * 1024,
  },
);
assert.equal(result.status, 0, `Rust addressed authorization failed:\n${result.stderr.slice(-8_000)}`);
const marker = `${result.stdout}\n${result.stderr}`
  .split("\n")
  .find((line) => line.startsWith("TC498_DELIVERY_RECEIPT="));
assert(marker, "Rust Node did not emit its verified delivery receipt");
const bridge = JSON.parse(marker.slice("TC498_DELIVERY_RECEIPT=".length));
const receipt = parseDeliveryRequest(bridge.receipt);
assert(receipt, "api.share rejected the Rust Node receipt shape");
const linkPayloadText = Buffer.from(new URL(receipt.request.returnLink).searchParams.get("tc2"), "base64url").toString("utf8");
const linkPayload = JSON.parse(linkPayloadText);
const envelopeText = Buffer.from(linkPayload.c, "base64url").toString("utf8");
const envelopeValue = JSON.parse(envelopeText);
const parsedEnvelope = shareEnvelopeV3Schema.safeParse(envelopeValue);
assert.equal(parsedEnvelope.success, true, `Rust envelope rejected by the SDK schema: ${JSON.stringify(parsedEnvelope.error?.issues)}`);
assert.equal(canonicalize(parsedEnvelope.data), envelopeText, "Rust envelope is not byte-exact JCS");
assert.equal(await computeCid(new TextEncoder().encode(envelopeText)), receipt.request.envelopeRef, "Rust envelope CID does not match its receipt");
assert.equal(verifyEnvelopeV3SignatureOnly(parsedEnvelope.data), true, "Rust envelope owner signature failed SDK verification");
const fullEnvelopeVerified = await verifyEnvelopeV3(parsedEnvelope.data, { expectedSignerDid: parsedEnvelope.data.policy.ownerDid });
assert.equal(fullEnvelopeVerified, true, "Rust envelope failed full SDK verification");

const registryOrigin = "https://registry.example";
const trustFetch = async (input) => {
  const url = String(input);
  if (url === `${registryOrigin}/v1/locations/${encodeURIComponent(bridge.locationRecord.subject)}`) {
    return Response.json({ record: bridge.locationRecord });
  }
  if (url === `${bridge.nodeOrigin}/info`) return Response.json({ nodeId: bridge.nodeDid });
  return new Response(null, { status: 404 });
};
const verified = await verifyDeliveryAuthorization(receipt, {
  deliveryAudience: "https://api.share.tinycloud.xyz",
  shareOrigin: "https://share.tinycloud.xyz",
  registryOrigin,
  fetch: trustFetch,
}, Date.now());
assert.equal(verified.ok, true, `api.share refused the Rust Node receipt: ${verified.reason}`);
assert.equal(verified.recipient, "alice@example.test");
assert.equal(verified.shareUrl, receipt.request.returnLink);
assert.equal(verified.shareCid, receipt.request.envelopeRef);
assert.equal(receipt.admission.ownerDid, bridge.locationRecord.subject);
assert.equal(receipt.admission.signature.signerDid, bridge.nodeDid);

console.log("native addressed E2E passed: real Rust authorization -> owner registry binding -> api.share verification");
