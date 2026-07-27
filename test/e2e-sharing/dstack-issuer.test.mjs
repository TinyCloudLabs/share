import assert from "node:assert/strict";
import test from "node:test";
import {
  ISSUER_SIGNING_KEY_PATH, buildDstackResponsePayload, dstackKeyMaterial, ed25519PublicKey,
  extractHttpResponseBody, formatGetKeyRequest, formatHttpResponse, parseDstackRequest,
} from "./dstack-issuer.mjs";

const issuerSeed = Buffer.alloc(32, 0x47);

test("ed25519PublicKey derives a stable 32-byte public key from a 32-byte seed", () => {
  const key = ed25519PublicKey(issuerSeed);
  assert.equal(key.length, 32);
  assert.deepEqual(key, ed25519PublicKey(issuerSeed));
  assert.notDeepEqual(key, ed25519PublicKey(Buffer.alloc(32, 0x09)));
});

test("ed25519PublicKey rejects a seed that is not exactly 32 bytes", () => {
  assert.throws(() => ed25519PublicKey(Buffer.alloc(31)));
  assert.throws(() => ed25519PublicKey(Buffer.alloc(33)));
  assert.throws(() => ed25519PublicKey("not-a-buffer"));
});

test("dstackKeyMaterial returns the pinned issuer seed only for the exact signing-key path", () => {
  assert.deepEqual(dstackKeyMaterial(ISSUER_SIGNING_KEY_PATH, issuerSeed), issuerSeed);
  const otherPurpose = dstackKeyMaterial("opencredentials/share-email/v1/otp-pepper", issuerSeed);
  assert.equal(otherPurpose.length, 32);
  assert.notDeepEqual(otherPurpose, issuerSeed);
  assert.notDeepEqual(otherPurpose, dstackKeyMaterial("opencredentials/share-email/v1/pii-envelope-encryption", issuerSeed));
});

test("parseDstackRequest waits for the full declared Content-Length before returning", () => {
  const full = formatGetKeyRequest(ISSUER_SIGNING_KEY_PATH);
  assert.equal(parseDstackRequest(full.subarray(0, full.length - 1)), undefined);
  const parsed = parseDstackRequest(full);
  assert.equal(parsed.path, "/GetKey");
  assert.deepEqual(JSON.parse(parsed.body), { path: ISSUER_SIGNING_KEY_PATH });
});

test("buildDstackResponsePayload serves /Info and derives /GetKey material by requested path", () => {
  const info = buildDstackResponsePayload("/Info", "", issuerSeed);
  assert.equal(typeof info.app_id, "string");
  assert.equal(typeof info.compose_hash, "string");
  assert.equal(typeof info.instance_id, "string");

  const body = JSON.stringify({ path: ISSUER_SIGNING_KEY_PATH });
  const getKey = buildDstackResponsePayload("/GetKey", body, issuerSeed);
  assert.equal(getKey.key, issuerSeed.toString("hex"));
});

test("formatHttpResponse/extractHttpResponseBody round-trip a JSON payload", () => {
  const payload = { key: issuerSeed.toString("hex") };
  const body = extractHttpResponseBody(formatHttpResponse(payload));
  assert.deepEqual(JSON.parse(body.toString("utf8")), payload);
});
