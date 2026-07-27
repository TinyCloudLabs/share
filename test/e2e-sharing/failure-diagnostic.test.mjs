import assert from "node:assert/strict";
import test from "node:test";
import { safeBrowserDiagnostic, safeFailedTelemetry } from "./failure-diagnostic.mjs";

// --- safeBrowserDiagnostic ---

test("safeBrowserDiagnostic: null/undefined returns null", () => {
  assert.equal(safeBrowserDiagnostic(null), null);
  assert.equal(safeBrowserDiagnostic(undefined), null);
});

test("safeBrowserDiagnostic: string categorization", () => {
  const cat = (s) => safeBrowserDiagnostic(s).category;
  assert.equal(cat("invalid signature from wallet"), "signature");
  assert.equal(cat("missing cid in payload"), "cid");
  assert.equal(cat("canonical timestamp expired"), "canonical-registration");
  assert.equal(cat("chain binding broken"), "registration-binding");
  assert.equal(cat("POLICY_REGISTRATION_INVALID mismatch"), "policy");
  assert.equal(cat("capability not found"), "capability");
  assert.equal(cat("config missing"), "config");
  assert.equal(cat("auth session lost"), "auth");
  assert.equal(cat("enforcer not responding"), "identity");
  assert.equal(cat("delegate invocation failed"), "authorization");
  assert.equal(cat("permission denied"), "permission");
  assert.equal(cat("sign-in required"), "sign-in");
  assert.equal(cat("space not found"), "space");
  assert.equal(cat("library load error"), "library");
  assert.equal(cat("network timeout"), "network");
  assert.equal(cat("invalid payload"), "invalid");
  assert.equal(cat("something failed"), "failure");
  assert.equal(cat("unknown error occurred"), "other");

  const s = "hello world";
  assert.equal(safeBrowserDiagnostic(s).length, s.length, "length must equal string byte count");
});

test("safeBrowserDiagnostic: non-string primitive", () => {
  assert.deepEqual(safeBrowserDiagnostic(42), { type: "number" });
  assert.deepEqual(safeBrowserDiagnostic(true), { type: "boolean" });
});

test("safeBrowserDiagnostic: object with message string", () => {
  const result = safeBrowserDiagnostic({ message: "signature mismatch" });
  assert.equal(result.type, "object");
  assert.deepEqual(result.message, { length: 18, category: "signature" });
});

test("safeBrowserDiagnostic: array shape", () => {
  const result = safeBrowserDiagnostic([1, 2]);
  assert.equal(result.type, "array");
});

// --- safeFailedTelemetry ---

test("safeFailedTelemetry: non-array input returns empty array", () => {
  assert.deepEqual(safeFailedTelemetry(null), []);
  assert.deepEqual(safeFailedTelemetry(undefined), []);
  assert.deepEqual(safeFailedTelemetry("oops"), []);
  assert.deepEqual(safeFailedTelemetry({}), []);
});

test("safeFailedTelemetry: excludes non-delegate/invoke paths", () => {
  const entries = [
    { url: "https://node.example.com/health", status: 500, ok: false },
    { url: "https://node.example.com/v0/store/put", status: 403, ok: false },
  ];
  assert.deepEqual(safeFailedTelemetry(entries), []);
});

test("safeFailedTelemetry: excludes successful delegate/invoke entries", () => {
  const entries = [
    { url: "https://node.example.com/delegate", status: 200, ok: true },
    { url: "https://node.example.com/invoke", status: 200, ok: true },
  ];
  assert.deepEqual(safeFailedTelemetry(entries), []);
});

test("safeFailedTelemetry: returns failed /delegate and /invoke entries", () => {
  const entries = [
    { url: "https://node.example.com/delegate", status: 403, ok: false, contentType: "application/json" },
    { url: "https://node.example.com/invoke", status: 401, ok: false, contentType: "application/json" },
    { url: "https://node.example.com/health", status: 503, ok: false },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 2);
  assert.equal(result[0].pathname, "/delegate");
  assert.equal(result[0].status, 403);
  assert.equal(result[1].pathname, "/invoke");
  assert.equal(result[1].status, 401);
});

test("safeFailedTelemetry: detects failure via ok:false even when status is absent", () => {
  const entries = [{ url: "https://node.example.com/delegate", ok: false }];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].status, null);
});

test("safeFailedTelemetry: detects failure via errorCode presence", () => {
  const entries = [{ url: "https://node.example.com/invoke", errorCode: "UNAUTHORIZED" }];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].errorCode, "UNAUTHORIZED");
});

test("safeFailedTelemetry: structured error code with alphanumeric-plus-underscore pattern", () => {
  const entries = [{ url: "https://node.example.com/delegate", status: 403, ok: false, errorCode: "POLICY_VIOLATION" }];
  const result = safeFailedTelemetry(entries);
  assert.equal(result[0].errorCode, "POLICY_VIOLATION");
});

test("safeFailedTelemetry: serverTraceIdPresent false when no trace headers", () => {
  const entries = [{ url: "https://node.example.com/delegate", status: 403, ok: false }];
  const result = safeFailedTelemetry(entries);
  assert.equal(result[0].serverTraceIdPresent, false);
});

test("safeFailedTelemetry: serverTraceIdPresent true when traceId field is set", () => {
  const entries = [{ url: "https://node.example.com/invoke", status: 500, ok: false, traceId: "abc123" }];
  const result = safeFailedTelemetry(entries);
  assert.equal(result[0].serverTraceIdPresent, true);
});

test("safeFailedTelemetry: responseKeys sorted from JSON responseBody", () => {
  const entries = [{
    url: "https://node.example.com/invoke",
    status: 403,
    ok: false,
    responseBody: JSON.stringify({ error: "forbidden", code: "DENIED", detail: "policy" }),
  }];
  const result = safeFailedTelemetry(entries);
  assert.deepEqual(result[0].responseKeys, ["code", "detail", "error"]);
});

test("safeFailedTelemetry: hostile text with bearer/cookie/auth header/private key/DID/email/OTP/provider payload — none surface in output", () => {
  const BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.secret.sig";
  const COOKIE = "session=abc123xyz; Path=/; HttpOnly";
  const AUTH_HEADER = "Authorization: Basic dXNlcjpwYXNz";
  const PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE....\n-----END EC PRIVATE KEY-----";
  const DID = "did:pkh:eip155:1:0xDeAdBeEf1234567890abcdef1234567890abcdef";
  const EMAIL = "user@example.com";
  const OTP = "123456";
  const PROVIDER_PAYLOAD = '{"provider":"google","id_token":"ya29.a0AfH6SMB...","access_token":"1//03zzz"}';

  const hostileBody = JSON.stringify({
    bearer: BEARER,
    cookie: COOKIE,
    authHeader: AUTH_HEADER,
    privateKey: PRIVATE_KEY,
    did: DID,
    email: EMAIL,
    otp: OTP,
    provider: PROVIDER_PAYLOAD,
  });

  const entries = [{
    url: "https://node.example.com/delegate",
    status: 401,
    ok: false,
    errorCode: "UNAUTHORIZED",
    responseBody: hostileBody,
    responseBodyPreview: BEARER,
    errorBody: DID,
    traceId: "trace-abc-secret",
    responseHeaders: { "x-trace-id": "trace-xyz-789", "authorization": AUTH_HEADER },
  }];

  const result = safeFailedTelemetry(entries);
  const serialized = JSON.stringify(result);

  // The output must be non-empty (it matched /delegate and is failed)
  assert.equal(result.length, 1, "should produce one failed entry");

  // None of the hostile values should appear in the serialized output
  assert.ok(!serialized.includes("eyJhbGciOiJIUzI1NiJ9"), "bearer token JWT must not appear");
  assert.ok(!serialized.includes("session=abc123xyz"), "cookie value must not appear");
  assert.ok(!serialized.includes("Authorization: Basic"), "auth header must not appear");
  assert.ok(!serialized.includes("BEGIN EC PRIVATE KEY"), "private key must not appear");
  assert.ok(!serialized.includes("0xDeAdBeEf1234567890"), "DID address must not appear");
  assert.ok(!serialized.includes("user@example.com"), "email must not appear");
  assert.ok(!serialized.includes("ya29.a0AfH6SMB"), "provider token must not appear");
  assert.ok(!serialized.includes("1//03zzz"), "provider access token must not appear");
  assert.ok(!serialized.includes("trace-abc-secret"), "trace ID value must not appear");
  assert.ok(!serialized.includes("trace-xyz-789"), "response trace header value must not appear");
  assert.ok(!serialized.includes("Authorization"), "raw Authorization key must not appear in headers");

  // Useful safe metadata must be preserved
  assert.equal(result[0].pathname, "/delegate");
  assert.equal(result[0].status, 401);
  assert.equal(result[0].errorCode, "UNAUTHORIZED");
  assert.ok(typeof result[0].responseBodyLength === "number", "responseBodyLength must be a number");
  assert.ok(result[0].responseBodyLength > 0, "responseBodyLength must be positive");
  assert.equal(result[0].serverTraceIdPresent, true, "serverTraceIdPresent must be true when traceId field set");
});
