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
  const FAKE_RAW_REQUEST_BODY = '{"capability":"did:key:z6Mkfake","nonce":"hostile-nonce-ABCDEF","secret":"TOP_SECRET_VALUE"}';
  const FAKE_DIGEST = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
  const FAKE_AUTH_VALUE = "Bearer eyJhbGciOiJFUzI1NiJ9.HOSTILE_AUTH_PAYLOAD.sig";
  const FAKE_AUTH_DIGEST = "aabbccdd1122334455667788aabbccdd1122334455667788aabbccdd11223344";

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
    requestBodyLength: FAKE_RAW_REQUEST_BODY.length,
    requestBodyDigest: FAKE_DIGEST,
    requestDigestAvailable: true,
    authorizationPresent: true,
    authorizationDigestAvailable: true,
    authorizationDigest: FAKE_AUTH_DIGEST,
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
  assert.ok(!serialized.includes(AUTH_HEADER), "raw Authorization header value must not appear in output");
  assert.ok(!serialized.includes(FAKE_RAW_REQUEST_BODY), "raw request body must not appear");
  assert.ok(!serialized.includes(FAKE_DIGEST), "requestBodyDigest must not appear in output");
  assert.ok(!serialized.includes("TOP_SECRET_VALUE"), "request body secret value must not appear");
  assert.ok(!serialized.includes("hostile-nonce-ABCDEF"), "request body nonce must not appear");
  assert.ok(!serialized.includes(FAKE_AUTH_VALUE), "raw Authorization header value must not appear");
  assert.ok(!serialized.includes(FAKE_AUTH_DIGEST), "authorizationDigest must not appear in output");
  assert.ok(!serialized.includes("HOSTILE_AUTH_PAYLOAD"), "Authorization payload fragment must not appear");

  // Useful safe metadata must be preserved
  assert.equal(result[0].pathname, "/delegate");
  assert.equal(result[0].status, 401);
  assert.equal(result[0].errorCode, "UNAUTHORIZED");
  assert.ok(typeof result[0].responseBodyLength === "number", "responseBodyLength must be a number");
  assert.ok(result[0].responseBodyLength > 0, "responseBodyLength must be positive");
  assert.equal(result[0].serverTraceIdPresent, true, "serverTraceIdPresent must be true when traceId field set");
  assert.equal(result[0].requestBodyLength, FAKE_RAW_REQUEST_BODY.length, "requestBodyLength must be the stored length");
  assert.equal(result[0].requestDigestAvailable, true, "requestDigestAvailable must be preserved");
  assert.ok(!("requestBodyDigest" in result[0]), "requestBodyDigest must not be present in output");
  assert.equal(result[0].authorizationPresent, true, "authorizationPresent must be preserved");
  assert.equal(result[0].authorizationDigestAvailable, true, "authorizationDigestAvailable must be preserved");
  assert.ok(!("authorizationDigest" in result[0]), "authorizationDigest must not be present in output");
});

// --- safeFailedTelemetry: request body correlation fields ---

test("safeFailedTelemetry: matchesSuccessfulRequestBody true when 2xx delegate shares digest", () => {
  const DIGEST = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
  const entries = [
    { url: "https://node.example.com/delegate", status: 200, requestBodyDigest: DIGEST, requestDigestAvailable: true, requestBodyLength: 64 },
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: DIGEST, requestDigestAvailable: true, requestBodyLength: 64 },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].matchesSuccessfulRequestBody, true);
  assert.equal(result[0].sameRequestBodyCount, 2);
  assert.equal(result[0].distinctDelegateRequestBodyCount, 1);
  assert.ok(!("requestBodyDigest" in result[0]), "requestBodyDigest must not appear in output");
});

test("safeFailedTelemetry: matchesSuccessfulRequestBody false when no 2xx delegate shares digest", () => {
  const DIGEST_A = "1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff1111aaaa2222bbbb";
  const DIGEST_B = "2222bbbb3333cccc4444dddd5555eeee6666ffff1111aaaa2222bbbb3333cccc";
  const entries = [
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: DIGEST_A, requestDigestAvailable: true, requestBodyLength: 32 },
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: DIGEST_B, requestDigestAvailable: true, requestBodyLength: 48 },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 2);
  assert.equal(result[0].matchesSuccessfulRequestBody, false);
  assert.equal(result[1].matchesSuccessfulRequestBody, false);
  assert.equal(result[0].distinctDelegateRequestBodyCount, 2);
  assert.equal(result[1].distinctDelegateRequestBodyCount, 2);
  assert.ok(!("requestBodyDigest" in result[0]), "requestBodyDigest must not appear");
  assert.ok(!("requestBodyDigest" in result[1]), "requestBodyDigest must not appear");
});

test("safeFailedTelemetry: requestDigestAvailable false yields zero counts and false match", () => {
  const entries = [
    { url: "https://node.example.com/delegate", status: 500, ok: false, requestDigestAvailable: false, requestBodyLength: 100 },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].requestDigestAvailable, false);
  assert.equal(result[0].matchesSuccessfulRequestBody, false);
  assert.equal(result[0].sameRequestBodyCount, 0);
  assert.equal(result[0].distinctDelegateRequestBodyCount, 0);
  assert.ok(!("requestBodyDigest" in result[0]), "requestBodyDigest must not appear");
});

test("safeFailedTelemetry: sameRequestBodyCount counts all delegate entries sharing digest", () => {
  const DIGEST = "cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444";
  const entries = [
    { url: "https://node.example.com/delegate", status: 200, requestBodyDigest: DIGEST, requestDigestAvailable: true, requestBodyLength: 10 },
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: DIGEST, requestDigestAvailable: true, requestBodyLength: 10 },
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: DIGEST, requestDigestAvailable: true, requestBodyLength: 10 },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 2);
  assert.equal(result[0].sameRequestBodyCount, 3);
  assert.equal(result[1].sameRequestBodyCount, 3);
});

test("safeFailedTelemetry: distinctDelegateRequestBodyCount counts unique valid digests", () => {
  const D1 = "1111111111111111111111111111111111111111111111111111111111111111";
  const D2 = "2222222222222222222222222222222222222222222222222222222222222222";
  const D3 = "3333333333333333333333333333333333333333333333333333333333333333";
  const entries = [
    { url: "https://node.example.com/delegate", status: 200, requestBodyDigest: D1, requestDigestAvailable: true, requestBodyLength: 10 },
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: D2, requestDigestAvailable: true, requestBodyLength: 20 },
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: D3, requestDigestAvailable: true, requestBodyLength: 30 },
    // entry without digest should not add to distinct count
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestDigestAvailable: false, requestBodyLength: 40 },
  ];
  const result = safeFailedTelemetry(entries);
  // 3 failed entries
  assert.equal(result.length, 3);
  // distinctDelegateRequestBodyCount is 3 (D1, D2, D3), not 4
  assert.ok(result.every((r) => r.distinctDelegateRequestBodyCount === 3), "all failed entries see 3 distinct digests");
});

test("safeFailedTelemetry: /invoke entries do not get request body correlation fields", () => {
  const entries = [
    { url: "https://node.example.com/invoke", status: 403, ok: false,
      requestBodyDigest: "deadbeef".repeat(8), requestDigestAvailable: true, requestBodyLength: 99 },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].pathname, "/invoke");
  assert.ok(!("requestBodyLength" in result[0]), "invoke must not have requestBodyLength");
  assert.ok(!("requestDigestAvailable" in result[0]), "invoke must not have requestDigestAvailable");
  assert.ok(!("matchesSuccessfulRequestBody" in result[0]), "invoke must not have matchesSuccessfulRequestBody");
  assert.ok(!("sameRequestBodyCount" in result[0]), "invoke must not have sameRequestBodyCount");
  assert.ok(!("distinctDelegateRequestBodyCount" in result[0]), "invoke must not have distinctDelegateRequestBodyCount");
  assert.ok(!("requestBodyDigest" in result[0]), "invoke must not have requestBodyDigest");
});

test("safeFailedTelemetry: zero-length empty-body digest cannot match successful delegate and yields requestDigestAvailable:false", () => {
  // SHA-256 of empty string — must never count as a valid correlatable digest
  const EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const entries = [
    // A successful delegate with zero-length body — should NOT be accepted into digestStats
    { url: "https://node.example.com/delegate", status: 200, requestBodyDigest: EMPTY_DIGEST, requestDigestAvailable: true, requestBodyLength: 0 },
    // A failed delegate with zero-length body — should yield requestDigestAvailable:false
    { url: "https://node.example.com/delegate", status: 403, ok: false, requestBodyDigest: EMPTY_DIGEST, requestDigestAvailable: true, requestBodyLength: 0 },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1, "only the failed entry is returned");
  assert.equal(result[0].requestDigestAvailable, false, "zero-length body must yield requestDigestAvailable:false");
  assert.equal(result[0].matchesSuccessfulRequestBody, false, "zero-length body must not match any successful request");
  assert.equal(result[0].sameRequestBodyCount, 0, "zero-length body must yield sameRequestBodyCount:0");
  assert.equal(result[0].distinctDelegateRequestBodyCount, 0, "zero-length body must yield distinctDelegateRequestBodyCount:0");
  assert.ok(!("requestBodyDigest" in result[0]), "requestBodyDigest must not appear in output");
});

// --- safeFailedTelemetry: authorization digest correlation fields ---

test("safeFailedTelemetry: matchesSuccessfulAuthorization true when 2xx delegate shares auth digest", () => {
  const AUTH_DIGEST = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222";
  const entries = [
    { url: "https://node.example.com/delegate", status: 200, authorizationPresent: true, authorizationDigest: AUTH_DIGEST, authorizationDigestAvailable: true },
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: true, authorizationDigest: AUTH_DIGEST, authorizationDigestAvailable: true },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].authorizationPresent, true);
  assert.equal(result[0].authorizationDigestAvailable, true);
  assert.equal(result[0].matchesSuccessfulAuthorization, true);
  assert.equal(result[0].sameAuthorizationCount, 2);
  assert.equal(result[0].distinctDelegateAuthorizationCount, 1);
  assert.ok(!("authorizationDigest" in result[0]), "authorizationDigest must not appear in output");
});

test("safeFailedTelemetry: matchesSuccessfulAuthorization false when no 2xx delegate shares auth digest", () => {
  const AUTH_A = "1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff1111aaaa2222bbbb";
  const AUTH_B = "2222bbbb3333cccc4444dddd5555eeee6666ffff1111aaaa2222bbbb3333cccc";
  const entries = [
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: true, authorizationDigest: AUTH_A, authorizationDigestAvailable: true },
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: true, authorizationDigest: AUTH_B, authorizationDigestAvailable: true },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 2);
  assert.equal(result[0].matchesSuccessfulAuthorization, false);
  assert.equal(result[1].matchesSuccessfulAuthorization, false);
  assert.equal(result[0].distinctDelegateAuthorizationCount, 2);
  assert.equal(result[1].distinctDelegateAuthorizationCount, 2);
  assert.ok(!("authorizationDigest" in result[0]), "authorizationDigest must not appear");
  assert.ok(!("authorizationDigest" in result[1]), "authorizationDigest must not appear");
});

test("safeFailedTelemetry: authorizationDigestAvailable false yields false/zero auth fields", () => {
  const entries = [
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: false, authorizationDigestAvailable: false },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 1);
  assert.equal(result[0].authorizationPresent, false);
  assert.equal(result[0].authorizationDigestAvailable, false);
  assert.equal(result[0].matchesSuccessfulAuthorization, false);
  assert.equal(result[0].sameAuthorizationCount, 0);
  assert.equal(result[0].distinctDelegateAuthorizationCount, 0);
  assert.ok(!("authorizationDigest" in result[0]), "authorizationDigest must not appear");
});

test("safeFailedTelemetry: distinctDelegateAuthorizationCount counts unique auth digests across all delegate entries", () => {
  const AUTH_A = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
  const AUTH_B = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
  const entries = [
    { url: "https://node.example.com/delegate", status: 200, authorizationPresent: true, authorizationDigest: AUTH_A, authorizationDigestAvailable: true },
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: true, authorizationDigest: AUTH_A, authorizationDigestAvailable: true },
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: true, authorizationDigest: AUTH_B, authorizationDigestAvailable: true },
    { url: "https://node.example.com/delegate", status: 403, ok: false, authorizationPresent: false, authorizationDigestAvailable: false },
  ];
  const result = safeFailedTelemetry(entries);
  assert.equal(result.length, 3);
  assert.ok(result.every((r) => r.distinctDelegateAuthorizationCount === 2), "all failed entries see 2 distinct auth digests");
  assert.equal(result[0].matchesSuccessfulAuthorization, true, "AUTH_A matches a 2xx entry");
  assert.equal(result[1].matchesSuccessfulAuthorization, false, "AUTH_B does not match a 2xx entry");
  assert.equal(result[2].matchesSuccessfulAuthorization, false, "unavailable auth does not match");
  assert.ok(!result.some((r) => "authorizationDigest" in r), "authorizationDigest must never appear in output");
});
