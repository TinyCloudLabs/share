import { test } from "node:test";
import assert from "node:assert/strict";
import { APPROVE_NAME, refusal, scrub } from "./smoke-redact.mjs";

test("the approval name guard accepts the approval's labels, ready and signing", () => {
  for (const name of ["Approve", "Approve exact bytes", "Signing…"]) assert.equal(APPROVE_NAME.test(name), true, name);
});

test("the approval name guard rejects every other button a dialog can end with", () => {
  for (const name of ["Cancel", "Copy text", "Copy space ID", "Edit", "Reset", "Extra help", "Approve all", "Reject", "Close", ""]) assert.equal(APPROVE_NAME.test(name), false, name);
});

test("refusal keeps the error code and message and drops a sign-up token", () => {
  const out = refusal(JSON.stringify({ code: "NEW_ACCOUNT_CONFIRMATION_REQUIRED", message: "No OpenKey account exists for this email.", signupToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG" }));
  assert.equal(out.code, "NEW_ACCOUNT_CONFIRMATION_REQUIRED");
  assert.deepEqual(JSON.parse(out.body), { code: "NEW_ACCOUNT_CONFIRMATION_REQUIRED", message: "No OpenKey account exists for this email.", signupToken: "<redacted>" });
});

test("refusal redacts every key that is not allowlisted, at any depth", () => {
  const out = JSON.parse(refusal(JSON.stringify({ error: "siwe_origin_refused", signupCode: "Zx9Qm2", verification: "AB12CD", nested: { a: { b: { signupToken: "sekret1" } } } })).body);
  assert.deepEqual(out, { error: "siwe_origin_refused", signupCode: "<redacted>", verification: "<redacted>", nested: "<redacted>" });
});

test("refusal keeps error.code and error.message only", () => {
  const out = refusal(JSON.stringify({ error: { code: "app_key_grant_refused", message: "Refused.", token: "t0k3n" } }));
  assert.equal(out.code, "app_key_grant_refused");
  assert.deepEqual(JSON.parse(out.body), { error: { code: "app_key_grant_refused", message: "Refused.", token: "<redacted>" } });
});

test("refusal does not keep a code that could be a one-time code", () => {
  for (const code of ["Zx9Qm2", "123456", "ab12cd"]) {
    const out = refusal(JSON.stringify({ code }));
    assert.equal(out.code, undefined, code);
    assert.equal(JSON.parse(out.body).code, "<redacted>", code);
  }
});

test("refusal scrubs a body that is not JSON", () => {
  assert.equal(refusal("Forbidden: https://example.com/verify/ab12cd34ef56?t=1 qa@mail.tm").body, "Forbidden: https://example.com/<redacted> <email>");
});

test("scrub removes tokens, codes, links' secrets, emails and long numbers", () => {
  const cases = [
    ["token eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln end", "token <jwt> end"],
    ["key Zm9vYmFyYmF6cXV4Kz8/Pz8+PT0= end", "key <id> end"],
    ["for user%40mail.tm", "for <email>"],
    ["/verify/ab12cd34ef56", "/verify/<id>"],
    ["id 1234567890", "id <digits>"],
    ["https://openkey.so/a/h7afotjzulbxlu4hdyrxwb2dd6#v=4&k=secret", "https://openkey.so/a/<id>"],
    ["https://mail.example/inbox/x?y=1", "https://mail.example/<redacted>"],
  ];
  for (const [input, expected] of cases) assert.equal(scrub(input), expected, input);
});

test("scrub keeps route words and error codes readable", () => {
  assert.equal(scrub("/api/delegate/authorize-sign-prepare"), "/api/delegate/authorize-sign-prepare");
  assert.equal(scrub("NEW_ACCOUNT_CONFIRMATION_REQUIRED"), "NEW_ACCOUNT_CONFIRMATION_REQUIRED");
  assert.equal(scrub("/api/keys/cmvyfu5yt005001o2rrw4kjzp/sign"), "/api/keys/<id>/sign");
  // A long lowercase run with no hyphen is an id, even without digits; hyphenated route words stay.
  assert.equal(scrub("/s/abcdefghijklmnopqrstuvwx/view"), "/s/<id>/view");
  assert.equal(scrub("/policy/v3/delegations/authorize-sign-prepare-now"), "/policy/v3/delegations/authorize-sign-prepare-now");
});

test("known limit: a short bare token in free text passes the scrub; the key allowlist is the control", () => {
  assert.equal(scrub("your code is Zx9Qm2"), "your code is Zx9Qm2");
  assert.deepEqual(JSON.parse(refusal(JSON.stringify({ otp: "Zx9Qm2" })).body), { otp: "<redacted>" });
});
