import assert from "node:assert/strict";
import test from "node:test";
import { credentialOtpFromMail, isCredentialOtpMail, resendFixtureJsonResponse } from "./native-stack.mjs";

test("Resend fixture responses declare their exact bounded UTF-8 length", () => {
  const response = resendFixtureJsonResponse({ id: "mail_é" }, { "cache-control": "no-store" });

  assert.equal(response.headers["content-type"], "application/json");
  assert.equal(response.headers["content-length"], String(Buffer.byteLength(response.body)));
  assert.equal(response.headers["cache-control"], "no-store");
  assert.deepEqual(JSON.parse(response.body), { id: "mail_é" });
});

test("OTP selection is bound to the verification subject and exact recipient", () => {
  const recipient = "unique@example.test";
  assert.equal(isCredentialOtpMail({ payload: { subject: "Your OpenCredentials verification code", to: [recipient], text: "123456" } }, recipient), true);
  assert.equal(isCredentialOtpMail({ payload: { subject: "Your TinyCloud share", to: [recipient], text: "Unrelated 654321" } }, recipient), false);
  assert.equal(isCredentialOtpMail({ payload: { subject: "Your OpenCredentials verification code", to: ["other@example.test"], text: "123456" } }, recipient), false);
});

test("OTP extraction ignores unrelated six-digit HTML tokens", () => {
  const message = {
    payload: {
      html: '<style>body { color: #654321 }</style>',
      text: "Your one-time OpenCredentials code is 123456. It expires in five minutes.",
    },
  };
  assert.equal(credentialOtpFromMail(message), "123456");
  assert.equal(credentialOtpFromMail({ payload: { text: "Use 123456" } }), undefined);
});
