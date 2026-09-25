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

test("OTP extraction reads only the 8-digit code line and ignores HTML tokens", () => {
  const message = {
    payload: {
      html: '<style>body { color: #65432187 }</style>',
      text: "Your 8-digit OpenCredentials code is 12345678.\n\nEnter it on the page that asked you to verify this mailbox. It expires in five minutes and works once.\n\nIf you did not request this code, you can ignore this email.",
    },
  };
  assert.equal(credentialOtpFromMail(message), "12345678");
  assert.equal(credentialOtpFromMail({ payload: { text: "Your 8-digit OpenCredentials code is 1234567." } }), undefined);
  assert.equal(credentialOtpFromMail({ payload: { text: "Use 123456" } }), undefined);
  assert.equal(credentialOtpFromMail({ payload: { text: "Your one-time OpenCredentials code is 123456. It expires in five minutes." } }), undefined);
});
