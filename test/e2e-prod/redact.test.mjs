import assert from "node:assert/strict";
import test from "node:test";
import { redactString, redactValue } from "./lib/redact.mjs";

test("redacts production receiver identifiers and credential material", () => {
  const input = [
    "recipient tcshare-rcpt-abc@mailinator.com",
    "https://share.tinycloud.xyz/s/share-id#k=private-key",
    "https://api.mailinator.com/api/v2/domains/public/inboxes/tcshare-rcpt-abc/messages/message-id",
    "OTP 123456",
  ].join("\n");
  const output = redactString(input);

  assert.doesNotMatch(output, /tcshare-rcpt-abc/);
  assert.doesNotMatch(output, /share-id|private-key|123456/);
  assert.match(output, /<redacted-email>/);
  assert.match(output, /<redacted-share-url>/);
  assert.match(output, /\/inboxes\/<redacted>/);
  assert.match(output, /<redacted-otp>/);
});

test("redacts nested receiver proof fields", () => {
  const output = redactValue({
    credential: "issued-credential",
    request: {
      authorization: "Bearer receiver-authority",
      body: '{"email":"tcshare-rcpt-abc@mailinator.com"}',
    },
  });

  assert.equal(output.credential, "<redacted>");
  assert.equal(output.request.authorization, "<redacted>");
  assert.doesNotMatch(output.request.body, /tcshare-rcpt-abc/);
});
