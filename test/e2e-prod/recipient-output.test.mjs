import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("recipient gate never prints invitation, mailbox, or OTP when a dependency fails", () => {
  const secrets = ["TOPSECRETFRAGMENT", "secret-recipient@mailinator.com", "123456"];
  const result = spawnSync(process.execPath, [new URL("./recipient-gate.mjs", import.meta.url).pathname], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      TC500_E2E_RUN: "1",
      TC500_E2E_SHARE_URL: `https://share.tinycloud.xyz/s/inline#v=2&p=${secrets[0]}`,
      TC500_E2E_RECIPIENT_EMAIL: secrets[1],
      TC500_E2E_EXPECTED_FILE: "/deliberately-missing-tc500-input",
      TC500_E2E_MAILBOX_OTP: secrets[2],
    },
  });
  assert.equal(result.status, 1);
  const output = `${result.stdout}${result.stderr}`;
  assert.match(output, /sensitive details withheld/);
  for (const secret of secrets) assert.doesNotMatch(output, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});
