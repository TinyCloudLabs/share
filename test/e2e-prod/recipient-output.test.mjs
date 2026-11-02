import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

test("recipient gate never prints invitation or mailbox when a dependency fails", () => {
  const secrets = ["TOPSECRETFRAGMENT", "qa-recipient-gate-5ec7e75ec7e7@mail.example", "TOPSECRETPASSWORD"];
  const directory = mkdtempSync("/var/tmp/tc500-recipient-output-");
  try {
    const inboxFile = join(directory, "inbox.json");
    writeFileSync(inboxFile, JSON.stringify({ address: secrets[1], password: secrets[2] }), { mode: 0o600 });
    const result = spawnSync(process.execPath, [new URL("./recipient-gate.mjs", import.meta.url).pathname], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        TC500_E2E_RUN: "1",
        TC500_E2E_SHARE_URL: `https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=${secrets[0]}&c=cid`,
        TC500_E2E_RECIPIENT_INBOX: inboxFile,
        TC500_E2E_EXPECTED_FILE: "/deliberately-missing-tc500-input",
      },
    });
    assert.equal(result.status, 1);
    const output = `${result.stdout}${result.stderr}`;
    assert.match(output, /sensitive details withheld/);
    for (const secret of secrets) assert.doesNotMatch(output, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("recipient gate types only the invitation-bound OTP through browser input", () => {
  const source = readFileSync(new URL("./recipient-gate.mjs", import.meta.url), "utf8");
  assert.match(source, /await input\.type\(code\)/);
  assert.match(source, /candidateInput\.value !== expected/);
  assert.doesNotMatch(source, /input\.value\s*=/);
  assert.doesNotMatch(source, /dispatchEvent\(new Event\("input"/);
  assert.doesNotMatch(source, /\.type\(recipientEmail\)/);
});
