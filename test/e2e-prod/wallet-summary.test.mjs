import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walletSummaryRecorder } from "./wallet-summary.mjs";

test("the summary records each wallet once and accepts only addresses", () => {
  const directory = mkdtempSync(join(tmpdir(), "wallet-summary-"));
  try {
    const path = join(directory, "summary");
    const record = walletSummaryRecorder(path);
    const first = `0x${"ab".repeat(20)}`;
    const second = `0x${"12".repeat(20)}`;
    record(first);
    record(`0x${"AB".repeat(20)}`);
    record(second);
    for (const value of [undefined, {}, "person@example.com", "token", `0x${"ab".repeat(32)}`, `${first}\nsecret`]) record(value);
    assert.equal(readFileSync(path, "utf8"), `Smoke wallet: ${first}\nSmoke wallet: ${second}\n`);
    walletSummaryRecorder("")(first);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
