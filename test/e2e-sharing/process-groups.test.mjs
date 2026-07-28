import assert from "node:assert/strict";
import test from "node:test";
import { findSurvivingOwnedProcesses, parsePsLines } from "./process-groups.mjs";

test("an unrelated matching command is ignored", () => {
  const psLines = parsePsLines("4242 4242 node test/e2e-sharing/integration.mjs\n");
  const surviving = findSurvivingOwnedProcesses(psLines, new Set([9999]), 1);
  assert.deepEqual(surviving, []);
});

test("an empty owned group passes", () => {
  const psLines = parsePsLines("4242 4242 cargo run --quiet -p tinycloud-node\n5150 4242 tinycloud-node\n");
  const surviving = findSurvivingOwnedProcesses(psLines, new Set(), 1);
  assert.deepEqual(surviving, []);
});

test("a surviving exact owned PID fails", () => {
  const psLines = parsePsLines("4242 4242 target/debug/tinycloud\n1 1 launchd\n");
  const surviving = findSurvivingOwnedProcesses(psLines, new Set([4242]), 1);
  assert.deepEqual(surviving, [{ pid: 4242, pgid: 4242, command: "target/debug/tinycloud" }]);
});
