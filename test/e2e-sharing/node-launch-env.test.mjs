import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import test from "node:test";
import { buildNodeLaunchEnv } from "./node-launch-env.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/feat/sharing-production-live");

test("node launch env pins the canonical datadir under the harness tempRoot, absolute and outside the Node checkout", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "node-launch-env-test-"));
  try {
    const env = buildNodeLaunchEnv(tempRoot);
    const datadir = env.TINYCLOUD_STORAGE__DATADIR;

    assert.ok(isAbsolute(datadir), "datadir must be an absolute path");

    const relativeToTempRoot = relative(resolve(tempRoot), datadir);
    assert.ok(
      relativeToTempRoot !== "" && !relativeToTempRoot.startsWith("..") && !isAbsolute(relativeToTempRoot),
      "datadir must resolve inside the harness tempRoot",
    );

    const relativeToNodeCheckout = relative(nodeRoot, datadir);
    assert.ok(
      relativeToNodeCheckout.startsWith("..") || isAbsolute(relativeToNodeCheckout),
      "datadir must not resolve to any path inside the Node checkout",
    );
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
});
