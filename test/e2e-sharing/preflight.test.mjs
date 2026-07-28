import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { verifyReleaseInputRepository } from "./preflight.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

async function makeRepoPair(branch) {
  const root = await mkdtemp(join(tmpdir(), "sharing-preflight-"));
  const originPath = join(root, "origin.git");
  const localPath = join(root, "local");
  git(root, ["init", "--bare", originPath]);
  git(root, ["init", "-b", branch, localPath]);
  git(localPath, ["config", "user.email", "test@example.com"]);
  git(localPath, ["config", "user.name", "Test"]);
  await writeFile(join(localPath, "file.txt"), "initial\n");
  git(localPath, ["add", "file.txt"]);
  git(localPath, ["commit", "-m", "initial"]);
  git(localPath, ["remote", "add", "origin", originPath]);
  git(localPath, ["push", "-u", "origin", branch]);
  return { root, localPath };
}

test("local-unpushed mode accepts a clean worktree ahead of its remote", async () => {
  const { root, localPath } = await makeRepoPair("feat/local-ahead");
  try {
    await writeFile(join(localPath, "file.txt"), "second\n");
    git(localPath, ["commit", "-am", "second"]);
    const localHead = git(localPath, ["rev-parse", "HEAD"]).trim();
    const result = await verifyReleaseInputRepository(
      { name: "fixture", path: localPath, branch: "feat/local-ahead", pr: "1" },
      { localUnpushedMode: true },
    );
    assert.equal(result.head, localHead);
    assert.match(result.digest, /^[0-9a-f]{64}$/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("local-unpushed mode rejects a dirty worktree", async () => {
  const { root, localPath } = await makeRepoPair("feat/local-dirty");
  try {
    await writeFile(join(localPath, "file.txt"), "dirty\n");
    await assert.rejects(
      verifyReleaseInputRepository({ name: "fixture", path: localPath, branch: "feat/local-dirty", pr: "1" }, { localUnpushedMode: true }),
      /worktree is dirty/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("release mode rejects local heads ahead of the remote", async () => {
  const { root, localPath } = await makeRepoPair("feat/release-mismatch");
  try {
    await writeFile(join(localPath, "file.txt"), "second\n");
    git(localPath, ["commit", "-am", "second"]);
    await assert.rejects(
      verifyReleaseInputRepository({ name: "fixture", path: localPath, branch: "feat/release-mismatch", pr: "1" }, { localUnpushedMode: false }),
      /local, upstream, and remote heads differ/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
