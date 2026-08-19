/*
 * Release-input preflight for the sharing E2E harness.
 *
 * Local pre-push runs (SHARING_E2E_LOCAL_UNPUSHED=1) only need clean
 * worktrees with their exact local heads/digests recorded; they must be
 * allowed to run while those heads are ahead of origin/remote/PR. The
 * release gate additionally requires local, upstream, remote, and PR heads
 * to be identical.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

export function assertWorktreeClean(name, path) {
  const dirty = execFileSync("git", ["-C", path, "status", "--porcelain", "--untracked-files=all"], { encoding: "utf8" });
  if (dirty.length > 0) throw new Error(`${name} worktree is dirty; release inputs must be committed`);
}

export function repositoryHeadDigest(path) {
  const head = execFileSync("git", ["-C", path, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const tree = execFileSync("git", ["-C", path, "ls-tree", "-r", "--full-tree", "HEAD"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { head, digest: createHash("sha256").update(tree).digest("hex") };
}

export function assertLocalMatchesUpstreamAndRemote(name, path, branch, local) {
  const upstream = execFileSync("git", ["-C", path, "rev-parse", `origin/${branch}`], { encoding: "utf8" }).trim();
  const remote = execFileSync("git", ["-C", path, "ls-remote", "origin", `refs/heads/${branch}`], { encoding: "utf8" }).split(/\s+/)[0];
  if (local !== upstream || local !== remote) throw new Error(`${name} local, upstream, and remote heads differ`);
}

export function assertLocalMatchesPr(name, path, pr, local) {
  const headRefOid = JSON.parse(execFileSync("gh", ["pr", "view", pr, "--json", "headRefOid"], { cwd: path, encoding: "utf8" })).headRefOid;
  if (local !== headRefOid) throw new Error(`${name} local and PR heads differ`);
}

export async function verifyReleaseInputRepository(repository, { localUnpushedMode }) {
  assertWorktreeClean(repository.name, repository.path);
  const { head, digest } = repositoryHeadDigest(repository.path);
  if (!localUnpushedMode) {
    assertLocalMatchesUpstreamAndRemote(repository.name, repository.path, repository.branch, head);
    if (repository.pr !== undefined) assertLocalMatchesPr(repository.name, repository.path, repository.pr, head);
  }
  return { head, digest };
}
