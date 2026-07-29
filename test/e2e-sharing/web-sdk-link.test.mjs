import assert from "node:assert/strict";
import { test } from "node:test";
import { join } from "node:path";
import { DEFAULT_JS_SDK_WORKTREE, RELINK_REMEDY, WEB_SDK_LINK_RELATIVE, resolveJsSdkWorktree, webSdkLinkPath, webSdkLinkProblem, webSdkTargetPath } from "./web-sdk-link.mjs";

const expected = "/workspace/worktrees/js-sdk/feat/sharing-production-live/packages/web-sdk";

test("a symlink resolving to the configured js-sdk worktree is the only accepted state", () => {
  assert.equal(webSdkLinkProblem({ kind: "symlink", resolved: expected }, expected), undefined);
});

test("a real directory is reported as exercising the published SDK, not local changes", () => {
  const problem = webSdkLinkProblem({ kind: "directory" }, expected);
  assert.match(problem, /real directory/);
  assert.match(problem, /published @tinycloud\/web-sdk/);
  assert.ok(problem.includes(RELINK_REMEDY));
});

test("a missing link is reported rather than surfacing as a bare ENOENT later", () => {
  const problem = webSdkLinkProblem({ kind: "missing" }, expected);
  assert.match(problem, /is missing/);
  assert.ok(problem.includes(expected));
  assert.ok(problem.includes(RELINK_REMEDY));
});

test("a symlink into a different js-sdk worktree is rejected with both paths named", () => {
  const stale = "/workspace/worktrees/js-sdk/feat/some-other-branch/packages/web-sdk";
  const problem = webSdkLinkProblem({ kind: "symlink", resolved: stale }, expected);
  assert.ok(problem.includes(stale));
  assert.ok(problem.includes(expected));
  assert.ok(problem.includes(RELINK_REMEDY));
});

test("every failure names the remedy, so the repair never has to be rediscovered", () => {
  for (const state of [{ kind: "missing" }, { kind: "directory" }, { kind: "symlink", resolved: "/elsewhere" }]) {
    const problem = webSdkLinkProblem(state, expected);
    assert.ok(problem.includes("npm run link:web-sdk"), `state ${state.kind} must name the remedy`);
    assert.ok(problem.includes(WEB_SDK_LINK_RELATIVE));
  }
});

test("malformed inputs throw rather than silently reporting a healthy link", () => {
  assert.throws(() => webSdkLinkProblem({ kind: "symlink" }, expected), /resolved path/);
  assert.throws(() => webSdkLinkProblem({ kind: "wat" }, expected), /unsupported web-sdk link state/);
  assert.throws(() => webSdkLinkProblem(undefined, expected), /link state is required/);
  assert.throws(() => webSdkLinkProblem({ kind: "missing" }, ""), /expected web-sdk path is required/);
});

test("the js-sdk worktree defaults to the release worktree and honours the explicit override", () => {
  assert.equal(resolveJsSdkWorktree({}, "/workspace"), join("/workspace", DEFAULT_JS_SDK_WORKTREE));
  assert.equal(resolveJsSdkWorktree({ TINYCLOUD_JS_SDK_WORKTREE: "" }, "/workspace"), join("/workspace", DEFAULT_JS_SDK_WORKTREE));
  assert.equal(resolveJsSdkWorktree({ TINYCLOUD_JS_SDK_WORKTREE: "/elsewhere/js-sdk" }, "/workspace"), "/elsewhere/js-sdk");
});

test("link and target paths are derived from one place", () => {
  assert.equal(webSdkLinkPath("/share"), "/share/node_modules/@tinycloud/web-sdk");
  assert.equal(webSdkTargetPath("/sdk"), "/sdk/packages/web-sdk");
});
