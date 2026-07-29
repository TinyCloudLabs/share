/*
 * TC-345. The sharing harness is only meaningful when
 * `node_modules/@tinycloud/web-sdk` resolves to the js-sdk worktree under
 * test. `npm install` replaces that symlink with the published registry
 * package, and nothing in the repository restores it: it has been relinked by
 * hand between runs. A harness that silently exercises the *published* SDK
 * while reporting on local SDK changes is the same false-green shape as
 * TC-306 (the harness testing the production node for eleven days) and
 * TC-338.
 *
 * The two integration.mjs call sites already lstat'd the link, but each
 * inlined its own copy of the rule and neither said how to repair it, so the
 * knowledge lived in a person rather than in the repository. This module is
 * the single statement of the rule. `webSdkLinkProblem` is pure so it can be
 * unit-tested without a node_modules tree; `assertWebSdkLink` is the thin
 * filesystem wrapper both call sites and `scripts/link-web-sdk.mjs` use, and
 * every failure names the exact remedy.
 */

import { lstatSync, realpathSync } from "node:fs";
import { join } from "node:path";

export const DEFAULT_JS_SDK_WORKTREE = "worktrees/js-sdk/feat/sharing-production-live";
export const WEB_SDK_LINK_RELATIVE = "node_modules/@tinycloud/web-sdk";
export const WEB_SDK_TARGET_RELATIVE = "packages/web-sdk";
export const RELINK_REMEDY = "run `npm run link:web-sdk` (npm install replaces the link with the published registry package)";

export function resolveJsSdkWorktree(env, workspaceRoot) {
  const configured = env.TINYCLOUD_JS_SDK_WORKTREE;
  if (typeof configured === "string" && configured.length > 0) return configured;
  return join(workspaceRoot, DEFAULT_JS_SDK_WORKTREE);
}

export function webSdkLinkPath(shareRoot) { return join(shareRoot, WEB_SDK_LINK_RELATIVE); }
export function webSdkTargetPath(sdkRoot) { return join(sdkRoot, WEB_SDK_TARGET_RELATIVE); }

/**
 * Pure decision. `state` describes what the filesystem reported:
 *   { kind: "missing" }                       nothing at the link path
 *   { kind: "directory" }                     a real directory (the published package)
 *   { kind: "symlink", resolved: "<path>" }   a symlink and where it lands
 * `expected` is the realpath the link must resolve to. Returns undefined when
 * the link is correct, otherwise the exact failure message to throw.
 */
export function webSdkLinkProblem(state, expected) {
  if (typeof expected !== "string" || expected.length === 0) throw new Error("expected web-sdk path is required");
  if (state === undefined || state === null || typeof state !== "object") throw new Error("web-sdk link state is required");
  if (state.kind === "missing") {
    return `${WEB_SDK_LINK_RELATIVE} is missing; the harness cannot prove which @tinycloud/web-sdk it exercises. Expected a symlink to ${expected}: ${RELINK_REMEDY}.`;
  }
  if (state.kind === "directory") {
    return `${WEB_SDK_LINK_RELATIVE} is a real directory, so the harness would exercise the published @tinycloud/web-sdk instead of ${expected}. This reports on local SDK changes without testing them: ${RELINK_REMEDY}.`;
  }
  if (state.kind !== "symlink") throw new Error(`unsupported web-sdk link state: ${String(state.kind)}`);
  if (typeof state.resolved !== "string" || state.resolved.length === 0) throw new Error("symlink state requires a resolved path");
  if (state.resolved !== expected) {
    return `${WEB_SDK_LINK_RELATIVE} resolves to ${state.resolved} but the harness is configured for ${expected}; the run would report on the wrong js-sdk worktree: ${RELINK_REMEDY}.`;
  }
  return undefined;
}

export function readWebSdkLinkState(linkPath) {
  let stat;
  try {
    stat = lstatSync(linkPath);
  } catch (error) {
    if (error?.code === "ENOENT") return { kind: "missing" };
    throw error;
  }
  if (!stat.isSymbolicLink()) return { kind: "directory" };
  return { kind: "symlink", resolved: realpathSync(linkPath) };
}

export function assertWebSdkLink(shareRoot, sdkRoot) {
  const linkPath = webSdkLinkPath(shareRoot);
  const targetPath = webSdkTargetPath(sdkRoot);
  let expected;
  try {
    expected = realpathSync(targetPath);
  } catch (error) {
    if (error?.code === "ENOENT") throw new Error(`js-sdk worktree ${targetPath} does not exist; set TINYCLOUD_JS_SDK_WORKTREE to the worktree under test`);
    throw error;
  }
  const problem = webSdkLinkProblem(readWebSdkLinkState(linkPath), expected);
  if (problem !== undefined) throw new Error(problem);
  return expected;
}
