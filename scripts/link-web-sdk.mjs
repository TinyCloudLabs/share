#!/usr/bin/env node

/*
 * TC-345. Restores (or, with --check, only verifies) the
 * `node_modules/@tinycloud/web-sdk` symlink into the js-sdk worktree the
 * sharing harness is configured to exercise.
 *
 * `npm install` writes the published registry package over that path. Until
 * now the link was restored by hand, so a run could exercise the published
 * SDK while reporting on local SDK changes. `npm run link:web-sdk` is the
 * remedy every assertion in test/e2e-sharing/web-sdk-link.mjs names, and
 * `npm run check:web-sdk-link` is the loud, dependency-free preflight.
 *
 * This script is deliberately not a `postinstall` hook: production and CI
 * installs have no js-sdk worktree to link to, and a hook that silently
 * succeeds or silently skips is the failure mode this issue exists to remove.
 */

import { lstatSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { assertWebSdkLink, resolveJsSdkWorktree, webSdkLinkPath, webSdkTargetPath } from "../test/e2e-sharing/web-sdk-link.mjs";

const shareRoot = resolve(import.meta.dirname, "..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const sdkRoot = resolveJsSdkWorktree(process.env, workspaceRoot);
const linkPath = webSdkLinkPath(shareRoot);
const targetPath = webSdkTargetPath(sdkRoot);
const checkOnly = process.argv.includes("--check");
const companionPackages = ["sdk-core", "share-envelope", "share-sdk"];

if (checkOnly) {
  const resolved = assertWebSdkLink(shareRoot, sdkRoot);
  for (const packageName of companionPackages) {
    const actual = realpathSync(resolve(shareRoot, "node_modules", "@tinycloud", packageName));
    const expected = realpathSync(resolve(sdkRoot, "packages", packageName));
    if (actual !== expected) throw new Error(`node_modules/@tinycloud/${packageName} resolves to ${actual}, expected ${expected}; run \`npm run link:web-sdk\``);
  }
  console.log(`@tinycloud/web-sdk resolves to the js-sdk worktree under test: ${resolved}`);
  process.exit(0);
}

// Verify the target before touching the link: a typo in
// TINYCLOUD_JS_SDK_WORKTREE must not leave the tree with no web-sdk at all.
lstatSync(targetPath);
rmSync(linkPath, { recursive: true, force: true });
symlinkSync(targetPath, linkPath);
for (const packageName of companionPackages) {
  const companionLink = resolve(shareRoot, "node_modules", "@tinycloud", packageName);
  const companionTarget = resolve(sdkRoot, "packages", packageName);
  lstatSync(companionTarget);
  rmSync(companionLink, { recursive: true, force: true });
  symlinkSync(companionTarget, companionLink);
}
const resolved = assertWebSdkLink(shareRoot, sdkRoot);
console.log(`linked ${linkPath} -> ${resolved} with ${companionPackages.join(", ")}`);
