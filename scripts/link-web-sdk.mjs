#!/usr/bin/env node

/*
 * TC-345. Restores (or, with --check, only verifies) the
 * `node_modules/@tinycloud/web-sdk` symlink into the explicit js-sdk worktree
 * the native sharing proof is configured to exercise.
 *
 * `npm install` writes the published registry package over that path. Until
 * now the link was restored by hand, so a run could exercise the published
 * SDK while reporting on local SDK changes. `npm run link:web-sdk` is the
 * repair and `npm run check:web-sdk-link` is the loud, dependency-free
 * preflight.
 *
 * This script is deliberately not a `postinstall` hook: production installs
 * use published packages, while the cross-repository CI gate supplies an
 * explicit checkout. A hook that silently succeeds or skips is the failure
 * mode this issue exists to remove.
 */

import { lstatSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

const shareRoot = resolve(import.meta.dirname, "..");
const configuredWorktree = process.env.TINYCLOUD_JS_SDK_WORKTREE?.trim();
if (!configuredWorktree) throw new Error("TINYCLOUD_JS_SDK_WORKTREE is required so this command cannot silently select a sibling or published SDK");
const sdkRoot = resolve(configuredWorktree);
const linkPath = resolve(shareRoot, "node_modules/@tinycloud/web-sdk");
const targetPath = resolve(sdkRoot, "packages/web-sdk");
const checkOnly = process.argv.includes("--check");
const companionPackages = ["sdk-services", "sdk-core", "node-sdk", "share-envelope", "share-sdk"];

function assertPackageLink(packageName, packagePath, expectedPath) {
  const expected = realpathSync(expectedPath);
  let stat;
  try { stat = lstatSync(packagePath); }
  catch (error) {
    if (error?.code === "ENOENT") throw new Error(`${packageName} link is missing; run \`npm run link:web-sdk\``);
    throw error;
  }
  if (!stat.isSymbolicLink()) throw new Error(`${packageName} is a real directory, so the proof would exercise a published package; run \`npm run link:web-sdk\``);
  const actual = realpathSync(packagePath);
  if (actual !== expected) throw new Error(`${packageName} resolves to ${actual}, expected ${expected}; run \`npm run link:web-sdk\``);
  return actual;
}

if (checkOnly) {
  const resolved = assertPackageLink("@tinycloud/web-sdk", linkPath, targetPath);
  for (const packageName of companionPackages) {
    assertPackageLink(`@tinycloud/${packageName}`, resolve(shareRoot, "node_modules", "@tinycloud", packageName), resolve(sdkRoot, "packages", packageName));
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
const resolved = assertPackageLink("@tinycloud/web-sdk", linkPath, targetPath);
console.log(`linked ${linkPath} -> ${resolved} with ${companionPackages.join(", ")}`);
