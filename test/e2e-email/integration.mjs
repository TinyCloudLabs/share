#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const shareRoot = resolve(import.meta.dirname, "../..");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(shareRoot, "../../../tinycloud-node/feat/email-claim-n4-integration");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? resolve(shareRoot, "../../../opencredentials/feat/email-claim-o4-integration");
const credentialsRustRoot = resolve(credentialsRoot, "rust/opencredentials_witness");
const vectorRoot = resolve(shareRoot, "test/vectors/email-claim-v1");
const expectedManifestDigest = "0KhpZQqEm2N01I3fNOSN0LclCbR3uw_EK8CoBtqua2g";

function run(command, args, cwd) {
  console.log(`$ ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, { cwd, stdio: "inherit", env: process.env });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function clean(repo) {
  const result = spawnSync("git", ["status", "--porcelain"], { cwd: repo, encoding: "utf8" });
  if (result.status !== 0 || result.stdout.trim() !== "") {
    throw new Error(`worktree must be clean: ${repo}`);
  }
}

if (!existsSync(resolve(vectorRoot, "manifest.json"))) throw new Error("Share vectors are missing");
if (!existsSync(resolve(nodeRoot, "Cargo.toml"))) throw new Error(`Node worktree is missing: ${nodeRoot}`);
if (!existsSync(resolve(credentialsRustRoot, "Cargo.toml"))) throw new Error(`OpenCredentials worktree is missing: ${credentialsRustRoot}`);

for (const repo of [shareRoot, nodeRoot, credentialsRoot]) clean(repo);

const manifest = JSON.parse(await readFile(resolve(vectorRoot, "manifest.json"), "utf8"));
if (manifest.manifestDigest !== expectedManifestDigest) {
  throw new Error(`unexpected Share manifest digest: ${manifest.manifestDigest}`);
}

// This is deliberately a native production-boundary gate. It runs the exact
// committed Share program, Node's mounted #117 read tests, and the
// OpenCredentials router/store tests serially. It never selects fake routes,
// unsigned credentials, fabricated database rows, or a simulated provider.
run("node", ["test/vectors/email-claim-v1/validate.mjs"], shareRoot);
run("cargo", ["test", "--test", "email_claim_frozen_manifest"], nodeRoot);
run("cargo", ["test", "--test", "challenge_to_native_read"], resolve(nodeRoot, "test/w5-policy-runtime-node-e2e"));
run("cargo", ["test", "--test", "tc119_registry_wire_paths"], resolve(nodeRoot, "test/w5-policy-runtime-node-e2e"));
run("cargo", ["test", "--test", "share_email_postgres"], credentialsRustRoot);
run("cargo", ["test", "--bin", "opencredentials-witness", "share_email::runtime::tests"], credentialsRustRoot);

console.log(`email-claim native cross-repository gate: PASS (${expectedManifestDigest})`);
