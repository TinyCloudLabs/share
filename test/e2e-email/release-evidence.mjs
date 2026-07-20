#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const nodeRoot = resolve(process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(root, "../../../tinycloud-node/feat/email-claim-n4-integration"));
const credentialsRoot = resolve(process.env.OPENCREDENTIALS_WORKTREE ?? resolve(root, "../../../opencredentials/feat/email-claim-o4-integration"));
const outputIndex = process.argv.indexOf("--output");
const runsIndex = process.argv.indexOf("--runs-dir");
const output = outputIndex >= 0 ? process.argv[outputIndex + 1] : undefined;
const runsDir = resolve(root, runsIndex >= 0 ? process.argv[runsIndex + 1] : ".release-evidence/runs");
if (output === undefined || output.length === 0) throw new Error("release evidence requires --output <path>");

function command(commandName, args, cwd = root) {
  return execFileSync(commandName, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function digest(value) { return createHash("sha256").update(value).digest("hex"); }
async function bytesHash(path) {
  const bytes = await readFile(path);
  return { sha256: digest(bytes), bytes: bytes.byteLength };
}
function requiredHead(name, cwd) {
  const expected = process.env[name];
  if (!/^[0-9a-f]{40}$/.test(expected ?? "")) throw new Error(`${name} must be a 40-character exact release head`);
  const actual = command("git", ["rev-parse", "HEAD"], cwd);
  if (actual !== expected) throw new Error(`${name} does not match ${actual}`);
  if (command("git", ["status", "--porcelain=v1"], cwd) !== "") throw new Error(`${name} worktree is dirty`);
  return actual;
}
function verifyDigest(record) {
  const candidate = { ...record };
  delete candidate.recordDigest;
  if (record.recordDigest !== digest(JSON.stringify(candidate))) throw new Error(`run ${record.runId ?? "unknown"} record digest mismatch`);
}
async function verifyRun(path, expectedHeads, expectedToolchain) {
  const record = JSON.parse(await readFile(path, "utf8"));
  if (record.schema !== "tinycloud.share-email-claim/joined-run-v1" || record.immutable !== true) throw new Error(`invalid immutable run record: ${path}`);
  if (typeof record.runId !== "string" || typeof record.command !== "string" || !record.command.includes("integration.mjs")) throw new Error(`run ${record.runId}: command is not the joined gate`);
  if (!/^\d{4}-\d\d-\d\dT/.test(record.start) || !/^\d{4}-\d\d-\d\dT/.test(record.end) || !Number.isInteger(record.durationMs) || record.durationMs < 0 || record.exitStatus !== 0) throw new Error(`run ${record.runId}: incomplete or failed execution`);
  if (record.cleanup?.complete !== true || !Array.isArray(record.cleanup.remaining) || record.cleanup.remaining.length !== 0) throw new Error(`run ${record.runId}: owned-process cleanup did not complete`);
  for (const [name, head] of Object.entries(expectedHeads)) {
    if (record.heads?.[name]?.actual !== head || record.heads?.[name]?.expected !== head) throw new Error(`run ${record.runId}: ${name} exact head mismatch`);
  }
  if (expectedToolchain !== undefined && JSON.stringify(record.toolVersions) !== expectedToolchain) throw new Error(`run ${record.runId}: toolchain differs from the first clean run`);
  const logPath = resolve(root, record.log?.path ?? "");
  const log = await bytesHash(logPath);
  if (log.sha256 !== record.log.digest || log.bytes !== record.log.bytes) throw new Error(`run ${record.runId}: immutable log artifact mismatch`);
  for (const [relative, expected] of Object.entries(record.artifacts ?? {})) {
    const actual = await bytesHash(resolve(root, relative));
    if (actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes) throw new Error(`run ${record.runId}: artifact changed: ${relative}`);
  }
  const recomputedArtifactHash = digest(JSON.stringify({ heads: record.heads, artifacts: record.artifacts, coverage: record.coverage, logDigest: record.log.digest }));
  if (record.artifactHash !== recomputedArtifactHash) throw new Error(`run ${record.runId}: artifact hash mismatch`);
  verifyDigest(record);
  return record;
}

const shareHead = requiredHead("SHARE_RELEASE_HEAD", root);
const nodeHead = requiredHead("TINYCLOUD_NODE_RELEASE_HEAD", nodeRoot);
const credentialsHead = requiredHead("OPEN_CREDENTIALS_RELEASE_HEAD", credentialsRoot);
const expectedHeads = { share: shareHead, node: nodeHead, opencredentials: credentialsHead };
const manifest = JSON.parse(await readFile(resolve(root, "test/vectors/email-claim-v1/manifest.json"), "utf8"));
const contractCommit = process.env.SHARE_CONTRACT_COMMIT;
if (!/^[0-9a-f]{40}$/.test(contractCommit ?? "")) throw new Error("SHARE_CONTRACT_COMMIT must be the exact immutable contract commit");
if (command("git", ["rev-parse", contractCommit], root) !== contractCommit) throw new Error("contract commit is not available in Share history");
if (manifest.manifestDigest !== "pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs") throw new Error("unexpected contract manifest digest");

const files = (await readdir(runsDir)).filter((name) => name.endsWith(".json")).sort();
if (files.length < 2) throw new Error(`release evidence requires two distinct clean joined-run records in ${runsDir}`);
const records = [];
let toolchain;
for (const name of files) {
  const record = await verifyRun(resolve(runsDir, name), expectedHeads, toolchain);
  toolchain ??= JSON.stringify(record.toolVersions);
  records.push(record);
}
const uniqueIds = new Set(records.map((record) => record.runId));
const uniqueDigests = new Set(records.map((record) => record.recordDigest));
const uniqueLogs = new Set(records.map((record) => record.log.digest));
if (uniqueIds.size < 2 || uniqueDigests.size < 2 || uniqueLogs.size < 2) throw new Error("release evidence requires two distinct immutable clean runs");

const siweProvenance = process.env.SIWE_ORIGIN_MAIN_HEAD && process.env.SIWE_FEATURE_HEAD
  ? { status: "supplied", toolchain: JSON.parse(toolchain), originMainHead: process.env.SIWE_ORIGIN_MAIN_HEAD, featureHead: process.env.SIWE_FEATURE_HEAD, command: process.env.SIWE_PROVENANCE_COMMAND ?? "not supplied" }
  : { status: "not-run", reason: "No same-toolchain origin/main versus feature-head SIWE execution was supplied; that comparison is owned by the integration lane." };
const evidence = {
  schema: "tinycloud.share-email-claim/release-evidence-v2",
  generatedAt: new Date().toISOString(),
  heads: expectedHeads,
  contract: { commit: contractCommit, manifestDigest: manifest.manifestDigest, manifestFiles: manifest.files },
  commands: {
    vectorValidation: "node test/vectors/email-claim-v1/validate.mjs",
    shareTest: "npm test",
    shareTypecheck: "npm run typecheck",
    shareBuild: "npm run build",
    joinedBrowserRun1: "npm run test:e2e:email",
    joinedBrowserRun2: "npm run test:e2e:email",
  },
  runs: records.map((record) => ({ runId: record.runId, start: record.start, end: record.end, durationMs: record.durationMs, exitStatus: record.exitStatus, command: record.command, logDigest: record.log.digest, artifactHash: record.artifactHash, toolVersions: record.toolVersions, coverage: record.coverage, cleanup: record.cleanup, recordDigest: record.recordDigest })),
  results: { status: "passed", cleanRuns: records.length, generatedBy: "release:evidence", siweProvenance },
  toolVersions: records[0].toolVersions,
  artifactHashes: {
    manifest: (await bytesHash(resolve(root, "test/vectors/email-claim-v1/manifest.json"))).sha256,
    packageLock: (await bytesHash(resolve(root, "package-lock.json"))).sha256,
    releaseGate: (await bytesHash(resolve(root, "test/e2e-email/integration.mjs"))).sha256,
    nodeDeployment: digest(command("git", ["ls-tree", "-r", "HEAD", "deploy/share-email"], nodeRoot)),
    credentialsDeployment: digest(command("git", ["ls-tree", "-r", "HEAD", "deploy/share-email", "docker-compose.email-claim-staging.yaml"], credentialsRoot)),
  },
  cleanup: { secretsIncluded: false, records: records.map((record) => record.cleanup) },
};
await mkdir(dirname(resolve(root, output)), { recursive: true });
await writeFile(resolve(root, output), `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
console.log(JSON.stringify({ output, manifestDigest: manifest.manifestDigest, shareHead, cleanRuns: records.length }));
