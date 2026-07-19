#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const nodeRoot = resolve(process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(root, "../../../tinycloud-node/feat/email-claim-n4-integration"));
const credentialsRoot = resolve(process.env.OPENCREDENTIALS_WORKTREE ?? resolve(root, "../../../opencredentials/feat/email-claim-o4-integration"));
const outputIndex = process.argv.indexOf("--output");
const output = outputIndex >= 0 ? process.argv[outputIndex + 1] : undefined;
if (output === undefined || output.length === 0) throw new Error("release evidence requires --output <path>");

function command(command, args, cwd = root) {
  try { return execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim(); }
  catch (error) { return `ERROR: ${error instanceof Error ? error.message : String(error)}`; }
}
function requiredHead(name, cwd) {
  const expected = process.env[name];
  if (!/^[0-9a-f]{40}$/.test(expected ?? "")) throw new Error(`${name} must be a 40-character exact release head`);
  const actual = command("git", ["rev-parse", "HEAD"], cwd);
  if (actual !== expected) throw new Error(`${name} does not match ${actual}`);
  if (command("git", ["status", "--porcelain=v1"], cwd) !== "") throw new Error(`${name} worktree is dirty`);
  return actual;
}
async function hash(path) {
  const bytes = await readFile(resolve(root, path));
  return createHash("sha256").update(bytes).digest("hex");
}
const manifest = JSON.parse(await readFile(resolve(root, "test/vectors/email-claim-v1/manifest.json"), "utf8"));
const contractCommit = process.env.SHARE_CONTRACT_COMMIT;
if (!/^[0-9a-f]{40}$/.test(contractCommit ?? "")) throw new Error("SHARE_CONTRACT_COMMIT must be the exact immutable contract commit");
if (command("git", ["rev-parse", contractCommit], root) !== contractCommit) throw new Error("contract commit is not available in Share history");
if (manifest.manifestDigest !== "pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs") throw new Error("unexpected contract manifest digest");
const evidence = {
  schema: "tinycloud.share-email-claim/release-evidence-v1",
  generatedAt: new Date().toISOString(),
  heads: {
    share: requiredHead("SHARE_RELEASE_HEAD", root),
    node: requiredHead("TINYCLOUD_NODE_RELEASE_HEAD", nodeRoot),
    opencredentials: requiredHead("OPEN_CREDENTIALS_RELEASE_HEAD", credentialsRoot),
  },
  contract: { commit: contractCommit, manifestDigest: manifest.manifestDigest, manifestFiles: manifest.files },
  commands: {
    vectorValidation: "node test/vectors/email-claim-v1/validate.mjs",
    shareTest: "npm test",
    shareTypecheck: "npm run typecheck",
    shareBuild: "npm run build",
    joinedBrowserRun1: "npm run test:e2e:email",
    joinedBrowserRun2: "npm run test:e2e:email",
  },
  results: { generatedBy: "release:evidence" },
  toolVersions: { node: command("node", ["--version"]), npm: command("npm", ["--version"]), git: command("git", ["--version"]), cargo: command("cargo", ["--version"]), chromium: process.env.BROWSER_EXECUTABLE ?? "puppeteer-managed" },
  artifactHashes: { manifest: await hash("test/vectors/email-claim-v1/manifest.json"), packageLock: await hash("package-lock.json"), releaseGate: await hash("test/e2e-email/integration.mjs"), nodeDeployment: createHash("sha256").update(command("git", ["ls-tree", "-r", "HEAD", "deploy/share-email"], nodeRoot)).digest("hex"), credentialsDeployment: createHash("sha256").update(command("git", ["ls-tree", "-r", "HEAD", "deploy/share-email", "docker-compose.email-claim-staging.yaml"], credentialsRoot)).digest("hex") },
  cleanup: { ownedProcessesStoppedBy: "test/e2e-email/integration.mjs", processScan: command("sh", ["-c", "ps -Ao pid,ppid,command | grep -E 'tinycloud-node-n4-mounted-fixture|email-claim-fixture|vite preview|postgres' | grep -v grep || true"], root), secretsIncluded: false },
};
await mkdir(dirname(resolve(root, output)), { recursive: true });
await writeFile(resolve(root, output), `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
console.log(JSON.stringify({ output, manifestDigest: manifest.manifestDigest, shareHead: evidence.heads.share }));
