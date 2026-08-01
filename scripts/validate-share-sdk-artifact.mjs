import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const root = dirname(fileURLToPath(import.meta.url));
const shareRoot = resolve(root, "..");
const manifestPath = join(shareRoot, "vendor", "share-sdk-artifact.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const artifactPath = join(shareRoot, "vendor", manifest.artifact);
const bytes = await readFile(artifactPath);
const digest = createHash("sha512").update(bytes).digest("base64");
const integrity = `sha512-${digest}`;
if (!/^[0-9a-f]{40}$/.test(manifest.sdkCommit)) throw new Error("Share SDK artifact manifest must name a full commit");
if (manifest.schema !== "tinycloud.share-sdk-artifact/v1") throw new Error("invalid Share SDK artifact manifest schema");
if (manifest.package !== "@tinycloud/share-sdk" || manifest.version !== "0.1.0") throw new Error("unexpected Share SDK artifact identity");
if (!manifest.artifact.endsWith(`-${manifest.sdkCommit.slice(0, 7)}.tgz`)) throw new Error("Share SDK artifact filename is not bound to sdkCommit");
if (manifest.sha512 !== integrity || manifest.integrity !== integrity) throw new Error("Share SDK artifact integrity mismatch");
const lockText = await readFile(join(shareRoot, "package-lock.json"), "utf8");
const lock = JSON.parse(lockText);
const entry = lock.packages?.["node_modules/@tinycloud/share-sdk"];
if (entry?.resolved !== `file:vendor/${manifest.artifact}` || entry.integrity !== integrity) throw new Error("package-lock does not pin the Share SDK artifact");

async function run(command, args, cwd) {
  return execFile(command, args, { cwd, maxBuffer: 16 * 1024 * 1024 });
}

const localSource = process.env.TINYCLOUD_JS_SDK_WORKTREE ?? resolve(root, "../../../../js-sdk/feat/share-cli-greenfield-20260729-a");
const source = process.env.TINYCLOUD_JS_SDK_REPO ?? (await exists(join(localSource, ".git")) ? localSource : "https://github.com/TinyCloudLabs/js-sdk.git");
const isolated = await mkdtemp(join(tmpdir(), "tinycloud-share-sdk-repro-"));
try {
  await run("git", ["clone", "--no-checkout", source, isolated], shareRoot);
  if (source === localSource && (await run("git", ["status", "--porcelain", "--untracked-files=all"], source)).stdout.trim() !== "") throw new Error("named js-sdk source is dirty");
  await run("git", ["checkout", "--detach", manifest.sdkCommit], isolated);
  if ((await run("git", ["status", "--porcelain", "--untracked-files=all"], isolated)).stdout.trim() !== "") throw new Error("isolated js-sdk checkout is dirty");
  await run("bun", ["install", "--frozen-lockfile", "--ignore-scripts"], isolated);
  await run("bun", ["run", "--cwd", "packages/share-envelope", "build"], isolated);
  await run("bun", ["run", "--cwd", "packages/share-sdk", "build"], isolated);
  const packed = await mkdtemp(join(tmpdir(), "tinycloud-share-sdk-pack-"));
  try {
    const result = await run("npm", ["pack", "--silent", "--pack-destination", packed], join(isolated, "packages/share-sdk"));
    const filename = result.stdout.trim().split(/\r?\n/).at(-1);
    const reproduced = await readFile(join(packed, filename ?? ""));
    if (!reproduced.equals(bytes)) throw new Error("Share SDK artifact is not reproducible from sdkCommit");
  } finally {
    await rm(packed, { recursive: true, force: true });
  }
} finally {
  await rm(isolated, { recursive: true, force: true });
}
console.log(`${manifest.package}@${manifest.version} ${manifest.sdkCommit} ${integrity}`);

async function exists(path) {
  try { await access(path); return true; } catch { return false; }
}
