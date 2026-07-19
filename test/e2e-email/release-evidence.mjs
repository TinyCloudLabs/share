#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const outputIndex = process.argv.indexOf("--output");
const output = outputIndex >= 0 ? process.argv[outputIndex + 1] : undefined;
if (output === undefined || output.length === 0) throw new Error("release evidence requires --output <path>");

function command(command, args, cwd = root) {
  try { return execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim(); }
  catch (error) { return `ERROR: ${error instanceof Error ? error.message : String(error)}`; }
}
async function hash(path) {
  const bytes = await readFile(resolve(root, path));
  return createHash("sha256").update(bytes).digest("hex");
}
const manifest = JSON.parse(await readFile(resolve(root, "test/vectors/email-claim-v1/manifest.json"), "utf8"));
const evidence = {
  schema: "tinycloud.share-email-claim/release-evidence-v1",
  generatedAt: new Date().toISOString(),
  heads: {
    share: command("git", ["rev-parse", "HEAD"]),
    node: process.env.TINYCLOUD_NODE_RELEASE_HEAD ?? null,
    opencredentials: process.env.OPEN_CREDENTIALS_RELEASE_HEAD ?? null,
  },
  contract: { manifestDigest: manifest.manifestDigest, manifestFiles: manifest.files },
  commands: {
    vectorValidation: "node test/vectors/email-claim-v1/validate.mjs",
    shareTest: "npm test",
    shareTypecheck: "npm run typecheck",
    shareBuild: "npm run build",
    joinedBrowser: "npm run test:e2e:email",
  },
  results: { generatedBy: "release:evidence" },
  toolVersions: { node: command("node", ["--version"]), npm: command("npm", ["--version"]), git: command("git", ["--version"]), cargo: command("cargo", ["--version"]), chromium: process.env.BROWSER_EXECUTABLE ?? "puppeteer-managed" },
  artifactHashes: { manifest: await hash("test/vectors/email-claim-v1/manifest.json"), packageLock: await hash("package-lock.json") },
  cleanup: { ownedProcessesStoppedBy: "test/e2e-email/integration.mjs", secretsIncluded: false },
};
await mkdir(dirname(resolve(root, output)), { recursive: true });
await writeFile(resolve(root, output), `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
console.log(JSON.stringify({ output, manifestDigest: manifest.manifestDigest, shareHead: evidence.heads.share }));
