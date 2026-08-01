import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";

import { startProductionServer } from "../../src/host/production-server.js";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../..");
const nodeWorktree = process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(workspaceRoot, "worktrees/tinycloud-node/feat/share-upload-attestation-20260731");
const sdkWorktree = process.env.TINYCLOUD_SDK_WORKTREE ?? resolve(workspaceRoot, "worktrees/js-sdk/feat/share-cli-greenfield-20260729-a");
const nodeBinary = process.env.TINYCLOUD_NODE_E2E_BIN ?? resolve(nodeWorktree, "target/debug/tinycloud-node-production-e2e");
const canonicalShare = "https://share.tinycloud.xyz";
const canonicalRegistry = "https://registry.tinycloud.xyz";

type Child = { process: ChildProcess; output: () => string };

function child(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): Child {
  const process = spawn(command, args, { cwd, env: { ...globalThis.process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  const collect = (chunk: Buffer): void => { output = `${output}${chunk.toString()}`.slice(-32_000); };
  process.stdout?.on("data", collect);
  process.stderr?.on("data", collect);
  return { process, output: () => output };
}

async function ready(entry: Child, pattern: RegExp): Promise<RegExpMatchArray> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const match = entry.output().match(pattern);
    if (match !== null) return match;
    if (entry.process.exitCode !== null) throw new Error("joined service exited before readiness");
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error("joined service readiness timed out");
}

async function stop(entry: Child): Promise<void> {
  if (entry.process.exitCode !== null) return;
  entry.process.kill("SIGTERM");
  await Promise.race([once(entry.process, "exit"), new Promise((resolveWait) => setTimeout(resolveWait, 5_000))]);
  if (entry.process.exitCode === null) entry.process.kill("SIGKILL");
}

function digest(path: string): Promise<string> {
  return readFile(path).then((bytes) => createHash("sha256").update(bytes).digest("hex"));
}

async function runCli(bin: string, args: string[], env: NodeJS.ProcessEnv, input?: string): Promise<{ status: number; stdout: string; stderr: string }> {
  const result = child(process.env.TINYCLOUD_CLI_RUNTIME ?? "node", [bin, ...args], dirname(bin), env);
  if (input !== undefined) result.process.stdin?.end(input);
  else result.process.stdin?.end();
  const [status] = await once(result.process, "exit");
  return { status: typeof status === "number" ? status : 1, stdout: result.output(), stderr: "" };
}

async function runNpx(prefix: string, args: string[], env: NodeJS.ProcessEnv, input?: string): Promise<{ status: number; stdout: string }> {
  const result = child("npx", ["--prefix", prefix, "--no-install", "tc", ...args], prefix, env);
  if (input !== undefined) result.process.stdin?.end(input);
  else result.process.stdin?.end();
  const [status] = await once(result.process, "exit");
  return { status: typeof status === "number" ? status : 1, stdout: result.output() };
}

async function main(): Promise<void> {
  if (process.argv.includes("--host")) {
    const server = startProductionServer(process.env);
    await once(server, "listening");
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("joined Share host did not bind an address");
    process.stdout.write(`joined Share host listening on http://127.0.0.1:${address.port}\n`);
    return;
  }

  const root = await mkdtemp(join(tmpdir(), "tinycloud-cli-joined-"));
  const nodeHome = join(root, "node-home");
  const cliHome = join(root, "cli-home");
  const trustBundle = join(root, "trust-bundle.json");
  const registryKey = join(root, "registry-upload.key");
  const inputPath = join(root, "input.md");
  const outputDir = join(root, "received");
  const preload = join(root, "transport-preload.mjs");
  const nodeStatus = join(root, "node-status");
  const children: Child[] = [];
  try {
    await writeFile(inputPath, "joined production path\n", { mode: 0o600 });
    const nodeSecret = Buffer.alloc(32, 0x09).toString("base64url");
    const node = child(nodeBinary, ["--target-origin", "https://node.tinycloud.xyz", "--profile-output", nodeHome, "--trust-bundle-output", trustBundle, "--keys-secret", nodeSecret, "--quiet"], nodeWorktree, {});
    children.push(node);
    const nodeMatch = await ready(node, /tinycloud-node-production-e2e listening on http:\/\/127\.0\.0\.1:(\d+)/);
    const nodeOrigin = `http://127.0.0.1:${nodeMatch[1]}`;
    const profile = JSON.parse(await readFile(join(nodeHome, ".tinycloud/profiles/joined/profile.json"), "utf8")) as { spaceId: string; sessionDid: string };
    const session = JSON.parse(await readFile(join(nodeHome, ".tinycloud/profiles/joined/session.json"), "utf8")) as { delegationHeader: { Authorization: string }; delegationCid: string; spaceId: string; jwk: object; verificationMethod: string };
    const { TinyCloudNode } = await import(`${sdkWorktree}/packages/node-sdk/dist/index.js`);
    const probeNode = new TinyCloudNode({ host: nodeOrigin });
    await probeNode.restoreSession({ ...session, verificationMethod: profile.sessionDid });
    const probeHeaders = probeNode.invokeAny([{ spaceId: session.spaceId, service: "capabilities", action: "tinycloud.capabilities/read" }], [{ requestBodyDigest: "probe" }]);
    const probe = await fetch(`${nodeOrigin}/share/upload/attestation`, { method: "POST", headers: { ...probeHeaders, "content-type": "application/json" }, body: "{}" });
    if (probe.status !== 400) throw new Error(`mounted Node authorization probe returned ${probe.status}`);
    const registry = child("bun", ["packages/registry/src/dev-server-cli.ts", "--port", "0"], shareRoot, {});
    children.push(registry);
    const registryMatch = await ready(registry, /dev share registry listening on (http:\/\/127\.0\.0\.1:\d+)/);
    const registryOrigin = registryMatch[1]!;
    const bundle = await readFile(trustBundle, "utf8");
    const share = child("bun", ["test/e2e-sharing/cli-joined.ts", "--host"], shareRoot, {
      SHARE_TRUST_BUNDLE_SOURCE: "environment",
      SHARE_TRUST_BUNDLE: bundle,
      SHARE_SENDER_ENABLED: "false",
      SHARE_REGISTRY_UPLOAD_KEY_PATH: registryKey,
      SHARE_HERMETIC_COMPOSITION: "true",
      SHARE_HERMETIC_REGISTRY_ORIGIN: registryOrigin,
      PORT: "0",
      HOST: "127.0.0.1",
    });
    children.push(share);
    const shareMatch = await ready(share, /joined Share host listening on (http:\/\/127\.0\.0\.1:\d+)/);
    const shareOrigin = shareMatch[1]!;
    await cp(join(nodeHome, ".tinycloud"), join(cliHome, ".tinycloud"), { recursive: true });
    await writeFile(preload, `import { appendFile } from "node:fs/promises";\nconst originalFetch = globalThis.fetch;\nglobalThis.fetch = async (input, init) => { const value = typeof input === "string" || input instanceof URL ? new URL(input) : input.url === undefined ? input : new URL(input.url); const originalOrigin = value.origin; let nextInit = init; if (originalOrigin === ${JSON.stringify(canonicalShare)}) { value.href = ${JSON.stringify(shareOrigin)} + value.pathname + value.search; const headers = new Headers(init?.headers); headers.set("x-forwarded-proto", "https"); nextInit = { ...init, headers }; } else if (originalOrigin === ${JSON.stringify(canonicalRegistry)}) value.href = ${JSON.stringify(registryOrigin)} + value.pathname + value.search; const response = await originalFetch(value, nextInit); if (process.env.TC_JOINED_NODE_STATUS_FILE) { let detail = ""; if (value.pathname === "/share/upload/attestation" && response.ok) { try { const body = await response.clone().json(); detail = " keys=" + Object.keys(body).sort().join(",") + " session=" + String(body.sessionDid ?? ""); } catch {} } if (value.pathname.endsWith("/registry/blobs") && !response.ok) { try { const body = await response.clone().json(); detail = " error=" + JSON.stringify(body.error ?? body); } catch {} } await appendFile(process.env.TC_JOINED_NODE_STATUS_FILE, value.pathname + "=" + response.status + detail + "\\n"); } return response; };\n`);

    const packPackage = (directory: string): Promise<string> => new Promise<string>((resolvePack, rejectPack) => {
      const pack = spawn("npm", ["pack", "--silent", "--pack-destination", root], { cwd: directory, env: globalThis.process.env, stdio: ["ignore", "pipe", "pipe"] });
      let output = "";
      pack.stdout.on("data", (chunk) => { output += chunk.toString(); });
      pack.once("error", rejectPack);
      pack.once("exit", (code) => code === 0 ? resolvePack(join(root, output.trim())) : rejectPack(new Error("packed CLI creation failed")));
    });
    const cliTarball = await packPackage(resolve(sdkWorktree, "packages/cli"));
    const envelopeTarball = await packPackage(resolve(sdkWorktree, "packages/share-envelope"));
    const shareSdkTarball = await packPackage(resolve(sdkWorktree, "packages/share-sdk"));
    const nodeSdkTarball = await packPackage(resolve(sdkWorktree, "packages/node-sdk"));
    const nodeWasmTarball = await packPackage(resolve(sdkWorktree, "packages/sdk-rs/packages/node"));
    const sdkCoreTarball = await packPackage(resolve(sdkWorktree, "packages/sdk-core"));
    const sdkServicesTarball = await packPackage(resolve(sdkWorktree, "packages/sdk-services"));
    const operationsTarball = await packPackage(resolve(sdkWorktree, "packages/operations"));
    const install = join(root, "packed-cli");
    const installResult = child("npm", ["install", "--legacy-peer-deps", "--no-audit", "--no-fund", "--prefix", install, cliTarball, envelopeTarball, shareSdkTarball, nodeSdkTarball, "ethers"], sdkWorktree, {});
    children.push(installResult);
    if ((await once(installResult.process, "exit"))[0] !== 0) throw new Error(`packed CLI install failed: ${installResult.output().slice(-8000)}`);
    const replacePackedDependency = async (tarball: string, packagePath: string): Promise<void> => {
      const unpacked = join(root, `unpacked-${packagePath.replaceAll("/", "-")}`);
      await mkdir(unpacked, { recursive: true });
      const extracted = child("tar", ["-xzf", tarball, "-C", unpacked], sdkWorktree, {});
      children.push(extracted);
      if ((await once(extracted.process, "exit"))[0] !== 0) throw new Error("packed dependency extraction failed");
      await cp(join(unpacked, "package"), join(install, "node_modules", packagePath), { recursive: true, force: true });
    };
    await replacePackedDependency(nodeWasmTarball, "@tinycloud/node-sdk-wasm");
    await replacePackedDependency(sdkCoreTarball, "@tinycloud/sdk-core");
    await replacePackedDependency(sdkServicesTarball, "@tinycloud/sdk-services");
    await replacePackedDependency(operationsTarball, "@tinycloud/operations");
    const packedSdk = await import(`${install}/node_modules/@tinycloud/node-sdk/dist/index.js`);
    const packedNode = new packedSdk.TinyCloudNode({ host: nodeOrigin });
    await packedNode.restoreSession({ ...session, verificationMethod: profile.sessionDid });
    const packedHeaders = packedNode.invokeAny([{ spaceId: session.spaceId, service: "capabilities", action: "tinycloud.capabilities/read" }], [{ requestBodyDigest: "probe" }]);
    const packedProbe = await fetch(`${nodeOrigin}/share/upload/attestation`, { method: "POST", headers: { ...packedHeaders, "content-type": "application/json" }, body: "{}" });
    if (packedProbe.status !== 400) throw new Error(`packed Node authorization probe returned ${packedProbe.status}`);
    const bin = join(install, "node_modules/@tinycloud/cli/bin/tc");
    const cliEnv = { TC_HOME: cliHome, CI: "1", NODE_OPTIONS: `--import ${preload}`, TC_JOINED_NODE_STATUS_FILE: nodeStatus };
    const published = await runCli(bin, ["--profile", "joined", "share", "publish", inputPath, "--registry", `${canonicalShare}/api/share/link-only/registry`], cliEnv);
    if (published.status !== 0) throw new Error(`packed CLI publish failed with transport statuses ${await readFile(nodeStatus, "utf8").catch(() => "unobserved")}`);
    const link = published.stdout.split(/\r?\n/).map((line) => line.trim()).find((line) => {
      try { const url = new URL(line); return url.origin === canonicalShare && /^\/s\/[a-z0-9]+$/.test(url.pathname) && url.hash.length > 1; }
      catch { return false; }
    });
    if (link === undefined) throw new Error("publish did not return a valid canonical compact link");
    const transportEnv = { ...cliEnv, NODE_OPTIONS: `--import ${preload}` };
    const inspected = await runCli(bin, ["share", "inspect", "-", "--stdin", "--json"], { ...transportEnv, TC_HOME: join(root, "public-inspect-home") }, `${link}\n`);
    if (inspected.status !== 0) throw new Error(`profile-free inspect failed status=${inspected.status} outputLength=${inspected.stdout.length} transport=${await readFile(nodeStatus, "utf8").catch(() => "unobserved")}`);
    const warmed = await runNpx(install, ["share", "inspect", "-", "--stdin"], { ...transportEnv, TC_HOME: join(root, "warm-npx-home") }, `${link}\n`);
    if (warmed.status !== 0) throw new Error("warm-cache npx inspect failed");
    await mkdir(outputDir, { recursive: true });
    const received = await runCli(bin, ["share", "receive", "-", "--stdin", "--output", outputDir], { ...transportEnv, TC_HOME: join(root, "public-receive-home") }, `${link}\n`);
    if (received.status !== 0) throw new Error("profile-free bearer receive failed");
    const names = await readdir(outputDir);
    if (names.length !== 1 || (await digest(join(outputDir, names[0]!))) !== await digest(inputPath)) throw new Error("joined receive digest mismatch");
    process.stdout.write(JSON.stringify({ status: "passed", nodeOrigin: true, shareProcess: true, registryProcess: true, packedCli: true, identicalDigest: true, profileFreeInspect: true, profileFreeBearerReceive: true }) + "\n");
  } finally {
    for (const entry of children.reverse()) await stop(entry);
    if (process.env.KEEP_JOINED_ARTIFACTS !== "1") await rm(root, { recursive: true, force: true });
  }
}

await main();
