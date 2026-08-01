import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile, lstat, readlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { startProductionServer } from "../../src/host/production-server.js";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../..");
const nodeWorktree = process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(workspaceRoot, "worktrees/tinycloud-node/feat/share-upload-attestation-20260731");
const sdkWorktree = process.env.TINYCLOUD_SDK_WORKTREE ?? resolve(workspaceRoot, "worktrees/js-sdk/feat/share-cli-greenfield-20260729-a");
const nodeBinary = process.env.TINYCLOUD_NODE_E2E_BIN ?? resolve(nodeWorktree, "target/debug/tinycloud-node-production-e2e");
const canonicalShare = "https://share.tinycloud.xyz";
const canonicalRegistry = "https://registry.tinycloud.xyz";

type Child = { process: ChildProcess; output: () => string };

type PackedPackage = { manifest: { name: string; version: string; [key: string]: unknown }; bytes: Buffer; filename: string };

async function startNpmRegistry(packages: PackedPackage[]): Promise<{ origin: string; close: () => Promise<void>; requested: Set<string> }> {
  const byName = new Map(packages.map((package_) => [package_.manifest.name, package_]));
  const requested = new Set<string>();
  const server = createServer((request, response) => {
    try {
      const pathname = decodeURIComponent(new URL(request.url ?? "/", "http://127.0.0.1").pathname);
      const separator = pathname.indexOf("/-/");
      const name = separator < 0 ? pathname.slice(1) : pathname.slice(1, separator);
      const package_ = byName.get(name);
      if (!package_) { response.writeHead(404).end(); return; }
      requested.add(name);
      if (separator < 0) {
        const integrity = `sha512-${createHash("sha512").update(package_.bytes).digest("base64")}`;
        const metadata = {
          name: package_.manifest.name,
          "dist-tags": { latest: package_.manifest.version },
          versions: {
            [package_.manifest.version]: {
              ...package_.manifest,
              dist: { tarball: `${origin}/${encodeURIComponent(name)}/-/${package_.filename}`, integrity },
            },
          },
        };
        const body = JSON.stringify(metadata);
        response.writeHead(200, { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }).end(body);
        return;
      }
      if (pathname !== `/${name}/-/${package_.filename}`) { response.writeHead(404).end(); return; }
      response.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(package_.bytes.length) }).end(package_.bytes);
    } catch {
      response.writeHead(400).end();
    }
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("hermetic npm registry did not bind");
  const origin = `http://127.0.0.1:${address.port}`;
  return { origin, requested, close: () => new Promise<void>((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose())) };
}

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

async function treeDigest(path: string): Promise<string> {
  const hash = createHash("sha256");
  const walk = async (current: string, relative: string): Promise<void> => {
    const entries = (await readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const child = join(current, entry.name);
      const childRelative = relative === "" ? entry.name : `${relative}/${entry.name}`;
      hash.update(childRelative);
      if (entry.isDirectory()) await walk(child, childRelative);
      else if (entry.isSymbolicLink()) hash.update(`link:${await readlink(child)}`);
      else hash.update(await readFile(child));
    }
  };
  await walk(path, "");
  return hash.digest("hex");
}

type PackageManifest = PackedPackage["manifest"] & { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; private?: boolean; scripts?: Record<string, string> };

async function readManifest(path: string): Promise<PackageManifest> {
  return JSON.parse(await readFile(join(path, "package.json"), "utf8")) as PackageManifest;
}

async function packageDirectoryFromRequire(name: string, from: string): Promise<string> {
  const segments = name.startsWith("@") ? name.split("/").slice(0, 2) : [name];
  let current = from;
  while (true) {
    const candidate = join(current, "node_modules", ...segments);
    try { if ((await lstat(join(candidate, "package.json"))).isFile()) return candidate; } catch { /* continue upward */ }
    const parent = resolve(current, "..");
    if (parent === current) break;
    current = parent;
  }
  throw new Error(`dependency ${name} is not installed in the frozen SDK graph`);
}

async function packFrozenSdkCatalog(sdkRoot: string, outputRoot: string): Promise<PackedPackage[]> {
  const lock = JSON.parse(await readFile(join(sdkRoot, "bun.lock"), "utf8")) as { workspaces?: Record<string, { name?: string; version?: string }> };
  const workspaceByName = new Map<string, string>();
  for (const workspacePath of Object.keys(lock.workspaces ?? {})) {
    if (workspacePath === "") continue;
    const directory = resolve(sdkRoot, workspacePath);
    try {
      const manifest = await readManifest(directory);
      if (typeof manifest.name === "string" && typeof manifest.version === "string" && manifest.private !== true) workspaceByName.set(manifest.name, directory);
    } catch { /* lock entries for non-package workspace paths are ignored */ }
  }
  const queue = [workspaceByName.get("@tinycloud/cli") ?? (() => { throw new Error("CLI workspace is missing from bun.lock"); })()];
  const directories = new Map<string, string>();
  while (queue.length > 0) {
    const directory = queue.shift()!;
    const manifest = await readManifest(directory);
    if (typeof manifest.name !== "string" || typeof manifest.version !== "string") throw new Error(`invalid package manifest at ${directory}`);
    if (directories.has(manifest.name)) continue;
    directories.set(manifest.name, directory);
    for (const dependency of Object.keys({ ...manifest.dependencies, ...manifest.optionalDependencies })) {
      const workspace = workspaceByName.get(dependency);
      queue.push(workspace ?? await packageDirectoryFromRequire(dependency, directory));
    }
  }
  const packages: PackedPackage[] = [];
  for (const [name, directory] of directories) {
    const manifest = await readManifest(directory);
    const pack = child("npm", ["pack", "--silent", "--pack-destination", outputRoot], directory, {});
    const [status] = await once(pack.process, "exit");
    if (status !== 0) throw new Error(`could not pack frozen dependency ${name}: ${pack.output()}`);
    const filename = pack.output().trim().split(/\r?\n/).at(-1);
    if (filename === undefined || filename.length === 0) throw new Error(`npm pack produced no artifact for ${name}`);
    packages.push({ manifest, bytes: await readFile(join(outputRoot, filename)), filename });
  }
  return packages;
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

  if (process.env.TINYCLOUD_ALLOW_SYNTHETIC_PROFILE !== "1") {
    throw new Error("joined proof requires the orchestrator's explicit OpenKey login; fixture-seeded profiles are opt-in and never acceptance evidence");
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
    const registryPrivateKey = randomBytes(32);
    await writeFile(registryKey, registryPrivateKey.toString("base64url"), { mode: 0o600 });
    const registryPublicKey = Buffer.from(ed25519.getPublicKey(registryPrivateKey)).toString("base64url");
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
    const registry = child("bun", ["packages/registry/src/production-server-cli.ts", "--port", "0"], shareRoot, {
      REGISTRY_AUTH_PUBLIC_KEY: registryPublicKey,
      REGISTRY_LINK_UPLOAD_PUBLIC_KEY: registryPublicKey,
    });
    children.push(registry);
    const registryMatch = await ready(registry, /production share registry listening on (http:\/\/127\.0\.0\.1:\d+)/);
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

    const publishedPackages = await packFrozenSdkCatalog(sdkWorktree, root);
    const npmRegistry = await startNpmRegistry(publishedPackages);
    const install = join(root, "packed-cli");
    await mkdir(install, { recursive: true });
    await writeFile(join(install, "package.json"), JSON.stringify({ name: "tinycloud-cli-consumer", private: true, type: "module" }));
    const cli = publishedPackages.find((package_) => package_.manifest.name === "@tinycloud/cli");
    if (cli === undefined) throw new Error("frozen SDK catalog omitted @tinycloud/cli");
    const networkGuard = join(root, "network-guard.mjs");
    await writeFile(networkGuard, [
      "import http from \"node:http\";",
      "import https from \"node:https\";",
      "const allowed = (input) => {",
      "  const raw = typeof input === \"string\" ? input : input instanceof URL ? input.href : input?.href ?? `${input?.protocol ?? \"\"}//${input?.host ?? \"\"}${input?.path ?? \"/\"}`;",
      "  const url = new URL(raw);",
      "  if (url.hostname !== \"127.0.0.1\" && url.hostname !== \"localhost\") throw new Error(\"hermetic network denied\");",
      "};",
      "for (const module of [http, https]) { const request = module.request; module.request = function(input, ...args) { allowed(input); return request.call(this, input, ...args); }; }",
      "const fetch = globalThis.fetch; globalThis.fetch = async (input, ...args) => { allowed(input); return fetch(input, ...args); };",
      "",
    ].join("\n"));
    const guardedInstallEnv = { NODE_OPTIONS: `--import ${networkGuard}`, HTTP_PROXY: "http://127.0.0.1:9", HTTPS_PROXY: "http://127.0.0.1:9", ALL_PROXY: "http://127.0.0.1:9", NO_PROXY: "127.0.0.1,localhost" };
    const installResult = child("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", `--registry=${npmRegistry.origin}`, "--prefix", install, `@tinycloud/cli@${cli.manifest.version}`], sdkWorktree, guardedInstallEnv);
    children.push(installResult);
    try {
      if ((await once(installResult.process, "exit"))[0] !== 0) throw new Error(`packed CLI install failed: ${installResult.output().slice(-8000)}`);
      const installedLock = JSON.parse(await readFile(join(install, "package-lock.json"), "utf8")) as { packages?: Record<string, { version?: string; resolved?: string; integrity?: string }> };
      const catalog = new Map(publishedPackages.map((package_) => [package_.manifest.name, package_]));
      for (const [location, entry] of Object.entries(installedLock.packages ?? {})) {
        if (location === "") continue;
        const name = location.slice(location.lastIndexOf("node_modules/") + "node_modules/".length);
        const package_ = catalog.get(name);
        if (package_ === undefined || entry.version !== package_.manifest.version || entry.resolved?.startsWith(npmRegistry.origin) !== true || entry.integrity !== `sha512-${createHash("sha512").update(package_.bytes).digest("base64")}`) throw new Error(`installed dependency ${name} is not an exact hermetic catalog artifact`);
      }
    } finally {
      await npmRegistry.close();
    }
    const packedSdk = await import(`${install}/node_modules/@tinycloud/node-sdk/dist/index.js`);
    const packedNode = new packedSdk.TinyCloudNode({ host: nodeOrigin });
    await packedNode.restoreSession({ ...session, verificationMethod: profile.sessionDid });
    const packedHeaders = packedNode.invokeAny([{ spaceId: session.spaceId, service: "capabilities", action: "tinycloud.capabilities/read" }], [{ requestBodyDigest: "probe" }]);
    const packedProbe = await fetch(`${nodeOrigin}/share/upload/attestation`, { method: "POST", headers: { ...packedHeaders, "content-type": "application/json" }, body: "{}" });
    if (packedProbe.status !== 400) throw new Error(`packed Node authorization probe returned ${packedProbe.status}`);
    const bin = join(install, "node_modules/@tinycloud/cli/bin/tc");
    const cliEnv = { TC_HOME: cliHome, CI: "1", NODE_OPTIONS: `--import ${networkGuard} --import ${preload}`, HTTP_PROXY: "http://127.0.0.1:9", HTTPS_PROXY: "http://127.0.0.1:9", ALL_PROXY: "http://127.0.0.1:9", NO_PROXY: "127.0.0.1,localhost", TC_JOINED_NODE_STATUS_FILE: nodeStatus };
    const published = await runCli(bin, ["--profile", "joined", "share", "publish", inputPath, "--registry", `${canonicalShare}/api/share/link-only/registry`], cliEnv);
    if (published.status !== 0) throw new Error(`packed CLI publish failed with transport statuses ${await readFile(nodeStatus, "utf8").catch(() => "unobserved")}`);
    const link = published.stdout.split(/\r?\n/).map((line) => line.trim()).find((line) => {
      try { const url = new URL(line); return url.origin === canonicalShare && /^\/s\/[a-z0-9]+$/.test(url.pathname) && url.hash.length > 1; }
      catch { return false; }
    });
    if (link === undefined) throw new Error("publish did not return a valid canonical compact link");
    const transportEnv = { ...cliEnv, NODE_OPTIONS: `--import ${networkGuard} --import ${preload}` };
    const inspected = await runCli(bin, ["share", "inspect", "-", "--stdin", "--json"], { ...transportEnv, TC_HOME: join(root, "public-inspect-home") }, `${link}\n`);
    if (inspected.status !== 0) throw new Error(`profile-free inspect failed status=${inspected.status} outputLength=${inspected.stdout.length} transport=${await readFile(nodeStatus, "utf8").catch(() => "unobserved")}`);
    const warmed = await runNpx(install, ["share", "inspect", "-", "--stdin"], { ...transportEnv, TC_HOME: join(root, "warm-npx-home"), npm_config_offline: "true" }, `${link}\n`);
    if (warmed.status !== 0) throw new Error("warm-cache npx inspect failed");
    const nodeModulesBeforeWarm = await treeDigest(join(install, "node_modules"));
    const warmPublished = await runNpx(install, ["--profile", "joined", "share", "publish", inputPath, "--registry", `${canonicalShare}/api/share/link-only/registry`], cliEnv);
    if (warmPublished.status !== 0) throw new Error("warm-cache npx publish failed");
    if (await treeDigest(join(install, "node_modules")) !== nodeModulesBeforeWarm) throw new Error("warm npx mutated or replaced node_modules");
    await mkdir(outputDir, { recursive: true });
    const received = await runCli(bin, ["share", "receive", "-", "--stdin", "--output", outputDir], { ...transportEnv, TC_HOME: join(root, "public-receive-home") }, `${link}\n`);
    if (received.status !== 0) throw new Error("profile-free bearer receive failed");
    const names = await readdir(outputDir);
    if (names.length !== 1 || (await digest(join(outputDir, names[0]!))) !== await digest(inputPath)) throw new Error("joined receive digest mismatch");
    process.stdout.write(JSON.stringify({ status: "passed", profileFixtureSeeded: true, acceptanceEvidence: false, nodeOrigin: true, shareProcess: true, registryProcess: true, packedCli: true, identicalDigest: true, profileFreeInspect: true, profileFreeBearerReceive: true }) + "\n");
  } finally {
    for (const entry of children.reverse()) await stop(entry);
    if (process.env.KEEP_JOINED_ARTIFACTS !== "1") await rm(root, { recursive: true, force: true });
  }
}

await main();
