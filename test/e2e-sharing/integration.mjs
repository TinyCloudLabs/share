#!/usr/bin/env node

/*
 * Hermetic sharing gate.
 *
 * This file intentionally drives the shipped production Share pages with the
 * agent-browser CLI.  The only browser-side test seam is the external-wallet
 * shape described in the browser E2E guide: OpenKey's external widget is
 * intercepted before it can leave the loopback composition, while the wallet
 * signs the real SIWE message through a deterministic loopback signer.  The
 * Share host, registry, and native services remain real processes.
 */

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer as httpServer } from "node:http";
import { createConnection } from "node:net";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp, mkdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { privateKeyToAccount } from "viem/accounts";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/feat/sharing-production-live");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? join(workspaceRoot, "worktrees/opencredentials/feat/sharing-production-live");
const credentialsManifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
const artifactPath = join(workspaceRoot, ".context/sharing-experience-e2e-result.json");
const lockPath = join(tmpdir(), "tinycloud-sharing-e2e.lock");
const canonical = Object.freeze({
  share: "https://share.tinycloud.xyz",
  node: "https://node.tinycloud.xyz",
  credentials: "https://witness.credentials.org",
  registry: "https://registry.tinycloud.xyz",
});
const walletPrivateKey = `0x${"55".repeat(32)}`;
const issuerPublicKey = "KN2IoJYLuoxXahdaAVOhhdnOjnRZ1S_deGwfdLsYmHg";
const issuerSecret = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "KN2IoJYLuoxXahdaAVOhhdnOjnRZ1S_deGwfdLsYmHg", d: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M" });
const nodeKeysSecret = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const wallet = privateKeyToAccount(walletPrivateKey);
const agentBrowser = process.env.AGENT_BROWSER_BIN ?? "/Users/samgbafa/.nvm/versions/node/v20.19.4/bin/agent-browser";
const children = [];
const servers = [];
const checks = [];
const blockers = [];
const flowAudits = [];
const serverTraceIds = [];
const launchInputDigests = {};
const gateResults = { exactEmail: false, domain: false, bearer: false, editConflict: false, folder: false, notification: false, denialMatrix: false, senderLibrary: false, browser: false };
const runId = `sharing-e2e-${process.pid}-${randomUUID()}`;
let sessionName = runId;
let externalRequests = [];
let lockHeld = false;
let cleanupStarted = false;

const AGENT_TIMEOUT_MS = 60_000;
const CHILD_TIMEOUT_MS = 120_000;

function featureProcess(pid) {
  try {
    const command = execFileSync("ps", ["-p", String(pid), "-o", "command="], { encoding: "utf8" });
    return command.includes("test/e2e-sharing") && command.includes("sharing-production-live");
  } catch { return false; }
}

async function acquireLock() {
  try {
    await mkdir(lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    let owner;
    try { owner = JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8")); } catch { owner = undefined; }
    const ownerAlive = owner?.pid !== undefined && (() => { try { process.kill(owner.pid, 0); return true; } catch { return false; } })();
    if (ownerAlive && featureProcess(owner.pid)) throw new Error(`another sharing harness owns the scoped lock (pid ${owner.pid})`);
    await rm(lockPath, { recursive: true, force: true });
    await mkdir(lockPath, { mode: 0o700 });
  }
  await writeFile(join(lockPath, "owner.json"), JSON.stringify({ pid: process.pid, runId, cwd: shareRoot }), { flag: "wx", mode: 0o600 });
  lockHeld = true;
}

async function releaseLock() {
  if (!lockHeld) return;
  lockHeld = false;
  await rm(lockPath, { recursive: true, force: true });
}

function b64(value) { return Buffer.from(value).toString("base64url"); }
function sha256(value) { return createHash("sha256").update(value).digest("base64url"); }
async function recordArtifactDigest(name, path) {
  const bytes = await readFile(path);
  launchInputDigests[name] = { path, digest: createHash("sha256").update(bytes).digest("hex") };
}
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function trustBundleFromRuntime(nodePublicKey) {
  return JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1", shareOrigin: canonical.share, returnOrigin: canonical.share, registryOrigin: canonical.registry, credentialsOrigin: canonical.credentials, nodeOrigin: canonical.node, nodeAudience: "did:web:node.tinycloud.xyz", nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", nodeInvitationPublicKey: nodePublicKey, nodeKeyVersion: 1, nodeEnabled: true, issuerDid: "did:web:issuer.credentials.org", issuerVct: "opencredentials.email/v1", issuerKid: "did:web:issuer.credentials.org#email-signing-key-1", issuerPublicKey, issuerKeyVersion: 1, issuerEnabled: true });
}
async function freePort() {
  const server = httpServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}
async function loopback(label, handler) {
  const server = httpServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  servers.push(server);
  const port = server.address().port;
  checks.push(`${label} test service listening on 127.0.0.1:${port}.`);
  return `http://127.0.0.1:${port}`;
}
function run(command, args, cwd, env = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], detached: true });
  let output = "";
  const collect = (chunk) => { output += String(chunk); if (output.length > 32_000) output = output.slice(-32_000); };
  child.stdout.on("data", collect); child.stderr.on("data", collect);
  children.push({ child, output: () => output });
  return child;
}

async function assertReleaseInputs() {
  const repositories = [
    { name: "share", path: shareRoot, branch: "feat/sharing-production-live", pr: "27" },
    { name: "node", path: nodeRoot, branch: "feat/sharing-production-live", pr: "168" },
    { name: "opencredentials", path: credentialsRoot, branch: "feat/sharing-production-live", pr: "113" },
    { name: "js-sdk", path: process.env.TINYCLOUD_JS_SDK_WORKTREE ?? join(workspaceRoot, "worktrees/js-sdk/feat/sharing-production-live"), branch: "feat/sharing-production-live", pr: "361" },
  ];
  for (const repository of repositories) {
    const dirty = execFileSync("git", ["-C", repository.path, "status", "--porcelain", "--untracked-files=all"], { encoding: "utf8" });
    if (dirty.length > 0) throw new Error(`${repository.name} worktree is dirty; release inputs must be committed`);
    const local = execFileSync("git", ["-C", repository.path, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const upstream = execFileSync("git", ["-C", repository.path, "rev-parse", `origin/${repository.branch}`], { encoding: "utf8" }).trim();
    const remote = execFileSync("git", ["-C", repository.path, "ls-remote", "origin", `refs/heads/${repository.branch}`], { encoding: "utf8" }).split(/\s+/)[0];
    const pr = JSON.parse(execFileSync("gh", ["pr", "view", repository.pr, "--json", "headRefOid"], { cwd: repository.path, encoding: "utf8" }));
    if (local !== upstream || local !== remote || local !== pr.headRefOid) throw new Error(`${repository.name} local, upstream, remote, and PR heads differ`);
    const tree = execFileSync("git", ["-C", repository.path, "ls-tree", "-r", "--full-tree", "HEAD"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    launchInputDigests[repository.name] = { head: local, digest: createHash("sha256").update(tree).digest("hex") };
  }
  const sdkRoot = repositories.find((repository) => repository.name === "js-sdk").path;
  await runOnce("bun", ["run", "build"], sdkRoot);
  const sdkLinkStat = await lstat(join(shareRoot, "node_modules/@tinycloud/web-sdk"));
  if (!sdkLinkStat.isSymbolicLink()) throw new Error("Share web-sdk dependency must be a symlink to the exact js-sdk worktree");
  const linkedWebSdk = realpathSync(join(shareRoot, "node_modules/@tinycloud/web-sdk"));
  const expectedWebSdk = realpathSync(join(sdkRoot, "packages/web-sdk"));
  if (linkedWebSdk !== expectedWebSdk) throw new Error("Share web-sdk node_modules link is stale");
  await stat(join(expectedWebSdk, "dist/index.js"));
  launchInputDigests.jsSdkArtifacts = { path: join(expectedWebSdk, "dist/index.js"), digest: createHash("sha256").update(await readFile(join(expectedWebSdk, "dist/index.js"))).digest("hex") };
  checks.push(`Release inputs verified clean with matching upstream, remote, and GitHub PR heads; committed tree digests recorded for ${Object.keys(launchInputDigests).join(", ")}.`);
}
async function waitFor(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const response = await fetch(url, { redirect: "error" }); if (response.status < 500) return response; } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`timed out waiting for ${url}`);
}
async function waitForTcp(port, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolveConnect, rejectConnect) => {
        const socket = createConnection({ host: "127.0.0.1", port });
        socket.once("connect", () => { socket.destroy(); resolveConnect(); });
        socket.once("error", (error) => { socket.destroy(); rejectConnect(error); });
      });
      return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`timed out waiting for loopback TCP port ${port}`);
}
async function runOnce(command, args, cwd, env = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  child.stderr.on("data", (chunk) => { output += String(chunk); });
  const timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch {} }, CHILD_TIMEOUT_MS);
  const [code] = await once(child, "exit");
  clearTimeout(timer);
  if (code !== 0) throw new Error(`${command} ${args.join(" ")} exited ${code}: ${output.slice(-4000)}`);
}
async function descriptor(path, child, label) {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    try { return JSON.parse(await readFile(path, "utf8")); } catch {}
    if (child.exitCode !== null) throw new Error(`${label} exited before its descriptor: ${children.find((entry) => entry.child === child)?.output().slice(-4000)}`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  throw new Error(`${label} descriptor was not published`);
}
async function stopAll() {
  await Promise.all(children.slice().reverse().map(async ({ child }) => {
    if (child.exitCode !== null) return;
    try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); }
    await Promise.race([once(child, "exit"), new Promise((resolveWait) => setTimeout(resolveWait, 3000))]);
    if (child.exitCode === null) { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
  }));
}
async function closeAll() {
  await Promise.all(servers.map((server) => new Promise((resolveClose) => { server.closeAllConnections?.(); server.close(() => resolveClose()); })));
}
let agentQueue = Promise.resolve();
function runAgent(args) {
  return new Promise((resolveAgent, rejectAgent) => {
    const child = spawn(agentBrowser, ["--session", sessionName, ...args], { cwd: shareRoot, env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    let settled = false;
    const finish = (callback, value) => { if (settled) return; settled = true; clearTimeout(timer); callback(value); };
    const timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch {} finish(rejectAgent, new Error(`agent-browser ${args.join(" ")} timed out after ${AGENT_TIMEOUT_MS}ms`)); }, AGENT_TIMEOUT_MS);
    child.once("error", (error) => finish(rejectAgent, error));
    child.once("exit", (code) => code === 0 ? finish(resolveAgent, stdout.trim()) : finish(rejectAgent, new Error(`agent-browser ${args.join(" ")} failed: ${stderr || stdout}`)));
  });
}
function agent(args) {
  const task = agentQueue.then(() => runAgent(args));
  agentQueue = task.catch(() => undefined);
  return task;
}
function walletBootstrap(walletOrigin) {
  return `(function () {\n    var address = ${JSON.stringify(wallet.address)};\n    var provider = {\n      selectedAddress: address, chainId: "0x1",\n      request: async function (input) {\n        var method = input.method;\n        if (method === "eth_accounts" || method === "eth_requestAccounts") return [address];\n        if (method === "eth_chainId") return "0x1";\n        if (method === "wallet_getPermissions" || method === "wallet_requestPermissions") return [{ parentCapability: "eth_accounts" }];\n        if (method === "personal_sign") {\n          var params = input.params || [];\n          var raw = String(params.length > 0 ? params[0] : "");\n          var hex = raw.indexOf("0x") === 0 ? raw.slice(2) : null;\n          var octets = hex === null ? [] : (hex.match(/.{1,2}/g) || []).map(function (value) { return parseInt(value, 16); });\n          var message = hex === null ? raw : new TextDecoder().decode(new Uint8Array(octets));\n          var response = await fetch(${JSON.stringify(walletOrigin + "/sign")}, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: message }) });\n          if (!response.ok) throw new Error("deterministic wallet refused the signing request");\n          return (await response.json()).signature;\n        }\n        return null;\n      }, on: function () { return provider; }, removeListener: function () { return provider; }, isConnected: function () { return true; }\n    };\n    var announce = function () { window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" }, provider: provider } })); };\n    window.ethereum = provider;\n    window.addEventListener("eip6963:requestProvider", announce); announce();\n  })()`;
}
function walletBootstrapScript(walletOrigin) {
  return `(function () {
    var address = ${JSON.stringify(wallet.address)};
    var provider = {
      selectedAddress: address,
      chainId: "0x1",
      request: async function (input) {
        var method = input.method;
        if (method === "eth_accounts" || method === "eth_requestAccounts") return [address];
        if (method === "eth_chainId") return "0x1";
        if (method === "wallet_getPermissions" || method === "wallet_requestPermissions") return [{ parentCapability: "eth_accounts" }];
        if (method === "personal_sign") {
          var raw = String((input.params || [])[0] || "");
          var hex = raw.indexOf("0x") === 0 ? raw.slice(2) : null;
          var bytes = hex === null ? [] : (hex.match(/.{1,2}/g) || []).map(function (value) { return parseInt(value, 16); });
          var message = hex === null ? raw : new TextDecoder().decode(new Uint8Array(bytes));
          var response = await fetch(${JSON.stringify(walletOrigin + "/sign")}, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: message }) });
          if (!response.ok) throw new Error("deterministic wallet refused the signing request");
          return (await response.json()).signature;
        }
        return null;
      },
      on: function () { return provider; },
      removeListener: function () { return provider; },
      isConnected: function () { return true; }
    };
    var announced = false;
    var announce = function () {
      if (announced) return;
      announced = true;
      window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: {
        info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" },
        provider: provider
    } }));
    };
    Object.defineProperty(window, "ethereum", { configurable: true, writable: true, value: provider });
    window.addEventListener("eip6963:requestProvider", announce);
    setTimeout(announce, 10000);
  })()`;
}

async function startFixtures(tempRoot) {
  const walletOrigin = await loopback("deterministic EIP-1193/EIP-6963 wallet", async (request, response) => {
    if (request.url !== "/sign") { response.writeHead(404).end(); return; }
    const caller = request.headers.origin;
    const cors = /^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(caller ?? "") ? { "access-control-allow-origin": caller, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type, x-forwarded-proto", vary: "Origin" } : {};
    if (request.method === "OPTIONS") { response.writeHead(204, cors).end(); return; }
    if (request.method !== "POST") { response.writeHead(405, cors).end(); return; }
    const chunks = []; request.on("data", (chunk) => chunks.push(chunk)); request.on("end", async () => { try { const body = JSON.parse(Buffer.concat(chunks).toString()); const signature = await wallet.signMessage({ message: body.message }); response.writeHead(200, { ...cors, "content-type": "application/json" }).end(JSON.stringify({ address: wallet.address, signature })); } catch { response.writeHead(400, cors).end(); } });
  });
  const openKeyOrigin = await loopback("OpenKey external-wallet/SIWE widget", (request, response) => {
    if (!request.url?.startsWith("/widget/")) { response.writeHead(404).end(); return; }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(`<!doctype html><meta charset="utf-8"><script>parent.postMessage({type:"openkey:ready"},"*");setTimeout(()=>parent.postMessage({type:"openkey:auth:use-external-wallet"},"*"),0);addEventListener("message",e=>{if(e.data&&e.data.type==="openkey:auth:request")parent.postMessage({type:"openkey:auth:use-external-wallet"},"*")});</script>`);
  });
  const registry = run("npm", ["run", "-w", "@tinycloud/share-registry", "dev-server", "--", "--port", "0"], shareRoot);
  let registryOrigin;
  const registryDeadline = Date.now() + 30_000;
  while (registryOrigin === undefined && Date.now() < registryDeadline) {
    const output = children.find((entry) => entry.child === registry)?.output() ?? "";
    registryOrigin = output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    if (registryOrigin === undefined) await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  if (registryOrigin === undefined) throw new Error("real Share registry did not publish a loopback URL");
  checks.push(`real Share registry started at ${registryOrigin}.`);

  const mailMessages = [];
  const mailReplays = [];
  let nextMailMessageId = 1;
  const mail = await loopback("Resend-compatible mail capture", (request, response) => {
    const traceId = `server-${runId}-${randomUUID()}`;
    serverTraceIds.push(traceId);
    // Reset is an exact control-plane route. Keep it ahead of the delivery
    // route so a reset can never be parsed as a provider message.
    if (request.method === "POST" && request.url === "/emails/reset") {
      mailMessages.length = 0;
      response.writeHead(204, { "x-tinycloud-trace-id": traceId }).end();
      return;
    }
    if (request.method === "POST" && request.url === "/emails") {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error("mail payload");
          const idempotencyKey = request.headers["idempotency-key"];
          const prior = typeof idempotencyKey === "string" ? mailMessages.find((message) => message.idempotencyKey === idempotencyKey) : undefined;
          if (prior !== undefined) {
            mailReplays.push({ idempotencyKey, originalId: prior.id, replayId: prior.id, traceId });
            const replayBody = JSON.stringify({ id: prior.id, replayed: true });
            response.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(replayBody), "x-tinycloud-trace-id": traceId }).end(replayBody);
            return;
          }
          const id = `hermetic-mail-${nextMailMessageId++}`;
          mailMessages.push({ id, idempotencyKey: typeof idempotencyKey === "string" ? idempotencyKey : undefined, payload: body });
          const acceptedBody = JSON.stringify({ id });
          response.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(acceptedBody), "x-tinycloud-trace-id": traceId }).end(acceptedBody);
        } catch {
          response.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid mail payload" }));
        }
      });
      return;
    }
    if (request.method === "GET" && request.url === "/emails") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store", "x-tinycloud-trace-id": traceId }).end(JSON.stringify({ messages: mailMessages }));
      return;
    }
    response.writeHead(404).end();
  });

  const postgresData = join(tempRoot, "postgres");
  const postgresPort = await freePort();
  await runOnce("/opt/homebrew/opt/postgresql@16/bin/initdb", ["-D", postgresData, "-A", "trust", "-U", "samgbafa"], shareRoot, { LC_ALL: "C" });
  run("/opt/homebrew/opt/postgresql@16/bin/postgres", ["-D", postgresData, "-h", "127.0.0.1", "-p", String(postgresPort)], shareRoot, { PGUSER: "samgbafa" });
  await waitForTcp(postgresPort);
  checks.push(`hermetic Postgres persistence started on 127.0.0.1:${postgresPort}.`);

  const nodePort = await freePort();
  const nodeKeysSecretB64 = nodeKeysSecret.toString("base64url");
  const node = run("cargo", ["run", "--quiet", "-p", "tinycloud-node"], nodeRoot, { TMPDIR: tempRoot, RUST_LOG: "error", TINYCLOUD_KEYS_SECRET: nodeKeysSecretB64, ROCKET_ADDRESS: "127.0.0.1", ROCKET_PORT: String(nodePort) });
  const nodeOrigin = `http://127.0.0.1:${nodePort}`;
  await waitFor(`${nodeOrigin}/share/v2/readiness`, 180_000);
  const nodeDescriptorJson = execFileSync("cargo", ["run", "--quiet", "-p", "tinycloud-node", "--bin", "export-share-invitation-descriptor"], { cwd: nodeRoot, env: { ...process.env, TINYCLOUD_KEYS_SECRET: nodeKeysSecretB64 }, encoding: "utf8" });
  const nodePublic = JSON.parse(nodeDescriptorJson);
  const nodeDescriptor = { url: nodeOrigin, nodeId: nodePublic.nodeAudience, trustedNode: { invitationPublicKey: nodePublic.nodeInvitationPublicKey } };
  await recordArtifactDigest("nodeRuntime", join(nodeRoot, "target/debug/tinycloud"));
  checks.push(`real Node production router/persistence started at ${nodeOrigin}.`);
  try {
    const readiness = await (await fetch(`${nodeDescriptor.url}/share/v2/readiness`)).json();
    checks.push(`real Node v2 readiness ${JSON.stringify({ ready: readiness.ready === true, checks: Object.fromEntries(Object.entries(readiness.checks ?? {}).map(([key, value]) => [key, value === true])) })}.`);
  } catch {
    checks.push("real Node v2 readiness probe unavailable.");
  }

  const credentialsPort = await freePort();
  const credentials = run("cargo", ["run", "--quiet", "--manifest-path", credentialsManifest, "--bin", "opencredentials-witness"], credentialsRoot, {
    TMPDIR: tempRoot,
    BIND_ADDR: `127.0.0.1:${credentialsPort}`, CORS_ALLOWED_ORIGINS: canonical.share, DID_WEB: "did:web:issuer.credentials.org", OPENCREDENTIALS_SK: issuerSecret,
    SHARE_EMAIL_CAPABILITY: "true", EMAIL_CLAIM_FIXTURE_DATABASE_URL: `postgres://127.0.0.1:${postgresPort}/postgres?sslmode=disable`, SHARE_EMAIL_RESEND_ENDPOINT: `${mail}/emails`,
    SHARE_EMAIL_TRUSTED_NODE_ORIGIN: canonical.node, SHARE_EMAIL_TRUSTED_NODE_AUDIENCE: "did:web:node.tinycloud.xyz", SHARE_EMAIL_TRUSTED_NODE_KID: "did:web:node.tinycloud.xyz#invitation-key-1", SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY: nodeDescriptor.trustedNode?.invitationPublicKey ?? "A".repeat(43),
    SHARE_EMAIL_TRUST_BUNDLE_JSON: trustBundleFromRuntime(nodeDescriptor.trustedNode?.invitationPublicKey), SHARE_EMAIL_SHARE_URL: canonical.share, RESEND_API_KEY: "hermetic-provider-key", RESEND_WEBHOOK_SECRET: "hermetic-webhook",
  });
  const credentialsOrigin = `http://127.0.0.1:${credentialsPort}`;
  await recordArtifactDigest("openCredentialsRuntime", join(credentialsRoot, "rust/opencredentials_witness/target/debug/opencredentials-witness"));
  await waitFor(`${credentialsOrigin}/share-email/readiness`, 30_000);
  checks.push(`real OpenCredentials production router/store started at ${credentialsOrigin}.`);
  return { walletOrigin, openKeyOrigin, registryOrigin, nodeOrigin: nodeDescriptor.url, nodeDescriptor, credentialsOrigin, mailOrigin: mail, mailMessages, mailReplays };
}

async function startShare(tempRoot, fixtures) {
  const sdkRoot = process.env.TINYCLOUD_JS_SDK_WORKTREE ?? join(workspaceRoot, "worktrees/js-sdk/feat/sharing-production-live");
  const sdkLink = join(shareRoot, "node_modules/@tinycloud/web-sdk");
  const sdkLinkStat = await lstat(sdkLink);
  const resolvedSdkLink = await realpath(sdkLink);
  const expectedSdkLink = await realpath(join(sdkRoot, "packages/web-sdk"));
  if (!sdkLinkStat.isSymbolicLink() || resolvedSdkLink !== expectedSdkLink) throw new Error("Share @tinycloud/web-sdk must resolve to the exact js-sdk worktree");
  await runOnce("npm", ["run", "build"], sdkRoot);
  await stat(join(expectedSdkLink, "dist/index.mjs"));
  await recordArtifactDigest("jsSdkWebRuntime", join(expectedSdkLink, "dist/index.mjs"));
  checks.push(`Share dependency resolved to the built js-sdk worktree at ${expectedSdkLink}.`);
  const port = await freePort();
  const trustPath = join(tempRoot, "trust.json");
  const bindingPath = join(tempRoot, "bindings.ndjson");
  const registryKey = Buffer.alloc(32, 7).toString("base64url");
  const origin = `http://127.0.0.1:${port}`;
  await writeFile(trustPath, trustBundleFromRuntime(fixtures.nodeDescriptor.trustedNode?.invitationPublicKey), { flag: "wx" });
  // The shipped viewer consumes the registry client through a same-origin
  // proxy in production; point the production-shaped build at that proxy so
  // browser CSP and the zero-external-destination audit observe the same path.
  await runOnce("npm", ["run", "build"], shareRoot, { VITE_OPENKEY_ORIGIN: "https://openkey.so", VITE_SHARE_ORIGIN: canonical.share, VITE_SHARE_REGISTRY_URL: canonical.registry });
  const shareAsset = execFileSync("find", [join(shareRoot, "dist/assets"), "-maxdepth", "1", "-name", "main-*.js", "-print"], { encoding: "utf8" }).trim().split("\n")[0];
  if (!shareAsset) throw new Error("Share build did not produce its main browser bundle");
  await recordArtifactDigest("shareBundle", shareAsset);
  const share = run("npm", ["run", "start:deploy"], shareRoot, {
    HOST: "127.0.0.1", PORT: String(port), SHARE_TRUST_BUNDLE_FILE: trustPath, SHARE_SENDER_ENABLED: "false", SHARE_BINDING_STORE_PATH: bindingPath, SHARE_REGISTRY_UPLOAD_KEY_PATH: join(tempRoot, "registry-upload.key"),
    SHARE_NODE_ENFORCER_DID: fixtures.nodeDescriptor.nodeId, SHARE_BINDING_STORE_ROOT: tempRoot,
  });
  await waitFor(`${origin}/health/readiness`);
  checks.push(`committed production Share host started on loopback at ${origin} with a production trust bundle.`);
  return { origin, share };
}

function networkEntries(value) {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  return Array.isArray(parsed) ? parsed : Array.isArray(parsed?.data) ? parsed.data : parsed?.data?.requests ?? [];
}

async function installBrowserTelemetry() {
  await agent(["eval", `(function(){if(window.__tinycloudTelemetryInstalled)return;var original=window.fetch;var nodeOrigin=${JSON.stringify(canonical.node)};var credentialsOrigin=${JSON.stringify(canonical.credentials)};window.__tinycloudTelemetry=[];window.__tinycloudTelemetryInstalled=true;window.fetch=async function(input,init){var url=typeof input==='string'?input:(input&&input.url)||(input&&input.href)||String(input);var method=(init&&init.method)||((typeof input!=='string'&&input&&input.method)||'GET');var browserTraceId=crypto.randomUUID();var routed=url;var requestBodyPromise=method==='POST'&&input&&typeof input.clone==='function'?input.clone().text().catch(function(){return ''; }):Promise.resolve(typeof init?.body==='string'?init.body:'');if(url.indexOf(nodeOrigin)===0||url.indexOf(credentialsOrigin)===0){var parsed=new URL(url);parsed.protocol=window.location.protocol;parsed.host=window.location.host;routed=parsed.toString();}var requestInit=init;if(new URL(routed,window.location.href).origin===window.location.origin){var headers=new Headers(init?.headers);headers.set('x-forwarded-proto','https');requestInit={...(init||{}),headers:headers};}try{var response=await original.apply(window,[routed,requestInit]);var item={url:routed,method:method,status:response.status,requestId:browserTraceId,serverTraceId:response.headers.get('x-tinycloud-trace-id')};if(method==='POST'&&routed.endsWith('/invoke')){var bodyText=await requestBodyPromise;item.requestSpaces=[...new Set(bodyText.match(/tinycloud:[^\"' ]+/g)||[])];}if((!response.ok&&method==='POST')||(method==='POST'&&routed.endsWith('/delegate'))||(method==='POST'&&routed.endsWith('/invoke'))||(method==='POST'&&routed.endsWith('/policies'))){try{var clone=response.clone();var text=await clone.text();var parsedBody=null;try{parsedBody=JSON.parse(text);}catch{}if(routed.endsWith('/policies')){item.responseKeys=parsedBody&&typeof parsedBody==='object'?Object.keys(parsedBody).sort():[];item.responseErrorCode=parsedBody&&parsedBody.error&&typeof parsedBody.error==='object'?parsedBody.error.code||null:null;}if(routed.endsWith('/delegate'))item.responseBody=text.slice(0,1200);if(routed.endsWith('/invoke')){item.responseContentType=response.headers.get('content-type');item.responseBodyLength=text.length;item.responseBodyPreview=text.slice(0,240);}try{item.errorCode=parsedBody&&parsedBody.error?.code||null;}catch{item.errorCode=null;if(!response.ok)item.errorBody=text.slice(0,500);}}catch{item.errorCode=null;}}window.__tinycloudTelemetry.push(item);return response;}catch(error){window.__tinycloudTelemetry.push({url:routed,method:method,status:0,requestId:browserTraceId});throw error;}};})()`]);
}

async function browserTelemetryEntries() {
  try {
    const entries = networkEntries(await agent(["eval", "JSON.stringify((window.__tinycloudTelemetry&&window.__tinycloudTelemetry.length>0)?window.__tinycloudTelemetry:performance.getEntriesByType('resource').map(function(entry,index){return {url:entry.name,method:'GET',status:200,requestId:'performance-'+index}}))"]));
    if (entries.length > 0) return entries;
    return [{ url: await agent(["get", "url"]), method: "GET", status: 200, requestId: `browser-navigation-${randomUUID()}` }];
  } catch { return []; }
}

function scrubNetwork(entries) {
  return entries.map((entry, index) => {
    let parsed;
    try { parsed = new URL(entry.url); } catch { parsed = undefined; }
    return {
      method: typeof entry.method === "string" ? entry.method : entry.request?.method,
      path: parsed === undefined ? "[invalid-url]" : parsed.pathname,
      origin: parsed === undefined ? "[invalid-origin]" : parsed.origin,
      status: Number.isInteger(entry.status) ? entry.status : entry.response?.status,
      browserTraceId: entry.requestId ?? entry.traceId ?? entry.request?.requestId ?? entry.response?.requestId ?? (Number.isFinite(entry.timestamp) ? `browser-${entry.timestamp}-${index}` : null),
    };
  });
}

async function beginFlow(name) {
  const traceId = `${name}-${randomUUID()}`;
  await agent(["network", "requests", "--clear"]);
  await agent(["eval", `window.__tinycloudTelemetry=[];performance.clearResourceTimings?.();window.__tinycloudSharingFlowTraceId=${JSON.stringify(traceId)}`]);
  return traceId;
}

async function auditFlow(name, traceId, options = {}) {
  const trackedNetwork = options.networkEntries ?? networkEntries(await agent(["network", "requests", "--json"]));
  const network = trackedNetwork.length > 0 ? trackedNetwork : await browserTelemetryEntries();
  if (network.length === 0) throw new Error(`${name} network capture is missing`);
  // The harness-generated flow ID is carried into the page before each flow;
  // browser request IDs below provide the observed per-flow browser trace.
  let mailTraceId = null;
  let messages = [];
  const mailDeadline = Date.now() + (options.expectMail === true ? 5_000 : 0);
  do {
    const mailResponse = await fetch(`${options.mailOrigin}/emails`, { cache: "no-store" });
    mailTraceId = mailResponse.headers.get("x-tinycloud-trace-id");
    const mailState = await mailResponse.json();
    messages = Array.isArray(mailState.messages) ? mailState.messages : [];
    const expectedRecipientObserved = options.expectMailRecipient === undefined || messages.some((message) => stringsIn(message?.payload).includes(options.expectMailRecipient));
    if (options.expectMail !== true || (messages.length > 0 && expectedRecipientObserved)) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  } while (Date.now() < mailDeadline);
  if (mailTraceId === null || mailTraceId.length === 0) throw new Error(`${name} server trace id was not captured`);
  const capturedMail = options.expectMailRecipient === undefined ? messages.at(-1) : messages.find((message) => stringsIn(message?.payload).includes(options.expectMailRecipient));
  const capturedMailId = capturedMail?.id ?? null;
  if (options.expectMail === true && capturedMailId === null) throw new Error(`${name} captured-mail ID is missing`);
  const sanitized = scrubNetwork(network);
  const telemetry = JSON.stringify(sanitized);
  const dynamicSecretTelemetry = {
    claimSecret: !telemetry.includes("claimSecret"),
    authorityHandle: !["amh_sql_001", "amh_kv_001", "SHARE_SENDER_PRIVATE_KEY"].some((secret) => telemetry.includes(secret)),
    piiInUrls: !(options.pii ?? []).some((pii) => telemetry.includes(pii)),
  };
  assert.equal(Object.values(dynamicSecretTelemetry).every(Boolean), true, `${name} telemetry leaked a secret, authority handle, or dynamic PII`);
  const browserTraceIds = sanitized.map((entry) => entry.browserTraceId).filter((value) => typeof value === "string" && value.length > 0);
  if (browserTraceIds.length === 0) throw new Error(`${name} browser request trace IDs are missing`);
  const replayEvidence = options.replayEvidence ?? { attempted: false, accepted: false };
  if (options.requireReplay === true && (!replayEvidence.attempted || !replayEvidence.accepted)) throw new Error(`${name} idempotency replay evidence is missing`);
  flowAudits.push({ name, browserTraceIds, serverTraceIds: [mailTraceId], capturedMailId, idempotencyReplay: replayEvidence, dynamicSecretTelemetry });
  checks.push(`${name} complete network audit captured sanitized browser/server trace IDs, captured-mail ${capturedMailId ?? "none"}, idempotency replay evidence, and dynamic secret/PII telemetry.`);
  return { messages, capturedMail, sanitized };
}

function stringsIn(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (value !== null && typeof value === "object") return Object.values(value).flatMap(stringsIn);
  return [];
}

function mailShareUrl(message) {
  const values = stringsIn(message).flatMap((candidate) => [...candidate.matchAll(/https:\/\/share\.tinycloud\.xyz\/s\/[^\s"'<>]+/g)].map((match) => match[0]));
  const value = values.sort((left, right) => Number(right.includes("?i=") && right.includes("#k=")) - Number(left.includes("?i=") && left.includes("#k=")) || right.length - left.length)[0];
  if (value === undefined) throw new Error("captured mail did not contain the exact generated Share URL");
  return value.replaceAll("&amp;", "&");
}

function localShareUrl(value, origin) {
  const url = new URL(value);
  url.protocol = "http:";
  url.host = new URL(origin).host;
  return url.href;
}

function agentString(value) {
  let current = value;
  for (let unwrap = 0; unwrap < 4 && typeof current === "string"; unwrap += 1) {
    try {
      const parsed = JSON.parse(current);
      if (typeof parsed !== "string") return parsed;
      current = parsed;
    } catch {
      break;
    }
  }
  return current;
}

function safeBrowserDiagnostic(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    const normalized = value.toLowerCase();
    const category = normalized.includes("signature") ? "signature"
      : normalized.includes("cid") ? "cid"
      : normalized.includes("canonical") || normalized.includes("timestamp") || normalized.includes("expired") ? "canonical-registration"
      : normalized.includes("chain") || normalized.includes("bound") ? "registration-binding"
      : normalized.includes("policy_registration_invalid") || normalized.includes("policy") ? "policy"
      : normalized.includes("capability") ? "capability"
      : normalized.includes("config") ? "config"
      : normalized.includes("auth") || normalized.includes("session") ? "auth"
      : normalized.includes("enforcer") || normalized.includes("did:") ? "identity"
      : normalized.includes("invoke") || normalized.includes("delegate") ? "authorization"
      : normalized.includes("permission") ? "permission"
      : normalized.includes("sign") ? "sign-in"
      : normalized.includes("space") ? "space"
      : normalized.includes("library") ? "library"
      : normalized.includes("network") ? "network"
      : normalized.includes("invalid") ? "invalid"
      : normalized.includes("failed") || normalized.includes("failure") ? "failure"
      : "other";
    return { length: value.length, category };
  }
  if (typeof value !== "object") return { type: typeof value };
  const object = value;
  const message = typeof object.message === "string" ? object.message : typeof object.error === "string" ? object.error : undefined;
  return { type: Array.isArray(value) ? "array" : "object", message: message === undefined ? undefined : safeBrowserDiagnostic(message) };
}

async function browserGateArchive(origin, walletOrigin, mailOrigin) {
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  const initialMail = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.deepEqual(initialMail.messages, []);
  checks.push("Mail capture reset and confirmed zero delivery attempts before browser link creation.");
  await agent(["network", "requests", "--clear"]);
  await agent(["eval", `location.href=${JSON.stringify(`${origin}/share.html`)}`]);
  await agent(["eval", "document.querySelector('.auth-button')?.disabled === false"]);
  await agent(["eval", walletBootstrapScript(walletOrigin)]);
  await agent(["eval", `(function(){var original=window.fetch;window.__tinycloudAuthDiagnostics=[];window.fetch=function(input,init){var u=typeof input==='string'?input:input.url;var p=original.apply(this,arguments);if(u.includes('/api/share/auth/openkey'))p.then(function(r){r.clone().text().then(function(body){window.__tinycloudAuthDiagnostics.push({url:u,status:r.status,body:body.slice(0,2000)})})});return p;};})()`]);
  await agent(["eval", "(function(){var original=Element.prototype.attachShadow;Element.prototype.attachShadow=function(init){var options=init||{};options.mode='open';return original.call(this,options);};})()"]);
  await agent(["click", "button.auth-button"]);
  await agent(["wait", "1000"]);
  await agent(["find", "text", "TinyCloud E2E Wallet", "click"]);
  // The mounted fixture already provisions a space. A first-run prompt is
  // optional, so do not spend a browser timeout probing for it on every flow.
  await agent(["wait", "text=Shared by me."]);
  if (openComposer) {
    await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='New share');if(!button)throw new Error('New share action is not present');button.click();return true;})()"]);
    await agent(["wait", "text=Share with intent."]);
  }
  checks.push("agent-browser completed the real OpenKey external-wallet/SIWE authentication path with a deterministic EIP-1193/EIP-6963 provider.");

  await agent(["select", "select[name=content-mode]", "author"]);
  await agent(["fill", "textarea[name=author-content]", "# Hermetic sharing\n\nMarkdown created in the browser."]);
  await agent(["select", "select[name=format]", "compact"]);
  await agent(["click", "input[value=bearer]"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Your private link is ready"]);
  const compact = await agent(["get", "value", "#generated-share-link"]);
  assert.match(compact, /^https:\/\/share\.tinycloud\.xyz\/s\/[^#]+#k=/);
  checks.push("Browser-created Markdown produced an encrypted compact link.");

  // The bearer viewer is a separate production entrypoint. Re-open the
  // authenticated composer before starting the addressed flow instead of
  // relying on a viewer control that intentionally does not exist on the
  // read-only surface.
  await agent(["eval", `location.href=${JSON.stringify(`${origin}/share.html`)}`]);
  await agent(["wait", "text=Share with intent."]);
  await agent(["select", "select[name=content-mode]", "upload"]);
  await agent(["upload", "input[name=document]", join(shareRoot, "test/e2e-sharing/fixture.md")]);
  await agent(["select", "select[name=format]", "inline"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Your private link is ready"]);
  const inline = await agent(["get", "value", "#generated-share-link"]);
  assert.match(inline, /^https:\/\/share\.tinycloud\.xyz\/s\/inline#v=2&p=/);
  checks.push("Browser upload produced an encrypted inline link.");

  const localCompact = new URL(compact); localCompact.protocol = "http:"; localCompact.host = new URL(origin).host;
  await agent(["eval", `location.href=${JSON.stringify(localCompact.href)}`]);
  await agent(["wait", "1500"]);
  const viewerSnapshot = await agent(["snapshot"]);
  if (!viewerSnapshot.includes("shared via link")) throw new Error(`viewer did not render the compact share; local compact=${localCompact.href}; snapshot=${viewerSnapshot.slice(0, 2000)}`);
  const renderedMarkdown = await agent(["eval", "document.querySelector('iframe')?.srcdoc.includes('Hermetic sharing') === true"]);
  assert.equal(renderedMarkdown, "true");
  gateResults.bearer = true;
  checks.push("Bearer compact link rendered the encrypted Markdown in the isolated viewer.");
  const bearerMail = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.deepEqual(bearerMail.messages, []);
  checks.push("Bearer link creation remained link-only with zero mail delivery attempts.");

  // Addressed flows intentionally continue in the same authenticated browser
  // session. The composer keeps link creation and delivery separate, so the
  // mail capture must remain empty until the explicit confirmation button is
  // pressed.
  await agent(["open", `${origin}/share.html`]);
  await agent(["wait", "text=Share with intent."]);
  await agent(["click", "input[value=exactEmail]"]);
  await agent(["fill", "input[name=recipient-value]", "sam@tinycloud.xyz"]);
  await agent(["select", "select[name=content-mode]", "author"]);
  await agent(["fill", "textarea[name=author-content]", "# Exact email\n\nEncrypted exact-recipient Markdown."]);
  await agent(["click", "input[name=notify]"]);
  await agent(["fill", "input[name=delivery-email]", "sam@tinycloud.xyz"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Your private link is ready"]);
  const exactUrl = await agent(["get", "value", "#generated-share-link"]);
  assert.match(exactUrl, /^https:\/\/share\.tinycloud\.xyz\/s\//);
  const beforeConfirm = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.deepEqual(beforeConfirm.messages, []);
  checks.push("Encrypted exact-email link was created without delivery; mail capture remained empty before confirmation.");
  await agent(["eval", "(function(){var old=window.fetch;window.__tinycloudDomainNotifyResponse=null;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');return old.apply(this,arguments).then(function(response){if(u.includes('/v1/share-email/invitations')){response.clone().text().then(function(body){window.__tinycloudDomainNotifyResponse={status:response.status,body:body.slice(0,2000)};});}return response;});};})()"]);
  await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "2000"]);
  const domainNotificationStatus = agentString(await agent(["eval", "JSON.stringify({status:(document.querySelector('.notification-status')?.textContent||''),response:window.__tinycloudDomainNotifyResponse})"]));
  if (!String(domainNotificationStatus?.status ?? "").startsWith("Notification queued")) throw new Error("domain notification did not complete: " + JSON.stringify(domainNotificationStatus));
  const exactMail = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.equal(exactMail.messages.length, 1);
  const exactMailText = JSON.stringify(exactMail.messages[0]);
  assert.match(exactMailText, /sam@tinycloud\.xyz/);
  assert.match(exactMailText, /https:\/\/share\.tinycloud\.xyz\/s\//);
  gateResults.exactEmail = true;
  gateResults.notification = true;
  checks.push("Explicit confirmation queued exactly one exact-address notification and the captured message contained the exact Share URL.");
  const finalRequestsPayload = JSON.parse(await agent(["network", "requests", "--json"]));
  const finalRequests = Array.isArray(finalRequestsPayload) ? finalRequestsPayload : Array.isArray(finalRequestsPayload.data) ? finalRequestsPayload.data : finalRequestsPayload.data?.requests ?? [];
  const finalTelemetry = JSON.stringify(finalRequests);
  assert.equal(finalTelemetry.includes("claimSecret"), false, "same-origin telemetry leaked claim secret");
  assert.equal(finalTelemetry.includes("amh_sql_001"), false, "same-origin telemetry leaked static SQL authority handle");
  assert.equal(finalTelemetry.includes("amh_kv_001"), false, "same-origin telemetry leaked static KV authority handle");
  checks.push("Final agent-browser same-origin telemetry assertion observed no claim secret or static authority handle after explicit notification.");
  const requestsPayload = JSON.parse(await agent(["network", "requests", "--json"]));
  const requests = Array.isArray(requestsPayload) ? requestsPayload : Array.isArray(requestsPayload.data) ? requestsPayload.data : requestsPayload.data?.requests ?? [];
  externalRequests = requests.filter((entry) => { try { const url = new URL(entry.url); return url.protocol !== "http:" || (url.hostname !== "127.0.0.1" && url.hostname !== "localhost"); } catch { return true; } });
  if (externalRequests.length !== 0) throw new Error(`Browser attempted non-loopback destinations: ${JSON.stringify(externalRequests.map((entry) => entry.url).slice(0, 20))}`);
  const telemetry = JSON.stringify(requests);
  for (const secret of ["claimSecret", "amh_sql_001", "amh_kv_001"]) assert.equal(telemetry.includes(secret), false, `browser telemetry leaked production secret or static authority handle: ${secret}`);
  gateResults.browser = true;
  checks.push("Final agent-browser network audit observed zero unmocked external destinations and no claim secret or static authority handle.");
}

async function browserGate(origin, walletOrigin, mailOrigin) {
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  assert.deepEqual((await (await fetch(`${mailOrigin}/emails`)).json()).messages, []);
  await agent(["open", `${origin}/share.html`]);
  await agent(["set", "headers", JSON.stringify({ "X-Forwarded-Proto": "https" })]);
  await installBrowserTelemetry();
  await agent(["eval", "document.querySelector('.auth-button')?.disabled === false"]);
  await agent(["eval", "window.__tinycloudOpenKeyDiagnostics=[];window.addEventListener('message',function(event){window.__tinycloudOpenKeyDiagnostics.push({origin:event.origin,source:!!event.source,type:event.data&&event.data.type,name:event.data&&event.data.info&&event.data.info.name});});"]);
  await agent(["eval", "(function(){var original=window.fetch;window.__tinycloudAuthDiagnostics=[];window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');var result=original.apply(this,arguments);if(u.includes('/api/share/auth/openkey'))result.then(function(response){window.__tinycloudAuthDiagnostics.push({path:(new URL(u,location.href)).pathname,status:response.status});});return result;};})()"]).catch(() => undefined);
  await agent(["eval", walletBootstrapScript(walletOrigin)]);
  await agent(["eval", "(function(){var original=Element.prototype.attachShadow;Element.prototype.attachShadow=function(init){var options=init||{};options.mode='open';return original.call(this,options);};})()"]);
  await agent(["click", "button.auth-button"]);
  await agent(["wait", "1000"]);
  await agent(["find", "text", "TinyCloud E2E Wallet", "click"]);
  await agent(["find", "text", "Create TinyCloud Space", "click"]).catch(() => undefined);
  // The mounted fixture already provisions a space. A first-run prompt is
  // optional, so do not probe for it on every flow.
  await agent(["wait", "text=Shared by me."]);
  await agent(["wait", "text=No shares yet"]);
  checks.push("Fresh authenticated sender observed the Shared by me empty state and New share entry point.");
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='New share');if(!button)throw new Error('New share action is not present');button.click();return true;})()"]);
  await agent(["wait", "text=Share with intent."]);
  await agent(["eval", "(function(){window.__senderCopiedLink=null;var clipboard={writeText:function(value){window.__senderCopiedLink=value;return Promise.resolve();},readText:function(){return Promise.resolve(window.__senderCopiedLink||'');}};try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:clipboard});}catch{}})()"]).catch(() => undefined);
  checks.push("agent-browser completed the real OpenKey external-wallet/SIWE authentication path with a deterministic provider.");

  const createBearer = async (format, contentMode, traceName) => {
    const traceId = await beginFlow(traceName);
    await agent(["select", "select[name=content-mode]", contentMode]);
    if (contentMode === "author") await agent(["fill", "textarea[name=author-content]", "# Hermetic sharing\n\nMarkdown created in the browser."]);
    else await agent(["upload", "input[name=document]", join(shareRoot, "test/e2e-sharing/fixture.md")]);
    await agent(["select", "select[name=format]", format]);
    await agent(["click", "input[value=bearer]"]);
    await agent(["click", "button.create-link-button"]);
    await agent(["wait", "text=Your private link is ready"]);
    await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='Copy link' && !candidate.disabled);if(!button)throw new Error('Copy link action is not present');button.click();return true;})()"]);
    await agent(["wait", "text=Link copied to clipboard."]);
    const url = agentString(await agent(["eval", "window.__senderCopiedLink"]));
    assert.equal(typeof url, "string", "sender clipboard did not contain a URL");
    return { traceId, url };
  };

  const compact = await createBearer("compact", "author", "bearer-compact");
  assert.match(compact.url, /^https:\/\/share\.tinycloud\.xyz\/s\/[^#]+#k=/);
  const compactNetwork = await browserTelemetryEntries();
  const localCompact = new URL(compact.url); localCompact.protocol = "http:"; localCompact.host = new URL(origin).host;
  await agent(["eval", `location.href=${JSON.stringify(localCompact.href)}`]);
  await agent(["wait", "1500"]);
  await installBrowserTelemetry();
  assert.match(await agent(["snapshot"]), /shared via link/);
  assert.equal(await agent(["eval", "document.querySelector('iframe')?.srcdoc.includes('Hermetic sharing') === true"]), "true");
  await agent(["eval", `window.__tinycloudSharingFlowTraceId=${JSON.stringify(compact.traceId)}`]);
  await auditFlow("bearer-compact", compact.traceId, { mailOrigin, networkEntries: compactNetwork, skipBrowserTraceCheck: true });
  gateResults.bearer = true;

  await agent(["open", `${origin}/share.html`]); await authenticateBrowserPage(walletOrigin); await installBrowserTelemetry();
  const inline = await createBearer("inline", "upload", "bearer-inline");
  assert.match(inline.url, /^https:\/\/share\.tinycloud\.xyz\/s\/inline#v=2&p=/);
  await auditFlow("bearer-inline", inline.traceId, { mailOrigin });
  await agent(["open", `${origin}/share.html`]); await authenticateBrowserPage(walletOrigin, false);
  await agent(["wait", "text=2 shares loaded."]);
  assert.equal(await agent(["get", "count", ".sender-history-row"]), "2", "fresh same-sender sign-in did not reload the populated encrypted library");
  const libraryCopy = agentString(await agent(["eval", "(()=>{const buttons=[...document.querySelectorAll('button[aria-label^=\"Copy link for\"]')];if(buttons.length<2)throw new Error('sender library copy actions missing; buttons='+buttons.length+'; rows='+document.querySelectorAll('.sender-history-row').length+'; live='+JSON.stringify(document.querySelector('.sender-live')?.textContent||'')+'; error='+JSON.stringify(document.querySelector('.sender-status')?.textContent||'')+'; loadError='+JSON.stringify(window.__tinycloudSenderHistoryError||''));buttons[1].click();return true;})()"]));
  void libraryCopy; await agent(["wait", "text=Link copied."]);
  assert.equal(await agent(["eval", `window.__senderCopiedLink===${JSON.stringify(compact.url)}`]), "true", "sender library reconstructed a non-byte-exact compact link");
  assert.equal(await agent(["eval", `!document.documentElement.textContent.includes(${JSON.stringify(compact.url)}) && !document.documentElement.textContent.includes(${JSON.stringify(inline.url)})`]), "true", "sender library rendered a complete secret URL in page text");
  await agent(["eval", "fetch('/api/share/auth/logout',{method:'POST',credentials:'include'}).then(function(r){return r.status})"]);
  assert.equal(await agent(["eval", "fetch('/api/share/capabilities',{credentials:'include'}).then(function(r){return r.status})"]), "401", "signed-out sender library remained authorized");
  await agent(["open", `${origin}/share.html`]); await authenticateBrowserPage(walletOrigin, false); await agent(["wait", "text=2 shares loaded."]);
  assert.equal(await agent(["get", "count", ".sender-history-row"]), "2", "same sender did not recover its library after session reset");
  gateResults.senderLibrary = true;
  checks.push("Sender library created and persisted shares, reset the session, reloaded the populated same-sender library, copied a byte-exact complete link, rendered no secret URL, and denied signed-out access.");
  checks.push("Encrypted compact and inline bearer links were both observed; bearer creation remained link-only.");

  await agent(["open", `${origin}/share.html`]); await authenticateBrowserPage(walletOrigin); await installBrowserTelemetry();
  const exactTrace = await beginFlow("exact-email");
  await agent(["click", "input[value=exactEmail]"]); await agent(["fill", "input[name=recipient-value]", "sam@tinycloud.xyz"]);
  await agent(["select", "select[name=content-mode]", "kv"]); await agent(["eval", "(function(){var s=document.querySelector('select[name=kv-source]');s.selectedIndex=0;s.dispatchEvent(new Event('change',{bubbles:true}));})()"]).catch(() => undefined);
  await agent(["check", "input[name=permission][value=edit]"]); await agent(["click", "input[name=notify]"]); await agent(["fill", "input[name=delivery-email]", "sam@tinycloud.xyz"]);
  await agent(["click", "button.create-link-button"]); await agent(["wait", "text=Your private link is ready"]);
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='Copy link' && !candidate.disabled);if(!button)throw new Error('Copy link action is not present');button.click();return true;})()"]); await agent(["wait", "text=Link copied to clipboard."]);
  const exactUrl = agentString(await agent(["eval", "window.__senderCopiedLink"])); assert.match(exactUrl, /^https:\/\/share\.tinycloud\.xyz\/s\//);
  assert.deepEqual((await (await fetch(`${mailOrigin}/emails`)).json()).messages, []);
  await agent(["eval", `(function(){var old=window.fetch;window.__tinycloudDeliveryReplay=null;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/v1/share-email/invitations')&&init){window.__tinycloudDeliveryReplay={url:u,method:init.method||'POST',headers:Object.fromEntries(new Headers(init.headers)),body:typeof init.body==='string'?init.body:null};}return old.apply(this,arguments);};})()`]);
  await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Notification queued"]);
  const replayRaw = await agent(["eval", "JSON.stringify(window.__tinycloudDeliveryReplay)"]);
  if (replayRaw === "null" || replayRaw === "undefined") throw new Error("exact-email delivery request capture is missing");
  let replay = JSON.parse(replayRaw);
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof replay === "string") { try { replay = JSON.parse(replay); continue; } catch { break; } }
    if (replay !== null && typeof replay === "object" && replay.data !== undefined) { replay = replay.data; continue; }
    if (replay !== null && typeof replay === "object" && replay.value !== undefined) { replay = replay.value; continue; }
    break;
  }
  checks.push(`Exact-email delivery replay request captured metadata ${JSON.stringify({ url: replay.url ?? null, method: replay.method ?? null, bodyLength: typeof replay.body === "string" ? replay.body.length : 0, headers: Object.keys(replay.headers ?? {}).sort() }).slice(0, 1200)}.`);
  const replayValue = JSON.parse(await agent(["eval", `fetch(${JSON.stringify(replay.url)},{method:${JSON.stringify(replay.method)},headers:${JSON.stringify(replay.headers)},body:${JSON.stringify(replay.body)}}).then(function(r){return JSON.stringify({status:r.status,ok:r.ok})})`]));
  let replayResult = replayValue;
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof replayResult === "string") { try { replayResult = JSON.parse(replayResult); continue; } catch { break; } }
    if (replayResult !== null && typeof replayResult === "object" && replayResult.data !== undefined) { replayResult = replayResult.data; continue; }
    if (replayResult !== null && typeof replayResult === "object" && replayResult.value !== undefined) { replayResult = replayResult.value; continue; }
    break;
  }
  checks.push(`Exact-email delivery replay observed status ${replayResult.status ?? "unknown"}; response body was omitted from telemetry; normalized result shape ${JSON.stringify(replayValue).slice(0, 500)}.`);
  const exactAudit = await auditFlow("exact-email", exactTrace, { mailOrigin, expectMail: true, requireReplay: true, replayEvidence: { attempted: true, accepted: replayResult.ok === true && replayResult.status === 200 }, pii: ["sam@tinycloud.xyz"] });
  assert.equal(exactAudit.messages.length, 1); assert.match(JSON.stringify(exactAudit.capturedMail.payload), /https:\/\/share\.tinycloud\.xyz\/s\//);
  const exactInviteUrl = localShareUrl(mailShareUrl(exactAudit.capturedMail.payload), origin);
  const canonicalExactInviteUrl = new URL(exactInviteUrl); canonicalExactInviteUrl.protocol = "https:"; canonicalExactInviteUrl.hostname = "share.tinycloud.xyz"; canonicalExactInviteUrl.port = "";
  await agent(["open", exactInviteUrl]); await agent(["wait", "2000"]); await installBrowserTelemetry();
  await agent(["eval", "(function(){window.__recipientCopiedLink=null;var clipboard={writeText:function(value){window.__recipientCopiedLink=value;return Promise.resolve();},readText:function(){return Promise.resolve(window.__recipientCopiedLink||'');}};try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:clipboard});}catch{}})()"]);
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='Copy link');if(!button)throw new Error('recipient Copy link button is missing');button.click();return true;})()"]); await agent(["wait", "text=Link copied."]);
  const recipientCopyEvidence = agentString(await agent(["eval", `JSON.stringify({exact:window.__recipientCopiedLink===${JSON.stringify(canonicalExactInviteUrl.href)},scrubbed:location.hash===''&&location.search==='',dom:!document.documentElement.textContent.includes(${JSON.stringify(canonicalExactInviteUrl.href)}),storage:![localStorage,sessionStorage].some(function(store){return Object.values(store).some(function(value){return String(value).includes(${JSON.stringify(canonicalExactInviteUrl.href)});});}),referrer:!document.referrer.includes(${JSON.stringify(canonicalExactInviteUrl.href)})})`]));
  if (recipientCopyEvidence?.exact !== true || recipientCopyEvidence?.scrubbed !== true || recipientCopyEvidence?.dom !== true || recipientCopyEvidence?.storage !== true || recipientCopyEvidence?.referrer !== true) throw new Error(`recipient copy/privacy boundary failed: ${JSON.stringify({ exact: recipientCopyEvidence?.exact === true, scrubbed: recipientCopyEvidence?.scrubbed === true, dom: recipientCopyEvidence?.dom === true, storage: recipientCopyEvidence?.storage === true, referrer: recipientCopyEvidence?.referrer === true })}`);
  checks.push("Production recipient Copy link copied the byte-exact complete in-memory URL, exposed accessible success feedback, and retained a scrubbed URL/privacy boundary.");
  await agent(["eval", `(function(){var old=window.fetch;window.__tinycloudInvokeReplay=null;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/invoke')&&init&&typeof init.body==='string'){try{var parsed=JSON.parse(init.body);var action=parsed&&parsed.request&&parsed.request.action;if(action==='tinycloud.kv/put'||action==='put'){window.__tinycloudInvokeReplay={url:u,method:init.method||'POST',headers:Object.fromEntries(new Headers(init.headers)),body:init.body};}}catch{}}return old.apply(this,arguments);};})()`]);
  const verifyButton = await agent(["get", "count", "button.viewer-primary-action:not([disabled])"]);
  if (verifyButton !== "0") await agent(["click", "button.viewer-primary-action:not([disabled])"]);
  await agent(["wait", "text=Edit shared text"]); await agent(["fill", "textarea[aria-label='Shared text draft']", "# Exact email\n\nA byte-identical stale draft."]);
  await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  const staleRequestRaw = await agent(["eval", "JSON.stringify(window.__tinycloudInvokeReplay)"]);
  if (staleRequestRaw === "null") throw new Error("edit conflict flow did not capture the conditional put request");
  let staleRequest = agentString(staleRequestRaw);
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof staleRequest === "string") { try { staleRequest = JSON.parse(staleRequest); continue; } catch { break; } }
    if (staleRequest !== null && typeof staleRequest === "object" && staleRequest.data !== undefined) { staleRequest = staleRequest.data; continue; }
    if (staleRequest !== null && typeof staleRequest === "object" && staleRequest.value !== undefined) { staleRequest = staleRequest.value; continue; }
    break;
  }
  if (staleRequest === null || typeof staleRequest !== "object") throw new Error("edit conflict flow captured an invalid conditional put request");
  try {
    const shape = JSON.parse(staleRequest.body);
    checks.push(`Conditional KV-put capture shape ${JSON.stringify({ action: shape.action ?? null, bodyKeys: Object.keys(shape).sort(), headerKeys: Object.keys(staleRequest.headers ?? {}).sort(), bodyLength: staleRequest.body.length, ifMatchLength: typeof shape.ifMatch === "string" ? shape.ifMatch.length : 0, jtiLength: typeof shape.jti === "string" ? shape.jti.length : 0 })}.`);
  } catch { checks.push("Conditional KV-put capture shape was not JSON-decodable."); }
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Exact email\n\nA competing current version."]);
  await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Exact email\n\nA byte-identical stale draft."]);
  let staleReplay = agentString(await agent(["eval", `fetch(${JSON.stringify(staleRequest.url)},{method:${JSON.stringify(staleRequest.method)},headers:${JSON.stringify(staleRequest.headers)},body:${JSON.stringify(staleRequest.body)}}).then(function(r){return r.text().then(function(body){return JSON.stringify({status:r.status,body:body})})})`]));
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof staleReplay === "string") { try { staleReplay = JSON.parse(staleReplay); continue; } catch { break; } }
    if (staleReplay !== null && typeof staleReplay === "object" && staleReplay.data !== undefined) { staleReplay = staleReplay.data; continue; }
    if (staleReplay !== null && typeof staleReplay === "object" && staleReplay.value !== undefined) { staleReplay = staleReplay.value; continue; }
    break;
  }
  checks.push(`Stale replay response shape ${JSON.stringify({ status: staleReplay?.status ?? null, bodyLength: typeof staleReplay?.body === "string" ? staleReplay.body.length : 0, bodyCode: typeof staleReplay?.body === "string" ? staleReplay.body.match(/\"code\"\s*:\s*\"([^\"]+)/)?.[1] ?? null : null })}.`);
  assert.equal(staleReplay.status, 412, `stale If-Match did not return 412 (${staleReplay.status})`);
  const preservedDraft = await agent(["get", "value", "textarea[aria-label='Shared text draft']"]); assert.equal(preservedDraft.includes("byte-identical stale draft"), true);
  await agent(["find", "text", "Reload current version", "click"]); await agent(["wait", "text=Reloaded current version"]);
  gateResults.editConflict = true;
  checks.push("Exact-email Markdown read/edit observed a stale If-Match 412 with a byte-identical draft preserved, then recovered by reloading the current version.");
  gateResults.exactEmail = true; gateResults.notification = true;
  checks.push("Exact-email Markdown link creation, explicit delivery, and byte-identical idempotency replay were observed.");

  const runDomainFlow = async () => {
  await agent(["open", `${origin}/share.html`]); await authenticateBrowserPage(walletOrigin); await installBrowserTelemetry();
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  const domainTrace = await beginFlow("domain");
  // The mounted credential fixture proves the full mailbox identity
  // sam@mailinator.com. Delivery is intentionally the same metadata value,
  // while the signed domain matcher remains the independent authorization.
  const domainDeliveryEmail = "sam@mailinator.com";
  await agent(["click", "input[value=emailDomain]"]); await agent(["fill", "input[name=recipient-value]", "mailinator.com"]);
  await agent(["select", "select[name=content-mode]", "kv"]); await agent(["fill", "input[name=delivery-email]", domainDeliveryEmail]); await agent(["click", "input[name=notify]"]);
  await agent(["eval", `(function(){window.__tinycloudDomainDeliveryObserved=false;window.__tinycloudDomainDeliveryShape=null;var old=window.fetch;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/v1/share-email/invitations')&&init&&typeof init.body==='string'){try{var value=JSON.parse(init.body);var auth=value.authorization&&typeof value.authorization==='object'?value.authorization:value;window.__tinycloudDomainDeliveryShape={topKeys:Object.keys(value).sort(),authKeys:auth&&typeof auth==='object'?Object.keys(auth).sort():[],deliveryType:typeof auth.deliveryEmail,matcherKind:auth.recipientMatcher&&auth.recipientMatcher.kind};window.__tinycloudDomainDeliveryObserved=auth.deliveryEmail===${JSON.stringify(domainDeliveryEmail)}&&auth.recipientMatcher&&auth.recipientMatcher.kind==='emailDomain'&&auth.recipientMatcher.value==='mailinator.com';}catch{}}return old.apply(this,arguments);};})()`]);
  await agent(["wait", "500"]);
  const domainFormState = agentString(await agent(["eval", `JSON.stringify((function(){var option=document.querySelector('select[name=kv-source] option:checked');return {recipient:document.querySelector('input[value=emailDomain]')?.checked===true,domain:document.querySelector('input[name=recipient-value]')?.value==='mailinator.com',delivery:document.querySelector('input[name=delivery-email]')?.value===${JSON.stringify(domainDeliveryEmail)},notify:document.querySelector('input[name=notify]')?.checked===true,matcherKind:option?.dataset.recipientMatcherKind||null,matcherValue:option?.dataset.recipientMatcherValue||null};})())`]));
  if (domainFormState?.recipient !== true || domainFormState?.domain !== true || domainFormState?.delivery !== true || domainFormState?.notify !== true || domainFormState?.matcherKind !== "emailDomain" || domainFormState?.matcherValue !== "mailinator.com") throw new Error(`domain form/capability binding failed: ${JSON.stringify({ recipient: domainFormState?.recipient === true, domain: domainFormState?.domain === true, delivery: domainFormState?.delivery === true, notify: domainFormState?.notify === true, matcherKind: domainFormState?.matcherKind ?? null, matcherValue: domainFormState?.matcherValue ?? null })}`);
  await agent(["fill", "input[name=delivery-email]", "sam@evil.example"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Check the sharing details"]);
  const mismatchedDomainDetail = await agent(["get", "text", ".sender-status-detail"]);
  assert.match(mismatchedDomainDetail, /must belong to the shared domain/i, "mismatched delivery domain was not denied by the shipped composer");
  checks.push("agent-browser denied a mailinator.com policy paired with an evil.example delivery address before link creation, with the user-visible shared-domain validation error.");
  await agent(["fill", "input[name=delivery-email]", domainDeliveryEmail]);
  await agent(["click", "button.create-link-button"]); await agent(["wait", "text=Your private link is ready"]);
  await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Notification queued"]);
  const domainAudit = await auditFlow("domain", domainTrace, { mailOrigin, expectMail: true, expectMailRecipient: domainDeliveryEmail, pii: [domainDeliveryEmail] });
  const domainDeliveryShape = agentString(await agent(["eval", "JSON.stringify(window.__tinycloudDomainDeliveryShape)"]));
  assert.equal(await agent(["eval", "window.__tinycloudDomainDeliveryObserved === true"]), "true", "domain delivery did not carry the generated full email and signed domain matcher at the enforcing delivery boundary");
  assert.equal(domainDeliveryShape?.deliveryType, "string", "domain delivery boundary did not receive a full delivery email");
  assert.equal(domainDeliveryShape?.matcherKind, "emailDomain", "domain delivery boundary did not receive an independent domain matcher");
  checks.push(`Domain delivery request shape sanitized: ${JSON.stringify(domainDeliveryShape)}.`);
  const domainMailPayload = domainAudit.capturedMail?.payload;
  const domainMailStrings = stringsIn(domainMailPayload);
  checks.push(`Domain provider recipient shape sanitized: ${JSON.stringify({ payloadKeys: domainMailPayload && typeof domainMailPayload === "object" ? Object.keys(domainMailPayload).sort() : [], recipientMatches: domainMailStrings.includes(domainDeliveryEmail), recipientStringLengths: domainMailStrings.filter((value) => value.includes("@mailinator.com")).map((value) => value.length).sort() })}.`);
  assert.equal(domainMailStrings.includes(domainDeliveryEmail), true, "domain provider email did not target the generated full delivery email");
  const domainInviteUrl = localShareUrl(mailShareUrl(domainAudit.capturedMail.payload), origin);
  await agent(["open", domainInviteUrl]); await installBrowserTelemetry(); await agent(["wait", "2000"]); await agent(["click", "button.viewer-primary-action"]); await agent(["wait", "2000"]);
  const domainOpenState = agentString(await agent(["eval", "JSON.stringify({contentPresent:(document.querySelector('.viewer-preview-frame')?.srcdoc||'').length>0,isolatedPreview:document.querySelector('.viewer-preview-frame')?.getAttribute('sandbox')==='',status:(document.querySelector('.viewer-policy-status')?.textContent||'').slice(0,240),responses:(window.__tinycloudTelemetry||[]).filter(function(entry){return String(entry.url||'').includes('/share/v1/')||String(entry.url||'').includes('/claims/')}).map(function(entry){return {status:entry.status,errorCode:entry.errorCode||null}})})"]));
  assert.equal(domainOpenState?.contentPresent, true, `full-email domain claim/open did not render authorized content: ${JSON.stringify(domainOpenState)}`);
  assert.equal(domainOpenState?.isolatedPreview, true, `full-email domain content did not use the isolated preview boundary: ${JSON.stringify(domainOpenState)}`);
  gateResults.domain = true;
  checks.push("Full-email domain claim/open rendered authorized content while the signed domain matcher remained independent of delivery email.");
  };

  const runFolderFlow = async () => {
  await agent(["open", `${origin}/share.html`]); await authenticateBrowserPage(walletOrigin); await installBrowserTelemetry();
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  const folderTrace = await beginFlow("folder");
  const folderDeliveryEmail = "sam@mailinator.com";
  await agent(["click", "input[value=emailDomain]"]); await agent(["fill", "input[name=recipient-value]", "mailinator.com"]); await agent(["fill", "input[name=delivery-email]", folderDeliveryEmail]); await agent(["select", "select[name=content-mode]", "kv"]);
  const folderPath = agentString(await agent(["eval", "JSON.stringify((function(){var s=document.querySelector('select[name=kv-source]');var o=[...s.options].find(function(x){return x.dataset.resourceKind==='prefix'&&x.value.endsWith('/')});if(!o)throw new Error('folder capability missing');s.value=o.value;s.dispatchEvent(new Event('change',{bubbles:true}));return o.value})())"]));
  assert.match(folderPath, /documents\/$/); await agent(["check", "input[name=permission][value=list]"]); await agent(["check", "input[name=permission][value=edit]"]); await agent(["check", "input[name=notify]"]);
  await agent(["eval", "(function(){window.__tinycloudFolderDeliveryShape=null;var old=window.fetch;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/v1/share-email/invitations')&&init&&typeof init.body==='string'){try{var value=JSON.parse(init.body);var auth=value.authorization&&typeof value.authorization==='object'?value.authorization:value;window.__tinycloudFolderDeliveryShape={actions:Array.isArray(auth.actions)?auth.actions.slice().sort():[],resource:typeof auth.resource==='string'?auth.resource:null,matcherKind:auth.recipientMatcher&&auth.recipientMatcher.kind};}catch{}}return old.apply(this,arguments);};})()"]);
  await agent(["click", "button.create-link-button"]); await agent(["wait", "text=Your private link is ready"]); await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Notification queued"]);
  const folderAudit = await auditFlow("folder", folderTrace, { mailOrigin, expectMail: true, expectMailRecipient: folderDeliveryEmail, pii: [folderDeliveryEmail] });
  const folderTelemetry = JSON.stringify(folderAudit.capturedMail.payload); const folderDeliveryShape = agentString(await agent(["eval", "JSON.stringify(window.__tinycloudFolderDeliveryShape)"])); checks.push(`Folder delivery action evidence sanitized: ${JSON.stringify(folderDeliveryShape)}.`); assert.equal(folderTelemetry.includes(folderDeliveryEmail), true); assert.equal(folderTelemetry.includes("mailinator.com"), true); assert.deepEqual(folderDeliveryShape?.actions, ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"]); assert.equal(folderDeliveryShape?.resource, "documents"); assert.equal(folderDeliveryShape?.matcherKind, "emailDomain");
  const folderInviteUrl = localShareUrl(mailShareUrl(folderAudit.capturedMail.payload), origin);
  await agent(["open", folderInviteUrl]); await agent(["wait", "2000"]); await installBrowserTelemetry(); await agent(["set", "headers", JSON.stringify({ Origin: canonical.share })]); await agent(["eval", "(function(){var previous=window.fetch;window.__folderPutCapture=null;window.__policyTrace=[];window.__claimTrace=[];window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');var result=previous.apply(this,arguments);if(u.includes('/policy/challenges')||u.includes('/policy/session')||u.includes('/v1/share-email/claims/')){result.then(function(response){response.clone().text().then(function(body){var parsed=null;try{parsed=JSON.parse(body);}catch{}var path=(new URL(u,location.href)).pathname;var target=path.includes('/claims/')?window.__claimTrace:window.__policyTrace;target.push({path:path,status:response.status,code:parsed&&parsed.error&&parsed.error.code||null,keys:parsed&&typeof parsed==='object'?Object.keys(parsed).sort():[],body:body.slice(0,400)});});});}if(u.includes('/invoke')&&init&&typeof init.body==='string'){try{var parsed=JSON.parse(init.body);var request=parsed&&parsed.request||{};var action=request.action||request.invocation&&request.invocation.action;if(action==='tinycloud.kv/put'||action==='put'){window.__folderPutCapture={url:u,method:init.method||'POST',headers:Object.fromEntries(new Headers(init.headers)),body:init.body};}}catch{}}return result;};})()"]); await agent(["click", "button.viewer-primary-action"]); await agent(["wait", "3000"]);
  const folderOpenState = agentString(await agent(["eval", "JSON.stringify({title:document.title,policy:(document.querySelector('.viewer-policy-status')?.textContent||'').slice(0,240),claim:(document.querySelector('.viewer-status')?.textContent||'').slice(0,240),trace:window.__policyTrace||[],claimTrace:window.__claimTrace||[],body:(document.body?.innerText||'').replace(/https?:\\/\\/[^\\s]+/g,'[URL]').slice(0,600)})"]));
  if (!String(folderOpenState?.body ?? "").includes("Shared folder")) throw new Error("folder authorization did not complete: " + JSON.stringify(folderOpenState));
  assert.notEqual(await agent(["get", "count", "button.viewer-folder-entry"]), "0", "folder child listing was not observed");
  const folderEntries = agentString(await agent(["eval", "JSON.stringify([...document.querySelectorAll('button.viewer-folder-entry')].map(function(button){return {path:button.dataset.path||'',label:button.textContent||''}}))"]));
  assert.equal(Array.isArray(folderEntries) && folderEntries.length > 0 && folderEntries.every((entry) => entry.path.startsWith("documents/") && entry.path.slice("documents/".length).includes("/") === false), true, "folder list escaped direct-child scope");
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button.viewer-folder-entry')].find((candidate)=>candidate.dataset.path?.endsWith('.md'));if(!button)throw new Error('direct child file missing');button.click();return true;})()"]); await agent(["wait", "2000"]);
  assert.equal(await agent(["get", "count", ".viewer-editor-panel"]), "1", "direct child get did not expose the authorized editor");
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Folder draft\n\nA byte-identical stale folder draft."]); await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  const folderStaleRequest = agentString(await agent(["eval", "JSON.stringify(window.__folderPutCapture)"])); assert.equal(folderStaleRequest !== null && typeof folderStaleRequest === "object", true, "folder put request was not captured");
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Folder draft\n\nA competing current folder version."]); await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Folder draft\n\nA byte-identical stale folder draft."]);
  const folderStaleReplay = agentString(await agent(["eval", `fetch(${JSON.stringify(folderStaleRequest.url)},{method:${JSON.stringify(folderStaleRequest.method)},headers:${JSON.stringify(folderStaleRequest.headers)},body:${JSON.stringify(folderStaleRequest.body)}}).then(function(r){return r.text().then(function(body){return JSON.stringify({status:r.status,body:body})})})`]));
  assert.equal(folderStaleReplay?.status, 412, "folder stale If-Match did not return 412"); assert.equal((await agent(["get", "value", "textarea[aria-label='Shared text draft']"])).includes("byte-identical stale folder draft"), true, "folder stale draft was not preserved"); await agent(["find", "text", "Reload current version", "click"]); await agent(["wait", "text=Reloaded current version"]);
  gateResults.folder = true;
  checks.push("Reusable mailinator.com folder flow observed direct-child list/get/put, rejected out-of-scope paths, and preserved a stale If-Match draft through 412 recovery.");
  };

  await runFolderFlow();
  await runDomainFlow();

  const denialTrace = await beginFlow("denial-matrix");
  const denialCases = [
    ["signed-out-capabilities", `${origin}/api/share/capabilities`, { method: "GET" }, 401],
    ["signed-out-capability", `${origin}/api/share/capability`, { method: "GET" }, 401],
    ["signed-out-bindings", `${origin}/api/share/bindings`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, 401],
    ["signed-out-registry-upload", `${origin}/api/share/link-only/registry/blobs`, { method: "POST", headers: { "content-type": "application/vnd.ipld.raw" }, body: "x" }, 401],
    ["malformed-cid", `${origin}/s/not-a-cid/raw`, { method: "GET" }, 404],
    ["removed-consume", `${origin}/share/v1/invitations/consume`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, 404],
    ["traversal-sibling", `${origin}/share/v1/read/../sibling`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, undefined],
    ["traversal-nested", `${origin}/share/v1/read/%2e%2e/nested`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, undefined],
    ["forged-cursor", `${origin}/api/share/capabilities?cursor=forged-cursor`, { method: "GET" }, 401],
    ["forged-invoke-query", `${origin}/invoke?cursor=forged-cursor`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, undefined],
    ["unauthorized-get", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/get", resource: { kind: "exact", path: "documents/policy-payload.md" } } }) }, undefined],
    ["sibling-escape", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/get", resource: { kind: "exact", path: "documents-archive/secret.md" } } }) }, undefined],
    ["nested-escape", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/get", resource: { kind: "exact", path: "documents/archive/secret.md" } } }) }, undefined],
    ["unauthorized-list", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/list", resource: { kind: "prefix", path: "documents/" } } }) }, undefined],
    ["unauthorized-put", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/put", resource: { kind: "exact", path: "documents/policy-payload.md" }, body: [1], ifMatch: null } }) }, undefined],
  ];
  for (const [label, url, init, expected] of denialCases) {
    const response = await fetch(url, init);
    if (expected === undefined) assert.equal(response.status >= 400, true, `${label} did not fail closed`); else assert.equal(response.status, expected, `${label} denial status`);
  }
  const evilOriginResponse = await fetch(`${origin}/api/share/capabilities`, { headers: { origin: "https://evil.example" } }); assert.equal(evilOriginResponse.status, 401, "wrong-origin capability access was accepted");
  await agent(["eval", "fetch('/api/share/auth/logout',{method:'POST',credentials:'include'}).then(function(r){return r.status})"]);
  assert.equal(await agent(["eval", "fetch('/api/share/capabilities',{credentials:'include'}).then(function(r){return r.status})"]), "401", "signed-out sender history boundary was not enforced");
  gateResults.denialMatrix = true; await auditFlow("denial-matrix", denialTrace, { mailOrigin }); checks.push("Enforcing boundary denial matrix observed signed-out history, wrong origin, malformed and traversal paths, forged cursor/query, removed routes, missing proof, and unauthorized get/list/put fail-closed responses.");

  const trackedRequests = networkEntries(await agent(["network", "requests", "--json"]));
  const allRequests = trackedRequests.length > 0 ? trackedRequests : await browserTelemetryEntries();
  externalRequests = allRequests.filter((entry) => { try { const url = new URL(entry.url); return url.protocol !== "http:" || (url.hostname !== "127.0.0.1" && url.hostname !== "localhost"); } catch { return true; } });
  if (externalRequests.length !== 0) blockers.push(`Browser attempted non-loopback destinations: ${JSON.stringify(externalRequests.map((entry) => entry.url).slice(0, 20))}`); else gateResults.browser = true;
}

async function writeArtifact(status, summary, extraBlockers = []) {
  const scopedRepositories = {
    share: shareRoot,
    node: nodeRoot,
    jsSdk: process.env.TINYCLOUD_JS_SDK_WORKTREE ?? join(workspaceRoot, "worktrees/js-sdk/feat/sharing-production-live"),
    openCredentials: credentialsRoot,
  };
  const repositoryDigests = {};
  for (const [name, repository] of Object.entries(scopedRepositories)) {
    const commit = execFileSync("git", ["-C", repository, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const diff = execFileSync("git", ["-C", repository, "diff", "--binary", "--no-ext-diff"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    const untracked = execFileSync("git", ["-C", repository, "ls-files", "--others", "--exclude-standard", "-z"], { encoding: "utf8" });
    const files = untracked.split("\0").filter(Boolean);
    const untrackedBytes = [];
    for (const file of files) untrackedBytes.push(`${file}\0`, await readFile(join(repository, file)));
    const digestInput = Buffer.concat([Buffer.from(commit), Buffer.from("\0"), Buffer.from(diff), Buffer.from("\0"), ...untrackedBytes.map((value) => typeof value === "string" ? Buffer.from(value) : value)]);
    repositoryDigests[name] = { commit, digest: createHash("sha256").update(digestInput).digest("hex"), untracked: files };
  }
  const result = { status, summary, browserE2ePassed: gateResults.browser && gateResults.bearer && gateResults.exactEmail && gateResults.domain && gateResults.editConflict && gateResults.folder && gateResults.notification && gateResults.denialMatrix, senderLibraryPassed: gateResults.senderLibrary, exactEmailPassed: gateResults.exactEmail, domainPassed: gateResults.domain, bearerPassed: gateResults.bearer, editConflictPassed: gateResults.editConflict, folderPassed: gateResults.folder, notificationPassed: gateResults.notification, denialMatrixPassed: gateResults.denialMatrix, zeroExternalDestinations: gateResults.browser && externalRequests.length === 0, launchInputDigests, repositoryDigests, flowAudits, checks: [...new Set(checks)], blockers: [...new Set([...blockers, ...extraBlockers])] };
  await writeFile(artifactPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
}

let tempRoot;
let share;
async function browserSmokeLoop(origin, walletOrigin) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await agent(["open", `${origin}/share.html`]);
    await authenticateBrowserPage(walletOrigin);
    assert.equal(await agent(["get", "count", "main.composer-shell"]), "1", `sequential browser smoke ${attempt} did not reach the production composer`);
  }
  checks.push("Clean sequential agent-browser smoke loop completed three serialized sessions without retry-as-success semantics.");
}

async function authenticateBrowserPage(walletOrigin, openComposer = true) {
  await agent(["eval", walletBootstrapScript(walletOrigin)]);
  await agent(["eval", "(function(){var original=Element.prototype.attachShadow;Element.prototype.attachShadow=function(init){var options=init||{};options.mode='open';return original.call(this,options);};})()"]).catch(() => undefined);
  await agent(["click", "button.auth-button"]);
  await agent(["wait", "1000"]);
  await agent(["find", "text", "TinyCloud E2E Wallet", "click"]);
  await agent(["wait", "text=Shared by me."]);
  if (openComposer) {
    await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='New share');if(!button)throw new Error('New share action is not present');button.click();return true;})()"]);
    await agent(["wait", "text=Share with intent."]);
  }
  await agent(["eval", "(function(){window.__senderCopiedLink=null;var clipboard={writeText:function(value){window.__senderCopiedLink=value;return Promise.resolve();},readText:function(){return Promise.resolve(window.__senderCopiedLink||'');}};try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:clipboard});}catch{}})()"]).catch(() => undefined);
}

async function cleanup() {
  if (cleanupStarted) return;
  cleanupStarted = true;
  try { await agent(["close"]); } catch (error) { blockers.push(`agent-browser cleanup failed: ${error instanceof Error ? error.message : String(error)}`); }
  await stopAll();
  await closeAll();
  if (tempRoot !== undefined) await rm(tempRoot, { recursive: true, force: true });
  await releaseLock();
  const remaining = execFileSync("ps", ["-axo", "pid=,command="], { encoding: "utf8" }).split("\n").filter((line) => /sharing-e2e-|e2e-sharing|tinycloud-sharing-e2e-/.test(line) && !line.includes("ps -axo") && !line.trimStart().startsWith(`${process.pid} `));
  if (remaining.length > 0) blockers.push(`harness-owned processes remained after cleanup: ${remaining.map((line) => line.trim().split(/\s+/, 1)[0]).filter(Boolean).join(",")}`);
  try {
    const sessions = execFileSync(agentBrowser, ["session", "list"], { cwd: shareRoot, encoding: "utf8", timeout: AGENT_TIMEOUT_MS });
    if (sessions.split("\n").some((line) => line.includes(sessionName))) blockers.push(`harness-owned agent-browser session remained after cleanup: ${sessionName}`);
  } catch (error) { blockers.push(`agent-browser session cleanup audit failed: ${error instanceof Error ? error.message : String(error)}`); }
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.once(signal, () => { void cleanup().finally(() => { process.exitCode = 1; }); });

try {
  await assertReleaseInputs();
  await acquireLock();
  tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-sharing-e2e-"));
  const fixtures = await startFixtures(tempRoot);
  share = await startShare(tempRoot, fixtures);
  await browserGate(share.origin, fixtures.walletOrigin, fixtures.mailOrigin);
  await browserSmokeLoop(share.origin, fixtures.walletOrigin);
} catch (error) {
  blockers.push(error instanceof Error ? error.message : String(error));
  try {
    checks.push("Failure diagnostic browser telemetry captured; raw telemetry omitted after privacy audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic browser telemetry unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const snapshot = await agent(["snapshot"]);
    checks.push("Failure diagnostic browser snapshot captured; raw DOM omitted after privacy audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic browser snapshot unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const browserNetwork = networkEntries(await agent(["network", "requests", "--json"]));
    const telemetry = await browserTelemetryEntries();
    const sanitizedNetwork = scrubNetwork(browserNetwork);
    checks.push(`Failure diagnostic browser network ${JSON.stringify(sanitizedNetwork.map((entry) => ({ path: entry.path, method: entry.method, status: entry.status })))}.`);
    const policyResult = sanitizedNetwork.find((entry) => entry.path === "/share/v2/policies");
    if (policyResult !== undefined) checks.push(`Failure diagnostic policy registration HTTP result ${JSON.stringify({ status: policyResult.status ?? null, method: policyResult.method ?? null })}.`);
    checks.push(`Failure diagnostic browser telemetry ${JSON.stringify(telemetry.map((entry) => ({ path: (() => { try { return new URL(entry.url).pathname; } catch { return null; } })(), method: entry.method ?? null, status: entry.status ?? null, errorCode: entry.errorCode ?? null })))}.`);
    checks.push("Failure diagnostic admission network captured; raw network omitted after privacy audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic admission network unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const authDiagnostics = await agent(["eval", "JSON.stringify(window.__tinycloudAuthDiagnostics||null)"]);
    checks.push("Failure diagnostic auth responses captured; raw response bodies omitted after secret audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic auth responses unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const uiDiagnostics = agentString(await agent(["eval", "JSON.stringify([...document.querySelectorAll('[role=status],[role=alert],.composer-live,.composer-status,.notification-status')].map(function(node){var text=node.textContent||'';var match=text.match(/(?:failed: )([0-9]{3})(?: ([A-Za-z0-9_]+))?/);return {className:node.className||null,state:node.dataset.state||null,errorCode:match?match[1]+' '+(match[2]||''):null,text:text,children:[...node.children].map(function(child){return child.textContent||''})}}))"]));
    checks.push(`Failure diagnostic UI state ${JSON.stringify(Array.isArray(uiDiagnostics) ? uiDiagnostics.map((entry) => ({ className: entry?.className ?? null, state: entry?.state ?? null, errorCode: entry?.errorCode ?? null, text: safeBrowserDiagnostic(entry?.text), children: Array.isArray(entry?.children) ? entry.children.map((child) => safeBrowserDiagnostic(child)) : [] })) : [])}.`);
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic UI state unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const openKeyDiagnostics = await agent(["eval", "JSON.stringify({status:document.querySelector('.auth-status')?.textContent||null,error:window.__tinycloudAuthError?.message||window.__tinycloudAuthError||null,senderHistoryError:window.__tinycloudSenderHistoryError||null,authResponses:window.__tinycloudAuthDiagnostics||null,messages:window.__tinycloudOpenKeyDiagnostics||null,telemetry:(window.__tinycloudTelemetry||[]).filter(function(entry){return String(entry.url||'').endsWith('/invoke')||String(entry.url||'').endsWith('/delegate')})})"]);
    const parsedDiagnostics = agentString(openKeyDiagnostics);
    checks.push(`Failure diagnostic browser state ${JSON.stringify({ status: safeBrowserDiagnostic(parsedDiagnostics?.status), authError: safeBrowserDiagnostic(parsedDiagnostics?.error), historyError: safeBrowserDiagnostic(parsedDiagnostics?.senderHistoryError), authResponseStatuses: Array.isArray(parsedDiagnostics?.authResponses) ? parsedDiagnostics.authResponses.map((entry) => ({ status: entry?.status ?? null, bodyLength: typeof entry?.body === "string" ? entry.body.length : 0, bodyKeys: (() => { try { const body = JSON.parse(entry.body); return body && typeof body === "object" ? Object.keys(body).sort() : []; } catch { return []; } })() })) : [], messageTypes: Array.isArray(parsedDiagnostics?.messages) ? parsedDiagnostics.messages.map((entry) => entry?.type ?? null).filter(Boolean) : [], telemetry: Array.isArray(parsedDiagnostics?.telemetry) ? parsedDiagnostics.telemetry.map((entry) => ({ path: (() => { try { return new URL(entry.url).pathname; } catch { return null; } })(), status: entry?.status ?? null, errorCode: entry?.errorCode ?? null, responseErrorCode: entry?.responseErrorCode ?? null, responseKeys: Array.isArray(entry?.responseKeys) ? entry.responseKeys : [] })) : [], telemetryCount: Array.isArray(parsedDiagnostics?.telemetry) ? parsedDiagnostics.telemetry.length : 0 })}.`);
    checks.push("Failure diagnostic OpenKey/browser auth captured; raw diagnostics omitted after secret audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic OpenKey/browser auth unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  for (const entry of children) {
    const output = entry.output();
    if (output.length > 0) {
      const outputLines = output.split("\n");
      const policyStages = outputLines.filter((line) => line.includes("policy session bridge rejected") || line.includes("policy session rejected"));
      if (policyStages.length > 0) checks.push(`Failure diagnostic policy stage observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const persistenceFailures = outputLines.filter((line) => line.includes("native share KV put failed"));
      if (persistenceFailures.length > 0) checks.push(`Failure diagnostic native persistence failure observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const delegationFailures = outputLines.filter((line) => line.includes("addressed delegation authorization failed"));
      if (delegationFailures.length > 0) checks.push(`Failure diagnostic addressed delegation failure observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const scopeFailures = outputLines.filter((line) => line.includes("share scope validation failed"));
      if (scopeFailures.length > 0) checks.push(`Failure diagnostic share scope failure observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const registrationFailures = outputLines.filter((line) => line.includes("Owner share policy registration failed:"));
      if (registrationFailures.length > 0) {
        const normalized = registrationFailures.map((line) => line.replace(/.*Owner share policy registration failed:\s*/, "").replace(/[^A-Za-z0-9_ :.-]/g, "").slice(0, 120));
        checks.push(`Failure diagnostic owner policy registration result ${JSON.stringify(normalized)}.`);
      }
      checks.push(`Failure diagnostic child ${entry.child.pid}: output omitted after secret audit; ${output.length} bytes were captured.`);
    }
  }
} finally {
  await cleanup();
}

const missingFlows = Object.entries({ exactEmail: gateResults.exactEmail, domain: gateResults.domain, bearer: gateResults.bearer, editConflict: gateResults.editConflict, folder: gateResults.folder, notification: gateResults.notification, denialMatrix: gateResults.denialMatrix }).filter(([, passed]) => !passed).map(([name]) => name);
if (missingFlows.length > 0) blockers.push(`Browser gate did not pass required flow(s): ${missingFlows.join(", ")}.`);
const complete = blockers.length === 0 && gateResults.browser && gateResults.senderLibrary && gateResults.bearer && gateResults.exactEmail && gateResults.domain && gateResults.editConflict && gateResults.folder && gateResults.notification && gateResults.denialMatrix && externalRequests.length === 0;
await writeArtifact(complete ? "complete" : "blocked", complete ? "Hermetic production-shaped sharing browser gate passed." : "Hermetic gate executed the real local composition and recorded the release blockers without inferring success.");
process.exitCode = complete ? 0 : 1;
