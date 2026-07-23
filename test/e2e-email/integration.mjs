#!/usr/bin/env node

/*
 * Continuous email-claim gate.
 *
 * The browser runs at the production Share origin and all production endpoint
 * URLs remain unchanged.  Local transport is hermetic test infrastructure;
 * application processes are the default-feature Node app and the dstack-
 * enabled OpenCredentials witness production binary.
 */

import { createRequire } from "node:module";
import { createHash, randomBytes, scryptSync } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import { createConnection, createServer } from "node:net";
import { existsSync } from "node:fs";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const shareRoot = resolve(import.meta.dirname, "../..");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(shareRoot, "../../../tinycloud-node/feat/email-claim-n4-integration");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? resolve(shareRoot, "../../../opencredentials/feat/email-claim-o4-integration");
const credentialsRustRoot = resolve(credentialsRoot, "rust/opencredentials_witness");
const vectorRoot = resolve(shareRoot, "test/vectors/email-claim-v1");
const expectedContractCommit = "36f6c4303eca3bee917692c77237c264b4dfa342";
const expectedManifestDigest = "pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs";

const canonical = Object.freeze({
  share: "https://share.tinycloud.xyz",
  node: "https://node.tinycloud.xyz",
  credentials: "https://witness.credentials.org",
  registry: "https://registry.tinycloud.xyz",
});

let activeCleanup;
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => {
    if (activeCleanup === undefined) process.exit(128);
    void activeCleanup().finally(() => process.exit(128));
  });
}

function arg(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

function required(value, name) {
  if (value === undefined || value.length === 0) throw new Error(`E2E prerequisite missing: ${name}`);
  return value;
}

function scryptPassword(password) {
  const salt = randomBytes(16);
  const digest = scryptSync(password, salt, 32, { N: 16_384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$16384$8$1$${salt.toString("base64url")}$${digest.toString("base64url")}`;
}

const runStartedAt = new Date();
const runId = process.env.SHARE_EMAIL_RUN_ID ?? `email-claim-${runStartedAt.toISOString().replace(/[-:.TZ]/g, "")}-${process.pid}`;
const runRecordPath = resolve(shareRoot, process.env.SHARE_EMAIL_RUN_RECORD ?? `.release-evidence/runs/${runId}.json`);
const runLogPath = `${runRecordPath}.log`;
const runEvents = [];
let runCoverage = { fixtures: 0, sources: [], browser: [], negativeBoundaryCases: [], binding: "independent-provisioned" };
let ownedProcessCleanup = { stopped: 0, remaining: [], complete: false };

function digestBytes(value) { return createHash("sha256").update(value).digest("hex"); }
function digestBase64Url(value) { return createHash("sha256").update(value).digest("base64url"); }
function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}
function recordRunEvent(event) { runEvents.push({ at: new Date().toISOString(), ...event }); }
function commandLabel(command, args) { return [command, ...args].join(" "); }

function diagnosticOutput(value = "") {
  const stages = value.split("\n").filter((line) => line.includes("stage=") || line.includes("stage\"")).slice(-32);
  return stages.length === 0 ? "no bounded stage events" : stages.join("\n").slice(-8_000);
}

function run(command, args, cwd, extraEnv = {}) {
  console.error(`$ ${command} ${args.join(" ")}`);
  const label = commandLabel(command, args);
  const started = Date.now();
  recordRunEvent({ type: "command-start", command: label });
  const result = spawn(command, args, { cwd, stdio: "inherit", env: { ...process.env, ...extraEnv } });
  return new Promise((resolveResult, reject) => {
    result.once("error", (error) => { recordRunEvent({ type: "command-end", command: label, status: "spawn-error", durationMs: Date.now() - started }); reject(error); });
    result.once("exit", (code, signal) => {
      const status = code === 0 ? "passed" : "failed";
      recordRunEvent({ type: "command-end", command: label, status, exitStatus: code ?? 128, signal: signal ?? null, durationMs: Date.now() - started });
      resolveResult(code === 0 ? undefined : new Error(`${command} exited ${code ?? signal}`));
    });
  }).then((error) => { if (error !== undefined) throw error; });
}

async function cleanAndExact(repo, expected, label) {
  const status = await runCapture("git", ["status", "--porcelain=v1"], repo);
  if (status.trim() !== "") throw new Error(`${label} worktree is dirty`);
  const head = (await runCapture("git", ["rev-parse", "HEAD"], repo)).trim();
  if (typeof expected !== "string" || !/^[0-9a-f]{40}$/.test(expected)) throw new Error(`${label} exact release head is required (set the convergence-time release head)`);
  if (head !== expected) throw new Error(`${label} exact release head mismatch: expected ${expected}, found ${head}`);
}

async function assertContractCommit(repo) {
  const contract = (await runCapture("git", ["rev-parse", expectedContractCommit], repo)).trim();
  if (contract !== expectedContractCommit) throw new Error(`Share contract commit is unavailable: ${expectedContractCommit}`);
}

function runCapture(command, args, cwd, extraEnv = {}) {
  const label = commandLabel(command, args);
  const started = Date.now();
  recordRunEvent({ type: "capture-start", command: label });
  const child = spawn(command, args, { cwd, env: { ...process.env, ...extraEnv } });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolveResult, reject) => {
    child.once("error", (error) => { recordRunEvent({ type: "capture-end", command: label, status: "spawn-error", durationMs: Date.now() - started }); reject(error); });
    child.once("exit", (code) => {
      recordRunEvent({ type: "capture-end", command: label, status: code === 0 ? "passed" : "failed", exitStatus: code, durationMs: Date.now() - started });
      code === 0 ? resolveResult(stdout) : reject(new Error(`${command} failed (${code}): ${stderr.slice(0, 800)}`));
    });
  });
}

async function nativeGate() {
  await cleanAndExact(shareRoot, process.env.SHARE_RELEASE_HEAD, "Share");
  await cleanAndExact(nodeRoot, process.env.TINYCLOUD_NODE_RELEASE_HEAD, "tinycloud-node");
  await cleanAndExact(credentialsRoot, process.env.OPEN_CREDENTIALS_RELEASE_HEAD, "OpenCredentials");
  await assertContractCommit(shareRoot);
  await run("node", ["test/e2e-email/release-positive-composition.mjs"], shareRoot);
  const manifest = JSON.parse(await readFile(resolve(vectorRoot, "manifest.json"), "utf8"));
  if (manifest.manifestDigest !== expectedManifestDigest) throw new Error(`Share manifest mismatch: ${manifest.manifestDigest}`);
  await run("node", ["test/vectors/email-claim-v1/validate.mjs"], shareRoot);
  await run("node", ["test/vectors/email-claim-v1/build.mjs"], shareRoot);
  await run("npm", ["ci", "--ignore-scripts"], shareRoot);
  await run("npm", ["test"], shareRoot);
  await run("npm", ["run", "typecheck"], shareRoot);
  await run("npm", ["run", "build"], shareRoot, { VITE_SHARE_REGISTRY_URL: `${canonical.share}/registry` });
  await run("cargo", ["fmt", "--all", "--", "--check"], nodeRoot);
  await run("cargo", ["clippy", "-p", "tinycloud-core", "-p", "tinycloud-node", "--all-targets", "--", "-D", "warnings"], nodeRoot);
  await run("cargo", ["test", "--test", "email_claim_frozen_manifest"], nodeRoot);
  await run("cargo", ["test", "-p", "tinycloud-node", "--lib", "share_email"], nodeRoot);
  await run("cargo", ["test", "--test", "email_claim_route_parity"], nodeRoot);
  await run("cargo", ["test", "--workspace", "--exclude", "tinycloud-sdk-wasm", "--exclude", "siwe"], nodeRoot);
  await run("cargo", ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"], nodeRoot);
  await run("cargo", ["fmt", "--check"], credentialsRustRoot);
  await run("cargo", ["test", "--bin", "opencredentials-witness"], credentialsRustRoot);
  await run("cargo", ["test", "--bin", "opencredentials-witness", "share_email::trust"], credentialsRustRoot);
  await run("cargo", ["test", "--test", "share_email_postgres"], credentialsRustRoot);
  await run("cargo", ["test", "--features", "dstack"], credentialsRustRoot);
  await run("cargo", ["test", "--features", "dstack", "--test", "share_email_postgres"], credentialsRustRoot);
  await run("cargo", ["clippy", "--features", "dstack", "--all-targets", "--", "-D", "warnings"], credentialsRustRoot);
  const sdJwtRoot = resolve(credentialsRoot, "rust/opencredentials_sd_jwt");
  await run("cargo", ["fmt", "--check"], sdJwtRoot);
  await run("cargo", ["test"], sdJwtRoot);
  await run("cargo", ["clippy", "--", "-D", "warnings"], sdJwtRoot);
  await run("node", ["scripts/oi-share-email/verify-readiness-contract.mjs"], credentialsRoot);
  await run("node", ["scripts/oi-share-email/verify-key-separation.mjs"], credentialsRoot);
  await run("node", ["scripts/oi-share-email/verify-production-compose.mjs"], credentialsRoot);
}

function spawnOwned(command, cwd, extraEnv = {}) {
  const child = spawn(command, { cwd, shell: true, detached: true, env: { ...process.env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  const collect = (chunk) => { output += String(chunk); if (output.length > 128_000) output = output.slice(-128_000); };
  child.stdout.on("data", collect);
    child.stderr.on("data", collect);
  return { child, output: () => output, done: new Promise((resolveDone) => child.once("exit", resolveDone)) };
}

function spawnOwnedArgs(command, args, cwd, extraEnv = {}) {
  const child = spawn(command, args, { cwd, detached: true, env: { ...process.env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  const collect = (chunk) => {
    const text = String(chunk);
    output += text;
    if (text.includes("mounted session:") || text.includes("mounted policy session:")) runEvents.push({ at: new Date().toISOString(), type: "fixture-output", text: text.trim().slice(0, 400) });
    if (output.length > 128_000) output = output.slice(-128_000);
  };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  return { child, output: () => output, done: new Promise((resolveDone) => child.once("exit", resolveDone)) };
}

async function commandAvailable(command) {
  try { await runCapture("sh", ["-c", `command -v ${command}`], shareRoot); return true; }
  catch { return false; }
}

async function freePort() {
  const server = createServer();
  await new Promise((resolvePort, rejectPort) => { server.once("error", rejectPort); server.listen(0, "127.0.0.1", resolvePort); });
  const port = server.address().port;
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
  return port;
}

async function waitForFileJson(path, label, process) {
  const deadline = Date.now() + 300_000;
  let lastError = "file not written";
  while (Date.now() < deadline) {
    try { return JSON.parse(await readFile(path, "utf8")); }
    catch (error) { lastError = error instanceof Error ? error.message : String(error); }
    if (process?.child.exitCode !== null) throw new Error(`${label} exited before publishing a descriptor:\n${process.output().slice(-8_000)}`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`${label} descriptor was not published: ${lastError}`);
}

async function waitForDescriptor(process, label) {
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    for (const line of process.output().split("\n").reverse()) {
      try { const value = JSON.parse(line); if (value?.production === true) return value; }
      catch { /* cargo diagnostics and tracing share the captured stream */ }
    }
    if (process.child.exitCode !== null) throw new Error(`${label} exited before publishing a descriptor`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`${label} descriptor was not published`);
}

function ed25519PublicKey(seed) {
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = require("node:crypto").createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return require("node:crypto").createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
}

async function startDstackSimulator(owned, tempRoot, issuerSeed) {
  const socketPath = join(tempRoot, "dstack.sock");
  const server = createServer((socket) => {
    let request = "";
    socket.on("data", (chunk) => {
      request += String(chunk);
      if (!request.includes("\r\n\r\n")) return;
      const [header, body = ""] = request.split("\r\n\r\n", 2);
      const contentLength = Number(header.match(/\r?\ncontent-length:\s*(\d+)/i)?.[1] ?? 0);
      if (Buffer.byteLength(body) < contentLength) return;
      const path = header.split("\n", 1)[0]?.split(" ")[1];
      recordRunEvent({ type: "dstack-request", path, bytes: Buffer.byteLength(body) });
      let payload;
      if (path === "/Info") {
        payload = { app_id: "hermetic-dstack-app", compose_hash: "hermetic-compose-hash", instance_id: "hermetic-instance" };
      } else {
        let requestedPath = "";
        try { requestedPath = JSON.parse(body).path ?? ""; } catch {}
        const key = requestedPath === "opencredentials/witness/signing-key"
          ? issuerSeed
          : createHash("sha256").update(requestedPath).digest();
        payload = { key: key.toString("hex") };
      }
      const bytes = Buffer.from(JSON.stringify(payload));
      recordRunEvent({ type: "dstack-response", path, status: 200 });
      socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${bytes.length}\r\nConnection: close\r\n\r\n${bytes}`);
    });
  });
  await new Promise((resolveServer, rejectServer) => {
    server.once("error", rejectServer);
    server.listen(socketPath, resolveServer);
  });
  owned.push({ child: { pid: undefined, kill: () => server.close() }, done: new Promise((resolveDone) => server.once("close", resolveDone)) });
  return socketPath;
}

async function waitForPort(port, label) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolvePort, rejectPort) => {
        const socket = createConnection({ host: "127.0.0.1", port });
        socket.once("connect", () => socket.end(resolvePort));
        socket.once("error", rejectPort);
      });
      return;
    } catch { await new Promise((resolveWait) => setTimeout(resolveWait, 250)); }
  }
  throw new Error(`${label} did not bind 127.0.0.1:${port}`);
}

async function startPostgres(owned, tempRoot) {
  if (!(await commandAvailable("initdb")) || !(await commandAvailable("postgres"))) {
    throw new Error("E2E prerequisite missing: local PostgreSQL (initdb and postgres) is required for the default gate");
  }
  const dataDir = join(tempRoot, "postgres");
  await run("initdb", ["--no-locale", "-A", "trust", "-U", "email_claim", "-D", dataDir], shareRoot);
  const caKey = join(tempRoot, "pg-ca.key");
  const caCert = join(tempRoot, "pg-ca.pem");
  const serverKey = join(tempRoot, "pg-server.key");
  const serverCsr = join(tempRoot, "pg-server.csr");
  const serverCert = join(tempRoot, "pg-server.pem");
  const serverExt = join(tempRoot, "pg-server.ext");
  await writeFile(serverExt, "subjectAltName=DNS:db.localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n", "utf8");
  await run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCert, "-subj", "/CN=TinyCloud hermetic PostgreSQL CA", "-days", "2"], shareRoot);
  await run("openssl", ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", serverKey, "-out", serverCsr, "-subj", "/CN=db.localhost"], shareRoot);
  await run("openssl", ["x509", "-req", "-in", serverCsr, "-CA", caCert, "-CAkey", caKey, "-CAcreateserial", "-out", serverCert, "-days", "2", "-extfile", serverExt], shareRoot);
  await run("chmod", ["600", serverKey], shareRoot);
  const port = await freePort();
  const server = spawnOwnedArgs("postgres", ["-D", dataDir, "-h", "127.0.0.1,::1", "-p", String(port), "-c", "ssl=on", "-c", `ssl_cert_file=${serverCert}`, "-c", `ssl_key_file=${serverKey}`, "-c", `ssl_ca_file=${caCert}`], shareRoot);
  owned.push(server);
  await waitForPort(port, "PostgreSQL");
  return { url: `postgres://email_claim@db.localhost:${port}/postgres?sslmode=verify-full`, dataDir, caCert };
}

async function assertFocusedOutbox(postgres) {
  if (!(await commandAvailable("psql"))) throw new Error("focused KV loop requires local PostgreSQL psql");
  const database = new URL(postgres.url);
  const result = await runCapture("psql", ["--no-psqlrc", "--tuples-only", "--no-align", "--command", "SELECT (SELECT count(*) FROM email_claim_delivery_outbox) || '|' || (SELECT count(*) FROM email_claim_delivery_outbox WHERE state = 'PROVIDER_ACCEPTED') || '|' || (SELECT count(*) FROM email_claim_provider_events);"], shareRoot, {
    PGHOST: "127.0.0.1", PGPORT: database.port, PGUSER: "email_claim", PGDATABASE: "postgres", PGSSLMODE: "disable",
  });
  if (result.trim() !== "1|1|1") throw new Error("focused KV loop did not leave one committed provider-accepted outbox row and one provider event");
}

async function startLocalResendProvider(mailArtifact) {
  const messages = [];
  const server = createHttpServer((request, response) => {
    if (request.method !== "POST" || request.url !== "/emails") {
      response.writeHead(404).end();
      return;
    }
    const chunks = [];
    let bytes = 0;
    request.on("data", (chunk) => { bytes += chunk.length; if (bytes <= 256 * 1024) chunks.push(chunk); });
    request.on("end", async () => {
      try {
        if (bytes > 256 * 1024) throw new Error("provider body too large");
        const raw = Buffer.concat(chunks);
        const body = JSON.parse(raw.toString("utf8"));
        if (!Array.isArray(body.to) || typeof body.to[0] !== "string" || typeof body.html !== "string" || typeof body.text !== "string") throw new Error("provider request shape");
        if (request.headers.authorization !== "Bearer hermetic-provider-key" || body.from !== "TinyCloud Share <invite@share.tinycloud.xyz>") throw new Error("provider authentication or sender shape");
        const idempotencyKey = request.headers["idempotency-key"];
        const id = `local-provider-${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const record = {
          id,
          acceptedAt: new Date().toISOString(),
          bytes,
          requestDigest: digestBytes(raw),
          hasRecipient: true,
          hasHtml: true,
          hasText: true,
          hasSender: true,
          idempotencyKeyDigest: typeof idempotencyKey === "string" ? digestBytes(idempotencyKey) : null,
        };
        await appendFile(mailArtifact, `${JSON.stringify(record)}\n`, "utf8");
        messages.push({ html: body.html, text: body.text });
        const result = JSON.stringify({ id });
        response.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(result) }).end(result);
      } catch {
        response.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "provider_rejected" }));
      }
    });
  });
  await new Promise((resolveServer, rejectServer) => {
    server.once("error", rejectServer);
    server.listen(0, "127.0.0.1", resolveServer);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("local Resend provider did not bind");
  return {
    endpoint: `http://127.0.0.1:${address.port}/emails`,
    captureCount: () => messages.length,
    messages,
    close: () => new Promise((resolveClose) => server.close(() => resolveClose())),
  };
}

/* Rendered mail stays in process memory for the recipient browser. The
 * durable capture is metadata and digests only. */

async function stopOwned(owned) {
  await Promise.all(owned.slice().reverse().map(async ({ child, done }) => {
    try { if (child.pid !== undefined) process.kill(-child.pid, "SIGTERM"); } catch { try { child.kill("SIGTERM"); } catch {} }
    await Promise.race([done, new Promise((resolveStop) => setTimeout(resolveStop, 5_000))]);
    try { if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch {} }
  }));
}

async function waitForUrl(url, label, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError = "unreachable";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { redirect: "manual" });
      if (response.status < 500) return response;
      lastError = `HTTP ${response.status}`;
    } catch (error) { lastError = error instanceof Error ? error.message : String(error); }
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`${label} did not become ready: ${lastError}`);
}

function decodeBase64(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${label} must be unpadded base64url`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length === 0 || Buffer.from(bytes).toString("base64url") !== value) throw new Error(`${label} is not canonical base64url`);
  return new Uint8Array(bytes);
}

function cloneScope(input) {
  const scope = structuredClone(input);
  if (scope.trustedNode && typeof scope.trustedNode.invitationPublicKey === "string") scope.trustedNode.invitationPublicKey = decodeBase64(scope.trustedNode.invitationPublicKey, "trustedNode.invitationPublicKey");
  else if (scope.trustedNode && Array.isArray(scope.trustedNode.invitationPublicKey)) scope.trustedNode.invitationPublicKey = new Uint8Array(scope.trustedNode.invitationPublicKey);
  return scope;
}

function providerModule() {
  try { return require("puppeteer"); }
  catch { throw new Error("E2E prerequisite missing: install the pinned puppeteer dev dependency and a Chromium browser, or set BROWSER_EXECUTABLE"); }
}

function canonicalRequestTarget(url, targets) {
  const parsed = new URL(url);
  if (parsed.origin === canonical.node) return new URL(`${parsed.pathname}${parsed.search}`, targets.node).toString();
  if (parsed.origin === canonical.credentials) return new URL(`${parsed.pathname}${parsed.search}`, targets.credentials).toString();
  if (parsed.origin === canonical.registry) return new URL(`${parsed.pathname}${parsed.search}`, targets.registry).toString();
  if (parsed.origin === canonical.share) {
    const registryPath = parsed.pathname === "/registry" || parsed.pathname.startsWith("/registry/");
    const path = registryPath
      ? parsed.pathname.slice("/registry".length) || "/"
      : `${parsed.pathname}${parsed.search}`;
    return registryPath ? new URL(path, targets.registry).toString() : new URL(path, targets.vite).toString();
  }
  return undefined;
}

async function proxyJsonMutation(request, target, mutation) {
  const response = await fetch(target, { method: request.method(), headers: request.headers(), body: request.postData() ?? undefined });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { throw new Error("mutated boundary response was not JSON"); }
  mutation(body);
  await request.respond({ status: response.status, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: JSON.stringify(body) });
}

async function proxyRequest(request, target) {
  if (request.method() === "OPTIONS") { await request.respond({ status: 204, headers: { "access-control-allow-origin": canonical.share, "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,accept,idempotency-key,if-none-match,x-delete-after", "access-control-max-age": "60" } }); return; }
  const response = await fetch(target, { method: request.method(), headers: request.headers(), body: request.method() === "GET" || request.method() === "HEAD" ? undefined : request.postData() ?? undefined });
  const headers = Object.fromEntries([...response.headers].filter(([name]) => ["cache-control", "content-type", "etag", "vary"].includes(name.toLowerCase()))); headers["access-control-allow-origin"] = canonical.share; headers["access-control-allow-methods"] = "GET,POST,OPTIONS"; headers["access-control-allow-headers"] = "content-type,accept,idempotency-key,if-none-match,x-delete-after";
  await request.respond({ status: response.status, headers, body: Buffer.from(await response.arrayBuffer()) });
}

async function installInterception(page, targets, fixtureConfig = {}) {
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const parsed = new URL(request.url());
    const target = canonicalRequestTarget(request.url(), targets);
    const localShare = parsed.origin === new URL(targets.vite).origin;
    if (target === undefined && !localShare) { void request.continue(); return; }
    if (fixtureConfig.responseMutation !== undefined && parsed.origin === canonical.node && parsed.pathname === fixtureConfig.responseMutation.path && fixtureConfig.responseMutation.used !== true) {
      fixtureConfig.responseMutation.used = true;
      void proxyJsonMutation(request, target, fixtureConfig.responseMutation.mutate).catch((error) => request.abort("failed").catch(() => { fixtureConfig.responseMutation.error = error instanceof Error ? error.message : String(error); }));
      return;
    }
    if (fixtureConfig.preserveOrigin === true && target !== undefined) { void proxyRequest(request, target).catch(() => request.abort("failed").catch(() => {})); return; }
    const headers = { ...request.headers(), origin: canonical.share };
    void request.continue({ ...(target === undefined ? {} : { url: target }), headers });
  });
}

async function readMailArtifact(path) {
  try {
    const content = await readFile(path, "utf8");
    const values = content.split("\n").filter(Boolean).map((line) => JSON.parse(line));
    return values.length > 0 ? values : [JSON.parse(content)];
  } catch { return []; }
}

function emittedLink(messages, after = 0) {
  for (const message of messages.slice(after)) {
    const haystack = `${message.html ?? ""}\n${message.text ?? ""}`;
    const match = haystack.match(/https:\/\/share\.tinycloud\.xyz\/s\/[a-z2-7]+#k=[A-Za-z0-9_-]{43}&i=[A-Za-z0-9_-]{22}&c=[A-Za-z0-9_-]{43}/);
    if (match !== null) return { href: match[0], message };
  }
  return undefined;
}

async function waitForDelivery(providerOrPath, after) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const messages = typeof providerOrPath === "string" ? await readMailArtifact(providerOrPath) : providerOrPath.messages;
    const found = emittedLink(messages, after);
    if (found !== undefined) return found;
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  throw new Error("local provider did not accept a rendered message");
}

function bodyFromLink(href) {
  const parsed = new URL(href);
  const values = new URLSearchParams(parsed.hash.slice(1));
  return { invitationId: values.get("i"), claimSecret: values.get("c") };
}

async function postJson(base, path, body) {
  return fetch(new URL(path, base), { method: "POST", headers: { "content-type": "application/json", origin: canonical.share }, body: JSON.stringify(body) });
}

async function runBrowserCase(browser, targets, fixture, issuerPublicKey, caseIndex, boundary = {}, attempt = 0, provider = undefined) {
  const scope = cloneScope(fixture.scope ?? fixture);
  const source = fixture.source ?? scope.source;
  if (source === undefined) throw new Error(`case ${caseIndex}: source is missing`);
  scope.expectedRecipientEmail = fixture.email ?? scope.expectedRecipientEmail;
  scope.expectedContentSourceDigest = fixture.contentSourceDigest ?? scope.expectedContentSourceDigest;
  if (typeof scope.expectedRecipientEmail !== "string" || typeof scope.expectedContentSourceDigest !== "string") throw new Error(`case ${caseIndex}: expected recipient/digest are required`);
  if (typeof fixture.policyCid !== "string" || !/^b[a-z2-7]{58}$/.test(fixture.policyCid)) throw new Error(`case ${caseIndex}: independently provisioned policyCid is required`);
  const authoritativeBinding = fixture.authoritativeBindings?.[attempt] ?? fixture.authoritativeBinding;
  if (authoritativeBinding === undefined || authoritativeBinding.policyCid !== fixture.policyCid || authoritativeBinding.recipientEmail !== scope.expectedRecipientEmail || authoritativeBinding.contentSourceDigest !== scope.expectedContentSourceDigest) throw new Error(`case ${caseIndex}: independently provisioned authority binding is required`);
  const deterministicUuid = authoritativeBinding.shareId.startsWith("share-") ? authoritativeBinding.shareId.slice("share-".length) : `00000000-0000-4000-8000-${String(caseIndex + 1).padStart(12, "0")}`;
  const before = provider === undefined ? (await readMailArtifact(fixture.mailArtifact)).length : provider.captureCount();

  const sender = await browser.newPage();
  const invitationStatuses = [];
  await sender.evaluateOnNewDocument((uuid) => {
    Object.defineProperty(crypto, "randomUUID", { configurable: false, value: () => uuid });
  }, deterministicUuid);
  await sender.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await sender.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
  sender.on("console", (message) => { if (message.type() === "error") console.error(`sender console: ${message.text()}`); });
  sender.on("pageerror", (error) => console.error(`sender page error: ${error.message}`));
  sender.on("requestfailed", (request) => console.error(`sender request failed: ${request.url()} ${request.failure()?.errorText ?? "unknown"}`));
  sender.on("response", (response) => {
    const responseUrl = new URL(response.url());
    if (response.request().method() === "POST" && responseUrl.pathname === "/v1/share-email/invitations") invitationStatuses.push(response.status());
    if (response.request().method() === "OPTIONS" || (response.status() < 400 && !responseUrl.pathname.includes("/v1/share-email/invitations") && !responseUrl.pathname.includes("/share/v1/invitations/authorize"))) return;
    console.error(`sender response: ${response.request().method()} ${response.status()} ${responseUrl.pathname}`);
  });
  await installInterception(sender, targets, {});
  const capabilityQuery = fixture.capabilityId === undefined ? "" : `?capabilityId=${encodeURIComponent(fixture.capabilityId)}`;
  await sender.goto(`${targets.vite}/share.html${capabilityQuery}`, { waitUntil: "domcontentloaded" }); await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  let login = await sender.$('input[name="username"]');
  if (login === null) { await sender.waitForSelector('input[name="username"]', { timeout: 5_000 }).catch(() => undefined); login = await sender.$('input[name="username"]'); }
  if (login !== null) {
    const username = required(process.env.SHARE_E2E_USERNAME, "SHARE_E2E_USERNAME");
    const password = required(process.env.SHARE_E2E_PASSWORD, "SHARE_E2E_PASSWORD");
    await sender.type('input[name="username"]', username); await sender.type('input[name="password"]', password); await sender.click('button[type="submit"]');
    await sender.waitForSelector('input[name="email"]', { timeout: 30_000 });
  }
  const emailInput = await sender.$('input[name="email"]');
  if (emailInput === null) throw new Error(`case ${caseIndex}: sender did not mount at ${sender.url()} (${await sender.content().catch(() => "no document")})`);
  const senderA11y = await sender.evaluate(() => { const widest = Array.from(document.querySelectorAll("body *")).map((node) => ({ tag: node.tagName, className: node.className, scrollWidth: node.scrollWidth, clientWidth: node.clientWidth })).filter((item) => item.scrollWidth > item.clientWidth).sort((a, b) => b.scrollWidth - a.scrollWidth).slice(0, 3); return { overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth, labelled: Array.from(document.querySelectorAll("input:not([type=hidden]),select,textarea")).every((input) => input.id !== "" || input.closest("label") !== null), status: document.querySelector("[data-sender-status]")?.getAttribute("role"), viewport: { scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth }, widest }; });
  if (senderA11y.overflow || !senderA11y.labelled || senderA11y.status !== "status") throw new Error(`case ${caseIndex}: sender accessibility/mobile assertion failed: ${JSON.stringify(senderA11y)}`);
  await sender.type('input[name="email"]', scope.expectedRecipientEmail);
  const expiry = new Date(fixture.expiresAt ?? scope.expiresAt ?? Date.now() + 3_600_000);
  const expiryInput = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60_000).toISOString().slice(0, 23);
  await sender.$eval('input[name="expiry"]', (input, value) => { input.value = value; input.dispatchEvent(new Event("input", { bubbles: true })); input.dispatchEvent(new Event("change", { bubbles: true })); }, expiryInput);
  await sender.click('input[name="scope-confirmation"]');
  await sender.click('button[type="submit"]');
  try {
    await sender.waitForFunction(() => document.querySelector("[data-sender-status]")?.getAttribute("data-state") === "requested", { timeout: 30_000 });
  } catch {
    throw new Error(`case ${caseIndex}: sender status did not reach requested`);
  }
  const senderStatus = await sender.evaluate(() => ({
    text: document.querySelector("[data-sender-status]")?.textContent ?? "",
    reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
    buttons: Array.from(document.querySelectorAll("button")).map((button) => {
      const rect = button.getBoundingClientRect();
      return { width: rect.width, height: rect.height, focusable: button.tabIndex >= 0 };
    }),
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
  }));
  if (!senderStatus.text.includes("does not claim that an email has arrived") || /email sent|delivered successfully/i.test(senderStatus.text)) throw new Error(`case ${caseIndex}: sender delivery copy was not truthful`);
  if (!senderStatus.reducedMotion || senderStatus.overflow || senderStatus.buttons.some((button) => button.width < 44 || button.height < 44 || !button.focusable)) throw new Error(`case ${caseIndex}: sender keyboard/touch/reduced-motion assertion failed`);
  await sender.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  if (await sender.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)) throw new Error(`case ${caseIndex}: sender desktop layout overflows horizontally`);
  if (invitationStatuses.length !== 1 || invitationStatuses[0] !== 200) throw new Error(`case ${caseIndex}: invitation HTTP status was not exactly one 200 response`);
  await sender.close();

  const captured = await waitForDelivery(provider ?? fixture.mailArtifact, before);
  const link = captured.href;
  const mailbox = bodyFromLink(link);
  if (mailbox.invitationId === null || mailbox.claimSecret === null) throw new Error(`case ${caseIndex}: malformed provider-delivered link`);
  const inertUrl = canonicalRequestTarget(link, targets) ?? link;
  const inert = await fetch(inertUrl, { redirect: "manual", referrerPolicy: "no-referrer" });
  if (inert.status !== 200 || inert.headers.get("content-type")?.split(";", 1)[0] !== "text/html") throw new Error(`case ${caseIndex}: scanner GET did not return the inert recipient entry (${inert.status})`);

  const recipient = await browser.createBrowserContext();
  const page = await recipient.newPage();
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
  await page.evaluateOnNewDocument(() => {
    const audit = { networkBeforeScrub: 0, scrubbedHistory: false };
    Object.defineProperty(window, "__emailClaimAudit", { configurable: false, value: audit });
    const replaceState = history.replaceState.bind(history);
    Object.defineProperty(history, "replaceState", { configurable: true, value: (state, title, url) => {
      const safeUrl = typeof url === "string" ? url : "";
      audit.scrubbedHistory = safeUrl.includes("#") === false && safeUrl.includes("?") === false;
      return replaceState(state, title, url);
    } });
    const fetchFn = window.fetch.bind(window);
    Object.defineProperty(window, "fetch", { configurable: true, value: (input, init) => {
      if (location.hash !== "" || location.search !== "") audit.networkBeforeScrub += 1;
      return fetchFn(input, init);
    } });
  });
  let claimMaterialInRequestUrl = false;
  page.on("request", (request) => {
    const parsedRequestUrl = new URL(request.url());
    const requestUrl = `${parsedRequestUrl.origin}${parsedRequestUrl.pathname}${parsedRequestUrl.search}`;
    if (requestUrl.includes(mailbox.invitationId) || requestUrl.includes(mailbox.claimSecret)) claimMaterialInRequestUrl = true;
  });
  page.on("console", (message) => {
    if (message.type() === "error") console.error(`recipient console ${message.text()}`);
  });
  page.on("pageerror", (error) => console.error(`recipient page error: ${error.message}`));
  page.on("requestfailed", (request) => console.error(`recipient request failed: ${request.url()} ${request.failure()?.errorText ?? "unknown"}`));
  page.on("response", (response) => {
    if (response.request().method() === "OPTIONS") return;
    const responsePath = new URL(response.url()).pathname;
    if (responsePath.startsWith("/.well-known/tinycloud-share/") || /node\.example|credentials\.org/.test(response.url())) {
      console.error(`recipient response: ${response.request().method()} ${response.status()} ${responsePath}`);
    }
    if (!/node\.example|credentials\.org/.test(response.url())) return;
    void response.text().then((body) => {
      let parsed;
      try { parsed = JSON.parse(body); } catch { parsed = undefined; }
      const errorCode = parsed?.error?.code;
      const keys = parsed !== undefined && typeof parsed === "object" && parsed !== null ? Object.keys(parsed).sort().join(",") : "non-json";
      console.error(`recipient response: ${response.request().method()} ${response.status()} ${responsePath} keys=${keys}${typeof errorCode === "string" ? ` error=${errorCode}` : ""}`);
    }).catch(() => {});
  });
  await installInterception(page, targets, { responseMutation: boundary.responseMutation, preserveOrigin: true });
  await page.goto(link, { waitUntil: "domcontentloaded" }); await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  try { await page.waitForFunction(() => location.hash === "" && location.search === "" && document.body.textContent?.includes("Open document"), { timeout: 30_000 }); }
  catch {
    const shareCid = new URL(link).pathname.slice("/s/".length);
    const bindingProbe = await page.evaluate(async (cid) => { try { const response = await fetch(`/.well-known/tinycloud-share/bindings/${cid}.json`, { credentials: "omit", cache: "no-store" }); return response.status; } catch { return "fetch-error"; } }, shareCid);
    throw new Error(`case ${caseIndex}: recipient did not reach explicit activation state at ${new URL(page.url()).pathname} binding-status=${bindingProbe}`);
  }
  const scrubbed = await page.evaluate(() => ({ href: location.href, body: document.body.textContent ?? "" }));
  if (scrubbed.href.includes("#") || scrubbed.href.includes("?")) throw new Error(`case ${caseIndex}: invitation URL was not scrubbed synchronously`);
  const recipientAudit = await page.evaluate(() => ({
    audit: (window.__emailClaimAudit ?? { networkBeforeScrub: -1, scrubbedHistory: false }),
    referrer: document.referrer,
    storage: `${localStorage.length}:${sessionStorage.length}`,
    historyState: history.state,
    reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
    text: document.body.textContent ?? "",
    controls: Array.from(document.querySelectorAll("button, input")).map((control) => {
      const rect = control.getBoundingClientRect();
      return { width: rect.width, height: rect.height, focusable: control.tabIndex >= 0 };
    }),
    overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    live: document.querySelector("[aria-live][role=status]") !== null,
    primary: document.querySelector("button.recipient-primary-action")?.textContent,
  }));
  if (recipientAudit.audit.networkBeforeScrub !== 0 || !recipientAudit.audit.scrubbedHistory || recipientAudit.referrer !== "" || recipientAudit.storage !== "0:0" || recipientAudit.historyState !== null || recipientAudit.overflow || !recipientAudit.reducedMotion || !recipientAudit.live || recipientAudit.primary !== "Open document" || claimMaterialInRequestUrl || recipientAudit.controls.some((control) => control.width < 44 || control.height < 44 || !control.focusable)) throw new Error(`case ${caseIndex}: recipient privacy/accessibility/mobile assertion failed`);
  if (/sign in|wallet|openkey|connect account/i.test(recipientAudit.text)) throw new Error(`case ${caseIndex}: recipient rendered an account or wallet ceremony`);
  await page.keyboard.press("Tab");
  if (!(await page.evaluate(() => document.activeElement?.matches("button.recipient-primary-action") && document.querySelector("button.recipient-primary-action")?.matches(":focus-visible")))) throw new Error(`case ${caseIndex}: recipient primary action was not keyboard focus-visible`);
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)) throw new Error(`case ${caseIndex}: recipient desktop layout overflows horizontally`);
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await page.click("button.recipient-primary-action");
  if (boundary.expectReject === true) {
    try {
      await page.waitForFunction(() => document.body.textContent?.includes("couldn't finish the invitation") || document.body.textContent?.includes("Ask the sender"), { timeout: 30_000 });
    } catch { throw new Error(`case ${caseIndex}: forged or stale Node response advanced the browser`); }
    if ((await page.evaluate((marker) => document.body.textContent?.includes(marker), fixture.expectedContent ?? source.path))) throw new Error(`case ${caseIndex}: rejected Node response exposed document content`);
    await recipient.close();
    return;
  }
  try {
    await page.waitForFunction((marker) => {
      const renderedMarker = marker.replace(/^#+\s*/, "").trim().split(/\r?\n/, 1)[0].trim().replace(/\s+/g, " ");
      const includesMarker = (text) => text.replace(/\s+/g, " ").includes(renderedMarker);
      if (includesMarker(document.body.textContent ?? "")) return true;
      return Array.from(document.querySelectorAll("iframe")).some((frame) => {
        try {
          return includesMarker(frame.contentDocument?.body?.textContent ?? "")
            || includesMarker(frame.getAttribute("srcdoc") ?? "");
        } catch { return (frame.getAttribute("srcdoc") ?? "").includes(renderedMarker); }
      });
    }, { timeout: 30_000 }, fixture.expectedContent ?? source.path);
  }
  catch {
    const renderProbe = await page.evaluate((marker) => {
      const renderedMarker = marker.replace(/^#+\s*/, "").trim().split(/\r?\n/, 1)[0].trim().replace(/\s+/g, " ");
      const includesMarker = (text) => text.replace(/\s+/g, " ").includes(renderedMarker);
      return {
        bodyHasMarker: includesMarker(document.body.textContent ?? ""),
        contentPresent: document.querySelector(".viewer-content") !== null,
        frameCount: document.querySelectorAll("iframe").length,
        frameHasMarker: Array.from(document.querySelectorAll("iframe")).some((frame) => includesMarker(frame.getAttribute("srcdoc") ?? "")),
        title: document.querySelector(".viewer-state-title")?.textContent ?? null,
      };
    }, fixture.expectedContent ?? source.path);
    throw new Error(`case ${caseIndex}: recipient did not render authoritative content (secure=${await page.evaluate(() => isSecureContext)}, subtle=${await page.evaluate(() => typeof crypto?.subtle)}, probe=${JSON.stringify(renderProbe)})`);
  }
  const contentSafety = await page.evaluate(() => ({
    scripts: document.querySelector(".viewer-content")?.querySelectorAll("script").length ?? 0,
    rawHtml: document.querySelector(".viewer-content")?.querySelectorAll("html, body").length ?? 0,
  }));
  if (contentSafety.scripts !== 0 || contentSafety.rawHtml !== 0) throw new Error(`case ${caseIndex}: rendered content escaped the hardened Markdown boundary`);
  await recipient.close();

  const replay = await postJson(targets.credentials, "/v1/share-email/claims/activate", mailbox);
  if (replay.ok) throw new Error(`case ${caseIndex}: activation replay unexpectedly succeeded`);
  const postClaimCaptureCount = provider === undefined ? (await readMailArtifact(fixture.mailArtifact)).length : provider.captureCount();
  const resendAfterClaim = await postJson(targets.credentials, "/v1/share-email/invitations/resend", mailbox);
  if (!resendAfterClaim.ok) throw new Error(`case ${caseIndex}: post-claim resend lost accepted-shaped response (${resendAfterClaim.status})`);
  await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
  const finalCaptureCount = provider === undefined ? (await readMailArtifact(fixture.mailArtifact)).length : provider.captureCount();
  if (finalCaptureCount !== postClaimCaptureCount) throw new Error(`case ${caseIndex}: claimed invitation emitted a resend`);
}

async function productionGateHermetic() {
  const owned = [];
  const tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-email-claim-production-"));
  const scopePath = join(tempRoot, "node.json");
  const deployEnvFile = join(tempRoot, "share-deploy.env");
  const bindingStorePath = join(tempRoot, "bindings.ndjson");
  let production;
  const cleanup = async () => {
    await stopOwned(owned);
    const remaining = (await runCapture("ps", ["-axo", "pid=,command="], shareRoot).catch(() => ""))
      .split("\n")
      .filter((line) => line.includes(tempRoot));
    if (remaining.length !== 0) throw new Error(`production composition left task-owned processes: ${remaining.join(" | ")}`);
    ownedProcessCleanup = { stopped: owned.length, remaining, complete: true };
    await rm(tempRoot, { recursive: true, force: true });
  };
  activeCleanup = cleanup;
  try {
    const postgres = await startPostgres(owned, tempRoot);
    // Keep the hermetic TEE deterministic without using a frozen fixture key;
    // the default-feature Node production validator rejects fixture identities.
    const issuerSeed = Buffer.alloc(32, 0x47);
    const issuerPublicKey = ed25519PublicKey(issuerSeed).toString("base64url");
    const nodeKeySecret = Buffer.alloc(32, 0x09).toString("base64url");
    const dstackSocket = await startDstackSimulator(owned, tempRoot, issuerSeed);
    const node = spawnOwnedArgs("cargo", ["run", "--quiet", "-p", "tinycloud-node-production-e2e", "--", "--descriptor", scopePath, "--issuer-public-key", issuerPublicKey, "--keys-secret", nodeKeySecret], nodeRoot, {
      TINYCLOUD_KEYS_SECRET: nodeKeySecret,
    });
    owned.push(node);
    const nodeDescriptor = await waitForFileJson(scopePath, "TinyCloud Node production composition", node);
    const nodeUrl = required(nodeDescriptor.url, "Node descriptor URL");
    const trustBundle = nodeDescriptor.trustBundle;
    if (trustBundle === undefined || trustBundle.issuerPublicKey !== issuerPublicKey) throw new Error("production Node trust bundle did not bind the dstack issuer key");
    const capabilityCases = Array.isArray(nodeDescriptor.cases) ? nodeDescriptor.cases : [];
    if (capabilityCases.length < 2) throw new Error("production Node composition did not publish KV and named-SQL capabilities");
    const migrationEnv = {
      ...process.env,
      DATABASE_URL: postgres.url,
      DATABASE_SSL_ROOT_CERT: postgres.caCert,
      DATABASE_MIGRATIONS_DIR: resolve(credentialsRoot, "deploy/share-email/migrations"),
      DATABASE_POOL_MIN: "2", DATABASE_POOL_MAX: "8", DATABASE_CONNECT_TIMEOUT_MS: "5000",
      DATABASE_RECYCLE_TIMEOUT_MS: "5000", DATABASE_ACQUIRE_TIMEOUT_MS: "500", DATABASE_STATEMENT_TIMEOUT_MS: "2000",
      DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: "1000", STORAGE_READINESS_FILE: join(tempRoot, "readiness.json"),
      STORAGE_READINESS_MAX_AGE_SECONDS: "30",
    };
    await run("bash", [resolve(credentialsRoot, "scripts/oi-share-email/migrate.sh")], credentialsRoot, migrationEnv);
    await run("bash", [resolve(credentialsRoot, "scripts/oi-share-email/readiness-check.sh")], credentialsRoot, migrationEnv);
    const credentialsPort = await freePort();
    const credentials = spawnOwnedArgs("cargo", ["run", "--quiet", "--manifest-path", resolve(credentialsRustRoot, "Cargo.toml"), "--features", "dstack", "--bin", "opencredentials-witness"], credentialsRustRoot, {
      KEYS_TYPE: "dstack", DSTACK_SIMULATOR_ENDPOINT: dstackSocket, DID_WEB: trustBundle.issuerDid,
      BIND_ADDR: `127.0.0.1:${credentialsPort}`, CORS_ALLOWED_ORIGINS: canonical.share,
      SHARE_EMAIL_CAPABILITY: "true", SHARE_EMAIL_TRUST_BUNDLE_JSON: JSON.stringify(trustBundle),
      SHARE_EMAIL_SHARE_URL: canonical.share, RESEND_API_KEY: "hermetic-production-key", RESEND_WEBHOOK_SECRET: "hermetic-production-webhook",
      DATABASE_URL: postgres.url, DATABASE_SSL_ROOT_CERT: postgres.caCert,
      DATABASE_POOL_MIN: "2", DATABASE_POOL_MAX: "8", DATABASE_CONNECT_TIMEOUT_MS: "5000", DATABASE_RECYCLE_TIMEOUT_MS: "5000",
      DATABASE_ACQUIRE_TIMEOUT_MS: "500", DATABASE_STATEMENT_TIMEOUT_MS: "2000", DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: "1000",
      DATABASE_MIGRATIONS_DIR: resolve(credentialsRoot, "deploy/share-email/migrations"), STORAGE_READINESS_FILE: migrationEnv.STORAGE_READINESS_FILE,
      STORAGE_READINESS_MAX_AGE_SECONDS: "30", SHARE_EMAIL_KEY_DERIVATION_VERSION: "1",
    });
    owned.push(credentials);
    await waitForPort(credentialsPort, "OpenCredentials production composition");
    const credentialsUrl = `http://127.0.0.1:${credentialsPort}`;
    const readiness = await fetch(`${credentialsUrl}/share-email/readiness`);
    if (readiness.status !== 200) throw new Error(`OpenCredentials production readiness failed (${readiness.status})`);
    const capabilities = await fetch(`${credentialsUrl}/share-email/capabilities`);
    if (capabilities.status !== 200) throw new Error(`OpenCredentials production capability failed (${capabilities.status})`);
    const registry = spawnOwned("npm run -w @tinycloud/share-registry dev-server -- --port 0", shareRoot);
    owned.push(registry);
    let registryUrl;
    const registryDeadline = Date.now() + 30_000;
    while (registryUrl === undefined && Date.now() < registryDeadline) {
      const match = registry.output().match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match !== null) registryUrl = match[0]; else await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    registryUrl = required(registryUrl, "local Share registry URL");
    const senderScope = capabilityCases[0].scope ?? capabilityCases[0];
    const senderPrivateKey = required(senderScope.senderPrivateKey, "server-only sender key");
    const capabilityJson = capabilityCases.map((entry) => {
      const scope = structuredClone(entry.scope ?? entry);
      delete scope.senderPrivateKey; delete scope.privateKey; delete scope.policy;
      scope.userId = "production-composition-user";
      const source = entry.source ?? scope.source;
      const policyDocument = entry.policy ?? scope.policy;
      const authority = entry.authorityMaterial ?? scope.authorityMaterial;
      const policyBytes = Buffer.from(stableJson(policyDocument), "utf8").toString("base64url");
      return JSON.stringify({ scope, source, policy: {
        action: source.action, authorityMaterialDigest: entry.authorityMaterialDigest ?? scope.authorityMaterialDigest,
        contentSourceDigest: policyDocument.contentSourceDigest, delegationCid: entry.delegationCid ?? scope.delegationCid,
        expiresAt: entry.expiresAt ?? scope.expiresAt, policyAuthorityBytes: authority.policyAuthorityBytes,
        policyAuthorityCid: authority.policyAuthorityCid, policyBytes, policyDigest: digestBase64Url(Buffer.from(stableJson(policyDocument), "utf8")),
        policyEnforcementBytes: authority.policyEnforcementBytes, policyEnforcementCid: authority.policyEnforcementCid,
        policyCid: entry.policyCid, recipientEmail: policyDocument.recipientEmail, resource: source.path, source,
        target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: source.space },
      }});
    });
    const envValues = {
      SHARE_TRUST_BUNDLE_FILE: join(tempRoot, "trust-bundle.json"), SHARE_SENDER_PRIVATE_KEY: senderPrivateKey,
      SHARE_SENDER_CAPABILITIES_JSON: JSON.stringify(capabilityJson),
      SHARE_AUTH_USERS_JSON: JSON.stringify([{ userId: "production-composition-user", username: "production-composition", passwordHash: scryptPassword("production-composition-password") }]),
      SHARE_BINDING_STORE_PATH: bindingStorePath, SHARE_HERMETIC_COMPOSITION: "true",
      SHARE_HERMETIC_UPSTREAMS_JSON: JSON.stringify({ node: { origin: canonical.node, transportOrigin: nodeUrl }, credentials: { origin: canonical.credentials, transportOrigin: credentialsUrl }, registry: { origin: canonical.registry, transportOrigin: registryUrl } }),
      VITE_SHARE_REGISTRY_URL: canonical.registry,
    };
    await writeFile(envValues.SHARE_TRUST_BUNDLE_FILE, `${JSON.stringify(trustBundle)}\n`, { encoding: "utf8", flag: "wx" });
    await writeFile(deployEnvFile, `${Object.entries(envValues).map(([key, value]) => `${key}=${value}`).join("\n")}\n`, { encoding: "utf8", flag: "wx" });
    const deployEnv = { ...process.env, ...envValues, SHARE_DEPLOY_STARTUP: "true" };
    const validationEnv = { ...deployEnv }; delete validationEnv.SHARE_HERMETIC_COMPOSITION; delete validationEnv.SHARE_HERMETIC_UPSTREAMS_JSON;
    await run("node", ["scripts/validate-deploy-config.mjs"], shareRoot, validationEnv);
    await run("npm", ["run", "build:deploy"], shareRoot, validationEnv);
    const port = await freePort();
    const host = spawnOwnedArgs("npm", ["run", "start:deploy"], shareRoot, { ...deployEnv, HOST: "127.0.0.1", PORT: String(port) });
    owned.push(host);
    try {
      await waitForPort(port, "Share production composition");
    } catch (error) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}: ${host.output().slice(-8_000)}`);
    }
    const shareHealth = await fetch(`http://127.0.0.1:${port}/share.html`);
    if (shareHealth.status !== 200) throw new Error(`Share production composition failed (${shareHealth.status})`);
    console.error("production OpenCredentials/Node/Share composition: PASS");
  } finally {
    await cleanup();
    if (activeCleanup === cleanup) activeCleanup = undefined;
  }
}

async function fixtureGate() {
  const owned = [];
  const focusedKvLoop = process.argv.includes("--kv-only");
  const tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-email-claim-"));
  const scopePath = join(tempRoot, "node.json");
  const mailArtifact = join(tempRoot, "mail.ndjson");
  const deployEnvFile = join(tempRoot, "share-deploy.env");
  const bindingStorePath = join(tempRoot, "bindings.ndjson");
  let resendProvider;
  let production;
  const cleanup = async () => {
    await resendProvider?.close();
    await stopOwned(owned);
    const processListing = await runCapture("ps", ["-axo", "pid=,command="], shareRoot).catch(() => "");
    const remaining = processListing.split("\n").filter((line) => line.includes("share-registry") || line.includes(tempRoot));
    ownedProcessCleanup = { stopped: owned.length, remaining, complete: remaining.length === 0 };
    await rm(tempRoot, { recursive: true, force: true });
  };
  activeCleanup = cleanup;
  try {
    const postgres = await startPostgres(owned, tempRoot);
    resendProvider = await startLocalResendProvider(mailArtifact);
    const issuerSeed = Buffer.alloc(32, 0x43);
    const issuerPublicKey = ed25519PublicKey(issuerSeed).toString("base64url");
    const nodeKeySecret = Buffer.alloc(32, 0x09).toString("base64url");
    const dstackSocket = await startDstackSimulator(owned, tempRoot, issuerSeed);
    const node = spawnOwnedArgs("cargo", ["run", "--quiet", "-p", "tinycloud-node-production-e2e", "--features", "mounted-fixture", "--", "--descriptor", scopePath, "--issuer-public-key", issuerPublicKey, "--keys-secret", nodeKeySecret], nodeRoot, {
      TINYCLOUD_KEYS_SECRET: nodeKeySecret, DSTACK_SIMULATOR_ENDPOINT: dstackSocket,
    });
    owned.push(node);
    const nodeDescriptor = await waitForFileJson(scopePath, "TinyCloud Node", node);
    const nodeUrl = required(nodeDescriptor.url, "Node descriptor URL");
    const trustedKey = required(nodeDescriptor.trustedNode?.invitationPublicKey, "Node invitation public key");
    const trustBundle = nodeDescriptor.trustBundle;
    if (trustBundle === undefined || trustBundle.nodeInvitationPublicKey !== trustedKey || trustBundle.issuerPublicKey !== issuerPublicKey) throw new Error("production Node did not publish the exact JSON trust bundle used at startup");
    const fixtureValue = JSON.parse(await readFile(scopePath, "utf8"));
    const allFixtures = Array.isArray(fixtureValue) ? fixtureValue : (fixtureValue.cases ?? [fixtureValue]);
    const fixtures = focusedKvLoop ? allFixtures.filter((fixture) => (fixture.kind ?? (fixture.source ?? {}).kind) === "kv") : allFixtures;
    if (focusedKvLoop ? fixtures.length !== 1 : fixtures.length < 2) throw new Error(focusedKvLoop ? "focused KV loop requires exactly one KV case" : "production gate requires both KV and named-SQL cases");
    const firstScope = fixtures[0].scope ?? fixtures[0];
    const privateKey = decodeBase64(required(firstScope.senderPrivateKey, "server-only sender key"), "senderPrivateKey");
    if (privateKey.length !== 32) throw new Error("sender key is not a 32-byte server-only key");
    const migrationEnv = {
      ...process.env,
      DATABASE_URL: postgres.url,
      DATABASE_SSL_ROOT_CERT: postgres.caCert,
      DATABASE_MIGRATIONS_DIR: resolve(credentialsRoot, "deploy/share-email/migrations"),
      DATABASE_POOL_MIN: "2", DATABASE_POOL_MAX: "8", DATABASE_CONNECT_TIMEOUT_MS: "5000",
      DATABASE_RECYCLE_TIMEOUT_MS: "5000", DATABASE_ACQUIRE_TIMEOUT_MS: "500", DATABASE_STATEMENT_TIMEOUT_MS: "2000",
      DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: "1000", STORAGE_READINESS_FILE: join(tempRoot, "readiness.json"),
      STORAGE_READINESS_MAX_AGE_SECONDS: "30",
    };
    await run("bash", [resolve(credentialsRoot, "scripts/oi-share-email/migrate.sh")], credentialsRoot, migrationEnv);
    await run("bash", [resolve(credentialsRoot, "scripts/oi-share-email/readiness-check.sh")], credentialsRoot, migrationEnv);
    const registry = spawnOwned("npm run -w @tinycloud/share-registry dev-server -- --port 0", shareRoot);
    owned.push(registry);
    let registryUrl;
    const registryDeadline = Date.now() + 30_000;
    while (registryUrl === undefined && Date.now() < registryDeadline) {
      const match = registry.output().match(/http:\/\/127\.0\.0\.1:\d+/);
      if (match !== null) registryUrl = match[0]; else await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    registryUrl = required(registryUrl, "local Share registry URL");
    const credentialsPort = await freePort();
    const credentials = spawnOwnedArgs("cargo", ["run", "--quiet", "--manifest-path", resolve(credentialsRustRoot, "Cargo.toml"), "--features", "email-claim-fixture", "--bin", "email-claim-fixture"], credentialsRustRoot, {
      BIND_ADDR: `127.0.0.1:${credentialsPort}`,
      EMAIL_CLAIM_FIXTURE_DATABASE_URL: postgres.url.replace("db.localhost", "127.0.0.1").replace("?sslmode=verify-full", ""), SHARE_EMAIL_RESEND_ENDPOINT: resendProvider.endpoint,
      SHARE_EMAIL_TRUSTED_NODE_ORIGIN: canonical.node, SHARE_EMAIL_TRUSTED_NODE_AUDIENCE: trustBundle.nodeAudience,
      SHARE_EMAIL_TRUSTED_NODE_KID: trustBundle.nodeInvitationKid, SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY: trustedKey,
      DATABASE_URL: postgres.url, DATABASE_SSL_ROOT_CERT: postgres.caCert,
      DATABASE_POOL_MIN: "2", DATABASE_POOL_MAX: "8", DATABASE_CONNECT_TIMEOUT_MS: "5000", DATABASE_RECYCLE_TIMEOUT_MS: "5000",
      DATABASE_ACQUIRE_TIMEOUT_MS: "500", DATABASE_STATEMENT_TIMEOUT_MS: "2000", DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: "1000",
      DATABASE_MIGRATIONS_DIR: resolve(credentialsRoot, "deploy/share-email/migrations"), STORAGE_READINESS_FILE: migrationEnv.STORAGE_READINESS_FILE,
      STORAGE_READINESS_MAX_AGE_SECONDS: "30", SHARE_EMAIL_KEY_DERIVATION_VERSION: "1",
    });
    owned.push(credentials);
    try {
      await waitForPort(credentialsPort, "OpenCredentials production witness");
    } catch (error) {
      throw new Error(`${error instanceof Error ? error.message : String(error)}:\n${credentials.output().slice(-8_000)}`);
    }
    const credentialsUrl = `http://127.0.0.1:${credentialsPort}`;
    const issuerResponse = await fetch(`${credentialsUrl}/issuer`); if (issuerResponse.status !== 200) throw new Error(`OpenCredentials issuer route failed (${issuerResponse.status})`);
    const issuerDescriptor = await issuerResponse.json();
    const credentialsDescriptor = { issuerDid: issuerDescriptor.did, issuerPublicKey: issuerDescriptor.publicKeyJwk?.x };
    if (credentialsDescriptor.issuerDid !== trustBundle.issuerDid || credentialsDescriptor.issuerPublicKey !== issuerPublicKey) throw new Error("production witness issuer did/key does not match the single JSON trust bundle");
    const capabilityJson = fixtures.map((fixture) => {
      const scope = structuredClone(fixture.scope ?? fixture); delete scope.senderPrivateKey; delete scope.privateKey; delete scope.policy;
      scope.userId = "sender-user-1";
      scope.recipientEmail = fixture.email ?? scope.expectedRecipientEmail;
      const source = fixture.source ?? (fixture.scope ?? fixture).source;
      const policyDocument = fixture.policy ?? (fixture.scope ?? fixture).policy;
      if (policyDocument === undefined) throw new Error(`fixture ${fixture.kind ?? index} did not publish its exact policy`);
      const authority = fixture.authorityMaterial ?? scope.authorityMaterial;
      const policyBytes = Buffer.from(stableJson(policyDocument), "utf8").toString("base64url");
      const policy = {
        action: source.action, authorityMaterialDigest: fixture.authorityMaterialDigest ?? scope.authorityMaterialDigest, contentSourceDigest: policyDocument.contentSourceDigest, delegationCid: fixture.delegationCid ?? scope.delegationCid,
        expiresAt: fixture.expiresAt ?? scope.expiresAt, policyAuthorityBytes: authority.policyAuthorityBytes, policyAuthorityCid: authority.policyAuthorityCid, policyBytes,
        policyDigest: digestBase64Url(Buffer.from(stableJson(policyDocument), "utf8")), policyEnforcementBytes: authority.policyEnforcementBytes, policyEnforcementCid: authority.policyEnforcementCid,
        policyCid: fixture.policyCid, recipientEmail: policyDocument.recipientEmail, resource: source.path, source,
        target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: source.space },
      };
      return JSON.stringify({ scope, source, policy });
    });
    const username = "release-sender"; const password = "release-password";
    process.env.SHARE_E2E_USERNAME = username;
    process.env.SHARE_E2E_PASSWORD = password;
    const authUsers = JSON.stringify([{ userId: "sender-user-1", username, passwordHash: scryptPassword(password) }, { userId: "other-user", username: "other-user", passwordHash: scryptPassword("other-password") }]);
    const envValues = {
      SHARE_TRUST_BUNDLE_FILE: join(tempRoot, "trust-bundle.json"), SHARE_SENDER_PRIVATE_KEY: Buffer.from(privateKey).toString("base64url"),
      SHARE_SENDER_CAPABILITIES_JSON: JSON.stringify(capabilityJson), SHARE_AUTH_USERS_JSON: authUsers,
      SHARE_BINDING_STORE_PATH: bindingStorePath, SHARE_HERMETIC_COMPOSITION: "true", SHARE_HERMETIC_UPSTREAMS_JSON: JSON.stringify({ node: { origin: canonical.node, transportOrigin: nodeUrl }, credentials: { origin: canonical.credentials, transportOrigin: credentialsUrl }, registry: { origin: canonical.registry, transportOrigin: registryUrl } }), VITE_SHARE_REGISTRY_URL: canonical.registry,
    };
    await writeFile(envValues.SHARE_TRUST_BUNDLE_FILE, `${JSON.stringify(trustBundle)}\n`, { encoding: "utf8", flag: "wx" });
    await writeFile(deployEnvFile, `${Object.entries(envValues).map(([key, value]) => `${key}=${value}`).join("\n")}\n`, { encoding: "utf8", flag: "wx" });
    const deployEnv = { ...process.env, ...envValues, SHARE_DEPLOY_STARTUP: "true" };
    if (deployEnv.SHARE_TRUST_BUNDLE_ALLOW_TEST !== undefined || deployEnv.SHARE_TEST_BINDINGS_JSON !== undefined || deployEnv.SHARE_SESSION_SECRET !== undefined) throw new Error("production Share env contains a fixture-only control");
    const validationEnv = { ...deployEnv }; delete validationEnv.SHARE_HERMETIC_COMPOSITION; delete validationEnv.SHARE_HERMETIC_UPSTREAMS_JSON;
    await run("node", ["scripts/validate-deploy-config.mjs"], shareRoot, validationEnv);
    await run("npm", ["run", "build:deploy"], shareRoot, validationEnv);
    // The witness readiness file is intentionally short-lived in production;
    // refresh the sidecar result after the Share build so the controlled
    // composition measures the live database/provider seam, not build time.
    await run("bash", [resolve(credentialsRoot, "scripts/oi-share-email/readiness-check.sh")], credentialsRoot, migrationEnv);
    const startHost = async () => {
      const port = await freePort();
      const host = spawnOwnedArgs("npm", ["run", "start:deploy"], shareRoot, { ...deployEnv, HOST: "127.0.0.1", PORT: String(port) });
      owned.push(host);
      try { await waitForPort(port, "production Share host"); }
      catch (error) { throw new Error(`${error instanceof Error ? error.message : String(error)}: ${diagnosticOutput(host.output())}`); }
      return { host, url: `http://127.0.0.1:${port}` };
    };
    production = await startHost();
    const shareUrl = production.url;
    const validShareCid = `bafkrei${"a".repeat(52)}`;
    for (const path of ["/share", "/share.html", "/viewer", "/viewer.html", `/s/${validShareCid}`]) {
      const response = await fetch(`${shareUrl}${path}`); if (response.status !== 200) throw new Error(`production Share rewrite failed for ${path}: ${response.status}`);
      const headers = Object.fromEntries(response.headers);
      if (headers["cache-control"] !== "no-store" || headers["referrer-policy"] !== "no-referrer" || headers["x-content-type-options"] !== "nosniff") throw new Error(`production Share security headers missing for ${path}`);
      if ((path === "/share" || path === "/share.html" || path === "/viewer" || path === "/viewer.html" || path.startsWith("/s/")) && !headers["content-security-policy"]?.includes("connect-src")) throw new Error(`production Share trust-derived CSP missing for ${path}`);
    }
    const descriptorResponse = await fetch(`${shareUrl}/api/share/capabilities`); if (descriptorResponse.status !== 401) throw new Error("production Share host exposed capabilities before authentication");
    const targets = { node: nodeUrl, credentials: credentialsUrl, registry: registryUrl, vite: shareUrl };
    await waitForUrl(new URL("/healthz", nodeUrl), "Node");
    const nodeInfoResponse = await fetch(new URL("/info", nodeUrl)); if (nodeInfoResponse.status !== 200) throw new Error(`Node production info route failed (${nodeInfoResponse.status})`);
    const nodeInfo = await nodeInfoResponse.json(); if (!nodeInfo.features?.includes("share-email-claim") || nodeInfo.shareEmail?.status !== "ready") throw new Error("Node production startup did not advertise its authenticated share-email capability");
    await waitForUrl(new URL("/health", credentialsUrl), "OpenCredentials");
    for (const path of ["/capabilities", "/share-email/capabilities", "/share-email/readiness"]) {
      const response = await fetch(new URL(path, credentialsUrl)); if (response.status !== 200) throw new Error(`OpenCredentials ${path} did not report fresh production readiness (${response.status})`);
    }
    const browser = providerModule(); const instance = await browser.launch({ headless: true, ...(process.env.BROWSER_EXECUTABLE ? { executablePath: process.env.BROWSER_EXECUTABLE } : {}), ignoreHTTPSErrors: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    try {
      const authPage = await instance.newPage();
      authPage.on("console", (message) => console.error(`auth console ${message.type()}: ${message.text()}`));
      authPage.on("pageerror", (error) => console.error(`auth page error: ${error.message}`));
      authPage.on("requestfailed", (request) => console.error(`auth request failed: ${request.url()} ${request.failure()?.errorText ?? "unknown"}`));
      authPage.on("response", (response) => { if (response.status() >= 400) console.error(`auth response ${response.status()} ${new URL(response.url()).pathname}`); });
      await installInterception(authPage, targets, {}); await authPage.goto(`${targets.vite}/share.html`, { waitUntil: "domcontentloaded" }); await new Promise((resolveWait) => setTimeout(resolveWait, 500));
      await authPage.waitForSelector('input[name="username"]', { timeout: 5_000 }).catch(() => undefined);
      if (await authPage.$('input[name="username"]') === null) throw new Error(`clean browser did not reach the authenticated Share login boundary: ${(await authPage.content()).slice(0, 2_000)}`);
      await authPage.type('input[name="username"]', username); await authPage.type('input[name="password"]', password); await authPage.click('button[type="submit"]'); await authPage.waitForSelector('input[name="email"]', { timeout: 30_000 });
      const capabilities = await authPage.evaluate(async () => (await fetch("/api/share/capabilities", { credentials: "include" })).json());
      if (!Array.isArray(capabilities.capabilities) || capabilities.capabilities.length !== fixtures.length) throw new Error("authenticated production Share host did not expose the exact per-user capability set");
      const otherContext = await instance.createBrowserContext();
      const otherPage = await otherContext.newPage(); await installInterception(otherPage, targets, {}); await otherPage.goto(`${targets.vite}/share.html`, { waitUntil: "domcontentloaded" }); await new Promise((resolveWait) => setTimeout(resolveWait, 500)); await otherPage.waitForSelector('input[name="username"]', { timeout: 5_000 }); await otherPage.type('input[name="username"]', "other-user"); await otherPage.type('input[name="password"]', "other-password"); await otherPage.click('button[type="submit"]');
      const otherCapabilities = await otherPage.evaluate(async () => { const response = await fetch("/api/share/capabilities", { credentials: "include" }); return { status: response.status, body: await response.json() }; }); if (otherCapabilities.status === 200 && (!Array.isArray(otherCapabilities.body.capabilities) || otherCapabilities.body.capabilities.length !== 0)) throw new Error(`cross-user capability exposure was not rejected: ${JSON.stringify(otherCapabilities)}`); if (otherCapabilities.status !== 200 && otherCapabilities.status !== 401) throw new Error(`cross-user capability boundary returned unexpected status: ${JSON.stringify(otherCapabilities)}`); await otherPage.close(); await authPage.close();
      await otherContext.close();
      runCoverage = { ...runCoverage, fixtures: focusedKvLoop ? 1 : fixtures.length * 2, sources: fixtures.map((fixture) => fixture.kind), browser: ["production Share host", "clean-browser authentication", "no pre-auth capability exposure", "per-user capability selection", "cross-user capability rejection", "KV", ...(focusedKvLoop ? [] : ["named-SQL"]), "scanner-safe inert GET", "explicit activation", "non-extractable holder key", "signed challenge/session/read verification", "durable binding restart/recovery", "corrupt journal fail-closed", "production CSP/rewrites/headers", "accessibility/mobile"], negativeBoundaryCases: focusedKvLoop ? [] : ["authoritative binding propagation", "forged policy challenge", "misbound read response", "source/resource/action/recipient/digest/expiry substitution", "terminal claim states", "activation replay", "concurrent/cross-process store behavior"] };
      for (const [index, fixture] of fixtures.entries()) {
        const selected = capabilities.capabilities.find((candidate) => candidate.source?.kind === fixture.kind); if (selected === undefined) throw new Error(`no authenticated capability for ${fixture.kind}`); fixture.capabilityId = selected.capabilityId; fixture.mailArtifact = mailArtifact;
        if (focusedKvLoop) {
          await runBrowserCase(instance, targets, fixture, decodeBase64(credentialsDescriptor.issuerPublicKey, "issuer public key descriptor"), index, {}, 0, resendProvider);
          continue;
        }
        const responseMutation = fixture.kind === "kv" ? { path: "/share/v1/policy/challenges", mutate: (body) => { body.proof.signature = `${body.proof.signature.slice(0, -1)}A`; } } : { path: "/share/v1/read", mutate: (body) => { body.readJti = `${body.readJti.slice(0, -1)}A`; } };
        try {
          await runBrowserCase(instance, targets, fixture, decodeBase64(credentialsDescriptor.issuerPublicKey, "issuer public key descriptor"), index, { responseMutation, expectReject: true }, 0, resendProvider); await runBrowserCase(instance, targets, fixture, decodeBase64(credentialsDescriptor.issuerPublicKey, "issuer public key descriptor"), index + fixtures.length, {}, 1, resendProvider);
        } catch (error) {
          const providerArtifact = await readFile(mailArtifact, "utf8").catch(() => "");
          const dstackEvents = runEvents.filter((event) => event.type === "dstack-request" || event.type === "dstack-response");
          throw new Error(`${error instanceof Error ? error.message : String(error)}\nProvider capture records: ${providerArtifact.split("\n").filter(Boolean).length}\nDstack events: ${JSON.stringify(dstackEvents.slice(-16))}\nShare host stages:\n${diagnosticOutput(production?.host.output())}\nNode stages:\n${diagnosticOutput(node.output())}\nOpenCredentials stages:\n${diagnosticOutput(credentials.output())}`);
        }
      }
    } finally { await instance.close(); }
    if (focusedKvLoop) await assertFocusedOutbox(postgres);
    await stopOwned([production.host]); production = undefined;
    production = await startHost();
    const journalLines = (await readFile(bindingStorePath, "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line)); if (journalLines.length < fixtures.length || journalLines.some((record) => record.op !== "put")) throw new Error("durable binding journal did not contain committed records");
    const recovered = await fetch(`${production.url}/.well-known/tinycloud-share/bindings/${journalLines[0].cid}`); if (recovered.status !== 200) throw new Error("durable binding was not recovered after Share restart");
    await stopOwned([production.host]); production = undefined; await appendFile(bindingStorePath, "{corrupt\n", "utf8");
    const corruptPort = await freePort(); const corrupt = spawnOwnedArgs("npm", ["run", "start:deploy"], shareRoot, { ...deployEnv, HOST: "127.0.0.1", PORT: String(corruptPort) }); owned.push(corrupt); await waitForPort(corruptPort, "corrupt-journal Share host"); const corruptResponse = await fetch(`http://127.0.0.1:${corruptPort}/.well-known/tinycloud-share/bindings/${validShareCid}`); if (corruptResponse.status !== 400) throw new Error(`corrupt binding journal did not fail closed (${corruptResponse.status})`); await stopOwned([corrupt]);
  } finally { await cleanup(); if (activeCleanup === cleanup) activeCleanup = undefined; }
}

async function mountedGate() {
  const owned = [];
  const tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-share-production-"));
  try {
  const scopePath = required(arg("scope-file") ?? process.env.SHARE_EMAIL_SCOPE_FILE, "SHARE_EMAIL_SCOPE_FILE");
  const mailArtifact = required(arg("mail-artifact") ?? process.env.SHARE_EMAIL_MAIL_ARTIFACT, "SHARE_EMAIL_MAIL_ARTIFACT");
  const nodeUrl = required(arg("node-url") ?? process.env.TINYCLOUD_NODE_URL, "TINYCLOUD_NODE_URL");
  const credentialsUrl = required(arg("credentials-url") ?? process.env.OPENCREDENTIALS_URL, "OPENCREDENTIALS_URL");
  const deployEnvFile = required(process.env.SHARE_DEPLOY_ENV_FILE, "SHARE_DEPLOY_ENV_FILE");
  const deployEnv = Object.fromEntries((await readFile(deployEnvFile, "utf8")).split("\n").filter((line) => line.trim() !== "" && !line.trim().startsWith("#")).map((line) => { const at = line.indexOf("="); if (at <= 0) throw new Error("invalid Share deployment env file"); return [line.slice(0, at), line.slice(at + 1)]; }));
  const port = await freePort();
  const effectiveDeployEnv = { ...process.env, ...deployEnv, SHARE_BINDING_STORE_PATH: join(tempRoot, "bindings.ndjson") };
  if (effectiveDeployEnv.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true" || effectiveDeployEnv.SHARE_TEST_BINDINGS_JSON !== undefined || effectiveDeployEnv.SHARE_SESSION_SECRET !== undefined) throw new Error("production Share env contains a fixture-only control");
  await run("node", ["scripts/validate-deploy-config.mjs"], shareRoot, effectiveDeployEnv);
  const host = spawnOwned("npm run start:deploy", shareRoot, { ...effectiveDeployEnv, HOST: "127.0.0.1", PORT: String(port) });
  owned.push(host);
  const shareUrl = `http://127.0.0.1:${port}`;
  await waitForPort(port, "production Share host");
  const validShareCid = `bafkrei${"a".repeat(52)}`;
  for (const path of ["/share", "/share.html", "/viewer", "/viewer.html", `/s/${validShareCid}`]) {
    const response = await fetch(`${shareUrl}${path}`);
    if (response.status !== 200) throw new Error(`production Share rewrite failed for ${path}: ${response.status}`);
    const headers = Object.fromEntries(response.headers);
    if (headers["cache-control"] !== "no-store" || headers["referrer-policy"] !== "no-referrer" || headers["x-content-type-options"] !== "nosniff") throw new Error(`production Share security headers missing for ${path}`);
    if ((path === "/share" || path === "/share.html" || path === "/viewer" || path === "/viewer.html" || path.startsWith("/s/")) && !headers["content-security-policy"]?.includes("connect-src")) throw new Error(`production Share trust-derived CSP missing for ${path}`);
  }
  const fixtureValue = JSON.parse(await readFile(scopePath, "utf8"));
  const fixtures = Array.isArray(fixtureValue) ? fixtureValue : (fixtureValue.cases ?? [fixtureValue]);
  if (fixtures.length < 2) throw new Error("mounted gate requires both KV and named-SQL cases");
  const descriptorResponse = await fetch(`${shareUrl}/api/share/capabilities`);
  if (descriptorResponse.status !== 401) throw new Error("production Share host exposed capabilities before authentication");
  const targets = { node: nodeUrl, credentials: credentialsUrl, registry: new URL(canonical.registry), vite: shareUrl };
  await waitForUrl(new URL("/healthz", nodeUrl), "Node");
  await waitForUrl(new URL("/health", credentialsUrl), "OpenCredentials");
  const browser = providerModule();
  const instance = await browser.launch({ headless: true, ...(process.env.BROWSER_EXECUTABLE ? { executablePath: process.env.BROWSER_EXECUTABLE } : {}), ignoreHTTPSErrors: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  try {
      const authPage = await instance.newPage();
      await installInterception(authPage, targets, {});
      await authPage.goto(`${canonical.share}/share.html`, { waitUntil: "networkidle0" });
      if (await authPage.$('input[name="username"]') === null) throw new Error("clean browser did not reach the authenticated Share login boundary");
      await authPage.type('input[name="username"]', required(process.env.SHARE_E2E_USERNAME, "SHARE_E2E_USERNAME"));
      await authPage.type('input[name="password"]', required(process.env.SHARE_E2E_PASSWORD, "SHARE_E2E_PASSWORD"));
      await authPage.click('button[type="submit"]'); await authPage.waitForSelector('input[name="email"]', { timeout: 30_000 });
      const capabilities = await authPage.evaluate(async () => (await fetch("/api/share/capabilities", { credentials: "include" })).json());
      await authPage.close();
      const issuerPublicKey = decodeBase64(required(deployEnv.SHARE_ISSUER_PUBLIC_KEY, "SHARE_ISSUER_PUBLIC_KEY"), "issuer public key");
      runCoverage = { ...runCoverage, fixtures: fixtures.length * 2, sources: fixtures.map((fixture) => fixture.kind), browser: ["production Share host", "clean-browser authentication", "per-user capability selection", "KV", "named-SQL", "scanner-safe inert GET", "explicit activation", "non-extractable holder key", "signed challenge/session/read verification", "durable binding restart/recovery", "production CSP/rewrites/headers", "accessibility/mobile"], negativeBoundaryCases: ["cross-user capability selection", "authoritative binding propagation", "forged policy challenge", "misbound read response", "terminal claim states", "activation replay"] };
      if (!Array.isArray(capabilities.capabilities) || capabilities.capabilities.length < 2) throw new Error("authenticated production Share host did not expose both per-user capabilities");
      for (const [index, fixture] of fixtures.entries()) {
        const selected = capabilities.capabilities.find((candidate) => candidate.source?.kind === fixture.kind);
        if (selected === undefined) throw new Error(`no authenticated capability for ${fixture.kind}`);
        fixture.capabilityId = selected.capabilityId;
        fixture.mailArtifact = mailArtifact;
        const responseMutation = fixture.kind === "kv"
          ? { path: "/share/v1/policy/challenges", mutate: (body) => { body.proof.signature = `${body.proof.signature.slice(0, -1)}A`; } }
          : { path: "/share/v1/read", mutate: (body) => { body.readJti = `${body.readJti.slice(0, -1)}A`; } };
        await runBrowserCase(instance, targets, fixture, issuerPublicKey, index, { responseMutation, expectReject: true }, 0);
        await runBrowserCase(instance, targets, fixture, issuerPublicKey, index + fixtures.length, {}, 1);
      }
    } catch (error) { throw error; }
    finally { await instance.close(); }
  } finally {
    await stopOwned(owned);
    ownedProcessCleanup = { stopped: owned.length, remaining: [], complete: true };
    await rm(tempRoot, { recursive: true, force: true });
    activeCleanup = undefined;
  }
}

async function writeRunRecord(exitStatus, errorMessage) {
  await mkdir(resolve(runRecordPath, ".."), { recursive: true });
  const endedAt = new Date();
  const heads = {};
  for (const [name, repo, cwd] of [["share", process.env.SHARE_RELEASE_HEAD, shareRoot], ["node", process.env.TINYCLOUD_NODE_RELEASE_HEAD, nodeRoot], ["opencredentials", process.env.OPEN_CREDENTIALS_RELEASE_HEAD, credentialsRoot]]) {
    heads[name] = { expected: repo ?? null, actual: await runCapture("git", ["rev-parse", "HEAD"], cwd).then((value) => value.trim()).catch(() => null) };
  }
  const logBytes = Buffer.from(JSON.stringify({ runId, events: runEvents }, null, 2) + "\n", "utf8");
  await writeFile(runLogPath, logBytes, { encoding: "utf8", flag: "wx" });
  const artifactPaths = ["test/vectors/email-claim-v1/manifest.json", "package-lock.json", "test/e2e-email/integration.mjs"];
  const artifacts = {};
  for (const relative of artifactPaths) {
    const bytes = await readFile(resolve(shareRoot, relative));
    artifacts[relative] = { sha256: digestBytes(bytes), bytes: bytes.byteLength };
  }
  const artifactHash = digestBytes(JSON.stringify({ heads, artifacts, coverage: runCoverage, logDigest: digestBytes(logBytes) }));
  const record = {
    schema: "tinycloud.share-email-claim/joined-run-v1",
    immutable: true,
    runId,
    command: process.argv.join(" "),
    start: runStartedAt.toISOString(),
    end: endedAt.toISOString(),
    durationMs: endedAt.getTime() - runStartedAt.getTime(),
    exitStatus,
    heads,
    log: { path: runLogPath, digest: digestBytes(logBytes), bytes: logBytes.byteLength },
    artifactHash,
    artifacts,
    toolVersions: {
      node: process.version,
      npm: await runCapture("npm", ["--version"], shareRoot).then((value) => value.trim()).catch(() => null),
      git: await runCapture("git", ["--version"], shareRoot).then((value) => value.trim()).catch(() => null),
      cargo: await runCapture("cargo", ["--version"], shareRoot).then((value) => value.trim()).catch(() => null),
      chromium: process.env.BROWSER_EXECUTABLE ?? "puppeteer-managed",
    },
    coverage: runCoverage,
    cleanup: ownedProcessCleanup,
    error: errorMessage ?? null,
  };
  record.recordDigest = digestBytes(JSON.stringify(record));
  await writeFile(runRecordPath, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
}

try {
  if (process.argv.includes("--fixture-only")) {
    await fixtureGate();
    console.error("email-claim fixture-backed browser gate: PASS");
  } else {
    if (!process.argv.includes("--mounted-only") && !process.argv.includes("--hermetic-only")) await nativeGate();
    await productionGateHermetic();
    console.error(`email-claim continuous production gate: PASS (${expectedManifestDigest})`);
  }
} catch (error) {
  console.error(`email-claim continuous production gate: BLOCKED — ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
  await writeRunRecord(1, error instanceof Error ? error.message : String(error));
}
if (process.exitCode === undefined) {
  await writeRunRecord(0, null);
}
