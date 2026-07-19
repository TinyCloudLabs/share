#!/usr/bin/env node

/*
 * Continuous email-claim gate.
 *
 * The service URLs are deliberately supplied by the mounted fixtures rather
 * than invented here.  The browser still runs at the production Share origin
 * and all production endpoint URLs remain unchanged; Puppeteer only routes
 * those requests to the ephemeral fixture listeners.  This keeps the same
 * origin, CSP, URL scrub, WebCrypto, signed-response, and browser lifecycle
 * boundary while making the test deterministic and offline-capable.
 */

import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { createConnection, createServer } from "node:net";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
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
  node: "https://node.example",
  credentials: "https://witness.credentials.org",
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

function diagnosticOutput(value) {
  return value.replace(/("(?:senderPrivateKey|privateKey|claimSecret|secret|password|token|authorization)"\s*:\s*")[^"]*(")/gi, "$1[REDACTED]$2").slice(-4_000);
}

function run(command, args, cwd, extraEnv = {}) {
  console.error(`$ ${command} ${args.join(" ")}`);
  const result = spawn(command, args, { cwd, stdio: "inherit", env: { ...process.env, ...extraEnv } });
  return new Promise((resolveResult, reject) => {
    result.once("error", reject);
    result.once("exit", (code, signal) => resolveResult(code === 0 ? undefined : new Error(`${command} exited ${code ?? signal}`)));
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

function runCapture(command, args, cwd) {
  const child = spawn(command, args, { cwd, env: process.env });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  return new Promise((resolveResult, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolveResult(stdout) : reject(new Error(`${command} failed (${code}): ${stderr.slice(0, 800)}`)));
  });
}

async function nativeGate() {
  await cleanAndExact(shareRoot, process.env.SHARE_RELEASE_HEAD, "Share");
  await cleanAndExact(nodeRoot, process.env.TINYCLOUD_NODE_RELEASE_HEAD, "tinycloud-node");
  await cleanAndExact(credentialsRoot, process.env.OPEN_CREDENTIALS_RELEASE_HEAD, "OpenCredentials");
  await assertContractCommit(shareRoot);
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
  await run("cargo", ["test", "--manifest-path", resolve(nodeRoot, "test/n4-mounted-e2e/Cargo.toml")], nodeRoot);
  await run("cargo", ["test", "--workspace", "--exclude", "tinycloud-sdk-wasm", "--exclude", "siwe"], nodeRoot);
  await run("cargo", ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"], nodeRoot);
  await run("cargo", ["fmt", "--check"], credentialsRustRoot);
  await run("cargo", ["test", "--bin", "opencredentials-witness"], credentialsRustRoot);
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
}

function spawnOwned(command, cwd, extraEnv = {}) {
  const child = spawn(command, { cwd, shell: true, env: { ...process.env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  const collect = (chunk) => { output += String(chunk); if (output.length > 128_000) output = output.slice(-128_000); };
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  return { child, output: () => output, done: new Promise((resolveDone) => child.once("exit", resolveDone)) };
}

function spawnOwnedArgs(command, args, cwd, extraEnv = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  const collect = (chunk) => {
    const text = String(chunk);
    output += text;
    if (text.includes("mounted session:") || text.includes("mounted policy session:")) console.error(`owned fixture: ${text.trim().slice(0, 400)}`);
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
    if (process?.child.exitCode !== null) throw new Error(`${label} exited before publishing a descriptor: ${diagnosticOutput(process.output())}`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`${label} descriptor was not published: ${lastError}`);
}

async function waitForDescriptor(process, label) {
  const deadline = Date.now() + 300_000;
  while (Date.now() < deadline) {
    for (const line of process.output().split("\n").reverse()) {
      try { const value = JSON.parse(line); if (value?.testOnly === true) return value; }
      catch { /* cargo diagnostics and tracing share the captured stream */ }
    }
    if (process.child.exitCode !== null) throw new Error(`${label} exited before publishing a descriptor`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
  throw new Error(`${label} descriptor was not published`);
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
  const port = await freePort();
  const server = spawnOwnedArgs("postgres", ["-D", dataDir, "-h", "127.0.0.1", "-p", String(port)], shareRoot);
  owned.push(server);
  await waitForPort(port, "PostgreSQL");
  return { url: `postgres://email_claim@127.0.0.1:${port}/postgres`, dataDir };
}

async function stopOwned(owned) {
  await Promise.all(owned.slice().reverse().map(async ({ child, done }) => {
    if (child.exitCode !== null) return;
    child.kill("SIGTERM");
    await Promise.race([done, new Promise((resolveStop) => setTimeout(resolveStop, 5_000))]);
    if (child.exitCode === null) child.kill("SIGKILL");
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
  if (typeof scope.senderPrivateKey === "string") scope.senderPrivateKey = decodeBase64(scope.senderPrivateKey, "scope.senderPrivateKey");
  else if (Array.isArray(scope.senderPrivateKey)) scope.senderPrivateKey = new Uint8Array(scope.senderPrivateKey);
  else throw new Error("scope.senderPrivateKey is required");
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
  if (parsed.origin === canonical.share) {
    const registryPath = parsed.pathname === "/registry" || parsed.pathname.startsWith("/registry/");
    const path = registryPath
      ? parsed.pathname.slice("/registry".length) || "/"
      : `${parsed.pathname}${parsed.search}`;
    return registryPath ? new URL(path, targets.registry).toString() : new URL(path, targets.vite).toString();
  }
  return undefined;
}

async function installInterception(page, targets, fixtureConfig = {}) {
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const parsed = new URL(request.url());
    if (parsed.origin === canonical.share && parsed.pathname === "/.well-known/tinycloud-share/config.json") {
      void request.respond({ status: 200, contentType: "application/json", headers: { "cache-control": "no-store" }, body: JSON.stringify(fixtureConfig.publicConfig) });
      return;
    }
    if (parsed.origin === canonical.share && parsed.pathname === "/api/share/capability") {
      void request.respond({ status: 200, contentType: "application/json", headers: { "cache-control": "no-store" }, body: JSON.stringify(fixtureConfig.capability) });
      return;
    }
    if (parsed.origin === canonical.share && parsed.pathname.startsWith("/.well-known/tinycloud-share/bindings/")) {
      void request.respond({ status: 200, contentType: "application/json", headers: { "cache-control": "no-store" }, body: JSON.stringify(fixtureConfig.binding) });
      return;
    }
    if (parsed.origin === canonical.node && parsed.pathname === "/share/v1/invitations/authorize" && fixtureConfig.binding !== undefined) {
      try {
        const body = JSON.parse(request.postData() ?? "{}").request;
        if (typeof body?.policyCid === "string") fixtureConfig.binding.policyCid = body.policyCid;
        if (typeof body?.shareId === "string") fixtureConfig.binding.shareId = body.shareId;
      } catch { /* the real Node response remains authoritative */ }
    }
    const target = canonicalRequestTarget(request.url(), targets);
    if (target === undefined) { void request.continue(); return; }
    void request.continue({ url: target });
  });
}

async function readCapture(path) {
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

async function waitForCapture(path, after) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const found = emittedLink(await readCapture(path), after);
    if (found !== undefined) return found;
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  throw new Error("delivery fixture did not capture a rendered message");
}

function bodyFromLink(href) {
  const parsed = new URL(href);
  const values = new URLSearchParams(parsed.hash.slice(1));
  return { invitationId: values.get("i"), claimSecret: values.get("c") };
}

async function postJson(base, path, body) {
  return fetch(new URL(path, base), { method: "POST", headers: { "content-type": "application/json", origin: canonical.share }, body: JSON.stringify(body) });
}

async function runBrowserCase(browser, targets, fixture, issuerPublicKey, caseIndex) {
  const scope = cloneScope(fixture.scope ?? fixture);
  const source = fixture.source ?? scope.source;
  if (source === undefined) throw new Error(`case ${caseIndex}: source is missing`);
  scope.expectedRecipientEmail = fixture.email ?? scope.expectedRecipientEmail;
  scope.expectedContentSourceDigest = fixture.contentSourceDigest ?? scope.expectedContentSourceDigest;
  if (typeof scope.expectedRecipientEmail !== "string" || typeof scope.expectedContentSourceDigest !== "string") throw new Error(`case ${caseIndex}: expected recipient/digest are required`);
  const before = (await readCapture(fixture.mailArtifact)).length;
  const browserScope = { ...scope, senderPrivateKey: Array.from(scope.senderPrivateKey), trustedNode: { ...scope.trustedNode, invitationPublicKey: Array.from(scope.trustedNode.invitationPublicKey) } };
  const publicConfig = {
    version: "tinycloud.share-email-claim/config-v1",
    shareOrigin: canonical.share,
    registryOrigin: canonical.share,
    nodeOrigin: canonical.node,
    credentialsOrigin: canonical.credentials,
    nodeAudience: "did:web:node.example",
    issuerDid: "did:web:issuer.credentials.org",
    issuerVct: "opencredentials.email/v1",
    nodeInvitationKid: scope.trustedNode.invitationKid,
    nodeInvitationPublicKey: Buffer.from(scope.trustedNode.invitationPublicKey).toString("base64url"),
    issuerPublicKey: Buffer.from(issuerPublicKey).toString("base64url"),
  };
  const capability = { scope: { ...browserScope, trustedNode: { ...browserScope.trustedNode, invitationPublicKey: Array.from(scope.trustedNode.invitationPublicKey) } }, source };
  const binding = {
    shareId: "pending",
    policyCid: "pending",
    recipientEmail: scope.expectedRecipientEmail,
    expiry: new Date(fixture.expiresAt ?? Date.now() + 3_600_000).toISOString(),
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
    contentSource: source,
    contentSourceDigest: scope.expectedContentSourceDigest,
    action: source.action,
    resource: source.path,
  };

  const sender = await browser.newPage();
  await sender.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  sender.on("console", (message) => { if (message.type() === "error") console.error(`sender console: ${message.text()}`); });
  sender.on("pageerror", (error) => console.error(`sender page error: ${error.message}`));
  sender.on("requestfailed", (request) => console.error(`sender request failed: ${request.url()} ${request.failure()?.errorText ?? "unknown"}`));
  sender.on("response", (response) => { if (response.request().method() === "OPTIONS") return; if (/\/v1\/share-email\/invitations/.test(response.url())) void response.text().then((body) => console.error(`sender delivery response: ${response.status()} ${response.url()} ${body.slice(0, 2000)}`)); else if (response.status() >= 400 && /node\.example|credentials\.org|127\.0\.0\.1/.test(response.url())) void response.text().then((body) => console.error(`sender response: ${response.status()} ${response.url()} ${body.slice(0, 500)}`)); });
  await installInterception(sender, targets, { publicConfig, capability, binding });
  await sender.goto(`${canonical.share}/share.html`, { waitUntil: "networkidle0" });
  const emailInput = await sender.$('input[name="email"]');
  if (emailInput === null) throw new Error(`case ${caseIndex}: sender did not mount at ${sender.url()} (${await sender.content().catch(() => "no document")})`);
  const senderA11y = await sender.evaluate(() => ({ overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth, labelled: Array.from(document.querySelectorAll("input,select,textarea")).every((input) => input.id !== "" || input.closest("label") !== null), status: document.querySelector("[data-sender-status]")?.getAttribute("role") }));
  if (senderA11y.overflow || !senderA11y.labelled || senderA11y.status !== "status") throw new Error(`case ${caseIndex}: sender accessibility/mobile assertion failed`);
  await sender.type('input[name="email"]', scope.expectedRecipientEmail);
  const expiry = fixture.expiresAt === undefined ? new Date(Date.now() + 3_600_000) : new Date(fixture.expiresAt);
  const expiryInput = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  await sender.$eval('input[name="expiry"]', (input, value) => { input.value = value; input.dispatchEvent(new Event("input", { bubbles: true })); input.dispatchEvent(new Event("change", { bubbles: true })); }, expiryInput);
  await sender.click('button[type="submit"]');
  try {
    await sender.waitForFunction(() => document.querySelector("[data-sender-status]")?.getAttribute("data-state") === "requested", { timeout: 30_000 });
  } catch {
    throw new Error(`case ${caseIndex}: sender status ${await sender.$eval("[data-sender-status]", (node) => node.outerHTML).catch(() => "missing")}`);
  }
  await sender.close();

  const captured = await waitForCapture(fixture.mailArtifact, before);
  const link = captured.href;
  const mailbox = bodyFromLink(link);
  if (mailbox.invitationId === null || mailbox.claimSecret === null) throw new Error(`case ${caseIndex}: malformed captured link`);
  const inert = await fetch(new URL(`/v1/share-email/claims/activate?invitationId=${mailbox.invitationId}&claimSecret=${mailbox.claimSecret}`, targets.credentials), { headers: { origin: canonical.share } });
  if (inert.status !== 200) throw new Error(`case ${caseIndex}: inert scanner GET was not accepted as read-only (${inert.status})`);

  const recipient = await browser.createBrowserContext();
  const page = await recipient.newPage();
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  page.on("console", (message) => {
    if (message.type() === "error" && message.text().startsWith("share test:")) console.error(`recipient ${message.text()}`);
  });
  page.on("response", (response) => {
    if (response.request().method() === "OPTIONS" || !/node\.example|credentials\.org/.test(response.url())) return;
    void response.text().then((body) => {
      let parsed;
      try { parsed = JSON.parse(body); } catch { parsed = undefined; }
      const errorCode = parsed?.error?.code;
      const keys = parsed !== undefined && typeof parsed === "object" && parsed !== null ? Object.keys(parsed).sort().join(",") : "non-json";
      console.error(`recipient response: ${response.request().method()} ${response.url()} ${response.status()} keys=${keys}${typeof errorCode === "string" ? ` error=${errorCode}` : ""}`);
    }).catch(() => {});
  });
  await installInterception(page, targets, { publicConfig, capability, binding });
  await page.goto(link, { waitUntil: "networkidle0" });
  try { await page.waitForFunction(() => location.hash === "" && location.search === "" && document.body.textContent?.includes("Open document"), { timeout: 30_000 }); }
  catch { throw new Error(`case ${caseIndex}: recipient did not reach explicit activation state at ${page.url().split(/[?#]/)[0]}: ${(await page.evaluate(() => document.body.textContent ?? "")).slice(0, 600)}`); }
  const scrubbed = await page.evaluate(() => ({ href: location.href, body: document.body.textContent ?? "" }));
  if (scrubbed.href.includes("#") || scrubbed.href.includes("?")) throw new Error(`case ${caseIndex}: invitation URL was not scrubbed synchronously`);
  const recipientA11y = await page.evaluate(() => ({ overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth, live: document.querySelector("[aria-live]") !== null, primary: document.querySelector("button.viewer-primary-action")?.textContent }));
  if (recipientA11y.overflow || !recipientA11y.live || recipientA11y.primary !== "Open document") throw new Error(`case ${caseIndex}: recipient accessibility/mobile assertion failed`);
  await page.click("button.viewer-primary-action");
  try {
    await page.waitForFunction((marker) => {
      const renderedMarker = marker.replace(/^#+\s*/, "").trim();
      if ((document.body.textContent ?? "").includes(renderedMarker)) return true;
      return Array.from(document.querySelectorAll("iframe")).some((frame) => {
        try {
          return (frame.contentDocument?.body?.textContent ?? "").includes(renderedMarker)
            || (frame.getAttribute("srcdoc") ?? "").includes(renderedMarker);
        } catch { return (frame.getAttribute("srcdoc") ?? "").includes(renderedMarker); }
      });
    }, { timeout: 30_000 }, fixture.expectedContent ?? source.path);
  }
  catch { throw new Error(`case ${caseIndex}: recipient did not render content: ${(await page.evaluate(() => JSON.stringify({ body: document.body.textContent ?? "", url: location.href, secure: isSecureContext, subtle: typeof crypto?.subtle }))).slice(0, 900)}`); }
  await recipient.close();

  const replay = await postJson(targets.credentials, "/v1/share-email/claims/activate", mailbox);
  if (replay.ok) throw new Error(`case ${caseIndex}: activation replay unexpectedly succeeded`);
  const postClaimCaptureCount = (await readCapture(fixture.mailArtifact)).length;
  const resendAfterClaim = await postJson(targets.credentials, "/v1/share-email/invitations/resend", mailbox);
  if (!resendAfterClaim.ok) throw new Error(`case ${caseIndex}: post-claim resend lost accepted-shaped response (${resendAfterClaim.status})`);
  await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
  if ((await readCapture(fixture.mailArtifact)).length !== postClaimCaptureCount) throw new Error(`case ${caseIndex}: claimed invitation emitted a resend`);
}

async function mountedGate() {
  const owned = [];
  const tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-email-claim-"));
  const scopePath = arg("scope-file") ?? process.env.SHARE_EMAIL_SCOPE_FILE ?? join(tempRoot, "node.json");
  const mailArtifact = arg("mail-artifact") ?? process.env.SHARE_EMAIL_CAPTURE_ARTIFACT ?? join(tempRoot, "mail.ndjson");
  let postgres;
  let nodeUrl = arg("node-url") ?? process.env.TINYCLOUD_NODE_URL;
  let credentialsUrl = arg("credentials-url") ?? process.env.OPENCREDENTIALS_URL;
  let nodeDescriptor;
  let credentialsDescriptor;
  const cleanup = async () => { await stopOwned(owned); await rm(tempRoot, { recursive: true, force: true }); };
  activeCleanup = cleanup;
  try {
    if (nodeUrl === undefined) {
      const node = arg("node-command") === undefined
        ? spawnOwnedArgs("cargo", ["run", "--quiet", "-p", "tinycloud-node-n4-mounted-fixture", "--", "--descriptor", scopePath, "--issuer-public-key", "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY"], nodeRoot)
        : spawnOwned(arg("node-command"), nodeRoot);
      owned.push(node);
      nodeDescriptor = await waitForFileJson(scopePath, "TinyCloud Node", node);
      nodeUrl = required(nodeDescriptor.url, "Node descriptor URL");
    } else nodeDescriptor = JSON.parse(await readFile(scopePath, "utf8"));
    const trustedKey = nodeDescriptor.trustedNode?.invitationPublicKey;
    if (typeof trustedKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(trustedKey)) throw new Error(`mounted Node enrollment key is missing or non-canonical: ${trustedKey ?? "missing"}`);
    if (credentialsUrl === undefined) {
      postgres = await startPostgres(owned, tempRoot);
      const credentials = arg("credentials-command") === undefined
        ? spawnOwnedArgs("cargo", ["run", "--quiet", "--manifest-path", resolve(credentialsRustRoot, "Cargo.toml"), "--features", "email-claim-fixture", "--bin", "email-claim-fixture"], credentialsRustRoot, {
        EMAIL_CLAIM_FIXTURE_DATABASE_URL: postgres.url,
        SHARE_EMAIL_CAPTURE_ARTIFACT: mailArtifact,
        SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY: trustedKey,
        })
        : spawnOwned(arg("credentials-command"), credentialsRustRoot, {
          EMAIL_CLAIM_FIXTURE_DATABASE_URL: postgres.url,
          SHARE_EMAIL_CAPTURE_ARTIFACT: mailArtifact,
          SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY: trustedKey,
        });
      owned.push(credentials);
      credentialsDescriptor = await waitForDescriptor(credentials, "OpenCredentials");
      credentialsUrl = required(credentialsDescriptor.url, "OpenCredentials descriptor URL");
    }
    if (!existsSync(scopePath)) throw new Error(`scope fixture is missing: ${scopePath}`);
    const fixtureValue = JSON.parse(await readFile(scopePath, "utf8"));
    const fixtures = Array.isArray(fixtureValue) ? fixtureValue : (fixtureValue.cases ?? [fixtureValue]);
    if (fixtures.length < 2) throw new Error("mounted gate requires both KV and named-SQL cases");
    let registryUrl = arg("registry-url") ?? process.env.SHARE_REGISTRY_URL;
    if (registryUrl === undefined) {
      const registryProcess = arg("registry-command") === undefined
        ? spawnOwned("npm run -w @tinycloud/share-registry dev-server -- --port 0", shareRoot)
        : spawnOwned(arg("registry-command"), shareRoot);
      owned.push(registryProcess);
      const deadline = Date.now() + 30_000;
      while (registryUrl === undefined && Date.now() < deadline) { const match = registryProcess.output().match(/http:\/\/127\.0\.0\.1:\d+/); if (match) registryUrl = match[0]; else await new Promise((resolveWait) => setTimeout(resolveWait, 100)); }
      if (registryUrl === undefined) throw new Error("Share registry did not publish a bound URL");
    }
    registryUrl = required(registryUrl, "registry URL");
    let vite;
    if (arg("vite-command") === undefined) {
      await run("npm", ["run", "build"], shareRoot, { VITE_SHARE_REGISTRY_URL: `${canonical.share}/registry` });
      vite = spawnOwned("npm run preview -- --host 127.0.0.1 --port 0", shareRoot, { VITE_SHARE_REGISTRY_URL: `${canonical.share}/registry` });
    } else vite = spawnOwned(arg("vite-command"), shareRoot, { VITE_SHARE_REGISTRY_URL: `${canonical.share}/registry` });
    owned.push(vite);
    const viteMatch = await (async () => { const deadline = Date.now() + 30_000; while (Date.now() < deadline) { const match = vite.output().match(/https?:\/\/127\.0\.0\.1:\d+/); if (match) return match[0]; await new Promise((resolveWait) => setTimeout(resolveWait, 100)); } throw new Error("Share Vite fixture did not publish a bound URL"); })();
    const targets = { node: nodeUrl, credentials: credentialsUrl, registry: registryUrl, vite: viteMatch };
    await waitForUrl(new URL("/healthz", nodeUrl), "Node");
    await waitForUrl(new URL("/health", credentialsUrl), "OpenCredentials");
    const browser = providerModule();
    const instance = await browser.launch({ headless: true, ...(process.env.BROWSER_EXECUTABLE ? { executablePath: process.env.BROWSER_EXECUTABLE } : {}), ignoreHTTPSErrors: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    try {
      for (const [index, fixture] of fixtures.entries()) {
        fixture.mailArtifact = mailArtifact;
        const issuerPublicKey = credentialsDescriptor?.issuerPublicKey ?? nodeDescriptor.issuerPublicKey;
        await runBrowserCase(instance, targets, fixture, decodeBase64(issuerPublicKey, "issuer public key descriptor"), index);
      }
    } catch (error) { throw error; }
    finally { await instance.close(); }
  } finally {
    await cleanup();
    if (activeCleanup === cleanup) activeCleanup = undefined;
  }
}

try {
  await nativeGate();
  await mountedGate();
  console.error(`email-claim continuous mounted gate: PASS (${expectedManifestDigest})`);
} catch (error) {
  console.error(`email-claim continuous mounted gate: BLOCKED — ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
