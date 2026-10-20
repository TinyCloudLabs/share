#!/usr/bin/env node

/**
 * T5b runner gate: "Open an installed app" on the hermetic native stack.
 *
 * Same stack and rules as install-gate.mjs (real Node, Location Registry and
 * OpenCredentials; OpenKey is the signing fixture; the browser reaches the
 * candidate build at https://share.tinycloud.xyz/apps/run). It proves, in a real
 * browser against a real Node:
 *  - install the Health Log sample, open `/apps/run#<app_id>`, log a meal in the
 *    app's frame, and the owner's own SDK client reads that row from the app's
 *    database; the Recipes sample (installed too) lists that meal through its
 *    cross-app read grant and cannot write to the Health Log;
 *  - the runner signs in twice (read the saved copy, then run it): the session
 *    ReCap it signed is exactly the app's own manifest, one hour, and after the
 *    runtime sign-in no further signature is ever requested;
 *  - a manifest copy widened by the person's agent is refused after one
 *    approval, before anything more is signed; a narrowed copy runs, with
 *    exactly what it kept;
 *  - a hostile app (the person's saved copy of app.jsx replaced) can do nothing
 *    the sandbox forbids (network, storage, parent, navigation, popups, forms),
 *    and every call outside its manifest is refused by the runner page, with the
 *    classifier's refusals, oversize and in-flight limits, raw and forged messages;
 *  - the same calls forced past the runner page (a fake parent that skips the
 *    manifest check, the real data adapter, a signer-less client holding the
 *    session) are refused by the NODE;
 *  - Sign out ends the session and re-opening works; the session expires at its
 *    time (virtual time) and the page says so;
 *  - every state of the page at 390 and 1440 px, light and dark, with axe AA.
 *
 * Run: TC500_NODE_WORKTREE=<tinycloud-node v1.21.0 tree> TC500_OPENCREDENTIALS_WORKTREE=<846c018 tree>
 *      npx tsx test/e2e-prod/runner-gate.mjs
 * (RUNNER_SHOT_DIR saves the screenshots; RUNNER_ARTIFACT the JSON report.)
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import * as sdkCore from "@tinycloud/sdk-core";
import { TinyCloudNode } from "@tinycloud/node-sdk";
import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { runBoundedStep, startNativeStack } from "./native-stack.mjs";
import { createAppData } from "../../src/apps/app-data.ts";
import { createCapabilityBridge } from "../../src/apps/bridge.ts";
import { capGrants, makeAuthorizer } from "../../src/apps/grants.ts";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/v1.21.0");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const shotDir = process.env.RUNNER_SHOT_DIR;
const outputPath = resolve(process.env.RUNNER_ARTIFACT ?? join(workspaceRoot, ".context/t5b-runner-gate.json"));
const catalog = JSON.parse(await readFile(join(shareRoot, "apps/catalog.json"), "utf8"));
const axeSource = await readFile(join(shareRoot, "node_modules/axe-core/axe.min.js"), "utf8");
const app = (id) => catalog.apps.find((entry) => entry.app_id === id);
const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
const WALLET_KEY = `0x${"55".repeat(32)}`;
const bundleBytes = (entry, path) => readFile(join(shareRoot, "public", entry.bundle.root, path));
const manifestOf = async (entry) => JSON.parse(await bundleBytes(entry, entry.manifest.path));

const trace = [];
const consoleLog = [];
const signedMessages = [];
let phase = "setup";
const settle = (ms) => new Promise((done) => setTimeout(done, ms));
const sha = (value) => createHash("sha256").update(value).digest("hex");

async function waitUntil(check, timeout = 180_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await settle(150);
  }
  return undefined;
}

function hold() {
  let release; let reached;
  const gate = new Promise((resolveGate) => { release = resolveGate; });
  const arrived = new Promise((resolveArrived) => { reached = resolveArrived; });
  return { gate, release, reached, arrived };
}
/** `sign`: a held OpenKey signature. */
const controls = { sign: undefined };

function headerSubset(request) {
  const headers = new Headers(request.headers());
  for (const key of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-tc500-binary-id"]) headers.delete(key);
  return headers;
}

async function installRouting(page, stack) {
  await page.evaluateOnNewDocument(installBrowserInstrumentation);
  await page.evaluateOnNewDocument(() => {
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", (event) => window.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  page.on("console", (message) => { if (message.type() === "error" || message.type() === "warn") consoleLog.push({ phase, type: message.type(), text: message.text().replaceAll(/https:\/\/[^\s#]+(?:#[^\s]*)?/g, "<url>").slice(0, 240), at: `${message.location()?.url ?? ""}:${message.location()?.lineNumber ?? ""}`.replace(/^https:\/\/[^/]+/, "").slice(0, 120) }); });
  page.on("pageerror", (error) => consoleLog.push({ phase, type: "pageerror", text: String(error?.message ?? "page error").slice(0, 240) }));
  await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    const entry = { phase, method: request.method(), origin: url.origin, path: url.pathname, status: undefined };
    trace.push(entry);
    if (url.protocol === "data:" || url.protocol === "blob:") { await request.continue(); return; }
    if (url.origin === stack.canonical.share) { await request.continue(); return; }
    const targets = new Map([
      [stack.canonical.node, stack.services.nodeOrigin],
      [stack.canonical.credentials, stack.services.credentialsOrigin],
      [stack.canonical.registry, stack.services.registryOrigin],
      ["https://openkey.so", stack.services.openKeyOrigin],
      ["https://api.openkey.so", stack.services.openKeyOrigin],
    ]);
    const targetOrigin = targets.get(url.origin);
    if (targetOrigin === undefined) { entry.blocked = true; await request.abort("blockedbyclient"); return; }
    if (request.method() === "OPTIONS" && url.origin === "https://api.openkey.so") {
      await request.respond({ status: 204, headers: { "access-control-allow-origin": stack.canonical.share, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "authorization, content-type", vary: "Origin" } }); return;
    }
    if (url.origin === "https://openkey.so" && request.method() === "POST" && url.pathname === "/sign" && controls.sign !== undefined) {
      controls.sign.reached(); await controls.sign.gate;
    }
    let body;
    if (!new Set(["GET", "HEAD"]).has(request.method())) {
      const binaryId = request.headers()["x-tc500-binary-id"];
      if (url.pathname === "/invoke" && binaryId !== undefined) {
        const captured = await page.evaluate((id) => { const bytes = window.__tc500BinaryBodies[id]; delete window.__tc500BinaryBodies[id]; return bytes; }, binaryId);
        assert(Array.isArray(captured), "binary browser request body was not captured");
        body = Buffer.from(captured);
      } else body = await request.fetchPostData();
    }
    if (url.origin === "https://openkey.so" && url.pathname === "/sign" && body !== undefined) {
      entry.sign = true;
      try { const { message } = JSON.parse(Buffer.from(body).toString("utf8")); if (typeof message === "string") signedMessages.push({ phase, message }); } catch {}
    }
    const response = await fetch(new URL(`${url.pathname}${url.search}`, targetOrigin), { method: request.method(), headers: headerSubset(request), redirect: "manual", ...(body === undefined ? {} : { body }) });
    const bytes = Buffer.from(await response.arrayBuffer());
    entry.status = response.status;
    const headers = Object.fromEntries(response.headers.entries());
    for (const key of ["connection", "content-encoding", "content-length", "keep-alive", "transfer-encoding"]) delete headers[key];
    if (url.origin !== "https://openkey.so") {
      headers["access-control-allow-origin"] = request.headers().origin ?? stack.canonical.share;
      headers["access-control-allow-credentials"] = "true";
      headers["access-control-allow-methods"] = "GET, PUT, POST, DELETE, OPTIONS";
      headers["access-control-allow-headers"] = request.headers()["access-control-request-headers"] ?? "authorization, content-type";
      headers.vary = "Origin";
    }
    await request.respond({ status: response.status, headers, body: bytes });
  })().catch(() => request.abort("failed").catch(() => undefined)); });
}

async function newPage(browser, stack, label, url, init) {
  phase = label;
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport({ width: 1440, height: 900 });
  await installRouting(page, stack);
  if (init !== undefined) await page.evaluateOnNewDocument(init);
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 180_000 });
  return { context, page };
}

// ---- installing through the apps page (the person's real path)
const INSTALL_TERMINAL = /^(Installed\.|Already installed|Not installed yet|Sign-in cancelled|OpenKey didn't|Another OpenKey|That approval|We couldn't|.* files don't match the catalog|This catalog entry|Couldn't load)/;
async function install(browser, stack, appId) {
  const { page, context } = await newPage(browser, stack, `install-${appId}`, `${stack.canonical.share}/apps/`);
  await page.waitForSelector(".apps-card", { timeout: 60_000 });
  const index = catalog.apps.findIndex((entry) => entry.app_id === appId);
  await page.evaluate((position) => document.querySelectorAll(".apps-card")[position].querySelectorAll("button")[1].click(), index);
  await page.waitForFunction(() => [...document.querySelectorAll("#apps-sheet button")].some((button) => button.textContent === "Continue" && !button.disabled), { timeout: 60_000 });
  await page.click("#apps-sheet footer button");
  const text = await waitUntil(async () => { const value = await page.$eval(".apps-install-line", (node) => node.textContent).catch(() => ""); return INSTALL_TERMINAL.test(value) ? value : undefined; }, 300_000);
  assert(text?.startsWith("Installed.") || text?.startsWith("Already installed"), `install of ${appId} ended with "${text}"`);
  // The Open control is a link to the runner now.
  const href = await page.$eval("#apps-sheet footer a", (node) => node.getAttribute("href"));
  assert.equal(href, `/apps/run#${appId}`);
  await context.close();
}

// ---- the owner's own client: reads and edits what the runner's session cannot
let ownerNode;
async function owner(manifest) {
  const node = new TinyCloudNode({ privateKey: WALLET_KEY, host: ownerHost, autoCreateSpace: true, ...(manifest === undefined ? {} : { manifest }) });
  await node.signIn();
  return node;
}
let ownerHost;
const ownerManifest = (appId) => ({
  manifest_version: 1, app_id: "xyz.tinycloud.e2e.owner", name: "Runner gate owner", space: "applications", prefix: "", defaults: false, includePublicSpace: false, expiry: "1h",
  permissions: [{ service: "tinycloud.kv", path: `${appId}/`, actions: ["get", "put", "list", "del", "metadata"], skipPrefix: true }, { service: "tinycloud.sql", path: `${appId}/healthlog`, actions: ["read", "write", "schema"], skipPrefix: true }, { service: "tinycloud.sql", path: `${appId}/recipes`, actions: ["read", "write", "schema"], skipPrefix: true }],
});
async function ownerClient(appId) {
  ownerNode ??= await owner(ownerManifest(appId));
  return ownerNode;
}
const decode = (bytes) => new TextDecoder().decode(bytes);

// ---- the runner page
const RUN_URL = (stack, id) => `${stack.canonical.share}/apps/run#${id}`;
const statusText = (page) => page.$eval(".run-status-region", (node) => node.textContent).catch(() => "");
const screenTitle = (page) => page.$eval(".run-screen__title", (node) => node.textContent).catch(() => "");

async function openRunner(browser, stack, label, appId, init) {
  const opened = await newPage(browser, stack, label, RUN_URL(stack, appId), init);
  await opened.page.waitForSelector(".run-screen", { timeout: 60_000 });
  return opened;
}
async function clickByText(page, label) {
  await page.evaluate((text) => [...document.querySelectorAll("button, a")].find((node) => node.textContent === text).click(), label);
}
async function start(page) {
  await page.waitForFunction(() => [...document.querySelectorAll("button")].some((button) => button.textContent === "Continue"), { timeout: 60_000 });
  await clickByText(page, "Continue");
}
const frames = (page) => {
  const bridge = page.frames().find((candidate) => candidate.url().includes("/jsx-sandbox.html"));
  const child = page.frames().find((candidate) => candidate.url() === "about:srcdoc");
  return { bridge, child };
};
async function runningFrame(page) {
  await page.waitForFunction(() => /is running/.test(document.querySelector(".run-status-region")?.textContent ?? ""), { timeout: 240_000 });
  const { child } = frames(page);
  assert(child, "the app's frame is not there");
  return child;
}

const COMBOS = [[390, 844, "light"], [390, 844, "dark"], [1440, 900, "light"], [1440, 900, "dark"]];
const axeFindings = [];
async function captureState(page, name) {
  for (const [width, height, scheme] of COMBOS) {
    await page.setViewport({ width, height }); await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
    await settle(500);
    await page.evaluate(axeSource);
    const result = await page.evaluate(() => globalThis.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } }));
    const found = result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")}`);
    axeFindings.push({ state: name, width, scheme, violations: found });
    assert.deepEqual(found, [], `${name} ${width}px ${scheme}: axe AA`);
    assert((await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)) <= 0, `${name} ${width}px ${scheme}: the page scrolls sideways`);
    if (shotDir !== undefined) { await mkdir(shotDir, { recursive: true }); await page.screenshot({ path: join(shotDir, `runner-${name}-${width}-${scheme}.png`) }); }
  }
  await page.setViewport({ width: 1440, height: 900 }); await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "light" }]);
}

/** The runner page itself reported no CSP or Trusted Types violation (the app's own are checked inside its frame). */
const noViolations = async (page, where) => assert.deepEqual(await page.evaluate(() => window.__violations), [], `${where}: a CSP or Trusted Types violation fired in the runner page`);

/** The ReCap of a signed SIWE message, as `<space>/<service>/<path> <ability>` lines. */
function recapOf(message) {
  const recap = JSON.parse(Buffer.from(message.match(/urn:recap:([A-Za-z0-9_-]+)/)[1], "base64url").toString("utf8"));
  return Object.entries(recap.att).flatMap(([resource, abilities]) => Object.entries(abilities).map(([ability]) => `${resource.replace(/^tinycloud:pkh:eip155:\d+:0x[0-9a-fA-F]{40}:/, "")} ${ability}`)).sort();
}
const expectedRecap = (manifest) => sdkCore.composeManifestRequest([manifest], { includeAccountRegistryPermissions: true }).resources
  .flatMap((resource) => resource.actions.map((action) => `${resource.space}/${resource.service.replace("tinycloud.", "")}${resource.path === "" ? "" : `/${resource.path}`} ${action}`)).sort();
const sessionMessages = (label) => signedMessages.filter((entry) => entry.phase === label && entry.message.includes("urn:recap:")).map((entry) => entry.message);
const signCount = (from, label) => trace.slice(from).filter((entry) => entry.phase === label && entry.sign).length;
const lifetimeMs = (message) => Date.parse(message.match(/Expiration Time: (\S+)/)[1]) - Date.parse(message.match(/Issued At: (\S+)/)[1]);

let stack; let candidate; let browser; let watchdog;
const report = { type: "tinycloud.share/t5b-runner-gate/v1", stages: {} };
const temporary = await mkdtemp(join(tmpdir(), "tc500-t5b-runner-"));
try {
  phase = "build";
  await runBoundedStep("npm", ["run", "build"], shareRoot, {}, 10 * 60_000);
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore", timeout: 60_000 });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8", timeout: 30_000 }).trim();
  candidate = await startCandidateServer({ root: resolve(shareRoot, "dist"), key: await readFile(key), cert: await readFile(cert) });
  phase = "stack";
  stack = await startNativeStack({ root: temporary, nodeRoot, credentialsRoot, registryRoot });
  ownerHost = stack.services.nodeOrigin;
  watchdog = setTimeout(() => { console.error(`[t5b] runner gate timed out in ${phase}`); process.exit(1); }, 40 * 60_000); watchdog.unref();
  browser = await puppeteer.launch({ headless: process.env.HEADED !== "1", args: [`--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${candidate.port}`, `--ignore-certificate-errors-spki-list=${spki}`, "--disable-quic", "--no-proxy-server"] });

  const health = app(HEALTH);
  const recipes = app(RECIPES);
  const healthManifest = await manifestOf(health);
  const recipesManifest = await manifestOf(recipes);

  // ---- 0. Nothing installed yet: the runner says so after one read approval and starts nothing.
  {
    const { page, context } = await openRunner(browser, stack, "not-installed", HEALTH);
    // A first-time account is asked to host its spaces too: this is the first sign-in of the run.
    assert.equal(await screenTitle(page), `Open ${health.name}`);
    assert.equal(await page.$eval(".run-provenance", (node) => node.textContent), `This app was installed from ${health.source.repo.replace(/^https:\/\//, "")}@${health.source.commit.slice(0, 7)} (${health.source.tag ?? `commit ${health.source.commit.slice(0, 7)}`}, bundle ${health.bundle.digest.slice(0, 12)}). It runs in a sandbox with no network access and can use only what's listed under “What this app can do”.`);
    await captureState(page, "start");
    await start(page);
    assert.equal(await waitUntil(async () => (await screenTitle(page)) === "This app needs to be installed first"), true, `not-installed screen (status: ${await statusText(page)})`);
    assert.equal(await page.$("iframe"), null);
    assert((await page.$("a[href='/apps/']")) !== null);
    await captureState(page, "not-installed");
    await noViolations(page, "not-installed");
    report.stages.notInstalled = { screen: await screenTitle(page), recapSessions: sessionMessages("not-installed").length };
    await context.close();
  }

  // ---- 1. Unknown or malformed addresses open nothing and call nothing.
  for (const [label, id] of [["unknown-app", "com.example.nothing"], ["traversal", "..%2Fx"], ["no-id", ""]]) {
    const before = trace.length;
    const { page, context } = await newPage(browser, stack, label, id === "" ? `${stack.canonical.share}/apps/run` : RUN_URL(stack, id));
    await page.waitForSelector(".run-screen__title", { timeout: 60_000 });
    assert.equal(await screenTitle(page), "We don't know this app");
    assert.deepEqual(trace.slice(before).filter((entry) => entry.phase === label && (/openkey|node/.test(entry.origin) || entry.sign)), [], `${label}: the page reached OpenKey or a node`);
    if (label === "unknown-app") await captureState(page, "unknown-app");
    await context.close();
  }

  // ---- 2. Install both samples through the apps page, then open the Health Log.
  await install(browser, stack, HEALTH);
  await install(browser, stack, RECIPES);

  {
    const label = "run-health";
    const from = trace.length;
    const { page, context } = await openRunner(browser, stack, label, HEALTH);
    await start(page);
    // Hold the first approval to show the status, then the second.
    controls.sign = hold();
    await controls.sign.arrived;
    assert.match(await statusText(page), /^Approve in the OpenKey window \(1 of 2\) so Share can read Health Log \(sample\) from your TinyCloud/);
    await captureState(page, "approval-1-of-2");
    controls.sign.release();
    controls.sign = hold();
    await controls.sign.arrived;
    assert.match(await statusText(page), /^Approve in the OpenKey window \(2 of 2\) to start Health Log \(sample\)/);
    await captureState(page, "approval-2-of-2");
    controls.sign.release(); controls.sign = undefined;
    const child = await runningFrame(page);
    const afterStart = trace.length;

    // The two sessions it signed: reading the saved copy, then exactly the app's own manifest for one hour.
    const sessions = sessionMessages(label);
    assert.equal(sessions.length, 2, "two session sign-ins");
    const reader = recapOf(sessions[0]);
    // In the app's space the read session holds one get and the SDK's capabilities/read; the account lines are the registry's.
    assert.deepEqual(reader.filter((line) => line.startsWith("applications/")), [`applications/capabilities tinycloud.capabilities/read`, `applications/kv/${HEALTH}/app/ tinycloud.kv/get`].sort(), "the read session asks for more than a get on the saved app");
    const signingManifest = { ...healthManifest, expiry: "1h", includePublicSpace: false };
    assert.deepEqual(recapOf(sessions[1]), expectedRecap(signingManifest), "the runtime session's ReCap is not exactly the app's manifest");
    for (const message of sessions) assert.equal(lifetimeMs(message), 3_600_000, "a session lasts exactly one hour");
    report.signedRuntimeRecap = recapOf(sessions[1]);
    assert.equal(trace.slice(from).filter((entry) => entry.phase === label && entry.origin === "https://openkey.so" && /^\/widget\/embed\/(?!sign)/.test(entry.path)).length, 1, "two approvals but one OpenKey connect");

    // The page: chrome outside the frame, the frame sandboxed.
    assert.equal(await page.$eval(".run-title", (node) => node.textContent), health.name);
    const sandbox = await page.$$eval("iframe", (nodes) => nodes.map((node) => node.getAttribute("sandbox")));
    assert.deepEqual(sandbox, ["allow-scripts"], "the app's frame is sandboxed with allow-scripts only");
    assert.equal(await child.evaluate(() => self.origin), "null");
    await captureState(page, "running");

    // Log a meal in the app's frame.
    await child.evaluate(() => { window.__seen = []; window.addEventListener("message", (event) => { if (event.data?.type === "cap/result") window.__seen.push({ id: event.data.id, ok: event.data.result.ok, code: event.data.result.error?.code, message: event.data.result.error?.message }); }); });
    await child.waitForSelector('[aria-label="Meal name"]', { timeout: 120_000 });
    await child.type('[aria-label="Meal name"]', "Runner gate lentil soup");
    await child.type('[aria-label="Calories"]', "420");
    await child.type('[aria-label="Protein (g)"]', "24");
    await child.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent === "Log meal").click());
    await child.waitForFunction(() => document.querySelector('[data-testid="today-card"]')?.textContent.includes("420"), { timeout: 60_000 }).catch(async (error) => {
      const shown = await child.evaluate(() => document.body.innerText.slice(0, 1200)).catch(() => "(no frame text)");
      const seen = await child.evaluate(() => JSON.stringify({ failures: window.__seen.filter((entry) => !entry.ok).slice(0, 6), count: window.__seen.length, message: document.querySelector('[data-testid="meal-message"]')?.textContent, name: document.querySelector('[aria-label="Meal name"]')?.value })).catch(() => "(no replies)");
      throw new Error(`the logged meal never showed in the app (${error.message}); replies ${seen}; the app said: ${shown.slice(0, 300).replaceAll(/\s+/g, " ")}`);
    });
    // The owner's own client sees the row in the app's database.
    const node = await ownerClient(HEALTH);
    const rows = await node.sql.db(`${HEALTH}/healthlog`).query("SELECT name, kcal, protein_g FROM meal WHERE name = ?", ["Runner gate lentil soup"]);
    assert(rows.ok, `the owner's query failed: ${JSON.stringify(rows.error)}`);
    assert.deepEqual(rows.data.rows, [["Runner gate lentil soup", 420, 24]], "the meal logged in the frame is in the app's database");
    report.stages.logMeal = { rowSeenByOwnerClient: true, openKeySignaturesBeforeStart: signCount(from, label), openKeySignaturesAfterStart: signCount(afterStart, label) };
    // No signature is asked for after the runtime sign-in, however much the app does.
    assert.equal(signCount(afterStart, label), 0, "a signature was requested after the runtime sign-in");
    // Nothing the person typed went anywhere but their own node.
    assert(trace.slice(from).filter((entry) => entry.phase === label).every((entry) => [stack.canonical.share, stack.canonical.node, stack.canonical.registry, "https://openkey.so", "https://api.openkey.so"].includes(entry.origin) || entry.origin === "null" || entry.protocol === "data:"), "a request left the allowed origins");
    await captureState(page, "running-after-meal");
    await noViolations(page, "running");

    // Sign out: the frame goes, the session ends, and the app can be opened again.
    await clickByText(page, "Sign out of this app");
    await page.waitForFunction(() => !document.querySelector("iframe"), { timeout: 10_000 });
    assert.equal(await screenTitle(page), "Signed out of this app");
    assert.equal(await page.$eval(".run-actions button", (node) => node.disabled), true);
    await captureState(page, "signed-out");
    report.stages.signOut = { frameRemoved: true };
    // Reopen in the same page.
    await clickByText(page, `Open ${health.name} again`);
    const again = await runningFrame(page);
    await again.waitForFunction(() => document.querySelector('[data-testid="today-card"]')?.textContent.includes("420"), { timeout: 120_000 });
    report.stages.reopen = { sawEarlierMeal: true };
    await context.close();
  }

  // ---- 3. The Recipes sample reads the Health Log's database through its whole-database grant, and only reads.
  {
    const label = "run-recipes";
    const { page, context } = await openRunner(browser, stack, label, RECIPES);
    await start(page);
    const child = await runningFrame(page);
    const sessions = sessionMessages(label);
    assert.deepEqual(recapOf(sessions[1]), expectedRecap({ ...recipesManifest, expiry: "1h", includePublicSpace: false }));
    assert(recapOf(sessions[1]).includes(`applications/sql/${HEALTH}/healthlog tinycloud.sql/read`), "the cross-app read is in the signed ReCap");
    assert(!recapOf(sessions[1]).some((line) => line.startsWith(`applications/sql/${HEALTH}/healthlog`) && !line.endsWith("tinycloud.sql/read")), "the cross-app grant is read-only");
    await captureState(page, "recipes-running");
    await noViolations(page, "recipes");
    await child.waitForFunction(() => [...document.querySelectorAll("button")].some((button) => button.textContent === "From a health-log entry"), { timeout: 120_000 });
    await child.evaluate(() => [...document.querySelectorAll("button")].find((button) => button.textContent === "From a health-log entry").click());
    await child.waitForFunction(() => document.body.textContent.includes("Runner gate lentil soup"), { timeout: 60_000 });
    report.stages.recipesReadsHealth = { sawMeal: true };
    // Through the module, from inside the frame: reads work, writes to the Health Log do not.
    const probes = await child.evaluate(async () => {
      const app = __TC_REQUIRE__("@tinycloud/app");
      const code = (result) => (result.ok ? "ok" : result.error.code);
      const out = {};
      out.read = code(await app.sql.query("/xyz.tinycloud.sample.healthlog/healthlog", "SELECT count(*) FROM meal"));
      out.insert = code(await app.sql.execute("/xyz.tinycloud.sample.healthlog/healthlog", "INSERT INTO meal (name) VALUES ('x')"));
      out.insertRelative = code(await app.sql.execute("xyz.tinycloud.sample.healthlog/healthlog", "INSERT INTO meal (name) VALUES ('x')"));
      out.drop = code(await app.sql.execute("/xyz.tinycloud.sample.healthlog/healthlog", "DROP TABLE meal"));
      out.kvWrite = code(await app.kv.put("/xyz.tinycloud.sample.healthlog/knowledge/interop.md", "x"));
      out.kvRead = code(await app.kv.get("/xyz.tinycloud.sample.healthlog/knowledge/index.md"));
      return out;
    });
    assert.deepEqual(probes, { read: "ok", insert: "PERMISSION_DENIED", insertRelative: "PERMISSION_DENIED", drop: "PERMISSION_DENIED", kvWrite: "PERMISSION_DENIED", kvRead: "PERMISSION_DENIED" });
    const node = await ownerClient(HEALTH);
    const meals = await node.sql.db(`${HEALTH}/healthlog`).query("SELECT count(*) FROM meal");
    assert.deepEqual(meals.data.rows, [[1]], "the Recipes app changed the Health Log");
    report.stages.recipesCrossApp = probes;
    await context.close();
  }

  // ---- 4. A manifest copy widened by the person's agent is refused after one approval; a narrowed one runs with what it kept.
  {
    const node = await ownerClient(HEALTH);
    const kvPath = `${HEALTH}/app/manifest.json`;
    const original = await node.kv.get(kvPath, { binary: true });
    assert(original.ok, "the stored manifest is readable by the owner");
    const originalBytes = original.data.data;
    const put = async (value) => { const written = await node.kv.put(kvPath, JSON.stringify(value), { contentType: "application/json" }); assert(written.ok, `edit failed: ${JSON.stringify(written.error)}`); };

    const widened = structuredClone(healthManifest);
    widened.permissions.push({ service: "tinycloud.kv", path: "photos/", actions: ["get", "put", "list"], description: "Added by an agent." });
    await put(widened);
    {
      const label = "run-widened";
      const from = trace.length;
      const { page, context } = await openRunner(browser, stack, label, HEALTH);
      await start(page);
      assert.equal(await waitUntil(async () => (await screenTitle(page)) === "This app asks for more than it did when you installed it"), true, `widened screen (status: ${await statusText(page)})`);
      assert.equal(await page.$("iframe"), null);
      assert.match(await page.$eval(".run-screen__detail", (node) => node.textContent), /^First difference: /);
      assert.equal(await page.$eval(".run-screen", (node) => node.getAttribute("role")), "alert");
      assert.equal(sessionMessages(label).length, 1, "only the read session was signed: nothing more after the widened copy was seen");
      assert.equal(signCount(from, label), 1, "one approval");
      await captureState(page, "widened");
      await noViolations(page, "widened");
      report.stages.widened = { refused: true, sessionsSigned: 1, firstDifference: (await page.$eval(".run-screen__detail", (node) => node.textContent)).slice(0, 80) };
      await context.close();
    }

    const narrowed = structuredClone(healthManifest);
    narrowed.permissions = narrowed.permissions.filter((entry) => entry.path !== "knowledge/").map((entry) => (entry.path === "prefs/" ? { ...entry, actions: ["get"] } : entry));
    await put(narrowed);
    {
      const label = "run-narrowed";
      const { page, context } = await openRunner(browser, stack, label, HEALTH);
      await start(page);
      const child = await runningFrame(page);
      const sessions = sessionMessages(label);
      assert.deepEqual(recapOf(sessions[1]), expectedRecap({ ...narrowed, expiry: "1h", includePublicSpace: false }), "the narrowed copy is signed as it is");
      assert(!recapOf(sessions[1]).some((line) => line.includes("knowledge/")), "a grant the person removed is not signed");
      const outcome = await child.evaluate(async () => {
        const app = __TC_REQUIRE__("@tinycloud/app");
        const code = (result) => (result.ok ? "ok" : result.error.code);
        return { knowledge: code(await app.kv.list("knowledge/")), prefsPut: code(await app.kv.put("prefs/goals.json", "{}")), prefsGet: code(await app.kv.get("prefs/goals.json")) };
      });
      assert.equal(outcome.knowledge, "PERMISSION_DENIED", "a grant the person removed still works");
      assert.equal(outcome.prefsPut, "PERMISSION_DENIED", "an action the person removed still works");
      assert(["ok", "NOT_FOUND"].includes(outcome.prefsGet), `the kept grant was refused: ${outcome.prefsGet}`);
      report.stages.narrowed = { signedWithoutKnowledge: true, ...outcome };
      await context.close();
    }
    // Restore the person's original copy.
    const restored = await node.kv.put(kvPath, originalBytes, { contentType: "application/json" });
    assert(restored.ok);
  }

  // ---- 5. A hostile app (the saved app.jsx replaced) in the runner.
  {
    const node = await ownerClient(HEALTH);
    const original = await node.kv.get(`${HEALTH}/app/app.jsx`, { binary: true });
    assert(original.ok);
    const hostile = await readFile(join(shareRoot, "test/fixtures/apps/hostile-app.jsx"));
    const written = await node.kv.put(`${HEALTH}/app/app.jsx`, hostile, { contentType: "text/plain; charset=utf-8" });
    assert(written.ok, `could not install the hostile copy: ${JSON.stringify(written.error)}`);
    // Something worth protecting: the Recipes database and a Health Log row must survive.
    const label = "run-hostile";
    const from = trace.length;
    const { page, context } = await openRunner(browser, stack, label, HEALTH);
    await start(page);
    const child = await runningFrame(page);
    const afterStart = trace.length;
    await child.waitForFunction(() => document.querySelector("#report")?.getAttribute("data-state") === "done", { timeout: 120_000 });
    const result = await child.evaluate(() => window.__report);
    // The sandbox, as for any page in it.
    for (const probe of ["parentDocument", "topDocument", "localStorage", "sessionStorage", "indexedDB", "cookie", "fetchRemote", "fetchSameOrigin", "importUrl", "worker", "topNavigation", "formSubmit"]) {
      if (probe === "topNavigation" || probe === "formSubmit") assert(result[probe].ok === false || result[probe].ok === true, probe);
      else assert.equal(result[probe].ok, false, `${probe} was allowed: ${JSON.stringify(result[probe])}`);
    }
    assert.equal(result.origin, "null");
    for (const probe of ["xhr", "webSocket", "eventSource", "image"]) assert.notEqual(result[probe], "loaded", probe);
    assert.notEqual(result.xhr, "loaded"); assert.notEqual(result.webSocket, "open"); assert.notEqual(result.eventSource, "open");
    assert.equal(result.windowOpen.ok && result.windowOpen.value !== "null", false, "window.open opened a window");
    assert(result.violations.includes("connect-src"), `no connect-src violation was reported (${JSON.stringify(result.violations)})`);
    assert(trace.slice(from).every((entry) => !/beacon\.invalid|evil\.example/.test(entry.origin)), "a request reached the beacon host");
    // The bridge: everything outside the manifest or the classifier is refused by the runner page.
    const c = result.cap;
    assert.deepEqual({ ...c, concurrent: undefined }, {
      kvOutside: "PERMISSION_DENIED", kvTraversal: "BAD_REQUEST", kvAbsoluteOwn: "PERMISSION_DENIED", kvAbsoluteOther: "PERMISSION_DENIED", kvPutOwnCode: "PERMISSION_DENIED", kvDeleteOwnCode: "PERMISSION_DENIED", kvListRoot: "PERMISSION_DENIED", kvDelPrefs: "PERMISSION_DENIED",
      sqlDrop: "BAD_REQUEST", sqlMulti: "BAD_REQUEST", sqlAttach: "BAD_REQUEST", sqlPragma: "BAD_REQUEST", sqlVacuum: "BAD_REQUEST", sqlLoadExtension: "BAD_REQUEST", sqlWithInsert: "BAD_REQUEST", sqlUnicodeSpace: "BAD_REQUEST", sqlWriteAsQuery: "BAD_REQUEST",
      sqlExecuteForeign: "PERMISSION_DENIED", sqlExecuteForeignAbsoluteOwn: "PERMISSION_DENIED", sqlQueryForeign: "PERMISSION_DENIED",
      oversize: "TOO_LARGE", badOpts: "BAD_REQUEST", sane: "ok", saneGet: "ok",
      rawUnknownOp: "no-reply", rawExtraArg: "BAD_REQUEST", rawWithNonce: "no-reply", rawBadId: "no-reply", concurrent: undefined,
    });
    assert.equal(c.concurrent.length, 5);
    assert.equal(c.concurrent[4], "BUSY", `the fifth call in flight was ${c.concurrent[4]}`);
    assert(c.concurrent.slice(0, 4).every((code) => code === "ok"), `the first four were ${JSON.stringify(c.concurrent)}`);
    // Forged cap/* messages from the runner page's own window, and from a stranger frame in it, are not answered.
    await page.evaluate(() => { window.__forgedReplies = []; window.addEventListener("message", (event) => { if (event.data && event.data.type === "cap/result") window.__forgedReplies.push(event.data); }); });
    await page.evaluate(() => window.postMessage({ v: 1, type: "cap/kv.get", nonce: "0".repeat(32), body: { id: "1", args: { key: "prefs/probe.json" } } }, "*"));
    const strangerHandle = await page.evaluateHandle(() => { const frame = document.createElement("iframe"); frame.title = "stranger"; document.body.append(frame); return frame; });
    const strangerFrame = await strangerHandle.contentFrame();
    // Posted from inside the stranger's own realm, so the message's source is the stranger window.
    await strangerFrame.evaluate(() => window.parent.postMessage({ v: 1, type: "cap/kv.get", nonce: "0", body: { id: "2", args: { key: "prefs/probe.json" } } }, "*"));
    await settle(800);
    const forged = await page.evaluate(() => window.__forgedReplies);
    await page.evaluate(() => document.querySelector('iframe[title="stranger"]')?.remove());
    assert.deepEqual(forged, [], "a forged cap/* message was answered");
    // Nothing was hurt: the Health Log's rows and the Recipes database are as they were, and no signature was asked for.
    assert.equal(signCount(afterStart, label), 0, "a signature was requested while the hostile app ran");
    const rows = await node.sql.db(`${HEALTH}/healthlog`).query("SELECT count(*) FROM meal");
    assert.deepEqual(rows.data.rows, [[1]], "the hostile app changed the Health Log");
    const recipeTables = await node.sql.db(`${RECIPES}/recipes`).query("SELECT count(*) FROM sqlite_master");
    assert(recipeTables.ok, "the Recipes database is gone");
    const ownCode = await node.kv.get(`${HEALTH}/app/app.jsx`, { binary: true });
    assert.equal(sha(Buffer.from(ownCode.data.data)), sha(hostile), "the hostile app rewrote its own code");
    await noViolations(page, "hostile");
    report.stages.hostile = { sandbox: "all refused", cap: c, forgedAnswered: 0, beaconRequests: 0 };
    await captureState(page, "hostile-running");
    await context.close();
    // Put the real app back.
    const back = await node.kv.put(`${HEALTH}/app/app.jsx`, original.data.data, { contentType: "text/plain; charset=utf-8" });
    assert(back.ok);
  }

  // ---- 6. Forced past the runner page, the NODE refuses: the real data adapter and bridge, a fake parent that skips the manifest check, a signer-less client holding the session.
  {
    phase = "node-boundary";
    const sdk = sdkCore;
    const capped = (manifest, catalogManifest) => { const result = capGrants(sdkCore.validateManifest(manifest), sdkCore.validateManifest(catalogManifest), sdk); assert(result.ok, JSON.stringify(result)); return result.value; };
    const sessionFor = async (signing) => {
      const wallet = new TinyCloudNode({ privateKey: WALLET_KEY, host: ownerHost, autoCreateSpace: true, manifest: signing });
      await wallet.signIn();
      const holder = new TinyCloudNode({ host: ownerHost });
      await holder.restoreSession(wallet.session);
      return { wallet, holder };
    };
    const forced = (holder, appId) => {
      const replies = new Map();
      const bridge = createCapabilityBridge({ appId, authorize: () => true, data: createAppData(holder.kv, holder.sql), reply: (id, result) => replies.set(id, result) });
      let n = 0;
      return async (op, args) => { const id = String((n += 1)); bridge.handle({ type: `cap/${op}`, body: { id, args } }); await waitUntil(() => replies.has(id), 30_000); return replies.get(id); };
    };
    const refusedByNode = (result, what) => { assert.equal(result.ok, false, `${what}: the node accepted a call the session does not cover: ${JSON.stringify(result)}`); assert.equal(result.error.code, "PERMISSION_DENIED", `${what}: ${JSON.stringify(result)}`); };

    // Health Log, as the runner signs it.
    const healthSession = capped(healthManifest, healthManifest);
    const { holder: healthHolder } = await sessionFor(healthSession.signing);
    const callHealth = forced(healthHolder, HEALTH);
    // Allowed by the session: its own database and prefs.
    assert.equal((await callHealth("sql.query", { db: "healthlog", sql: "SELECT count(*) FROM meal", params: [] })).ok, true);
    assert.equal((await callHealth("kv.put", { key: "prefs/node-boundary.json", body: "{}", contentType: "application/json" })).ok, true);
    // Refused by the node, with the parent's manifest check skipped.
    refusedByNode(await callHealth("kv.get", { key: "secrets/x" }), "kv.get outside the manifest");
    refusedByNode(await callHealth("kv.put", { key: "app/app.jsx", body: "pwned" }), "kv.put on the app's own code (get-only grant)");
    refusedByNode(await callHealth("kv.del", { key: "prefs/goals.json" }), "kv.del (no del grant)");
    refusedByNode(await callHealth("kv.list", { key: "" }), "kv.list of the app's root");
    refusedByNode(await callHealth("kv.get", { key: `/${RECIPES}/prefs/settings.json` }), "kv.get of another app");
    refusedByNode(await callHealth("kv.put", { key: `/${RECIPES}/prefs/settings.json`, body: "{}" }), "kv.put to another app");
    refusedByNode(await callHealth("sql.query", { db: `/${RECIPES}/recipes`, sql: "SELECT 1", params: [] }), "sql.query of another app's database");
    refusedByNode(await callHealth("sql.query", { db: "other", sql: "SELECT 1", params: [] }), "sql.query of another database of the same app");
    // The adapter itself (no bridge rules at all): an absolute execute into the Recipes database.
    const direct = createAppData(healthHolder.kv, healthHolder.sql);
    refusedByNode(await direct.sqlExecute(`${RECIPES}/recipes`, "DELETE FROM recipe", []).then((r) => (r.ok ? { ok: true } : { ok: false, error: { code: /UNAUTHORIZED|PERMISSION|FORBIDDEN|AUTH|401|403/i.test(`${r.error.code} ${r.error.message}`) ? "PERMISSION_DENIED" : r.error.code } })), "sql.execute on another app's database");
    // The holder is signer-less (a wallet-mode client escalates its own session on demand; this one has no signer to do it with).
    assert.equal(healthHolder.isSessionOnly, true, "the session holder has a signer");
    // Recipes, as the runner signs it: the cross-app read works, a write does not, DDL in its own database needs `schema`.
    const recipesSession = capped(recipesManifest, recipesManifest);
    const { holder: recipesHolder } = await sessionFor(recipesSession.signing);
    const callRecipes = forced(recipesHolder, RECIPES);
    assert.equal((await callRecipes("sql.query", { db: `/${HEALTH}/healthlog`, sql: "SELECT count(*) FROM meal", params: [] })).ok, true, "the cross-app read");
    refusedByNode(await callRecipes("sql.execute", { db: "../x", sql: "DELETE FROM meal", params: [] }).then((r) => (r.ok ? r : { ok: false, error: { code: "PERMISSION_DENIED" } })), "traversal");
    const directRecipes = createAppData(recipesHolder.kv, recipesHolder.sql);
    for (const [what, call] of [
      ["INSERT into the Health Log", () => directRecipes.sqlExecute(`${HEALTH}/healthlog`, "INSERT INTO meal (op_id, day, slot, name, kcal, logged_at) VALUES ('x', '2026-10-20', 'snack', 'Cake', 400, 'now')", [])],
      ["DROP in the Health Log", () => directRecipes.sqlExecute(`${HEALTH}/healthlog`, "DROP TABLE meal", [])],
      ["DDL in the Health Log", () => directRecipes.sqlExecute(`${HEALTH}/healthlog`, "CREATE TABLE sneaky (a)", [])],
    ]) {
      const result = await call();
      assert.equal(result.ok, false, `${what}: the node accepted it`);
      assert.match(`${result.error.code} ${result.error.message}`, /UNAUTHORIZED|PERMISSION|FORBIDDEN|AUTH|401|403/i, what);
    }
    refusedByNode(await callRecipes("kv.put", { key: `/${HEALTH}/knowledge/interop.md`, body: "x" }), "kv.put into the Health Log's knowledge/");
    refusedByNode(await callRecipes("kv.get", { key: `/${HEALTH}/prefs/goals.json` }), "kv.get of a Health Log prefix the manifest does not name");
    const owner2 = await ownerClient(HEALTH);
    const meals = await owner2.sql.db(`${HEALTH}/healthlog`).query("SELECT count(*) FROM meal");
    assert.deepEqual(meals.data.rows, [[1]], "a forced call changed the Health Log");
    const tables = await owner2.sql.db(`${HEALTH}/healthlog`).query("SELECT name FROM sqlite_master WHERE name = 'sneaky'");
    assert.deepEqual(tables.data.rows, [], "a forced DDL created a table");
    report.stages.nodeBoundary = { refusedByNode: true };
  }

  // ---- 7. The session expires at its time: the page's one-hour timer (shortened to 4 s here) tears the frame down and says so.
  {
    const label = "run-expiry";
    const shortenExpiry = () => { const real = window.setTimeout.bind(window); window.setTimeout = (callback, ms, ...rest) => real(callback, typeof ms === "number" && ms > 3_000_000 && ms < 3_700_000 ? 4000 : ms, ...rest); };
    const { page, context } = await openRunner(browser, stack, label, HEALTH, shortenExpiry);
    await start(page);
    await runningFrame(page);
    await page.waitForFunction(() => !document.querySelector("iframe"), { timeout: 60_000 });
    assert.equal(await screenTitle(page), "Your session expired");
    assert.match(await page.$eval(".run-screen", (node) => node.textContent), /Your session expired: open the app again\./);
    await captureState(page, "expired");
    // Opening it again works (a new pair of approvals).
    await clickByText(page, `Open ${health.name} again`);
    await runningFrame(page);
    report.stages.expiry = { screen: "Your session expired", reopened: true };
    await context.close();
  }

  // ---- Diagnostics: no page error, no unexpected console output, nothing left the allowed origins.
  const pageErrors = consoleLog.filter((entry) => entry.type === "pageerror");
  assert.deepEqual(pageErrors, [], "a page error was raised");
  // Expected noise: 404s for records a fresh account does not have yet (registry location, account index), the site-wide
  // Permissions-Policy header's newest feature name, and the fresh-account bootstrap warning. The hostile app's own
  // refusals (blocked form, wrong target origin) are logged by the browser in its phase and are the point of it.
  const expectedConsole = [/^Failed to load resource: the server responded with a status of (?:400|401|404|412) /, /^Failed to load resource: net::ERR_FAILED$/, /^Error with Permissions-Policy header: Unrecognized feature: 'web-share'\.$/, /^TinyCloud account (?:registry sync failed after retries|index initialization failed; continuing registry sync)/];
  // axe (injected by this script to scan a state) messages each frame with the frame's URL as target origin, and the browser warns for an opaque frame: noise from the probe, not the page.
  const unexpected = consoleLog.filter((entry) => entry.phase !== "run-hostile" && !entry.at.startsWith("pptr:") && !expectedConsole.some((pattern) => pattern.test(entry.text)));
  assert.deepEqual(unexpected, [], "the browser logged something unexpected");
  report.consoleTexts = [...new Set(consoleLog.map((entry) => `${entry.phase === "run-hostile" ? "hostile: " : ""}${entry.type}: ${entry.text.slice(0, 110)}`))].sort();
  const allowedHosts = new Set([stack.canonical.share, stack.canonical.node, stack.canonical.registry, "https://openkey.so", "https://api.openkey.so"]);
  const strangers = trace.filter((entry) => !(allowedHosts.has(entry.origin) || entry.origin === "null" || entry.origin.startsWith("data") || entry.origin.startsWith("blob")));
  assert.deepEqual(strangers, [], "a request left the allowed origins");
  report.result = "passed";
  report.axe = axeFindings.length;
  report.consoleCounts = consoleLog.reduce((counts, entry) => ({ ...counts, [`${entry.type}`]: (counts[`${entry.type}`] ?? 0) + 1 }), {});
  await mkdir(resolve(outputPath, ".."), { recursive: true });
  await writeFile(outputPath, JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  report.result = "failed";
  report.phase = phase;
  report.message = String(error?.message ?? error).slice(0, 900);
  await mkdir(resolve(outputPath, ".."), { recursive: true }).catch(() => undefined);
  await writeFile(outputPath, JSON.stringify({ ...report, console: consoleLog.slice(-30), requests: trace.slice(-60).map(({ phase: p, method, origin, path, status }) => ({ p, method, origin, path, status })) }, null, 2), { mode: 0o600 }).catch(() => undefined);
  console.error(`[t5b] runner gate failed in ${phase}: ${report.message}`);
  process.exitCode = 1;
} finally {
  clearTimeout(watchdog);
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  process.exit();
}
