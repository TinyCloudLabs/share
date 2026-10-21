#!/usr/bin/env node

/**
 * T5b runner gate: "Open an installed app" on the hermetic native stack.
 *
 * Same stack and rules as install-gate.mjs (real Node, Location Registry and
 * OpenCredentials; OpenKey is the signing fixture; the browser reaches the
 * candidate build at https://share.tinycloud.xyz/apps/run). It proves, in a real
 * browser against a real Node:
 *  - open the Health Log sample from the apps page (the first Open saves its files, then runs it), log a meal in the
 *    app's frame, and the owner's own SDK client reads that row from the app's
 *    database; the Recipes sample (installed too) lists that meal through its
 *    cross-app read grant and cannot write to the Health Log;
 *  - the runner signs in twice (read the saved copy, then run it): the session
 *    ReCap it signed is exactly the app's own manifest, one hour, and after the
 *    runtime sign-in no further signature is ever requested;
 *  - a manifest copy widened by the person's agent is refused after one
 *    approval, before anything more is signed; a narrowed copy runs, with
 *    exactly what it kept;
 *  - the saved code is PINNED: an edited app.jsx or an extra file is refused before any
 *    runtime session or frame, Repair (the repair sheet) puts the
 *    catalog's code back with one approval and the app opens, and an installed version
 *    that has left the catalog gets the honest message and no Repair;
 *  - a hostile app (a catalog entry the gate adds for the run) can do nothing the
 *    sandbox forbids (network, storage, parent, navigation, popups, forms), and reads
 *    data it then tries to "send" by every browser-initiated request there is (leak
 *    vectors: prerender, prefetch, preconnect, dns-prefetch, modulepreload, <a ping>,
 *    <img>, <form>, <meta refresh>, window.open, WebRTC, fetch, import(), CSS url(),
 *    @import, image-set ...): a loopback listener sees NOTHING (no request, connection or
 *    UDP packet); every call outside its manifest is refused by the runner page, with
 *    the classifier's refusals, oversize and in-flight limits, raw and forged messages;
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
import dgram from "node:dgram";
import { createServer } from "node:http";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { describeBundle } from "../../scripts/apps-catalog.mjs";
import { createAppData } from "../../src/apps/app-data.ts";
import { createCapabilityBridge } from "../../src/apps/bridge.ts";
import { openManifest } from "../../src/apps/grants.ts";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/v1.21.0");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const shotDir = process.env.RUNNER_SHOT_DIR;
const outputPath = resolve(process.env.RUNNER_ARTIFACT ?? join(workspaceRoot, ".context/t5b-runner-gate.json"));
const HOSTILE = "xyz.tinycloud.e2e.hostile";

/** A loopback listener (HTTP, upgrades, and UDP on the same port for STUN): anything that reaches it is a request that got out. */
async function startListener() {
  const state = { requests: [], connections: 0, upgrades: 0, udpPackets: 0 };
  state.server = createServer((request, response) => { state.requests.push(request.url); response.writeHead(200, { "content-type": "text/plain" }); response.end("seen"); });
  state.server.on("connection", () => { state.connections += 1; });
  state.server.on("upgrade", (_request, socket) => { state.upgrades += 1; socket.destroy(); });
  await new Promise((done) => state.server.listen(0, "127.0.0.1", done));
  state.udp = dgram.createSocket("udp4");
  state.udp.on("message", () => { state.udpPackets += 1; });
  await new Promise((done) => state.udp.bind(state.server.address().port, "127.0.0.1", done));
  state.origin = `http://127.0.0.1:${state.server.address().port}`;
  state.reset = () => { state.requests.length = 0; state.connections = 0; state.upgrades = 0; state.udpPackets = 0; };
  state.close = () => { state.server.closeAllConnections(); state.server.close(); state.udp.close(); };
  return state;
}
const listener = await startListener();

/**
 * The gate adds ONE catalog entry for the run: a hostile app (the saved code is pinned, so a hostile app can only reach
 * the runner as a catalog entry). It writes `public/apps/b/<digest>/` and an entry in apps/catalog.json, and puts both back
 * (restore) when the run ends, however it ends.
 */
function addHostileEntry() {
  const catalogPath = join(shareRoot, "apps/catalog.json");
  const original = readFileSync(catalogPath, "utf8");
  const parsed = JSON.parse(original);
  const health = parsed.apps.find((entry) => entry.app_id === "xyz.tinycloud.sample.healthlog");
  const healthManifest = JSON.parse(readFileSync(join(shareRoot, "public", health.bundle.root, "manifest.json"), "utf8"));
  const manifest = { ...healthManifest, app_id: HOSTILE, name: "Hostile app (test)", description: "A hostile app the runner gate installs to prove the sandbox, the bridge and the leak guards hold. Test only." };
  delete manifest.knowledge;
  const source = readFileSync(join(shareRoot, "test/fixtures/apps/hostile-app.jsx"), "utf8")
    .replace("/*__LEAK_VECTORS__*/", readFileSync(join(shareRoot, "test/fixtures/apps/leak-vectors.js"), "utf8"))
    .replaceAll("__BEACON__", listener.origin)
    .replaceAll("__HOSTILE_ID__", HOSTILE);
  const stagingDir = join(tmpdir(), `tc500-t5b-hostile-${process.pid}`);
  rmSync(stagingDir, { recursive: true, force: true });
  mkdirSync(stagingDir, { recursive: true });
  writeFileSync(join(stagingDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(stagingDir, "app.jsx"), source);
  const described = describeBundle(stagingDir);
  const target = join(shareRoot, "public", described.bundle.root);
  cpSync(stagingDir, target, { recursive: true });
  rmSync(stagingDir, { recursive: true, force: true });
  parsed.apps.push({
    app_id: HOSTILE, name: manifest.name, description: manifest.description,
    publisher: { name: "Runner gate (test)" },
    source: { repo: "https://github.com/example/hostile-test-app", tag: null, commit: "0".repeat(40) },
    manifest: described.manifest, bundle: described.bundle, knowledge: described.knowledge,
  });
  writeFileSync(catalogPath, `${JSON.stringify(parsed, null, 2)}\n`);
  let restored = false;
  const restore = () => {
    if (restored) return;
    restored = true;
    writeFileSync(catalogPath, original);
    rmSync(target, { recursive: true, force: true });
  };
  process.once("exit", restore);
  return restore;
}
const restoreCatalog = addHostileEntry();
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
/** A held signature that never arrives is a failure with the page's own explanation, not a hang. */
async function arrivedOrExplain(page, held, what) {
  const timeout = new Promise((resolveTimeout) => setTimeout(() => resolveTimeout("timeout"), 120_000));
  if ((await Promise.race([held.arrived.then(() => "arrived"), timeout])) === "arrived") return;
  const title = await page.$eval(".run-screen__title", (node) => node.textContent).catch(() => "(no screen)");
  const detail = await page.$eval(".run-screen", (node) => node.textContent).catch(() => "");
  throw new Error(`${what} was never asked for. Status: "${await statusText(page)}". Screen: "${title}" ${detail.slice(0, 300)}`);
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

// ---- opening from the apps page (the person's real path): the card's Open link lands on the runner
async function openFirst(browser, stack, appId) {
  const { page, context } = await newPage(browser, stack, `open-${appId}`, `${stack.canonical.share}/apps/`);
  await page.waitForSelector(".apps-card", { timeout: 60_000 });
  const index = catalog.apps.findIndex((entry) => entry.app_id === appId);
  await page.evaluate((position) => document.querySelectorAll(".apps-card")[position].querySelector(".apps-card__actions a").click(), index);
  await page.waitForSelector(".run-screen, .run-working", { timeout: 60_000 });
  assert.equal(new URL(page.url()).hash, `#${appId}`);
  await start(page);
  await page.waitForFunction(() => /is running/.test(document.querySelector(".run-status-region")?.textContent ?? ""), { timeout: 300_000 });
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
  await opened.page.waitForSelector(".run-screen, .run-working", { timeout: 60_000 });
  return opened;
}
async function clickByText(page, label) {
  await page.evaluate((text) => [...document.querySelectorAll("button, a")].find((node) => node.textContent === text).click(), label);
}
async function start(page) {
  await page.waitForSelector(".run-screen, .run-working", { timeout: 60_000 });
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

/** Installed in every frame before its scripts run: every message the document receives, as text (bytes by length only). */
const recordMessages = () => {
  window.__inbound = [];
  // The runner page also hears OpenKey's own window; only opaque-origin senders (the app's frames) are the subject here.
  window.addEventListener("message", (event) => { if (window.top === window && event.origin !== "null") return; try { window.__inbound.push(JSON.stringify(event.data, (key, value) => (value instanceof Uint8Array ? `bytes:${value.length}` : value))); } catch { /* not serialisable */ } }, true);
};
/** What nothing in any frame may ever be sent: the account, a token, a recap, a key, a DID. */
const secretShapes = (address) => [new RegExp(address.slice(2), "i"), /tc1[A-Za-z0-9_-]{16,}/, /urn:recap/i, /"kty"/, /eyJ[A-Za-z0-9_-]{20,}/, /did:(?:pkh|key):/i, /-----BEGIN/, /private_?key/i, /siwe/i];

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

  /** From a runner refusal screen: Repair -> the repair sheet -> Continue -> the sheet's last line. */
  async function repairFromRunner(page, label) {
    await page.click(`a[href='/apps/#repair=${HEALTH}']`);
    await page.waitForFunction(() => document.querySelector("#apps-sheet")?.open === true && [...document.querySelectorAll("#apps-sheet button")].some((button) => button.textContent === "Continue"), { timeout: 60_000 });
    assert.match(await page.$eval("#apps-sheet", (node) => node.innerText), /Your data is untouched/);
    await clickByText(page, "Continue");
    const text = await waitUntil(async () => { const line = await page.$eval(".apps-install-line", (node) => node.textContent).catch(() => ""); return /^(Repaired\.|Not repaired|Sign-in|OpenKey|We couldn't)/.test(line) ? line : undefined; }, 300_000);
    return text ?? "";
  }

  // ---- 1. Unknown or malformed addresses open nothing and call nothing.
  phase = "1. Unknown or malformed addresses open nothing and call noth"; console.error(`[t5b] ${phase}`);
  for (const [label, id] of [["unknown-app", "com.example.nothing"], ["traversal", "..%2Fx"], ["no-id", ""]]) {
    const before = trace.length;
    const { page, context } = await newPage(browser, stack, label, id === "" ? `${stack.canonical.share}/apps/run` : RUN_URL(stack, id));
    await page.waitForSelector(".run-screen__title", { timeout: 60_000 });
    assert.equal(await screenTitle(page), "We don't know this app");
    assert.deepEqual(trace.slice(before).filter((entry) => entry.phase === label && (/openkey|node/.test(entry.origin) || entry.sign)), [], `${label}: the page reached OpenKey or a node`);
    if (label === "unknown-app") await captureState(page, "unknown-app");
    await context.close();
  }

  // ---- 2. Open both samples from the apps page; the first Open saves each app's files, then opens it.
  phase = "2. Open both samples from the apps page, then open the"; console.error(`[t5b] ${phase}`);
  await openFirst(browser, stack, HEALTH);
  await openFirst(browser, stack, RECIPES);

  {
    const label = "run-health";
    const from = trace.length;
    const { page, context } = await openRunner(browser, stack, label, HEALTH, recordMessages);
    controls.sign = hold();
    await start(page);
    await arrivedOrExplain(page, controls.sign, "the approval");
    assert.match(await statusText(page), /^Approve in the OpenKey window so Share can open Health Log from your TinyCloud/);
    await captureState(page, "approval");
    controls.sign.release(); controls.sign = undefined;
    const child = await runningFrame(page);
    const afterStart = trace.length;

    // The one session it signed: the open's union for one hour, the catalog grants plus get, list and put on its own folders.
    const sessions = sessionMessages(label);
    assert.equal(sessions.length, 1, "one session sign-in");
    assert.deepEqual(recapOf(sessions[0]), expectedRecap(openManifest(sdkCore.validateManifest(healthManifest))), "the session's ReCap is not exactly the open's union");
    assert.equal(lifetimeMs(sessions[0]), 3_600_000, "the session lasts exactly one hour");
    report.signedRuntimeRecap = recapOf(sessions[0]);
    assert.equal(trace.slice(from).filter((entry) => entry.phase === label && entry.origin === "https://openkey.so" && /^\/widget\/embed\/(?!sign)/.test(entry.path)).length, 1, "one approval and one OpenKey connect");

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
    // Nothing secret crossed any hop: what the runner page, the bridge document and the app's frame received, in full.
    const { bridge: bridgeFrame } = frames(page);
    const received = { runnerPage: await page.evaluate(() => window.__inbound), bridge: await bridgeFrame.evaluate(() => window.__inbound), app: await child.evaluate(() => window.__inbound) };
    for (const [where, messages] of Object.entries(received)) {
      assert(messages.length > 0, `${where}: no messages were recorded`);
      for (const shape of secretShapes(stack.walletAddress)) assert(!messages.some((message) => shape.test(message)), `${where}: a message matches ${shape}`);
    }
    report.stages.frameMessages = Object.fromEntries(Object.entries(received).map(([where, messages]) => [where, messages.length]));

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
  phase = "3. The Recipes sample reads the Health Log's database throug"; console.error(`[t5b] ${phase}`);
  {
    const label = "run-recipes";
    const { page, context } = await openRunner(browser, stack, label, RECIPES);
    await start(page);
    const child = await runningFrame(page);
    const sessions = sessionMessages(label);
    assert.deepEqual(recapOf(sessions[0]), expectedRecap(openManifest(sdkCore.validateManifest(recipesManifest))), "the Recipes session's ReCap is not exactly the app's union");
    assert(recapOf(sessions[0]).includes(`applications/sql/${HEALTH}/healthlog tinycloud.sql/read`), "the cross-app read is in the signed ReCap");
    assert(!recapOf(sessions[0]).some((line) => line.startsWith(`applications/sql/${HEALTH}/healthlog`) && !line.endsWith("tinycloud.sql/read")), "the cross-app grant is read-only");
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
  phase = "4. A manifest copy widened by the person's agent is refused "; console.error(`[t5b] ${phase}`);
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
      // Repair is offered here too: it replaces manifest.json with the catalog's, with one approval, and the app opens again.
      assert((await page.$(`a[href='/apps/#repair=${HEALTH}']`)) !== null, "the widened screen offers no Repair");
      assert.match(await page.$eval(".run-screen", (node) => node.textContent), /Repair replaces the app's code files, manifest\.json included, with the catalog's\. Your data is untouched\./);
      const repairFrom = trace.length;
      const repaired = await repairFromRunner(page, label);
      assert.match(repaired, /^Repaired\./, `repair of the widened copy ended with "${repaired}"`);
      assert.equal(signCount(repairFrom, label), 1, "Repair of the widened copy needed one approval");
      const restored = await node.kv.get(kvPath, { binary: true });
      assert.equal(sha(Buffer.from(restored.data.data)), sha(Buffer.from(originalBytes)), "manifest.json is not the catalog's again");
      report.stages.widened.repaired = true;
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
      assert.equal(sessions.length, 1, "one session sign-in");
      // The session holds the catalog union; the saved copy's removed grant is refused by the bridge (checked below), not by the node.
      assert.deepEqual(recapOf(sessions[0]), expectedRecap(openManifest(sdkCore.validateManifest(healthManifest))), "the narrowed copy's session is not the catalog union");
      const outcome = await child.evaluate(async () => {
        const app = __TC_REQUIRE__("@tinycloud/app");
        const code = (result) => (result.ok ? "ok" : result.error.code);
        return { knowledge: code(await app.kv.list("knowledge/")), prefsPut: code(await app.kv.put("prefs/goals.json", "{}")), prefsGet: code(await app.kv.get("prefs/goals.json")) };
      });
      assert.equal(outcome.knowledge, "PERMISSION_DENIED", "a grant the person removed still works");
      assert.equal(outcome.prefsPut, "PERMISSION_DENIED", "an action the person removed still works");
      assert(["ok", "NOT_FOUND"].includes(outcome.prefsGet), `the kept grant was refused: ${outcome.prefsGet}`);
      report.stages.narrowed = { sessionIsUnion: true, ...outcome };
      await context.close();
    }
    // Restore the person's original copy.
    const restored = await node.kv.put(kvPath, originalBytes, { contentType: "application/json" });
    assert(restored.ok);
  }

  // ---- 5. The code is pinned: an edited app.jsx or an extra file opens nothing, Repair puts the catalog's code back, a removed version cannot be repaired.
  phase = "5. The code is pinned: an edited app.jsx or an extra file op"; console.error(`[t5b] ${phase}`);
  {
    const node = await ownerClient(HEALTH);
    const codeKey = `${HEALTH}/app/app.jsx`;
    const originalCode = await node.kv.get(codeKey, { binary: true });
    assert(originalCode.ok);
    const put = async (key, value) => { const written = await node.kv.put(key, value, { contentType: "text/plain; charset=utf-8" }); assert(written.ok, `edit of ${key} failed: ${JSON.stringify(written.error)}`); };
    const evil = Buffer.from(`${Buffer.from(originalCode.data.data).toString("utf8")}\nfetch("${listener.origin}/tampered");\n`);
    for (const [label, edit, undo] of [
      ["run-tampered", () => put(codeKey, evil), undefined],
      ["run-extra-file", () => put(`${HEALTH}/app/extra.js`, Buffer.from("1")), undefined],
    ]) {
      await edit();
      const from = trace.length;
      listener.reset();
      const { page, context } = await openRunner(browser, stack, label, HEALTH);
      await start(page);
      assert.equal(await waitUntil(async () => (await screenTitle(page)) === "This app's code doesn't match the pinned version"), true, `${label}: the mismatch screen (status: ${await statusText(page)})`);
      assert.equal(await page.$("iframe"), null, `${label}: a frame was started`);
      assert.equal(sessionMessages(label).length, 1, `${label}: only the read session was signed: no runtime session exists`);
      assert.equal(signCount(from, label), 1, `${label}: one approval`);
      assert.match(await page.$eval(".run-screen__detail", (node) => node.textContent), /differs from the pinned version|unexpected file/);
      assert.equal(await page.$eval(".run-screen", (node) => node.getAttribute("role")), "alert");
      assert((await page.$("a[href='/apps/#repair=" + HEALTH + "']")) !== null, `${label}: no Repair link`);
      assert.deepEqual(listener.requests, [], `${label}: the tampered code ran`);
      if (label === "run-tampered") await captureState(page, "code-mismatch");
      report.stages[label] = { refused: true, sessionsSigned: 1, approvals: 1 };
      // Repair: the apps page opens the repair sheet; one approval; the code files come back; the stray goes.
      const repairFrom = trace.length;
      await page.click(`a[href='/apps/#repair=${HEALTH}']`);
      await page.waitForFunction(() => document.querySelector("#apps-sheet")?.open === true && [...document.querySelectorAll("#apps-sheet button")].some((button) => button.textContent === "Continue"), { timeout: 60_000 });
      assert.match(await page.$eval("#apps-sheet", (node) => node.innerText), /Your data is untouched/);
      if (label === "run-tampered") await captureState(page, "repair-sheet");
      await clickByText(page, "Continue");
      const repaired = await waitUntil(async () => { const text = await page.$eval(".apps-install-line", (node) => node.textContent).catch(() => ""); return /^(Repaired\.|Not repaired|Sign-in|OpenKey|We couldn't)/.test(text) ? text : undefined; }, 300_000);
      assert.match(repaired ?? "", /^Repaired\./, `${label}: repair ended with "${repaired}"`);
      assert.equal(signCount(repairFrom, label), 1, `${label}: Repair needed one approval`);
      const sessionsAfterRepair = sessionMessages(label);
      const repairRecap = recapOf(sessionsAfterRepair.at(-1));
      assert.deepEqual(repairRecap.filter((line) => line.startsWith("applications/") && !line.startsWith("applications/capabilities")).sort(), [`applications/kv/${HEALTH}/app/ tinycloud.kv/del`, `applications/kv/${HEALTH}/app/ tinycloud.kv/list`, `applications/kv/${HEALTH}/app/ tinycloud.kv/put`].sort(), `${label}: Repair signed for more than put, del and list on app/`);
      assert.equal(lifetimeMs(sessionsAfterRepair.at(-1)), 15 * 60_000);
      // On the node: the code is the catalog's again, the stray is gone, and the person's data and notes are untouched.
      const healthEntry = app(HEALTH);
      const listed = await node.kv.list({ prefix: `${HEALTH}/app/` });
      assert.deepEqual([...listed.data.keys].sort(), [...healthEntry.bundle.files.filter((file) => !file.path.startsWith("knowledge/")).map((file) => `${HEALTH}/app/${file.path}`), `${HEALTH}/app/install.json`].sort(), `${label}: the saved code is not exactly the catalog's files`);
      const back = await node.kv.get(codeKey, { binary: true });
      assert.equal(sha(Buffer.from(back.data.data)), sha(Buffer.from(originalCode.data.data)), `${label}: app.jsx is not the catalog's again`);
      const rowCount = await node.sql.db(`${HEALTH}/healthlog`).query("SELECT count(*) FROM meal");
      assert.deepEqual(rowCount.data.rows, [[1]], `${label}: Repair touched the data`);
      if (label === "run-tampered") await captureState(page, "repaired");
      await context.close();
      // And the app opens again.
      const reopened = await openRunner(browser, stack, `${label}-reopen`, HEALTH);
      await start(reopened.page);
      await runningFrame(reopened.page);
      report.stages[label].repairedAndOpens = true;
      await reopened.context.close();
      void undo;
    }
    // An installed version that has left the catalog: the honest message and what to delete, no Repair, nothing signed beyond the read.
    const recordKey = `${HEALTH}/app/install.json`;
    const record = await node.kv.get(recordKey, { binary: true });
    const old = JSON.parse(Buffer.from(record.data.data).toString("utf8"));
    await put(recordKey, Buffer.from(JSON.stringify({ ...old, digest: "ab".repeat(32) })));
    {
      const label = "run-removed-version";
      const { page, context } = await openRunner(browser, stack, label, HEALTH);
      await start(page);
      assert.equal(await waitUntil(async () => (await screenTitle(page)) === "This version of the app isn't in the catalog any more"), true, `${label}: screen (status: ${await statusText(page)})`);
      assert.equal(await page.$("a[href*='repair']"), null, `${label}: Repair offered for a version with no pin`);
      const text = await page.$eval(".run-screen", (node) => node.textContent);
      assert(text.includes(`tinycloud kv list --space applications --prefix ${HEALTH}/app/`) && text.includes("tinycloud kv delete --space applications"), `${label}: no removal guidance`);
      assert.equal(sessionMessages(label).length, 1);
      await captureState(page, "removed-version");
      report.stages.removedVersion = { guidance: true, repairOffered: false };
      await context.close();
    }
    await put(recordKey, Buffer.from(record.data.data));
  }

  // ---- 5b. A hostile app, installed from a catalog entry (its code is pinned, so this is the only way it can reach the runner).
  phase = "5b. A hostile app, installed from a catalog entry (its code "; console.error(`[t5b] ${phase}`);
  {
    await openFirst(browser, stack, HOSTILE);
    const node = await ownerClient(HOSTILE);
    const label = "run-hostile";
    const from = trace.length;
    listener.reset();
    const { page, context } = await openRunner(browser, stack, label, HOSTILE);
    await start(page);
    const child = await runningFrame(page);
    const afterStart = trace.length;
    await child.waitForFunction(() => document.querySelector("#report")?.getAttribute("data-state") === "done", { timeout: 240_000 });
    const result = await child.evaluate(() => window.__report);
    // The sandbox, as for any page in it.
    for (const probe of ["parentDocument", "topDocument", "localStorage", "sessionStorage", "indexedDB", "cookie", "fetchRemote", "fetchSameOrigin", "importUrl", "worker"]) {
      assert.equal(result[probe].ok, false, `${probe} was allowed: ${JSON.stringify(result[probe])}`);
    }
    assert.equal(result.origin, "null");
    for (const probe of ["xhr", "webSocket", "eventSource", "image"]) assert.notEqual(result[probe], "loaded", probe);
    assert.notEqual(result.webSocket, "open"); assert.notEqual(result.eventSource, "open");
    assert.equal(result.windowOpen.ok && result.windowOpen.value !== "null", false, "window.open opened a window");
    assert(result.violations.includes("connect-src"), `no connect-src violation was reported (${JSON.stringify(result.violations)})`);
    // THE LEAK VECTORS: the page read data (result.marker) and tried every browser-initiated request there is. The listener saw nothing.
    await settle(2500);
    assert.notEqual(result.marker, "none", "the hostile app read no data to leak");
    assert.equal(result.vectors.webrtc, "removed", "WebRTC is still there");
    assert.deepEqual(listener.requests, [], `a vector reached the listener: ${JSON.stringify(listener.requests)}`);
    assert.equal(listener.connections, 0, "a vector opened a connection to the listener");
    assert.equal(listener.upgrades, 0);
    assert.equal(listener.udpPackets, 0, "a vector sent UDP to the listener (WebRTC)");
    assert(trace.slice(from).every((entry) => !/127\.0\.0\.1:|evil\.example/.test(`${entry.origin}`) || entry.origin === stack.canonical.share), "a request reached the listener host through the page");
    const leftInDocument = await child.evaluate((origin) => [...document.querySelectorAll("*")].filter((node) => [...node.attributes].some((attribute) => attribute.value.includes(origin))).map((node) => node.localName), listener.origin);
    assert.deepEqual(leftInDocument, [], "an element that names the listener is still in the app's document");
    // The bridge: everything outside the manifest or the classifier is refused by the runner page.
    const c = result.cap;
    assert.deepEqual({ ...c, concurrent: undefined }, {
      kvOutside: "PERMISSION_DENIED", kvTraversal: "BAD_REQUEST", kvAbsoluteOwn: "PERMISSION_DENIED", kvAbsoluteOther: "PERMISSION_DENIED", kvPutOwnCode: "PERMISSION_DENIED", kvDeleteOwnCode: "PERMISSION_DENIED", kvListRoot: "PERMISSION_DENIED", kvDelPrefs: "PERMISSION_DENIED",
      sqlDrop: "BAD_REQUEST", sqlMulti: "BAD_REQUEST", sqlAttach: "BAD_REQUEST", sqlPragma: "BAD_REQUEST", sqlVacuum: "BAD_REQUEST", sqlLoadExtension: "BAD_REQUEST", sqlWithInsert: "BAD_REQUEST", sqlUnicodeSpace: "BAD_REQUEST", sqlWriteAsQuery: "BAD_REQUEST",
      sqlExecuteForeign: "PERMISSION_DENIED", sqlExecuteForeignAbsoluteOwn: "PERMISSION_DENIED", sqlExecuteHealth: "PERMISSION_DENIED", sqlQueryForeign: "PERMISSION_DENIED",
      secretCreate: "ok", secretInsert: "ok",
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
    const health = await ownerClient(HEALTH);
    const rows = await health.sql.db(`${HEALTH}/healthlog`).query("SELECT count(*) FROM meal");
    assert.deepEqual(rows.data.rows, [[1]], "the hostile app changed the Health Log");
    const recipeTables = await health.sql.db(`${RECIPES}/recipes`).query("SELECT count(*) FROM sqlite_master");
    assert(recipeTables.ok, "the Recipes database is gone");
    void node;
    await noViolations(page, "hostile");
    report.stages.hostile = { sandbox: "all refused", cap: c, vectors: Object.keys(result.vectors).length, listener: { requests: 0, connections: 0, udp: 0 }, forgedAnswered: 0 };
    await captureState(page, "hostile-running");
    await context.close();
  }

  // ---- 6. Forced past the runner page, the NODE refuses: the real data adapter and bridge, a fake parent that skips the manifest check, a signer-less client holding the session.
  phase = "6. Forced past the runner page, the NODE refuses: the real d"; console.error(`[t5b] ${phase}`);
  {
    phase = "node-boundary";
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

    // Health Log, as the runner signs it: the open's one session.
    const { holder: healthHolder } = await sessionFor(openManifest(sdkCore.validateManifest(healthManifest)));
    const callHealth = forced(healthHolder, HEALTH);
    // Allowed by the session: its own database and prefs.
    assert.equal((await callHealth("sql.query", { db: "healthlog", sql: "SELECT count(*) FROM meal", params: [] })).ok, true);
    assert.equal((await callHealth("kv.put", { key: "prefs/node-boundary.json", body: "{}", contentType: "application/json" })).ok, true);
    // Refused by the node, with the parent's manifest check skipped.
    refusedByNode(await callHealth("kv.get", { key: "secrets/x" }), "kv.get outside the manifest");
    // The union grants put on the app's own folder, so the node accepts it; the bridge refuses it (stage 5b, kvPutOwnCode).
    assert.equal((await callHealth("kv.put", { key: "app/node-boundary.txt", body: "ok" })).ok, true, "the node refused the union's put on app/");
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
    const { holder: recipesHolder } = await sessionFor(openManifest(sdkCore.validateManifest(recipesManifest)));
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
    // Remove the probe file the node accepted above, so the app folder is what the catalog installed; stage 7 reopens the app and its pin check refuses extra files.
    const probeDeleted = await owner2.kv.delete(`${HEALTH}/app/node-boundary.txt`);
    assert(probeDeleted.ok, `deleting the probe file failed: ${JSON.stringify(probeDeleted.error)}`);
    const probeLeft = await owner2.kv.list({ prefix: `${HEALTH}/app/node-boundary` });
    assert.deepEqual(probeLeft.data.keys, [], "the probe file is still in the app's folder");
    report.stages.nodeBoundary = { refusedByNode: true };
  }

  // ---- 7. The session expires at its time: the page's one-hour timer (shortened to 4 s here) tears the frame down and says so.
  phase = "7. The session expires at its time: the page's one-hour time"; console.error(`[t5b] ${phase}`);
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
    // Opening it again works (one approval).
    await clickByText(page, `Open ${health.name} again`);
    await runningFrame(page);
    report.stages.expiry = { screen: "Your session expired", reopened: true };
    await context.close();
  }

  // ---- 8. Uninstall the Health Log from the apps page: the runner then says it needs installing and starts nothing.
  phase = "8. Uninstall the Health Log from the apps page: the runner t"; console.error(`[t5b] ${phase}`);
  {
    const { page, context } = await newPage(browser, stack, "uninstall-health", `${stack.canonical.share}/apps/`);
    await page.waitForSelector(".apps-card", { timeout: 60_000 });
    await page.evaluate((name) => document.querySelector(`button[aria-label='Details for ${name}']`).click(), health.name);
    await page.evaluate((name) => document.querySelector(`#apps-sheet button[aria-label='Uninstall ${name}']`).click(), health.name);
    await page.evaluate(() => [...document.querySelectorAll("#apps-sheet footer button")].find((node) => node.textContent === "Remove app").click());
    const removed = await waitUntil(async () => { const value = await page.$eval(".apps-install-line", (node) => node.textContent).catch(() => ""); return /^Removed /.test(value) ? value : undefined; }, 300_000);
    assert(removed?.includes("Your app data and settings are kept."), `uninstall ended with "${removed}"`);
    await context.close();
    // After the uninstall, opening the app starts OpenKey on load; the approval reinstalls its files from the catalog and runs it.
    controls.sign = hold();
    const { page: runner, context: runnerContext } = await openRunner(browser, stack, "after-uninstall", HEALTH);
    await arrivedOrExplain(runner, controls.sign, "the approval after the uninstall");
    assert.match(await statusText(runner), /^Approve in the OpenKey window so Share can open Health Log from your TinyCloud/, "after the uninstall the runner did not ask for the approval");
    assert.equal(frames(runner).child, undefined, "the app's frame started before the approval");
    controls.sign.release(); controls.sign = undefined;
    await runningFrame(runner);
    const reinstalled = await (await ownerClient(HEALTH)).kv.list({ prefix: `${HEALTH}/app/` });
    assert(reinstalled.data.keys.includes(`${HEALTH}/app/app.jsx`), "the open after the uninstall did not reinstall the app's code");
    report.stages.uninstalled = { reinstalledAfterApproval: true };
    await runnerContext.close();
  }

  // ---- Diagnostics: no page error, no unexpected console output, nothing left the allowed origins.
  const pageErrors = consoleLog.filter((entry) => entry.type === "pageerror");
  assert.deepEqual(pageErrors, [], "a page error was raised");
  // Expected noise: 404s for records a fresh account does not have yet (registry location, account index), the site-wide
  // Permissions-Policy header's newest feature name, and the fresh-account bootstrap warning. The hostile app's own
  // refusals (blocked form, wrong target origin) are logged by the browser in its phase and are the point of it.
  const expectedConsole = [/^Failed to load resource: the server responded with a status of (?:400|401|404|412) /, /^Failed to load resource: net::ERR_FAILED$/, /^Error with Permissions-Policy header: Unrecognized feature: 'web-share'\.$/, /^TinyCloud account (?:registry sync failed after retries|index initialization failed; continuing registry sync)/];
  // axe (injected by this script to scan a state) messages each frame with the frame's URL as target origin, and the browser warns for an opaque frame: noise from the probe, not the page.
  // A console error is accepted from the hostile app's open phase only when it is the browser's blocked-request message for that app. Any other error or warning still fails.
  const hostileRefusals = [/^Connecting to '[^']*' violates the following Content Security Policy directive: "[^"]*"\. The action has been blocked\.$/, /^Fetch API cannot load \S+\. Refused to connect because it violates the document's Content Security Policy\.$/];
  const isHostileRefusal = (entry) => entry.phase === `open-${HOSTILE}` && entry.type === "error" && hostileRefusals.some((pattern) => pattern.test(entry.text));
  // Self-test of that predicate: the observed refusal is accepted; an untagged copy of it and a tagged non-CSP error are not.
  const refusalText = "Connecting to 'http://127.0.0.1:1/fetch' violates the following Content Security Policy directive: \"connect-src 'none'\". The action has been blocked.";
  assert.equal(isHostileRefusal({ phase: `open-${HOSTILE}`, type: "error", text: refusalText }), true, "self-test: the hostile app's refusal is accepted");
  assert.equal(isHostileRefusal({ phase: "run-expiry", type: "error", text: refusalText }), false, "self-test: an untagged CSP message is not accepted");
  assert.equal(isHostileRefusal({ phase: `open-${HOSTILE}`, type: "error", text: "Failed to load resource: the server responded with a status of 500 (Internal Server Error)" }), false, "self-test: a tagged non-CSP error is not accepted");
  const unexpected = consoleLog.filter((entry) => entry.phase !== "run-hostile" && !isHostileRefusal(entry) && !entry.at.startsWith("pptr:") && !expectedConsole.some((pattern) => pattern.test(entry.text)));
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
  restoreCatalog();
  listener.close();
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  process.exit();
}
