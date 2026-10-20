/**
 * Real /courier smoke (TC-712 G7).
 *
 * Signs a brand-new throwaway OpenKey account (email OTP through a public
 * Mailinator inbox) into the candidate /courier view, served at the production
 * origin, against production OpenKey and the production owner node. No real
 * person's account or key is involved: every run creates a new inbox.
 *
 *   node test/e2e-prod/courier-live-smoke.mjs
 *
 * What it proves:
 *  1. Sign-in. The session the view asks OpenKey to sign is decoded from the
 *     signed SIWE message's ReCap: the exact courier grant (get+list on the
 *     courier prefix, put only on me/approvals/ and me/orders/, all in the
 *     `agents` space) and no other put, delete, metadata or delegation on it.
 *     The account-registry permissions the SDK adds to every sign-in are listed
 *     separately.
 *  2. A fresh account's mailbox: what the page says before anything is seeded.
 *  3. With a seeded thread (test/fixtures/courier-seed, built only here): the
 *     thread list, the merged thread, the "needs you" card.
 *  4. Approve writes me/approvals/<id>.json {requestId, requestHash, decision,
 *     note, decidedAt} to the real node; after a new sign-in the request is
 *     listed as decided and the decision reads back; the orders file is written
 *     and reads back.
 *
 * Output: one JSON line (and COURIER_SMOKE_ARTIFACT). The inbox, OTP, address,
 * keys and message text never leave process memory. COURIER_SMOKE_SHOT_DIR
 * keeps screenshots.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { build } from "vite";
import { startCandidateServer } from "./candidate-server.mjs";

const SHARE = "https://share.tinycloud.xyz";
const OPENKEY = process.env.COURIER_SMOKE_OPENKEY_ORIGIN ?? "https://openkey.so";
const MAILINATOR = "https://www.mailinator.com/api/v2/domains/public/inboxes";
const shotDir = process.env.COURIER_SMOKE_SHOT_DIR;
const AGENTS = "agents";
const PREFIX = "xyz.tinycloud.courier/";
const inbox = `tc-courier-smoke-${randomBytes(8).toString("hex")}`;
const t0 = Date.now();
const since = (start = t0) => Date.now() - start;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const scrub = (value) => String(value)
  .replace(/#\S*/g, "#<fragment>")
  .replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, "<email>")
  .replace(/0x[0-9a-fA-F]{40}/g, "0x<address>")
  .replace(/did(:|%3A)(key|pkh)[\w:.%-]{8,}/gi, "did:$2:<id>")
  .replace(/\b\d{6,8}\b/g, "<digits>");

const report = { type: "tinycloud.share/courier-live-smoke/v1", openkey: OPENKEY, result: "failed", stage: "start", approvals: {}, timingsMs: {} };
let stage = "start";
const setStage = (next) => { stage = next; report.stage = next; };
const consoleErrors = [];

async function mailinator(path) {
  for (let attempt = 1; attempt <= 4; attempt++) {
    const response = await fetch(`${MAILINATOR}/${inbox}${path}`, { headers: { "user-agent": "tinycloud-courier-smoke" } }).catch(() => undefined);
    if (response?.ok) { const text = await response.text(); if (text.trim()) return JSON.parse(text); }
    await sleep(2_000 * attempt);
  }
  return {};
}

/** Mails whose code was already typed: a later sign-in in the same inbox needs the newer one. */
const usedMail = new Set();
async function openKeyOtp(timeout = 150_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const { msgs = [] } = await mailinator("");
    const codeMail = msgs.filter((entry) => /openkey/i.test(entry.subject ?? "") && !usedMail.has(entry.id)).sort((a, b) => (a.seconds_ago ?? 0) - (b.seconds_ago ?? 0));
    for (const message of codeMail) {
      const body = JSON.stringify(await mailinator(`/messages/${message.id}`)).replace(/<[^>]+>/g, " ");
      const codes = new Set([...body.matchAll(/verification code[^0-9]{0,80}(\d{6})(?!\d)/gi)].map((match) => match[1]));
      if (codes.size === 1) { usedMail.add(message.id); return [...codes][0]; }
    }
    await sleep(4_000);
  }
  throw new Error("no OpenKey code arrived in the Mailinator inbox");
}

const frameAt = (page, path) => page.frames().find((frame) => frame.url().startsWith(`${OPENKEY}${path}`));
async function until(probe, timeout, what) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await Promise.resolve().then(probe).catch(() => undefined);
    if (value) return value;
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${what}`);
}
const clickButton = (frame, label) => frame.evaluate((text) => {
  const button = [...document.querySelectorAll("button")].find((candidate) => candidate.innerText.trim().startsWith(text) && !candidate.disabled);
  button?.click();
  return button !== undefined;
}, label);

/** The SIWE messages OpenKey was asked to sign: held in memory, only their capability lists are reported. */
const signedMessages = [];
const installSignCapture = (page) => page.evaluateOnNewDocument(() => {
  window.__tcSigned = [];
  addEventListener("message", (event) => {
    const data = event.data;
    if (data !== null && typeof data === "object" && data.type === "openkey:sign:request" && typeof data.message === "string") window.__tcSigned.push(data.message);
  });
});

/** `<space>/<service>/<path> <ability>` for every capability in a signed session message's ReCap. */
function recapList(message) {
  const match = /urn:recap:([A-Za-z0-9_-]+)/.exec(message);
  if (match === null) return undefined;
  const recap = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
  return Object.entries(recap.att).flatMap(([resource, abilities]) => Object.keys(abilities).map((ability) => `${resource.replace(/^tinycloud:pkh:eip155:\d+:0x[0-9a-fA-F]{40}:/, "")} ${ability}`)).sort();
}

let emailDone = false;
/** Drives OpenKey (email sign-in the first time, every sign review) until `done` holds in the page. */
async function drive(page, done, counter, timeout = 240_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (Date.now() - (deadline - timeout) > 100_000 && report.stuck === undefined) {
      // Origin and path only; widget text with any address or email scrubbed.
      const text = async (frame) => scrub(await frame.evaluate(() => document.body.innerText.replace(/\s+/g, " ").slice(0, 240)).catch(() => ""));
      report.stuck = { in: counter, frames: page.frames().map((frame) => { try { const url = new URL(frame.url()); return `${url.origin}${url.pathname}`; } catch { return frame.url().slice(0, 30); } }), widgets: await Promise.all(page.frames().filter((frame) => frame.url().startsWith(OPENKEY)).map(text)) };
      if (shotDir !== undefined) await page.screenshot({ path: join(shotDir, `stuck-${counter}.png`) }).catch(() => undefined);
    }
    const connect = frameAt(page, "/widget/embed/connect");
    if (connect !== undefined) {
      // Labels only (never the account's text): what a later sign-in in the same browser asks of the person.
      const labels = await connect.evaluate(() => [...document.querySelectorAll("button")].map((button) => button.innerText.trim().replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, "<email>")).filter((text) => text !== "")).catch(() => []);
      report.connectButtons = [...new Set([...(report.connectButtons ?? []), ...labels])].slice(0, 16);
    }
    // OpenKey remembers nothing between pages of this browser, so every page's sign-in is the full email flow (a new code from the same inbox).
    if (connect !== undefined && await clickButton(connect, "Continue with email").catch(() => false)) {
      setStage("openkey-email");
      const field = await until(() => connect.$("input[type=email]"), 30_000, "OpenKey's email field");
      await field.type(`${inbox}@mailinator.com`);
      await until(() => clickButton(connect, "Send code"), 10_000, "Send code");
      setStage("openkey-otp");
      const otp = await openKeyOtp();
      const code = await until(() => connect.$("input[type=text], input[inputmode=numeric], input[autocomplete=one-time-code]"), 30_000, "OpenKey's code field");
      await code.type(otp);
      await until(() => clickButton(connect, "Verify"), 10_000, "Verify");
      await until(async () => connect.isDetached() || frameAt(page, "/widget/embed/sign") !== undefined || await clickButton(connect, "Create a new account"), 30_000, "the next OpenKey step").catch(() => undefined);
      emailDone = true;
      setStage(counter);
    }
    const sign = frameAt(page, "/widget/embed/sign");
    if (sign !== undefined) {
      for (const message of await sign.evaluate(() => window.__tcSigned ?? []).catch(() => [])) if (!signedMessages.includes(message)) signedMessages.push(message);
      if (await clickButton(sign, "Approve").catch(() => false)) {
        report.approvals[counter] = (report.approvals[counter] ?? 0) + 1;
        await until(() => frameAt(page, "/widget/embed/sign") !== sign || sign.isDetached(), 30_000, "the OpenKey review to close").catch(() => undefined);
      }
    }
    if (await page.evaluate(done).catch(() => false)) return;
    for (const frame of page.frames().filter((candidate) => candidate.url().startsWith(OPENKEY))) {
      const alert = await frame.evaluate(() => [...document.querySelectorAll("[role=alert]")].map((node) => node.textContent ?? "").join(" ").trim()).catch(() => "");
      if (alert) { report.openKeyAlert = scrub(alert).replace(/\s+/g, " ").slice(0, 200); throw new Error("OpenKey showed an error"); }
    }
    await sleep(250);
  }
  throw new Error(`timed out in ${counter}`);
}

const shot = async (page, name) => { if (shotDir !== undefined) await page.screenshot({ path: join(shotDir, `${name}.png`) }); };
const panelText = (page) => page.evaluate(() => (document.querySelector(".cr-panel")?.textContent ?? "").replace(/\s+/g, " ").trim());

const temporary = mkdtempSync(join(tmpdir(), "courier-smoke-"));
let browser; let server;
try {
  if (shotDir !== undefined) mkdirSync(shotDir, { recursive: true });
  setStage("build");
  const dist = join(temporary, "dist");
  await build({ configFile: resolve(import.meta.dirname, "courier-live.vite.config.ts"), logLevel: "error", build: { outDir: dist, emptyOutDir: true } });

  setStage("candidate-server");
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate-key.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore" });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8" }).trim();
  server = await startCandidateServer({ root: dist, key: readFileSync(key), cert: readFileSync(cert) });
  browser = await puppeteer.launch({
    headless: process.env.HEADED !== "1",
    args: ["--disable-quic", "--no-proxy-server", `--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${server.port}`, `--ignore-certificate-errors-spki-list=${spki}`, ...(process.env.GITHUB_ACTIONS === "true" ? ["--no-sandbox"] : [])],
    userDataDir: join(temporary, "profile"),
  });

  const open = async (path, width = 1280) => {
    const page = await browser.newPage();
    await page.setViewport({ width, height: 900 });
    await installSignCapture(page);
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${scrub(error.message).slice(0, 200)}`));
    page.on("console", (message) => { if (message.type() === "error" && !/Failed to load resource/.test(message.text())) consoleErrors.push(scrub(message.text()).slice(0, 200)); });
    page.on("response", (response) => { if (response.status() >= 400 && /tinycloud|openkey/.test(new URL(response.url()).origin)) (report.failedResponses ??= []).push(`${response.status()} ${new URL(response.url()).origin}${scrub(new URL(response.url()).pathname).slice(0, 60)}`); });
    await page.goto(`${SHARE}${path}`, { waitUntil: "domcontentloaded", timeout: 90_000 });
    return page;
  };

  // 1+2: a fresh account opens the view.
  setStage("view-fresh");
  const fresh = await open("/courier/");
  await fresh.waitForSelector("button.auth-button:not([disabled])", { timeout: 60_000 });
  await fresh.click("button.auth-button");
  const freshStart = Date.now();
  await drive(fresh, () => document.querySelector(".cr-tabs") !== null || document.querySelector(".auth-status .tc-status") !== null, "viewSignIn");
  report.timingsMs.firstSignIn = since(freshStart);
  await fresh.waitForFunction(() => document.querySelector(".cr-panel")?.getAttribute("aria-busy") === "false", { timeout: 60_000 }).catch(() => undefined);
  report.fresh = { panel: scrub(await panelText(fresh)).slice(0, 400), signInFailure: await fresh.evaluate(() => document.querySelector(".auth-status .tc-status")?.textContent ?? null) };
  await shot(fresh, "01-fresh-account");
  const sessionMessage = signedMessages.map((message) => ({ message, list: recapList(message) })).find((entry) => entry.list !== undefined);
  assert.ok(sessionMessage !== undefined, "OpenKey was asked to sign a session message with a ReCap");
  report.recap = sessionMessage.list;
  // The courier grant, exactly.
  const inAgents = sessionMessage.list.filter((entry) => entry.startsWith(`${AGENTS}/`));
  // The SDK's own read of the space's capability list is the only non-kv entry the SDK adds to a space.
  assert.deepEqual(inAgents.filter((entry) => /capabilities/.test(entry)).map((entry) => entry.replace(/^.* /, "")), ["tinycloud.capabilities/read"]);
  const courier = inAgents.filter((entry) => !/capabilities/.test(entry));
  assert.deepEqual(courier, [
    `${AGENTS}/kv/${PREFIX} tinycloud.kv/get`,
    `${AGENTS}/kv/${PREFIX} tinycloud.kv/list`,
    `${AGENTS}/kv/${PREFIX}me/approvals/ tinycloud.kv/put`,
    `${AGENTS}/kv/${PREFIX}me/orders/ tinycloud.kv/put`,
  ].sort(), "the agents-space grant is exactly the courier manifest");
  for (const entry of sessionMessage.list) {
    // Outside `agents`, only what the SDK adds to every sign-in for the account's own space registry may be written.
    if (/ tinycloud\.kv\/put$/.test(entry)) assert.match(entry, /^(?:agents\/kv\/xyz\.tinycloud\.courier\/me\/(?:approvals|orders)\/|account\/kv\/(?:applications\/|spaces\/|system\/bootstrap\/complete ))/, `unexpected put: ${entry}`);
    if (entry.startsWith(`${AGENTS}/`)) assert.doesNotMatch(entry, /kv\/(?:del|metadata)|delegat/i, `unexpected ability: ${entry}`);
  }
  report.recapAgentsOnly = courier;

  // 3: seed a throwaway mailbox (test tooling), then read it in a new view session.
  setStage("seed");
  const seed = await open("/test/fixtures/courier-seed/index.html");
  await seed.waitForSelector("#seed", { timeout: 60_000 });
  await seed.click("#seed");
  await drive(seed, () => ["seeded", "failed"].includes(document.querySelector("#status")?.dataset.state), "seedSignIn", 240_000);
  const seeded = await seed.evaluate(() => document.querySelector("#status").textContent);
  assert.equal(seeded, "Seeded.", seeded);
  await seed.close();

  // The view's own session is still open in the first tab: Refresh reads the node again, no second sign-in.
  setStage("view-seeded");
  const view = fresh;
  await view.bringToFront();
  const refresh = async () => {
    await view.evaluate(() => [...document.querySelectorAll("[role=tab]")].find((tab) => tab.textContent.startsWith("Threads")).click());
    await view.evaluate(() => [...document.querySelectorAll(".cr-screen-head button")].find((button) => button.textContent === "Refresh").click());
    await view.waitForFunction(() => { const button = [...document.querySelectorAll(".cr-screen-head button")].find((candidate) => candidate.textContent === "Refresh"); return button !== undefined && !button.disabled && document.querySelector(".cr-panel")?.getAttribute("aria-busy") === "false"; }, { timeout: 60_000 });
  };
  await refresh();
  assert.ok(await view.$(".cr-row-button"), `the seeded thread is listed (page says: ${scrub(await panelText(view)).slice(0, 200)})`);
  const list = await view.evaluate(() => ({ subject: document.querySelector(".cr-row-subject")?.textContent, badge: document.querySelector(".cr-badge--attention")?.textContent, tab: [...document.querySelectorAll("[role=tab]")].map((tab) => tab.textContent) }));
  assert.equal(list.subject, "Seed: review the status table");
  assert.equal(list.badge, "Needs you");
  await shot(view, "02-threads");
  await view.click(".cr-row-button");
  await view.waitForSelector(".cr-message--peer", { timeout: 60_000 });
  await view.waitForSelector(".cr-body iframe", { timeout: 30_000 });
  await sleep(800);
  const thread = await view.evaluate(() => ({ messages: document.querySelectorAll(".cr-message").length, tasks: document.querySelectorAll(".cr-task").length, state: document.querySelector(".cr-state")?.textContent, sandbox: [...document.querySelectorAll(".cr-body iframe")].map((frame) => frame.getAttribute("sandbox")) }));
  assert.deepEqual({ messages: thread.messages, tasks: thread.tasks, state: thread.state }, { messages: 2, tasks: 1, state: "Waiting for you to approve" });
  assert.ok(thread.sandbox.every((value) => value === ""), "every body is in a fully sandboxed frame");
  await shot(view, "03-thread");

  setStage("approve");
  await view.evaluate(() => [...document.querySelectorAll("[role=tab]")].find((tab) => tab.textContent.startsWith("Needs you")).click());
  await view.waitForSelector(".cr-request", { timeout: 30_000 });
  await view.waitForFunction(() => document.querySelector(".cr-approve")?.disabled === false, { timeout: 10_000 });
  await view.type(".cr-note-input", "Throwaway approval from the live smoke.");
  await shot(view, "04-needs-you");
  await view.click(".cr-approve");
  await view.waitForFunction(() => /Approved\.|Already decided|couldn't record/.test(document.querySelector(".cr-result")?.textContent ?? ""), { timeout: 60_000 });
  const verdict = await view.evaluate(() => document.querySelector(".cr-result")?.textContent);
  assert.match(verdict, /^Approved\./, `the decision was recorded (page says: ${verdict})`);
  await shot(view, "05-approved");
  setStage("readback");
  const again = view;
  await refresh();
  await again.evaluate(() => [...document.querySelectorAll("[role=tab]")].find((tab) => tab.textContent.startsWith("Needs you")).click());
  await again.waitForSelector(".cr-settled", { timeout: 30_000 });
  const settled = await again.evaluate(() => ({ cards: document.querySelectorAll(".cr-request").length, settled: document.querySelector(".cr-settled")?.textContent.replace(/\s+/g, " ") }));
  assert.equal(settled.cards, 0, "a decided request is no longer waiting");
  assert.match(settled.settled, /Approved/);
  assert.match(settled.settled, /Throwaway approval from the live smoke\./);
  await shot(again, "06-decided");

  setStage("orders");
  await again.evaluate(() => [...document.querySelectorAll("[role=tab]")].find((tab) => tab.textContent.startsWith("Orders")).click());
  await again.waitForFunction(() => document.querySelector(".cr-orders-input") !== null && !document.querySelector(".cr-orders-input").disabled, { timeout: 30_000 });
  await again.type(".cr-orders-input", "# Throwaway orders\n\n- ask before any merge\n");
  await again.click(".cr-shell .button-primary");
  await again.waitForFunction(() => /Saved\.|couldn't|changed somewhere/.test(document.querySelector(".cr-result")?.textContent ?? ""), { timeout: 60_000 });
  const saved = await again.evaluate(() => document.querySelector(".cr-result")?.textContent);
  assert.match(saved, /^Saved\./, `orders were saved (page says: ${saved})`);
  const readBack = await again.evaluate(() => document.querySelector(".cr-orders-input").value);
  assert.equal(readBack, "# Throwaway orders\n\n- ask before any merge\n", "the orders read back from the node");
  await shot(again, "07-orders");

  // Nothing about the mailbox is kept in the tab.
  const storage = await again.evaluate(async () => ({ local: Object.keys(localStorage).length, session: Object.keys(sessionStorage).length, databases: (await indexedDB.databases?.())?.length ?? 0, cookies: document.cookie.length, url: location.href }));
  assert.deepEqual({ local: storage.local, session: storage.session, cookies: storage.cookies }, { local: 0, session: 0, cookies: 0 });
  assert.equal(storage.url, `${SHARE}/courier/`, "the address bar carries nothing");
  report.storage = { local: storage.local, session: storage.session, indexedDbDatabases: storage.databases };
  report.consoleErrors = consoleErrors;
  assert.deepEqual(consoleErrors.filter((line) => /Content Security Policy|Trusted Type|violat/i.test(line)), [], "no CSP or Trusted Types violation");
  report.result = "passed";
  setStage("done");
} catch (error) {
  report.error = scrub(error instanceof Error ? error.message : String(error)).slice(0, 500);
  report.consoleErrors = consoleErrors.slice(-10);
  const pages = await browser?.pages().catch(() => []) ?? [];
  const last = pages.at(-1);
  report.pageStatus = scrub(await last?.evaluate(() => `${document.querySelector(".auth-status")?.textContent ?? ""} ${document.querySelector(".cr-panel")?.textContent ?? ""}`.replace(/\s+/g, " ").trim()).catch(() => "") ?? "").slice(0, 300);
  if (shotDir !== undefined && last !== undefined) await last.screenshot({ path: join(shotDir, "failure.png") }).catch(() => undefined);
} finally {
  report.timingsMs.total = since();
  await browser?.close().catch(() => undefined);
  await server?.close().catch(() => undefined);
  rmSync(temporary, { recursive: true, force: true });
}

const line = JSON.stringify(report);
if (process.env.COURIER_SMOKE_ARTIFACT) writeFileSync(process.env.COURIER_SMOKE_ARTIFACT, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(line);
process.exit(report.result === "passed" ? 0 : 1);
