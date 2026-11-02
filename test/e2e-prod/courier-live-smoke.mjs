/**
 * Real /courier smoke (TC-712 G7).
 *
 * Signs a brand-new throwaway OpenKey account (email OTP through a private
 * mail.tm inbox made for the run, deleted at its end) into the candidate /courier view, served at the production
 * origin, against production OpenKey and the production owner node. No real
 * person's account or key is involved: every run creates a new inbox. Every click
 * in OpenKey's widget is real browser input, as a person's is.
 *
 *   node test/e2e-prod/courier-live-smoke.mjs
 *
 * What it proves:
 *  1. Sign-in. The session the view asks OpenKey to sign is decoded from the
 *     signed SIWE message's ReCap: the exact courier grant (get+list on the
 *     courier prefix, put only on me/approvals/ and me/orders/, all in the
 *     `agents` space) and no other put, delete, metadata or delegation on it.
 *     The whole decoded grant equals the four Courier KV abilities plus the
 *     SDK's capabilities/read on agents; no account-registry grants.
 *  2. A fresh account sees no Courier space and tc courier init; no hosting signature.
 *     A second throwaway account is seeded, then a new view signs in to its existing space.
 *  3. With a seeded thread (test/fixtures/courier-seed, built only here): the
 *     thread list, the merged thread, the "needs you" card.
 *  4. Approve writes me/approvals/<id>.json {requestId, requestHash, decision,
 *     note, decidedAt} to the real node; after a new sign-in the request is
 *     listed as decided and the decision reads back; the orders file is written
 *     and reads back.
 *
 * Output: one JSON line (and COURIER_SMOKE_ARTIFACT). The inbox, OTP, address,
 * keys and message text never leave process memory. Refused TinyCloud/OpenKey
 * responses are reported with their status, error code and a scrubbed body.
 * COURIER_SMOKE_SHOT_DIR keeps screenshots.
 *
 * COURIER_SMOKE_DID_FILE (off by default) appends the run's throwaway owners, one
 * "<owner DID> <inbox email>" line each, to a 0600 file under /var/tmp for the QA
 * exclusion list; the path is checked before the run starts. Its contents are never
 * printed or reported: the report says only `didFile: written n/m` or `refused`.
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
import { didFileTarget, didFromSiwe, writeDidFile } from "./did-file.mjs";
import { APPROVE_NAME, refusal, scrub } from "./smoke-redact.mjs";

const SHARE = "https://share.tinycloud.xyz";
const OPENKEY = process.env.COURIER_SMOKE_OPENKEY_ORIGIN ?? "https://openkey.so";
const MAIL_TM = "https://api.mail.tm";
const shotDir = process.env.COURIER_SMOKE_SHOT_DIR;
const AGENTS = "agents";
const PREFIX = "xyz.tinycloud.courier/";
/** The current identity's private inbox (mail.tm); every inbox made in the run is deleted at its end. */
const mailboxes = [];
let mailbox;
const t0 = Date.now();
const since = (start = t0) => Date.now() - start;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

const EXPECTED_VIEW_GRANT = [
  "agents/capabilities tinycloud.capabilities/read",
  "agents/kv/xyz.tinycloud.courier/ tinycloud.kv/get",
  "agents/kv/xyz.tinycloud.courier/ tinycloud.kv/list",
  "agents/kv/xyz.tinycloud.courier/me/approvals/ tinycloud.kv/put",
  "agents/kv/xyz.tinycloud.courier/me/orders/ tinycloud.kv/put",
].sort();
const report = { type: "tinycloud.share/courier-live-smoke/v2", openkey: OPENKEY, result: "failed", stage: "start", approvals: {}, approvalClicks: {}, approvalCountUnit: "OpenKey Approve-button clicks; no passkey ceremony measured", timingsMs: {} };
let stage = "start";
const setStage = (next) => { stage = next; report.stage = next; };
const consoleErrors = [];

/** One mail.tm call; retries a timeout, a transport error, 429 and 5xx. Resolves to the last response, or undefined. */
async function mailTm(path, { method = "GET", body, token, attempts = 4 } = {}) {
  let response;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    response = await fetch(`${MAIL_TM}${path}`, {
      method,
      signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }).catch(() => undefined);
    if (response && response.status !== 429 && response.status < 500) return response;
    if (attempt < attempts) await sleep(3_000 * attempt);
  }
  return response;
}
/** A mail.tm call's JSON, or undefined (a refused, failed or non-JSON reply). */
const mailTmJson = async (path, options) => {
  const response = await mailTm(path, options);
  if (!response?.ok) return undefined;
  return response.json().catch(() => undefined);
};

async function inboxToken(entry) {
  for (let attempt = 1; attempt <= 4 && !entry.token; attempt++) {
    entry.token = (await mailTmJson("/token", { method: "POST", body: { address: entry.address, password: entry.password } }))?.token ?? "";
    if (!entry.token && attempt < 4) await sleep(3_000 * attempt);
  }
  return entry.token;
}

/** A new private mail.tm inbox ("qa" in the name) for the next identity; its password stays in memory. */
async function newMailbox() {
  const domains = await mailTmJson("/domains");
  const domain = (domains?.["hydra:member"] ?? []).find((entry) => entry.isActive)?.domain;
  if (!domain) throw new Error("mail.tm offered no active domain");
  const next = { address: `qa-courier-smoke-${randomBytes(6).toString("hex")}@${domain}`, password: randomBytes(18).toString("base64url"), id: "", token: "" };
  mailboxes.push(next);
  const created = await mailTm("/accounts", { method: "POST", body: { address: next.address, password: next.password } });
  if (created?.status === 201) next.id = (await created.json().catch(() => ({}))).id ?? "";
  // A retried create whose first reply was lost answers 422 (the address exists): it is still ours, with our password.
  else if (created?.status !== 422) throw new Error(`mail.tm refused the inbox (HTTP ${created?.status ?? "no reply"})`);
  if (!(await inboxToken(next))) throw new Error("mail.tm gave no inbox token");
  if (!next.id) next.id = (await mailTmJson("/me", { token: next.token }))?.id ?? "";
  if (!next.id) throw new Error("mail.tm did not say which inbox was created");
  mailbox = next;
}

let deleting;
function deleteMailboxes() {
  deleting ??= (async () => {
    const results = [];
    for (const entry of mailboxes) {
      if (!entry.token) await inboxToken(entry).catch(() => "");
      if (!entry.id && entry.token) entry.id = (await mailTmJson("/me", { token: entry.token }))?.id ?? "";
      const response = entry.id && entry.token ? await mailTm(`/accounts/${entry.id}`, { method: "DELETE", token: entry.token }) : undefined;
      results.push(response?.status === 204);
    }
    report.inboxesDeleted = `${results.filter(Boolean).length}/${mailboxes.length}`;
  })().catch(() => { report.inboxesDeleted = `unknown/${mailboxes.length}`; });
  return deleting;
}
// A stopped run (Ctrl-C, kill) does not reach `finally`: still delete the inboxes.
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => { void deleteMailboxes().finally(() => process.exit(signal === "SIGINT" ? 130 : 143)); });
}

/** Mails whose code was already typed: a later sign-in in the same inbox needs the newer one. */
const usedMail = new Set();
async function openKeyOtp(timeout = 150_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    // A failed or unreadable poll is retried until the deadline.
    const list = await mailTmJson("/messages", { token: mailbox.token, attempts: 2 });
    const codeMail = (list?.["hydra:member"] ?? []).filter((entry) => /openkey/i.test(entry.subject ?? "") && !usedMail.has(entry.id))
      .sort((a, b) => Date.parse(b.createdAt ?? 0) - Date.parse(a.createdAt ?? 0));
    for (const message of codeMail) {
      const full = await mailTmJson(`/messages/${message.id}`, { token: mailbox.token, attempts: 2 });
      if (!full) continue;
      const body = `${full.text ?? ""} ${[].concat(full.html ?? []).join(" ")}`.replace(/<[^>]+>/g, " ");
      const codes = new Set([...body.matchAll(/verification code[^0-9]{0,80}(\d{6})(?!\d)/gi)].map((match) => match[1]));
      if (codes.size === 1) { usedMail.add(message.id); return [...codes][0]; }
    }
    await sleep(4_000);
  }
  throw new Error("no OpenKey code arrived in the test inbox");
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
// Every click in an OpenKey frame is real browser input (Puppeteer's element click), never a
// script-made click: OpenKey ignores script-made clicks on a framed approval.
async function clickHandle(handle) {
  try {
    const button = handle.asElement();
    if (!button) return false;
    await button.click();
    return true;
  } finally {
    await handle.dispose();
  }
}
const clickButton = async (frame, label) => clickHandle(await frame.evaluateHandle((text) =>
  [...document.querySelectorAll("button")].find((candidate) => candidate.innerText.trim().startsWith(text) && !candidate.disabled) ?? null, label));
// The approval's primary action: the last visible button of OpenKey's approval dialog (Cancel comes
// first), found by role and position, and only if its name is one of the approval's labels
// (APPROVE_NAME: ready or signing). Anything else (Cancel, a copy button, an extra button) is "not
// found", so the smoke keeps polling instead of clicking it, and the report records the rejected
// label. Without a dialog: the button named Approve or Approve exact bytes. The pick and its name
// check are one in-page read, and the element clicked (real browser input) is the one checked.
const clickApprove = async (frame) => {
  const result = await frame.evaluateHandle((approveName) => {
    const named = new RegExp(approveName);
    const visible = (element) => element.getClientRects().length > 0;
    const dialog = [...document.querySelectorAll("[role=dialog]")].filter(visible).at(-1);
    const button = dialog
      ? [...dialog.querySelectorAll("button")].filter(visible).at(-1)
      : [...document.querySelectorAll("button")].find((candidate) => /^Approve( exact bytes)?$/.test(candidate.innerText.trim()));
    const name = button?.innerText.trim() ?? "";
    if (button && !named.test(name)) return { button: null, rejected: name };
    return { button: button && !button.disabled ? button : null, rejected: "" };
  }, APPROVE_NAME.source);
  try {
    const rejected = await (await result.getProperty("rejected")).jsonValue();
    if (rejected) report.approveLabelRejected = scrub(rejected).slice(0, 40);
    return await clickHandle(await result.getProperty("button"));
  } finally {
    await result.dispose();
  }
};

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
      await field.type(mailbox.address);
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
      const messages = await sign.evaluate(() => window.__tcSigned ?? []).catch(() => []);
      for (const message of messages) {
        if (signedMessages.includes(message)) continue;
        signedMessages.push(message);
        // The identity's owner, for the opt-in DID file only (never printed or reported).
        if (mailbox !== undefined && mailbox.did === undefined) mailbox.did = didFromSiwe(message);
      }
      if (await clickApprove(sign).catch(() => false)) {
        report.approvals[counter] = (report.approvals[counter] ?? 0) + 1;
        const message = messages.at(-1) ?? "";
        let kind;
        if (counter !== "seedSignIn") {
          assert.deepEqual(recapList(message), EXPECTED_VIEW_GRANT, "every view signature is only the exact Courier session, never a host grant");
          kind = "courier-session";
        } else {
          kind = recapList(message)?.includes(`agents/kv/${PREFIX} tinycloud.kv/put`) ? "seed-session" : message.includes(":agents") ? "host-agents" : message.includes(":account") ? "host-account" : "seed-other";
        }
        (report.approvalClicks[counter] ??= []).push(kind);
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
let browser; let server; let didFile;
try {
  // Checked before anything touches production: a bad path stops the run here.
  setStage("options");
  didFile = didFileTarget();
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

  let context = await browser.createBrowserContext();
  const open = async (path, width = 1280) => {
    const page = await context.newPage();
    await page.setViewport({ width, height: 900 });
    await installSignCapture(page);
    page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${scrub(error.message).slice(0, 200)}`));
    page.on("console", (message) => { if (message.type() === "error" && !/Failed to load resource/.test(message.text())) consoleErrors.push(scrub(message.text()).slice(0, 200)); });
    page.on("response", async (response) => {
      const url = new URL(response.url());
      if (response.status() >= 400 && /tinycloud|openkey/.test(url.origin)) {
        const path = url.pathname.startsWith("/v1/locations/") ? "/v1/locations/<owner-did>" : scrub(url.pathname).slice(0, 100);
        const entry = { method: response.request().method(), host: url.host, path, status: response.status() };
        (report.failedResponses ??= []).push(entry);
        Object.assign(entry, refusal(await response.text().catch(() => "")));
      }
    });
    await page.goto(`${SHARE}${path}`, { waitUntil: "domcontentloaded", timeout: 90_000 });
    return page;
  };

  const signInView = async (counter) => {
    const start = signedMessages.length;
    const page = await open("/courier/");
    await page.waitForSelector("button.auth-button:not([disabled])", { timeout: 60_000 });
    await page.click("button.auth-button");
    await drive(page, () => document.querySelector(".cr-tabs") !== null || document.querySelector(".auth-status .tc-status") !== null, counter);
    await page.waitForFunction(() => document.querySelector(".cr-panel")?.getAttribute("aria-busy") === "false", { timeout: 60_000 });
    const messages = signedMessages.slice(start);
    assert.equal(messages.length, 1, "the view asks for one session signature and no hosting signature");
    const grant = recapList(messages[0]);
    assert.deepEqual(grant, EXPECTED_VIEW_GRANT, "the ENTIRE signed session grant is exactly Courier + agents capabilities/read");
    assert.deepEqual(report.approvalClicks[counter], ["courier-session"]);
    return { page, grant };
  };

  // Fresh identity: signing in reads an absent space, and must not create it.
  setStage("inbox");
  await newMailbox();
  setStage("view-fresh");
  const freshStart = Date.now();
  const { page: fresh, grant: freshGrant } = await signInView("freshViewSignIn");
  report.timingsMs.firstSignIn = since(freshStart);
  report.recap = freshGrant;
  report.fresh = { panel: scrub(await panelText(fresh)).slice(0, 400), signInFailure: await fresh.evaluate(() => document.querySelector(".auth-status .tc-status")?.textContent ?? null) };
  assert.equal(report.fresh.signInFailure, null);
  assert.match(report.fresh.panel, /No Courier space yet\./);
  assert.ok(report.fresh.panel.includes("Run tc courier init once on your machine, then reload this page."));
  await shot(fresh, "01-fresh-account");
  await context.close();

  // Separate identity/context: test tooling creates an existing mailbox before the view signs in.
  setStage("inbox");
  await newMailbox();
  usedMail.clear();
  context = await browser.createBrowserContext();

  // 3: seed a throwaway mailbox (test tooling), then read it in a new view session.
  setStage("seed");
  const seed = await open("/test/fixtures/courier-seed/index.html");
  await seed.waitForSelector("#seed", { timeout: 60_000 });
  await seed.click("#seed");
  await drive(seed, () => ["seeded", "failed"].includes(document.querySelector("#status")?.dataset.state), "seedSignIn", 240_000);
  const seeded = await seed.evaluate(() => document.querySelector("#status").textContent);
  assert.equal(seeded, "Seeded.", seeded);
  await seed.close();

  setStage("view-existing");
  const { page: view, grant: existingGrant } = await signInView("existingViewSignIn");
  report.recapExisting = existingGrant;
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
  const cards = await view.evaluate(() => [...document.querySelectorAll(".cr-request")].map((card) => ({ line: card.querySelector(".cr-sentence")?.textContent ?? null, summary: card.querySelector(".cr-summary")?.textContent ?? null, buttons: card.querySelectorAll("button").length })));
  assert.equal(cards.length, 2, "both seeded requests are listed");
  assert.ok(cards.some((card) => card.line === null && card.buttons === 0), "the request without verb/target/summary has no buttons");
  const reviewable = cards.find((card) => card.line !== null);
  assert.equal(reviewable.line, "Approving lets your agent merge throwaway/repo#20 for hunter:");
  assert.equal(reviewable.summary, "\u201CSquash-merge a throwaway PR; nothing is merged\u201D");
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
  const settled = await again.evaluate(() => ({ decidable: document.querySelectorAll(".cr-approve").length, unreviewable: document.querySelectorAll(".cr-request").length, settled: document.querySelector(".cr-settled")?.textContent.replace(/\s+/g, " ") }));
  assert.deepEqual({ decidable: settled.decidable, unreviewable: settled.unreviewable }, { decidable: 0, unreviewable: 1 }, "the decided request is no longer waiting; the request without a verb still can't be decided");
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
  // The owners go only to the opt-in 0600 file; the report says just whether it was written.
  if (didFile !== undefined) {
    try { report.didFile = `written ${writeDidFile(didFile, mailboxes.map((entry) => ({ did: entry.did, email: entry.address })))}/${mailboxes.length}`; }
    catch { report.didFile = "refused"; }
  }
  await deleteMailboxes();
  await browser?.close().catch(() => undefined);
  await server?.close().catch(() => undefined);
  rmSync(temporary, { recursive: true, force: true });
}

const line = JSON.stringify(report);
if (process.env.COURIER_SMOKE_ARTIFACT) writeFileSync(process.env.COURIER_SMOKE_ARTIFACT, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(line);
process.exit(report.result === "passed" ? 0 : 1);
