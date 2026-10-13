/**
 * Real sender sign-in smoke (TC-994).
 *
 * Signs a brand-new throwaway OpenKey account (email OTP through a public
 * Mailinator inbox) into Share, creates a link-only share and opens it as a
 * recipient. Everything is production: OpenKey, the owner Node, the registry.
 * Unlike the joined gate, nothing about OpenKey is faked.
 *
 *   node test/e2e-prod/sender-signin-smoke.mjs                 # live https://share.tinycloud.xyz
 *   SHARE_SMOKE_CANDIDATE=dist node test/e2e-prod/sender-signin-smoke.mjs
 *       # a local build served at the production origin (Chrome resolver rule)
 *
 * OpenKey's release checks can run it against production Share with no
 * Share checkout beyond `npm ci`.
 *
 * Output is one JSON line on stdout (and `SHARE_SMOKE_ARTIFACT`, if set): result,
 * approval-prompt counts, timings, and on failure the stage, the copy Share
 * showed, and every failed or still-pending request with its status or network
 * error and timing. The inbox, OTP, address, link and any authorization never
 * leave process memory; URLs are reduced to origin and a scrubbed path.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { startCandidateServer } from "./candidate-server.mjs";

const SHARE = "https://share.tinycloud.xyz";
const OPENKEY = process.env.SHARE_SMOKE_OPENKEY_ORIGIN ?? "https://openkey.so";
const MAILINATOR = "https://www.mailinator.com/api/v2/domains/public/inboxes";
const MAX_SIGNIN_PROMPTS = Number(process.env.SHARE_SMOKE_MAX_SIGNIN_PROMPTS ?? 2);
const MAX_SHARE_PROMPTS = Number(process.env.SHARE_SMOKE_MAX_SHARE_PROMPTS ?? 1);
// Share's failure copy (src/share/sender-failure.ts) ends a sign-in or a share.
const FAILURE_COPY = /temporarily unavailable|couldn't reach tinycloud|could not be completed|went wrong|session expired|isn't set up|storage isn't ready|didn't go through|couldn't create/i;

const inbox = `tc-share-smoke-${randomBytes(8).toString("hex")}`;
const nonce = `tc-share-smoke-${randomBytes(6).toString("hex")}`;
const t0 = Date.now();
const since = (start = t0) => Date.now() - start;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

const scrub = (value) => String(value)
  .replace(/#\S*/g, "#<fragment>")
  .replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, "<email>")
  .replace(/0x[0-9a-fA-F]{40}/g, "0x<address>")
  .replace(/did(:|%3A)(key|pkh)[\w:.%-]{8,}/gi, "did:$2:<id>")
  .replace(/[A-Za-z0-9_-]{20,}/g, "<id>")
  .replace(/\b\d{6,8}\b/g, "<digits>");

const report = { type: "tinycloud.share/sender-signin-smoke/v1", target: process.env.SHARE_SMOKE_CANDIDATE ? "candidate" : "production", openkey: OPENKEY, result: "failed", stage: "start", prompts: { signIn: 0, share: 0 }, timingsMs: {} };
const requests = [];
let stage = "start";
const setStage = (next) => { stage = next; report.stage = next; };

// Only API traffic: static assets add noise, never a sign-in failure.
const isApi = (url) => url.protocol.startsWith("http") && !/\.(js|mjs|css|woff2?|png|svg|ico|wasm|webp|jpg)$/.test(url.pathname);

function track(page, phase) {
  const open = new Map();
  page.on("request", (request) => { if (isApi(new URL(request.url()))) open.set(request, Date.now()); });
  const record = (request, outcome) => {
    const started = open.get(request);
    if (started === undefined) return undefined;
    open.delete(request);
    const url = new URL(request.url());
    const entry = { phase, stage, method: request.method(), origin: url.origin, path: scrub(url.pathname), atMs: started - t0, durationMs: Date.now() - started, ...outcome };
    requests.push(entry);
    return entry;
  };
  page.on("requestfinished", async (request) => {
    const response = request.response();
    const entry = record(request, { status: response?.status() ?? 0 });
    // An error body's machine code (e.g. INVALID_OTP) classifies a failure; nothing else is kept.
    if (entry !== undefined && entry.status >= 400) {
      const body = await response.json().catch(() => undefined);
      const code = body?.code ?? body?.error?.code ?? (typeof body?.error === "string" ? body.error : undefined);
      if (code !== undefined) entry.errorCode = scrub(code).slice(0, 80);
    }
  });
  page.on("requestfailed", (request) => record(request, { error: request.failure()?.errorText ?? "failed" }));
  page.on("console", (message) => { if (message.type() === "error") requests.push({ phase, stage, console: scrub(message.text()).slice(0, 240), atMs: since() }); });
  page.on("pageerror", (error) => requests.push({ phase, stage, pageerror: scrub(error.message).slice(0, 240), atMs: since() }));
  return () => [...open].map(([request, start]) => {
    const url = new URL(request.url());
    return { phase, stage, method: request.method(), origin: url.origin, path: scrub(url.pathname), atMs: start - t0, pendingMs: Date.now() - start };
  });
}

async function mailinator(path) {
  for (let attempt = 1; attempt <= 4; attempt++) {
    const response = await fetch(`${MAILINATOR}/${inbox}${path}`, { headers: { "user-agent": "tinycloud-share-smoke" } }).catch(() => undefined);
    if (response?.ok) { const text = await response.text(); if (text.trim()) return JSON.parse(text); }
    await sleep(2_000 * attempt);
  }
  return {};
}

async function openKeyOtp(timeout = 150_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const { msgs = [] } = await mailinator("");
    const codeMail = msgs.filter((entry) => /openkey/i.test(entry.subject ?? "")).sort((a, b) => (a.seconds_ago ?? 0) - (b.seconds_ago ?? 0));
    for (const message of codeMail) {
      const body = JSON.stringify(await mailinator(`/messages/${message.id}`)).replace(/<[^>]+>/g, " ");
      // The mail repeats the code; a second six-digit run elsewhere is not it.
      const codes = new Set([...body.matchAll(/verification code[^0-9]{0,80}(\d{6})(?!\d)/gi)].map((match) => match[1]));
      report.otp = { messages: codeMail.length, codesInMessage: codes.size, mailAgeSeconds: message.seconds_ago, afterMs: since() };
      if (codes.size === 1) return [...codes][0];
    }
    await sleep(4_000);
  }
  throw new Error("no OpenKey code arrived in the Mailinator inbox");
}

function frameAt(page, path) {
  return page.frames().find((frame) => frame.url().startsWith(`${OPENKEY}${path}`));
}

async function until(probe, timeout, what) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await Promise.resolve().then(probe).catch(() => undefined);
    if (value) return value;
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function clickButton(frame, label) {
  return frame.evaluate((text) => {
    const button = [...document.querySelectorAll("button")].find((candidate) => candidate.innerText.trim().startsWith(text) && !candidate.disabled);
    button?.click();
    return button !== undefined;
  }, label);
}

/** Approve every OpenKey sign review until `done` holds; Share's failure copy ends the wait. */
async function approveUntil(page, done, counter, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const sign = frameAt(page, "/widget/embed/sign");
    if (sign !== undefined && await clickButton(sign, "Approve").catch(() => false)) {
      report.prompts[counter] += 1;
      await until(() => frameAt(page, "/widget/embed/sign") !== sign || sign.isDetached(), 30_000, "the OpenKey review to close").catch(() => undefined);
    }
    if (await page.evaluate(done).catch(() => false)) return;
    const copy = await page.evaluate(() => `${document.querySelector(".auth-status")?.textContent ?? ""} ${document.querySelector(".composer-status")?.textContent ?? ""}`).catch(() => "");
    if (FAILURE_COPY.test(copy)) { report.shareCopy = copy.replace(/\s+/g, " ").trim().slice(0, 200); throw new Error("Share showed its failure copy"); }
    for (const frame of page.frames().filter((candidate) => candidate.url().startsWith(OPENKEY))) {
      const alert = await frame.evaluate(() => [...document.querySelectorAll("[role=alert]")].map((node) => node.textContent ?? "").join(" ").trim()).catch(() => "");
      if (alert) { report.openKeyAlert = scrub(alert).replace(/\s+/g, " ").slice(0, 200); throw new Error("OpenKey showed an error"); }
    }
    await sleep(250);
  }
  throw new Error("timed out");
}

const temporary = mkdtempSync(join(tmpdir(), "share-sender-smoke-"));
let browser; let server; let pending = [];
try {
  const args = ["--disable-quic", "--no-proxy-server"];
  if (process.env.SHARE_SMOKE_CANDIDATE) {
    setStage("candidate-server");
    const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate-key.pem");
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore" });
    const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8" }).trim();
    server = await startCandidateServer({ root: resolve(process.env.SHARE_SMOKE_CANDIDATE), key: readFileSync(key), cert: readFileSync(cert) });
    args.push(`--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${server.port}`, `--ignore-certificate-errors-spki-list=${spki}`);
  }
  browser = await puppeteer.launch({ headless: process.env.HEADED !== "1", args, userDataDir: join(temporary, "profile") });
  const sender = await browser.newPage();
  const senderPending = track(sender, "sender");
  pending = senderPending;
  await sender.evaluateOnNewDocument(() => {
    window.__smokeClipboard = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value) => { window.__smokeClipboard.push(value); } } });
  });

  setStage("share-load");
  await sender.goto(`${SHARE}/share#/new`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 });
  await sender.click("button.auth-button");

  setStage("openkey-email");
  const connect = await until(() => frameAt(sender, "/widget/embed/connect"), 60_000, "the OpenKey sign-in widget");
  await until(() => clickButton(connect, "Continue with email"), 30_000, "OpenKey's email option");
  const email = await until(() => connect.$("input[type=email]"), 30_000, "OpenKey's email field");
  await email.type(`${inbox}@mailinator.com`);
  await until(() => clickButton(connect, "Send code"), 10_000, "OpenKey's Send code button");

  setStage("openkey-otp");
  const otp = await openKeyOtp();
  const codeField = await until(() => connect.$("input[type=text], input[inputmode=numeric], input[autocomplete=one-time-code]"), 30_000, "OpenKey's code field");
  await codeField.type(otp);
  const signInStart = Date.now();
  await until(() => clickButton(connect, "Verify"), 10_000, "OpenKey's Verify button");

  setStage("share-sign-in");
  await approveUntil(sender, () => document.querySelector("form.composer-form") !== null, "signIn", 240_000);
  report.timingsMs.signIn = since(signInStart);
  assert(report.prompts.signIn <= MAX_SIGNIN_PROMPTS, `sign-in needed ${report.prompts.signIn} OpenKey approvals (max ${MAX_SIGNIN_PROMPTS})`);

  setStage("share-create");
  writeFileSync(join(temporary, "smoke.md"), `# Share sender smoke\n\n${nonce}\n`);
  await sender.$eval('input[name="recipient"][value="bearer"]', (input) => input.click());
  await (await sender.$('input[name="document"]')).uploadFile(join(temporary, "smoke.md"));
  const shareStart = Date.now();
  await sender.click("button.create-link-button");
  await approveUntil(sender, () => document.querySelector(".composer-status")?.dataset.state === "created", "share", 180_000);
  report.timingsMs.share = since(shareStart);
  assert(report.prompts.share <= MAX_SHARE_PROMPTS, `creating a share needed ${report.prompts.share} OpenKey approvals (max ${MAX_SHARE_PROMPTS})`);

  setStage("recipient-open");
  await until(() => clickButton(sender.mainFrame(), "Copy link"), 10_000, "Copy link");
  const link = await until(() => sender.evaluate(() => window.__smokeClipboard.at(-1)), 10_000, "the copied link");
  assert(link.startsWith(`${SHARE}/`), "the copied link is not a Share link");
  const recipientContext = await browser.createBrowserContext();
  const recipient = await recipientContext.newPage();
  const recipientPending = track(recipient, "recipient");
  pending = () => [...senderPending(), ...recipientPending()];
  const openStart = Date.now();
  await recipient.goto(link, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await until(async () => {
    for (const frame of recipient.frames()) if ((await frame.evaluate(() => document.body?.innerText ?? "").catch(() => "")).includes(nonce)) return true;
    return false;
  }, 120_000, "the shared text to render");
  report.timingsMs.open = since(openStart);
  report.result = "passed";
  setStage("done");
} catch (error) {
  report.error = scrub(error instanceof Error ? error.message : String(error)).slice(0, 300);
  report.failedRequests = requests.filter((entry) => entry.error !== undefined || entry.status >= 400 || entry.console !== undefined || entry.pageerror !== undefined).slice(-25);
  report.pendingRequests = pending();
  report.lastRequests = requests.filter((entry) => entry.method !== undefined && entry.method !== "OPTIONS").slice(-15);
  report.classification = classify(report);
  if (process.env.SHARE_SMOKE_SCREENSHOT && browser) {
    const pages = await browser.pages().catch(() => []);
    await pages.at(-1)?.screenshot({ path: process.env.SHARE_SMOKE_SCREENSHOT }).catch(() => undefined);
  }
} finally {
  report.timingsMs.total = since();
  await browser?.close().catch(() => undefined);
  await server?.close().catch(() => undefined);
  rmSync(temporary, { recursive: true, force: true });
}

/** Name the failure class so a single run's report says whose problem it is. */
function classify({ stage: failedStage, error, failedRequests = [], pendingRequests = [], openKeyAlert }) {
  const network = failedRequests.find((entry) => entry.error !== undefined);
  if (network?.error === "net::ERR_NETWORK_CHANGED") return `runner-network-changed: ${network.method} ${network.origin}${network.path}`;
  if (failedStage === "openkey-otp" && /no OpenKey code/.test(error ?? "")) return "mail-delivery: no OpenKey code reached Mailinator";
  if (openKeyAlert !== undefined || failedRequests.some((entry) => /openkey/.test(entry.origin ?? "") && entry.status >= 400)) return "openkey: OpenKey refused a step";
  const node = [...failedRequests, ...pendingRequests].find((entry) => /node\.tinycloud|registry\.tinycloud/.test(entry.origin ?? "") && entry.path !== undefined && !entry.path.startsWith("/v1/locations/"));
  if (node?.status >= 500 || node?.pendingMs > 30_000 || node?.error !== undefined) return `tinycloud: ${node.method} ${node.origin}${node.path} ${node.status ?? node.error ?? `pending ${node.pendingMs} ms`}`;
  if (network !== undefined) return `network: ${network.method} ${network.origin}${network.path} ${network.error}`;
  return `share: failed at ${failedStage}`;
}

const line = JSON.stringify(report);
if (process.env.SHARE_SMOKE_ARTIFACT) writeFileSync(process.env.SHARE_SMOKE_ARTIFACT, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(line);
process.exit(report.result === "passed" ? 0 : 1);
