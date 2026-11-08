/**
 * Real sender sign-in smoke (TC-994).
 *
 * Signs a brand-new throwaway OpenKey account (email OTP through a private
 * mail.tm inbox made for the run and deleted at its end, also when the run is
 * stopped) into Share, creates a link-only share and opens it as a
 * recipient, then reloads Share (the saved session resumes with no approval)
 * and signs out (the saved session is gone). Everything is production:
 * OpenKey, the owner Node, the registry.
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
import { clickApprove, isSignature, signatureMismatch, signaturesIn } from "./approval-click.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { createInbox, deleteInboxes, deleteInboxesOnStop, openKeyCode } from "./mail-tm.mjs";
import { scrub } from "./smoke-redact.mjs";

const SHARE = "https://share.tinycloud.xyz";
const OPENKEY = process.env.SHARE_SMOKE_OPENKEY_ORIGIN ?? "https://openkey.so";
const MAX_SIGNIN_PROMPTS = Number(process.env.SHARE_SMOKE_MAX_SIGNIN_PROMPTS ?? 2);
const MAX_SHARE_PROMPTS = Number(process.env.SHARE_SMOKE_MAX_SHARE_PROMPTS ?? 1);
// Share's failure copy (src/share/sender-failure.ts) ends a sign-in or a share.
const FAILURE_COPY = /temporarily unavailable|couldn't reach tinycloud|could not be completed|went wrong|session expired|isn't set up|storage isn't ready|didn't go through|couldn't create/i;

let inbox;
const nonce = `tc-share-smoke-${randomBytes(6).toString("hex")}`;
const t0 = Date.now();
const since = (start = t0) => Date.now() - start;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

// Deletes the run's inbox once; a stopped run (Ctrl-C, kill) does not reach `finally`.
const deleteInbox = async () => { const { deleted, total } = await deleteInboxes(); report.inboxDeleted = deleted === total; };
deleteInboxesOnStop();

const report = { type: "tinycloud.share/sender-signin-smoke/v1", target: process.env.SHARE_SMOKE_CANDIDATE ? "candidate" : "production", openkey: OPENKEY, result: "failed", stage: "start", prompts: { signIn: 0, share: 0, resume: 0 }, approveClicksNotTaken: 0, timingsMs: {} };
const requests = [];
let stage = "start";
const setStage = (next) => { stage = next; report.stage = next; };

// Static assets are kept out of the trail unless they fail: a missing chunk
// can stop sign-in before any API call.
const isStatic = (url) => /\.(js|mjs|css|woff2?|png|svg|ico|wasm|webp|jpg)$/.test(url.pathname);

function track(page, phase) {
  // Each request keeps the stage it STARTED in, so a late-settling sign call counts for its own step.
  const open = new Map();
  page.on("request", (request) => { if (new URL(request.url()).protocol.startsWith("http")) open.set(request, { started: Date.now(), stage }); });
  const record = (request, outcome) => {
    const opened = open.get(request);
    if (opened === undefined) return undefined;
    open.delete(request);
    const url = new URL(request.url());
    if (isStatic(url) && outcome.error === undefined && outcome.status < 400) return undefined;
    const entry = { phase, stage: opened.stage, method: request.method(), origin: url.origin, path: scrub(url.pathname), atMs: opened.started - t0, durationMs: Date.now() - opened.started, ...outcome };
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
  return () => [...open].filter(([request]) => !isStatic(new URL(request.url()))).map(([request, opened]) => {
    const url = new URL(request.url());
    return { phase, stage: opened.stage, method: request.method(), origin: url.origin, path: scrub(url.pathname), atMs: opened.started - t0, pendingMs: Date.now() - opened.started };
  });
}

async function openKeyOtp() {
  const code = await openKeyCode(inbox, {
    onMessage: (message, value) => { report.otp = { messages: (report.otp?.messages ?? 0) + 1, codeFound: value !== undefined, mailAgeSeconds: Math.round((Date.now() - Date.parse(message.createdAt ?? 0)) / 1000), afterMs: since() }; },
  });
  return code;
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
  const handle = await frame.evaluateHandle((text) => {
    return [...document.querySelectorAll("button")].find((candidate) => candidate.innerText.trim().startsWith(text) && !candidate.disabled) ?? null;
  }, label);
  try {
    const button = handle.asElement();
    if (!button) return false;
    // DOM .click() is untrusted; OpenKey refuses it inside an iframe.
    await button.click();
    return true;
  } finally {
    await handle.dispose();
  }
}

/** When each OpenKey review frame first appeared (for a dropped click's timing). */
const reviewSeen = new WeakMap();

/** Approve every OpenKey sign review until `done` holds; Share's failure copy ends the wait. */
async function approveUntil(page, done, counter, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const sign = frameAt(page, "/widget/embed/sign");
    if (sign !== undefined && !reviewSeen.has(sign)) reviewSeen.set(sign, since());
    // What the sender was asked to grant, as OpenKey's review words it.
    const review = await sign?.evaluate(() => document.body.innerText.replace(/\s+/g, " ")).catch(() => "") ?? "";
    // A click counts only once OpenKey took it (review closed, "Signing…", or a sign call after the
    // click); a disabled button alone is not taken. A dropped one is reported and clicked again.
    if (sign !== undefined && await clickApprove({
      sign, during: counter, report, at: since, stage: () => stage, reviewSeenAt: reviewSeen.get(sign),
      closed: () => frameAt(page, "/widget/embed/sign") !== sign || sign.isDetached(),
      signedSince: (fromMs) => requests.some((entry) => isSignature(entry) && entry.atMs >= fromMs),
    }).catch(() => false)) {
      report.prompts[counter] += 1;
      (report.reviews ??= []).push({ during: counter, atMs: since(), grants: scrub(review.replace(/^.*?(do not want to grant\.|grant\.)\s*/i, "").replace(/\s*Advanced details.*$/i, "")).slice(0, 240) });
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
let browser; let server; let pending = () => [];
try {
  // GitHub's Ubuntu runners block the unprivileged user namespaces Chrome's
  // sandbox needs; the runner is disposable and visits only production sites.
  const args = ["--disable-quic", "--no-proxy-server", ...(process.env.GITHUB_ACTIONS === "true" ? ["--no-sandbox"] : [])];
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

  setStage("inbox");
  inbox = await createInbox("share-smoke");

  setStage("share-load");
  await sender.goto(`${SHARE}/share#/new`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 });
  await sender.click("button.auth-button");

  setStage("openkey-email");
  const connect = await until(() => frameAt(sender, "/widget/embed/connect"), 60_000, "the OpenKey sign-in widget");
  await until(() => clickButton(connect, "Continue with email"), 30_000, "OpenKey's email option");
  const email = await until(() => connect.$("input[type=email]"), 30_000, "OpenKey's email field");
  await email.type(inbox.address);
  await until(() => clickButton(connect, "Send code"), 10_000, "OpenKey's Send code button");

  setStage("openkey-otp");
  const otp = await openKeyOtp();
  const codeField = await until(() => connect.$("input[type=text], input[inputmode=numeric], input[autocomplete=one-time-code]"), 30_000, "OpenKey's code field");
  await codeField.type(otp);
  const signInStart = Date.now();
  await until(() => clickButton(connect, "Verify"), 10_000, "OpenKey's Verify button");
  // OpenKey asks before creating an account for an email it doesn't know
  // (TC-1114). The inbox is new on every run, so the smoke creates it. Older
  // OpenKey created the account silently; then sign-in simply moves on.
  await until(
    async () => connect.isDetached() || frameAt(sender, "/widget/embed/sign") !== undefined || await clickButton(connect, "Create a new account"),
    30_000,
    "OpenKey's new-account choice or the next step",
  ).catch(() => undefined);

  setStage("share-sign-in");
  await approveUntil(sender, () => document.querySelector("form.composer-form") !== null, "signIn", 240_000);
  report.timingsMs.signIn = since(signInStart);
  // Counted approvals must equal OpenKey's signatures for the step (approval-click.mjs, signatureMismatch):
  // more signatures = a hidden review; fewer = a counted click OpenKey never signed for.
  report.signatures = { signIn: signaturesIn(requests, "share-sign-in"), share: 0 };
  const signInMismatch = signatureMismatch(report.prompts.signIn, report.signatures.signIn);
  assert(signInMismatch === null, `sign-in: ${signInMismatch}`);
  assert(report.prompts.signIn <= MAX_SIGNIN_PROMPTS, `sign-in needed ${report.prompts.signIn} OpenKey approvals (max ${MAX_SIGNIN_PROMPTS})`);

  setStage("share-create");
  writeFileSync(join(temporary, "smoke.md"), `# Share sender smoke\n\n${nonce}\n`);
  await sender.$eval('input[name="recipient"][value="bearer"]', (input) => input.click());
  await (await sender.$('input[name="document"]')).uploadFile(join(temporary, "smoke.md"));
  const shareStart = Date.now();
  await sender.click("button.create-link-button");
  await approveUntil(sender, () => document.querySelector(".composer-status")?.dataset.state === "created", "share", 180_000);
  report.timingsMs.share = since(shareStart);
  report.signatures.share = signaturesIn(requests, "share-create");
  const shareMismatch = signatureMismatch(report.prompts.share, report.signatures.share);
  assert(shareMismatch === null, `creating a share: ${shareMismatch}`);
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

  // The library session is saved on the device: a reload opens on "Welcome back", and Continue
  // resumes it with no OpenKey approval. Any review that does appear is approved and counted.
  setStage("share-resume");
  const wallHeading = () => document.querySelector(".auth-form h2")?.textContent ?? "";
  await sender.reload({ waitUntil: "domcontentloaded", timeout: 90_000 });
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 });
  assert.equal(await sender.evaluate(wallHeading), "Welcome back", "a reload did not offer to resume the saved session");
  const resumeStart = Date.now();
  await sender.click("button.auth-button");
  await approveUntil(sender, () => document.querySelector(".sender-chrome") !== null, "resume", 180_000);
  report.timingsMs.resume = since(resumeStart);
  assert.equal(report.prompts.resume, 0, `resuming the saved session needed ${report.prompts.resume} OpenKey approvals`);
  assert.equal(signaturesIn(requests, "share-resume"), 0, "resuming the saved session asked OpenKey for a signature");

  // Sign-out clears the saved session: nothing is left under the library's prefix, and a reload is a plain sign-in.
  setStage("share-sign-out");
  await sender.click(".sender-signout");
  await sender.waitForSelector(".sender-confirm-dialog .sender-confirm-revoke", { timeout: 10_000 });
  await sender.click(".sender-confirm-dialog .sender-confirm-revoke");
  await sender.waitForSelector("form.auth-form", { timeout: 30_000 });
  const saved = () => Object.keys(localStorage).filter((key) => key.startsWith("tinycloud-share-library-")).length;
  assert.equal(await sender.evaluate(saved), 0, "sign-out left the library session saved");
  await sender.reload({ waitUntil: "domcontentloaded", timeout: 90_000 });
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 });
  assert.equal(await sender.evaluate(wallHeading), "One key, your files", "a reload after sign-out still offered to resume");
  report.result = "passed";
  setStage("done");
} catch (error) {
  report.error = scrub(error instanceof Error ? error.message : String(error)).slice(0, 300);
  report.pendingRequests = pending();
  report.lastRequests = requests.filter((entry) => entry.method !== undefined && entry.method !== "OPTIONS").slice(-15);
  report.consoleErrors = requests.filter((entry) => entry.console !== undefined).slice(-10).map(({ stage: at, console: text }) => ({ stage: at, text }));
  const sender = (await browser?.pages().catch(() => []))?.find((page) => page.url().startsWith(SHARE));
  report.pageStatus = scrub(await sender?.evaluate(() => `${document.querySelector(".auth-status")?.textContent ?? ""} ${document.querySelector(".composer-status")?.textContent ?? ""}`.replace(/\s+/g, " ").trim()).catch(() => "") ?? "").slice(0, 200);
  if (process.env.SHARE_SMOKE_SCREENSHOT && browser) {
    const pages = await browser.pages().catch(() => []);
    await pages.at(-1)?.screenshot({ path: process.env.SHARE_SMOKE_SCREENSHOT }).catch(() => undefined);
  }
} finally {
  // Kept on passing runs too: a pass that needed an extra prompt is explained here.
  report.failedRequests = requests.filter((entry) => entry.error !== undefined || entry.status >= 400 || entry.pageerror !== undefined).slice(-25);
  if (report.result !== "passed") report.classification = classify(report);
  report.timingsMs.total = since();
  await deleteInbox();
  await browser?.close().catch(() => undefined);
  await server?.close().catch(() => undefined);
  rmSync(temporary, { recursive: true, force: true });
}

/** Name the failure class so a single run's report says whose problem it is. */
function classify({ stage: failedStage, error, failedRequests = [], pendingRequests = [], openKeyAlert, shareCopy }) {
  const changed = failedRequests.find((entry) => entry.error === "net::ERR_NETWORK_CHANGED");
  if (changed !== undefined) return `runner-network-changed: ${changed.method} ${changed.origin}${changed.path}`;
  if (failedStage === "inbox") return "mail-delivery: the test inbox could not be made";
  if (failedStage === "openkey-otp" && /no OpenKey code/.test(error ?? "")) return "mail-delivery: no OpenKey code reached the test inbox";
  if (openKeyAlert !== undefined || failedRequests.some((entry) => /openkey/.test(entry.origin ?? "") && entry.status >= 400)) return "openkey: OpenKey refused a step";
  // The SDK aborts its own account-registry sync after 4 s (net::ERR_ABORTED)
  // and carries on; only server errors, real transport errors or long hangs
  // are TinyCloud's.
  const tinycloud = [...pendingRequests, ...failedRequests.toReversed()].find((entry) => /node\.tinycloud|registry\.tinycloud/.test(entry.origin ?? "")
    && (entry.status >= 500 || entry.pendingMs > 30_000 || (entry.error !== undefined && entry.error !== "net::ERR_ABORTED")));
  if (tinycloud !== undefined) return `tinycloud: ${tinycloud.method} ${tinycloud.origin}${tinycloud.path} ${tinycloud.status ?? tinycloud.error ?? `pending ${tinycloud.pendingMs} ms`} after ${tinycloud.durationMs ?? tinycloud.pendingMs} ms`;
  if (shareCopy !== undefined) return `share: failed at ${failedStage} with "${shareCopy}"`;
  const network = failedRequests.findLast((entry) => entry.error !== undefined);
  if (network !== undefined) return `network: ${network.method} ${network.origin}${network.path} ${network.error}`;
  return `share: failed at ${failedStage}`;
}

const line = JSON.stringify(report);
if (process.env.SHARE_SMOKE_ARTIFACT) writeFileSync(process.env.SHARE_SMOKE_ARTIFACT, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
console.log(line);
process.exit(report.result === "passed" ? 0 : 1);
