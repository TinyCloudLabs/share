/**
 * Real sender smoke for an ENCRYPTED ADDRESSED share (TC-2933).
 *
 * The sender smoke (sender-signin-smoke.mjs) makes a link-only share. This one makes the share for
 * one named person ("Only this person", exactEmail): the file is encrypted to the share's key and
 * the policy roots are signed by the owner. A brand-new throwaway OpenKey account (email OTP through
 * a private mail.tm inbox) signs in to Share, creates the share for a second private inbox, and the
 * recipient opens the link in a clean browser context: asks for a code, reads the 8-digit code from
 * the second inbox, enters it and sees the shared text. Both inboxes are deleted at the end, also
 * when the run is stopped. Everything is production: OpenKey, the owner Node, the registry, the
 * code mail. Nothing about OpenKey is faked.
 *
 *   node test/e2e-prod/sender-encrypted-share-smoke.mjs                 # live https://share.tinycloud.xyz
 *   SHARE_SMOKE_CANDIDATE=dist node test/e2e-prod/sender-encrypted-share-smoke.mjs
 *       # a local build served at the production origin (Chrome resolver rule)
 *
 * Owner approvals are counted per step and each must equal OpenKey's signatures for the step.
 * Creating the encrypted share may take at most SHARE_SMOKE_MAX_SHARE_PROMPTS approvals (default 1).
 *
 * Output is one JSON line on stdout (and `SHARE_SMOKE_ARTIFACT`, if set): result, approval counts,
 * timings, and on failure the stage, Share's copy and every failed or pending request. The inboxes,
 * codes, addresses, link and any authorization never leave process memory.
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
import { createInbox, deleteInboxes, deleteInboxesOnStop, openKeyCode, seenMail, waitForMail } from "./mail-tm.mjs";
import { scrub } from "./smoke-redact.mjs";
import { walletSummaryRecorder } from "./wallet-summary.mjs";

const SHARE = "https://share.tinycloud.xyz";
const OPENKEY = process.env.SHARE_SMOKE_OPENKEY_ORIGIN ?? "https://openkey.so";
const MAX_SIGNIN_PROMPTS = Number(process.env.SHARE_SMOKE_MAX_SIGNIN_PROMPTS ?? 2);
const MAX_SHARE_PROMPTS = Number(process.env.SHARE_SMOKE_MAX_SHARE_PROMPTS ?? 1);
// What OpenKey's extra warning (TC-2927) must show at sign-in: the same request as sender-signin-smoke.mjs.
const ELEVATED_SIGN_IN = {
  site: new URL(SHARE).host,
  cards: ["Unlock all your encrypted data", "Unlock encrypted items in a folder named share"],
  required: ["Unlock all your encrypted data"],
};
// An addressed link is /s/<26 base32 chars>#v=4&k=<key>; a link-only share does not look like this.
const ADDRESSED_LINK = /^https:\/\/share\.tinycloud\.xyz\/s\/[a-z2-7]{26}#v=4&k=\S+$/;
const FAILURE_COPY = /temporarily unavailable|couldn't reach tinycloud|could not be completed|went wrong|session expired|isn't set up|storage isn't ready|didn't go through|couldn't create/i;

let senderInbox;
let recipientInbox;
const nonce = `tc-share-enc-smoke-${randomBytes(6).toString("hex")}`;
const t0 = Date.now();
const since = (start = t0) => Date.now() - start;
async function sleep(ms) {
  stopIfRateLimited();
  await new Promise((done) => setTimeout(done, ms));
  stopIfRateLimited();
}

// One run makes at most two throwaway inboxes: the sender's (its OpenKey account) and the recipient's.
// A third is refused before mail.tm is called.
const MAX_INBOXES = 2;
let inboxesMade = 0;
async function makeInbox(label) {
  if (inboxesMade >= MAX_INBOXES) throw new Error(`a run makes at most ${MAX_INBOXES} throwaway inboxes`);
  inboxesMade += 1;
  return createInbox(label);
}

const deleteBoth = async () => { const { deleted, total } = await deleteInboxes(); report.inboxesDeleted = deleted === total; };
deleteInboxesOnStop();

const report = { type: "tinycloud.share/sender-encrypted-share-smoke/v1", target: process.env.SHARE_SMOKE_CANDIDATE ? "candidate" : "production", openkey: OPENKEY, result: "failed", stage: "start", prompts: { signIn: 0, share: 0 }, approveClicksNotTaken: 0, timingsMs: {} };
report.rateLimited = false;
const requests = [];
let stage = "start";
const setStage = (next) => { stage = next; report.stage = next; };

// A smoke file's name is stored in the owner's space as the share's object key (share/<id>/<name>), so the
// fixed `tcqa-` prefix marks the objects a run makes. The inboxes carry the same prefix (mail-tm.mjs).
const SMOKE_FILE = "tcqa-share-encrypted-smoke.md";

// Any HTTP 429, from Share, OpenKey, a TinyCloud service or mail.tm, stops the run at once with no retry:
// the browser closes (which ends any wait on a page), every later wait throws, mail polling is aborted and
// mail.tm calls are refused so mail-tm.mjs cannot retry. The inboxes are still deleted, once, in `finally`.
const MAIL_TM_ORIGIN = "https://api.mail.tm";
const stopMail = new AbortController();
let cleaning = false;
function stopIfRateLimited() {
  if (report.rateLimited) throw new Error(`HTTP 429 from ${report.rateLimitedAt.origin}`);
}
function rateLimitedBy(origin) {
  if (report.rateLimited) return;
  report.rateLimited = true;
  report.rateLimitedAt = { stage, origin };
  stopMail.abort(new Error("HTTP 429"));
  void browser?.close().catch(() => undefined);
}
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const origin = new URL(typeof input === "string" || input instanceof URL ? input : input.url).origin;
  if (origin !== MAIL_TM_ORIGIN) return realFetch(input, init);
  if (report.rateLimited && !cleaning) return new Response(null, { status: 400 });
  const response = await realFetch(input, init);
  if (response.status !== 429) return response;
  rateLimitedBy(origin);
  // Not a 429 to mail-tm.mjs, which retries those.
  return new Response(null, { status: 400 });
};

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
    if (isStatic(url) && outcome.error === undefined && outcome.status < 400) { staticOk[phase] = (staticOk[phase] ?? 0) + 1; return undefined; }
    const entry = { phase, stage: opened.stage, method: request.method(), origin: url.origin, path: scrub(url.pathname), atMs: opened.started - t0, durationMs: Date.now() - opened.started, ...outcome };
    requests.push(entry);
    return entry;
  };
  page.on("response", (response) => { if (response.status() === 429) rateLimitedBy(new URL(response.url()).origin); });
  page.on("requestfinished", async (request) => {
    const response = request.response();
    const entry = record(request, { status: response?.status() ?? 0 });
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

/** Approve every OpenKey sign review until `done` holds; Share's failure copy or an unexpected extra warning ends the wait. */
async function approveUntil(page, done, counter, timeout, elevated = null) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const sign = frameAt(page, "/widget/embed/sign");
    if (sign !== undefined && !reviewSeen.has(sign)) reviewSeen.set(sign, since());
    const review = await sign?.evaluate(() => document.body.innerText.replace(/\s+/g, " ")).catch(() => "") ?? "";
    if (sign !== undefined && await clickApprove({
      sign, during: counter, report, at: since, stage: () => stage, reviewSeenAt: reviewSeen.get(sign), elevated,
      closed: () => frameAt(page, "/widget/embed/sign") !== sign || sign.isDetached(),
      signedSince: (fromMs) => requests.some((entry) => isSignature(entry) && entry.atMs >= fromMs),
    }).catch(() => false)) {
      report.prompts[counter] += 1;
      (report.reviews ??= []).push({ during: counter, atMs: since(), grants: scrub(review.replace(/^.*?(do not want to grant\.|grant\.)\s*/i, "").replace(/\s*Advanced details.*$/i, "")).slice(0, 240) });
      await until(() => frameAt(page, "/widget/embed/sign") !== sign || sign.isDetached(), 30_000, "the OpenKey review to close").catch(() => undefined);
    }
    if (report.elevatedRefused) throw new Error(`OpenKey's extra warning was not clicked: ${report.elevatedRefused.reason}`);
    if (await page.evaluate(done).catch(() => false)) return;
    const copy = await page.evaluate(() => `${document.querySelector(".auth-status")?.textContent ?? ""} ${document.querySelector(".composer-status")?.textContent ?? ""}`).catch(() => "");
    if (FAILURE_COPY.test(copy)) { report.shareCopy = scrub(copy.replace(/\s+/g, " ").trim()).slice(0, 200); throw new Error("Share showed its failure copy"); }
    for (const frame of page.frames().filter((candidate) => candidate.url().startsWith(OPENKEY))) {
      const alert = await frame.evaluate(() => [...document.querySelectorAll("[role=alert]")].map((node) => node.textContent ?? "").join(" ").trim()).catch(() => "");
      if (alert) { report.openKeyAlert = scrub(alert).replace(/\s+/g, " ").slice(0, 200); throw new Error("OpenKey showed an error"); }
    }
    await sleep(250);
  }
  throw new Error("timed out");
}

/** The recipient's code field: the SDK's credential control, inside a shadow root. */
async function otpInput(page, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const handle = await page.evaluateHandle(() => {
      const candidate = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input");
      if (!(candidate instanceof HTMLInputElement)) return null;
      return candidate.type === "text" || candidate.inputMode === "numeric" || candidate.name === "otp" ? candidate : null;
    }).catch(() => undefined);
    const input = handle?.asElement();
    if (input !== null && input !== undefined) return input;
    await sleep(500);
  }
  return undefined;
}

/** Types the code; the control submits itself at eight digits, an older one waits for its submit button. */
async function submitCode(page, code) {
  const input = await otpInput(page, 120_000);
  if (input === undefined) return false;
  await input.click({ clickCount: 3 });
  await page.keyboard.press("Backspace");
  await input.type(code);
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const state = await page.evaluate((expected) => {
      const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
      const field = root?.querySelector("input");
      if (!(field instanceof HTMLInputElement) || field.value !== expected) return "empty";
      if (field.readOnly) return "submitted";
      const button = [...(root?.querySelectorAll("button[type=submit]") ?? [])].find((candidate) => !candidate.disabled);
      if (button instanceof HTMLButtonElement) { button.click(); return "submitted"; }
      return "waiting";
    }, code).catch(() => "empty");
    if (state === "submitted") return true;
    await sleep(200);
  }
  return false;
}

const temporary = mkdtempSync(join(tmpdir(), "share-encrypted-smoke-"));
let browser; let server; let pending = () => []; let recipientPage;
const staticOk = {};
try {
  // GitHub's Ubuntu runners block the unprivileged user namespaces Chrome's sandbox needs; the
  // runner is disposable and visits only production sites.
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
  await sender.exposeFunction("recordSmokeWallet", walletSummaryRecorder());
  await sender.evaluateOnNewDocument((openkeyOrigin) => {
    window.addEventListener("message", (event) => {
      if (event.origin === openkeyOrigin && event.data?.type === "openkey:auth:response" && event.data.success === true) {
        void window.recordSmokeWallet(event.data.address);
      }
    });
  }, new URL(OPENKEY).origin);
  const senderPending = track(sender, "sender");
  pending = senderPending;
  await sender.evaluateOnNewDocument(() => {
    window.__smokeClipboard = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value) => { window.__smokeClipboard.push(value); } } });
  });

  setStage("inbox");
  senderInbox = await makeInbox("share-enc-sender");
  recipientInbox = await makeInbox("share-enc-recipient");

  setStage("share-load");
  await sender.goto(`${SHARE}/share#/new`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 });
  await sender.click("button.auth-button");

  setStage("openkey-email");
  const connect = await until(() => frameAt(sender, "/widget/embed/connect"), 60_000, "the OpenKey sign-in widget");
  await until(() => clickButton(connect, "Continue with email"), 30_000, "OpenKey's email option");
  const email = await until(() => connect.$("input[type=email]"), 30_000, "OpenKey's email field");
  await email.type(senderInbox.address);
  await until(() => clickButton(connect, "Send code"), 10_000, "OpenKey's Send code button");

  setStage("openkey-otp");
  const otp = await openKeyCode(senderInbox, {
    onMessage: (message, value) => { report.otp = { messages: (report.otp?.messages ?? 0) + 1, codeFound: value !== undefined, mailAgeSeconds: Math.round((Date.now() - Date.parse(message.createdAt ?? 0)) / 1000), afterMs: since() }; },
    signal: stopMail.signal,
  });
  const codeField = await until(() => connect.$("input[type=text], input[inputmode=numeric], input[autocomplete=one-time-code]"), 30_000, "OpenKey's code field");
  await codeField.type(otp);
  const signInStart = Date.now();
  await until(() => clickButton(connect, "Verify"), 10_000, "OpenKey's Verify button");

  setStage("openkey-confirm");
  // OpenKey asks before creating an account for an email it doesn't know (TC-1114); the inbox is new
  // on every run, so this click is part of the smoke.
  report.newAccount = { screen: false, clicks: 0 };
  {
    const confirmDeadline = Date.now() + 90_000;
    let confirmed = false;
    while (Date.now() < confirmDeadline) {
      if (connect.isDetached() || frameAt(sender, "/widget/embed/sign") !== undefined) { confirmed = true; break; }
      const ready = await connect.evaluate(() => [...document.querySelectorAll("button")].some((candidate) => candidate.innerText.trim().startsWith("Create a new account") && !candidate.disabled)).catch(() => false);
      if (ready && report.newAccount.clicks < 3 && await clickButton(connect, "Create a new account").catch(() => false)) {
        report.newAccount.clicks += 1;
      }
      await sleep(250);
    }
    if (!confirmed && !connect.isDetached() && frameAt(sender, "/widget/embed/sign") === undefined) {
      const shown = await connect.evaluate(() => document.body.innerText.replace(/\s+/g, " ")).catch(() => "");
      report.newAccount.screen = /new account/i.test(shown);
      throw new Error(`OpenKey's new-account confirmation never resolved (screen shown: ${report.newAccount.screen})`);
    }
  }

  setStage("share-sign-in");
  await approveUntil(sender, () => document.querySelector("form.composer-form") !== null, "signIn", 240_000, ELEVATED_SIGN_IN);
  report.timingsMs.signIn = since(signInStart);
  report.signatures = { signIn: signaturesIn(requests, "share-sign-in"), share: 0 };
  const signInMismatch = signatureMismatch(report.prompts.signIn, report.signatures.signIn);
  assert(signInMismatch === null, `sign-in: ${signInMismatch}`);
  assert(report.prompts.signIn <= MAX_SIGNIN_PROMPTS, `sign-in needed ${report.prompts.signIn} OpenKey approvals (max ${MAX_SIGNIN_PROMPTS})`);

  // "Only this person": the share is addressed to the second inbox, so its file is encrypted to the
  // share's key and the owner signs the policy roots. Nothing is mailed: the link is copied.
  setStage("share-create-encrypted");
  writeFileSync(join(temporary, SMOKE_FILE), `# Share encrypted smoke\n\n${nonce}\n`);
  await sender.$eval('input[name="recipient"][value="exactEmail"]', (input) => input.click());
  await sender.type('input[name="recipient-value"]', recipientInbox.address);
  await (await sender.$('input[name="document"]')).uploadFile(join(temporary, SMOKE_FILE));
  const shareStart = Date.now();
  await sender.click("button.create-link-button");
  await approveUntil(sender, () => document.querySelector(".composer-status")?.dataset.state === "created", "share", 180_000);
  report.timingsMs.share = since(shareStart);
  report.signatures.share = signaturesIn(requests, "share-create-encrypted");
  const shareMismatch = signatureMismatch(report.prompts.share, report.signatures.share);
  assert(shareMismatch === null, `creating the encrypted share: ${shareMismatch}`);
  assert(report.prompts.share <= MAX_SHARE_PROMPTS, `creating the encrypted share needed ${report.prompts.share} OpenKey approvals (max ${MAX_SHARE_PROMPTS})`);

  setStage("recipient-open");
  await until(() => clickButton(sender.mainFrame(), "Copy link"), 10_000, "Copy link");
  const link = await until(() => sender.evaluate(() => window.__smokeClipboard.at(-1)), 10_000, "the copied link");
  assert(ADDRESSED_LINK.test(link), "the copied link is not an addressed Share link");
  const recipientContext = await browser.createBrowserContext();
  const recipient = await recipientContext.newPage();
  recipientPage = recipient;
  const recipientPending = track(recipient, "recipient");
  pending = () => [...senderPending(), ...recipientPending()];
  const openStart = Date.now();
  await recipient.goto(link, { waitUntil: "domcontentloaded", timeout: 90_000 });

  // A code is requested only by this click, never on load (mail scanners open links).
  setStage("recipient-code");
  // The link reader shows "Open this link" and fetches nothing until Open is pressed (src/main.ts:65).
  const gate = await until(() => recipient.$(".link-confirm-action, .claim-request-code"), 120_000, "the recipient's Open or code button");
  const openShown = await gate.evaluate((node) => node.classList.contains("link-confirm-action"));
  report.openConfirm = openShown ? "shown" : "absent";
  if (openShown) await gate.click();
  await recipient.waitForSelector(".claim-request-code", { timeout: 120_000 });
  const earlier = await seenMail(recipientInbox);
  await recipient.click(".claim-request-code");
  const code = await waitForMail(recipientInbox, {
    subject: /code/i,
    extract: (text) => { const codes = new Set([...text.matchAll(/(?<!\d)(\d{8})(?!\d)/g)].map((match) => match[1])); return codes.size === 1 ? [...codes][0] : undefined; },
    used: earlier,
    timeout: 180_000,
    failure: "no recipient code arrived in the test inbox",
    signal: stopMail.signal,
    onMessage: (message, value) => { report.recipientCode = { messages: (report.recipientCode?.messages ?? 0) + 1, codeFound: value !== undefined, mailAgeSeconds: Math.round((Date.now() - Date.parse(message.createdAt ?? 0)) / 1000), afterMs: since() }; },
  });
  assert(await submitCode(recipient, code), "the recipient's code field did not take the code");

  setStage("recipient-open");
  await until(async () => {
    for (const frame of recipient.frames()) if ((await frame.evaluate(() => document.body?.innerText ?? "").catch(() => "")).includes(nonce)) return true;
    return false;
  }, 120_000, "the shared text to render");
  report.timingsMs.open = since(openStart);
  report.result = "passed";
  setStage("done");
} catch (error) {
  report.error = scrub(error instanceof Error ? error.message : String(error)).slice(0, 300);
  if (report.rateLimited) report.error = scrub(`HTTP 429 from ${report.rateLimitedAt.origin} at ${report.rateLimitedAt.stage}`);
  // Capture only. Each step runs alone, ends within 5 s and cannot throw, so the error above and the report
  // line always print; a step that fails is named in `report.captureError`. Everything goes through scrub().
  const capture = async (what, step) => {
    let timer;
    try {
      await Promise.race([step(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timed out")), 5_000); })]);
    } catch (failure) {
      (report.captureError ??= []).push(scrub(`${what}: ${failure instanceof Error ? failure.message : String(failure)}`).slice(0, 160));
    } finally {
      clearTimeout(timer);
    }
  };
  // A tab without a frame (closing, or not yet attached) throws on url(); it is skipped.
  const urlOf = (page) => { try { return page.url(); } catch { return ""; } };
  let pages = [];
  await capture("pending requests", () => { report.pendingRequests = pending(); });
  await capture("requests", () => {
    report.lastRequests = requests.filter((entry) => entry.method !== undefined && entry.method !== "OPTIONS").slice(-15);
    report.consoleErrors = requests.filter((entry) => entry.console !== undefined).slice(-10).map(({ stage: at, console: text }) => ({ stage: at, text }));
  });
  await capture("pages", async () => { pages = await browser?.pages() ?? []; });
  await capture("recipient page", async () => {
    if (recipientPage === undefined) return;
    const shown = await recipientPage.evaluate(() => document.body?.innerText ?? "").catch(() => "");
    const where = (url) => { try { const parsed = new URL(url); return scrub(`${parsed.origin}${parsed.pathname}`); } catch { return "(unreadable)"; } };
    report.recipientPage = {
      text: scrub(shown.replace(/\s+/g, " ").trim()).slice(0, 400),
      frames: recipientPage.frames().map((frame) => where(frame.url())).slice(0, 8),
      staticLoaded: staticOk.recipient ?? 0,
      requests: requests.filter((entry) => entry.phase === "recipient" && entry.method !== undefined).slice(-25).map(({ stage: at, method, origin, path, status, error, atMs }) => ({ stage: at, method, origin, path, status, error, atMs })),
    };
  });
  await capture("sender page", async () => {
    const senderPage = pages.find((page) => urlOf(page).startsWith(SHARE));
    report.pageStatus = scrub(await senderPage?.evaluate(() => `${document.querySelector(".auth-status")?.textContent ?? ""} ${document.querySelector(".composer-status")?.textContent ?? ""}`.replace(/\s+/g, " ").trim()).catch(() => "") ?? "").slice(0, 200);
  });
  if (process.env.SHARE_SMOKE_SCREENSHOT && browser) {
    await pages.at(-1)?.screenshot({ path: process.env.SHARE_SMOKE_SCREENSHOT }).catch(() => undefined);
  }
} finally {
  report.failedRequests = requests.filter((entry) => entry.error !== undefined || entry.status >= 400 || entry.pageerror !== undefined).slice(-25);
  if (report.result !== "passed") report.classification = classify(report);
  report.timingsMs.total = since();
  cleaning = true;
  await deleteBoth();
  await browser?.close().catch(() => undefined);
  await server?.close().catch(() => undefined);
  rmSync(temporary, { recursive: true, force: true });
}

/** Name the failure class so a single run's report says whose problem it is. */
function classify({ stage: failedStage, error, failedRequests = [], pendingRequests = [], openKeyAlert, shareCopy, rateLimited, rateLimitedAt }) {
  if (rateLimited) return `rate-limited: HTTP 429 from ${rateLimitedAt.origin} at ${rateLimitedAt.stage}`;
  const changed = failedRequests.find((entry) => entry.error === "net::ERR_NETWORK_CHANGED");
  if (changed !== undefined) return `runner-network-changed: ${changed.method} ${changed.origin}${changed.path}`;
  if (failedStage === "inbox") return "mail-delivery: a test inbox could not be made";
  if (failedStage === "openkey-otp" && /no OpenKey code/.test(error ?? "")) return "mail-delivery: no OpenKey code reached the test inbox";
  if (failedStage === "recipient-code" && /no recipient code/.test(error ?? "")) return "mail-delivery: no recipient code reached the test inbox";
  if (openKeyAlert !== undefined) return "openkey: OpenKey refused a step";
  const openkeyRefusal = failedRequests.find((entry) => /openkey/.test(entry.origin ?? "") && entry.status >= 400 && entry.errorCode !== "NEW_ACCOUNT_CONFIRMATION_REQUIRED");
  if (openkeyRefusal !== undefined) return `openkey: OpenKey refused a step (${openkeyRefusal.method} ${openkeyRefusal.path} ${openkeyRefusal.status}${openkeyRefusal.errorCode ? ` ${openkeyRefusal.errorCode}` : ""})`;
  // The SDK aborts its own account-registry sync after 4 s (net::ERR_ABORTED) and carries on; a 409
  // on POST /encryption/networks is the SDK's "already created", not a failure.
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
