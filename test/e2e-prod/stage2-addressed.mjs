/**
 * STAGE 2 — addressed / exact-email share to a Mailinator inbox, against LIVE
 * production.
 *
 * MAILINATOR ADDRESSES ONLY. This harness picks its own `@mailinator.com`
 * recipient and refuses to run against anything else, so it cannot mail a real
 * person.
 *
 * The full path, and what each step is the first real-browser exercise of:
 *
 *   sign in                       — production OpenKey passkey
 *   compose an addressed share    — `createDelegatedShareKey`, which now uses
 *                                   the WebCrypto Ed25519 path that replaced a
 *                                   @noble implementation
 *   register the owner policy     — the Node's registration receipt, verified
 *                                   by the SDK against the trust bundle's
 *                                   `nodeInvitationKid`
 *   authorize delivery            — `authorizeShareDelivery`; the SDK verifies
 *                                   the Node's detached EdDSA proof against
 *                                   `nodeInvitationKid`, and requires
 *                                   `openCredentialsAudience === credentialsOrigin`
 *                                   and that it collide with neither
 *                                   `nodeAudience` nor `returnOrigin`
 *   POST {emailOrigin}/share/v3     — the actual send
 *   read the Mailinator inbox     — the invitation must really arrive
 *   follow the link signed out    — accountless session-key recipient claim
 *   verify mailbox inline         — no OpenKey request or extra page before render
 *   read the exact shared bytes
 *   explicitly save               — OpenKey starts only after render, then the
 *                                   Files for you write and readback complete
 *
 * The three items above the send do NOT depend on `senderReady`: they run in
 * the browser and against `tee.node.tinycloud.xyz` before anything is POSTed to
 * the witness. So this harness is worth running even while
 * `https://api.share.tinycloud.xyz/health/readiness` reports
 * `senderReady:false` — it will get as far as the send and then report the
 * exact rejection, and it captures the Node's authorization body (including
 * `returnOrigin`, which is not readable from the public config) on the way.
 *
 * Usage: node stage2-addressed.mjs
 */
import { chromium } from "playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OPENKEY_ORIGIN, attachVirtualAuthenticator, restoreCredential, registerFreshAccount, loadAccount, saveAccount, signInToShare, startOpenKeyAutopilot } from "./lib/openkey.mjs";
import { newInbox, waitForMessage, extractOtp, extractUrls } from "./lib/mailinator.mjs";
import { DEEP_TRACE } from "./lib/deep-trace.mjs";
import { redactString, redactValue } from "./lib/redact.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACCOUNT_PATH = resolve(HERE, ".account.json");
const RECIPIENT_ACCOUNT_PATH = resolve(HERE, ".account-recipient.json");
const RUN_DIR = resolve(HERE, "runs", `stage2-${new Date().toISOString().replace(/[:.]/g, "-")}`);
const SHARE_ORIGIN = process.env.SHARE_ORIGIN ?? "https://share.tinycloud.xyz";
const COMPOSER_URL = `${SHARE_ORIGIN}/share#/new`;
const OPENKEY_REQUEST_ORIGIN = new URL(OPENKEY_ORIGIN).origin;

mkdirSync(RUN_DIR, { recursive: true });
const lines = [];
const log = (line) => {
  const safe = redactString(line);
  console.log(safe);
  lines.push(`${new Date().toISOString()} ${safe}`);
  writeFileSync(resolve(RUN_DIR, "run.log"), lines.join("\n"));
};

const results = [];
function record(name, ok, detail) {
  const safeDetail = detail === undefined ? undefined : redactString(detail);
  results.push({ name, ok, ...(safeDetail === undefined ? {} : { detail: safeDetail }) });
  log(`${ok ? "PASS" : "FAIL"}  ${name}${safeDetail === undefined ? "" : ` — ${safeDetail}`}`);
}

const CLIPBOARD_TAP = () => {
  window.__clipboardWrites = [];
  const clipboard = navigator.clipboard ?? {};
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      ...clipboard,
      writeText: async (value) => { window.__clipboardWrites.push(value); },
    },
  });
};

const recipient = newInbox("tcshare-rcpt");
if (!recipient.address.endsWith("@mailinator.com")) throw new Error("refusing to run: recipient is not a mailinator address");
log(`[stage2] recipient ${recipient.address}`);

const readiness = await fetch("https://api.share.tinycloud.xyz/health/readiness", { cache: "no-store" }).then((response) => response.json());
log(`[stage2] readiness ${JSON.stringify(readiness)}`);
if (readiness.senderReady !== true) log("[stage2] senderReady is false — the POST to the witness is expected to be rejected; everything before it still runs");

const browser = await chromium.launch({ headless: process.env.HEADED !== "1" });
log(`[browser] ${browser.version()}`);

/** Every response body from the Node, the email Worker and the witness, for the proof audit. */
const captured = [];

try {
  const context = await browser.newContext();
  await context.addInitScript(CLIPBOARD_TAP);
  if (process.env.TRACE_DEEP === "1") await context.addInitScript(DEEP_TRACE);
  const page = await context.newPage();
  page.on("console", (message) => log(`[console ${message.type()}] ${message.text()}`));
  page.on("pageerror", (error) => log(`[pageerror] ${error.message}`));
  page.on("response", async (response) => {
    const url = response.url();
    // `email.tinycloud.xyz` is the hop that decides whether the mail is sent,
    // and it was the one hop this filter omitted: a run could trace the Node
    // signing the authorization, then report "The email didn't go out" with
    // nothing but a bare `502` in the console. The Worker's error body carries
    // its refusal reason and the upstream provider's numeric status (TC-444)
    // and no recipient data, so capturing it is what makes a delivery failure
    // diagnosable from the artifacts alone.
    if (!/tee\.node\.tinycloud|witness\.credentials\.org|email\.tinycloud\.xyz|\/api\/share\/|registry/.test(url)) return;
    // Record the exchange BEFORE awaiting the body, and fill the body in later.
    //
    // For several of these responses `response.text()` does not settle until the
    // browser context closes. This handler used to await it first, so those
    // entries were pushed *after* the `finally` block had already written
    // `network.json` — the file was missing the email Worker's response
    // entirely, and every assertion reading `captured` raced the same promise.
    // The bodies still arrive; they are just no longer a precondition for
    // knowing the request happened.
    const entry = { status: response.status(), method: response.request().method(), url, body: "" };
    captured.push(entry);
    log(`[res ${response.status()}] ${response.request().method()} ${url}`);
    const body = await response.text().catch(() => "<unreadable>");
    entry.body = body.slice(0, 20_000);
    if (/policy|invoke|share\/v2|delivery|authoriz|email\.tinycloud/i.test(url)) log(`  body: ${body.slice(0, 1200)}`);
  });

  // Owner-share requests carry their authority in the Authorization header, so
  // a rejection is only diagnosable with the request beside the response.
  page.on("request", (request) => {
    if (!/\/share\/v[123]\/|\/api\/share\/bindings/.test(request.url())) return;
    const headers = request.headers();
    captured.push({
      direction: "request",
      method: request.method(),
      url: request.url(),
      headers: { ...headers, authorization: headers.authorization === undefined ? undefined : `${headers.authorization.slice(0, 120)}…` },
      body: (request.postData() ?? "").slice(0, 20_000),
    });
    log(`[req] ${request.method()} ${request.url()}`);
  });

  const { cdp, authenticatorId } = await attachVirtualAuthenticator(context, page);
  let account = process.env.FRESH_ACCOUNT === "1" ? undefined : loadAccount(ACCOUNT_PATH);
  if (account === undefined) {
    account = await registerFreshAccount(page, cdp, authenticatorId, log);
    saveAccount(ACCOUNT_PATH, account);
  } else {
    log(`[openkey] reusing account ${account.address}`);
    await restoreCredential(cdp, authenticatorId, account.credential);
  }

  await signInToShare(page, { appUrl: COMPOSER_URL, log });

  // The owner path signs mid-compose; keep answering OpenKey from here on.
  const stopAutopilot = startOpenKeyAutopilot(page, log);

  if (await page.locator("form.composer-form").count() === 0) {
    await page.evaluate(() => { window.location.hash = "#/new"; });
  }
  await page.locator("form.composer-form").waitFor({ timeout: 60_000 });
  // Recorded here rather than immediately after `signInToShare`, where it was a
  // hardcoded `true` that could only ever pass. The claim is "reaches the
  // composer", so assert the composer — a signed-out page has no composer form,
  // and an authenticated session is what puts one there.
  record("production OpenKey sign-in reaches the composer", await page.locator("form.composer-form").count() > 0, account.address);
  await page.locator("div.content-dropzone").waitFor({ state: "visible", timeout: 60_000 });

  const nonce = `tc-addressed-${crypto.randomUUID()}`;
  const markdown = `# Addressed share proof\n\nnonce: ${nonce}\n`;
  await page.setInputFiles('input[name="document"]', { name: "stage2-proof.md", mimeType: "text/markdown", buffer: Buffer.from(new TextEncoder().encode(markdown)) });
  await page.locator("div.content-chosen").waitFor({ state: "visible", timeout: 30_000 });

  await page.check('input[name="recipient"][value="exactEmail"]');
  await page.fill('input[name="recipient-value"]', recipient.address);
  // The delivery address defaults to the recipient; assert rather than assume.
  const delivery = await page.inputValue('input[name="delivery-email"]').catch(() => "");
  record("the delivery address defaults to the exact recipient", delivery === recipient.address, `delivery-email=${JSON.stringify(delivery)}`);

  await page.locator("button.create-link-button").click();

  const status = page.locator("div.composer-status");
  const settled = await page.waitForFunction(
    () => {
      const state = document.querySelector("div.composer-status")?.dataset.state;
      return state === "created" || state?.startsWith("error") === true;
    },
    undefined,
    { timeout: 600_000 },
  ).then(() => true).catch(() => false);
  const state = await status.getAttribute("data-state");
  const statusText = (await status.innerText().catch(() => "")).replace(/\n+/g, " | ");
  log(`[composer] settled=${settled} data-state=${state} :: ${statusText}`);
  record("the addressed share was created", state === "created", `data-state=${state}; ${statusText}`);
  await page.screenshot({ path: resolve(RUN_DIR, "composer.png"), fullPage: true });
  if (state !== "created") throw new Error(`addressed share creation failed (${state})`);

  await page.getByRole("button", { name: /^copy link$/i }).click();
  const copiedShareUrl = await page.evaluate(() => window.__clipboardWrites?.at(-1));
  record("the exact-email private link was captured", typeof copiedShareUrl === "string" && copiedShareUrl.includes("/s/") && copiedShareUrl.includes("#k="));
  if (typeof copiedShareUrl !== "string") throw new Error("exact-email private link was not captured");

  // Delivery is a second, explicit gesture: the composer creates the link, then
  // offers "Notify recipient". Nothing is requested until it is clicked.
  let invitationRequested = false;
  if (state === "created") {
    const send = page.getByRole("button", { name: "Notify recipient" });
    const sendVisible = await send.isVisible().catch(() => false);
    record('the result screen offers "Notify recipient" for an addressed share', sendVisible);
    if (sendVisible) {
      await send.click();
      await page.waitForFunction(
        () => (document.querySelector("span.notification-status")?.textContent ?? "").length > 0,
        undefined,
        { timeout: 300_000 },
      ).catch(() => {});
      const deliveryStatus = (await page.locator("span.notification-status").textContent().catch(() => "")) ?? "";
      log(`[composer] delivery status: ${JSON.stringify(deliveryStatus)}`);
      invitationRequested = deliveryStatus.startsWith("Invitation requested");
      record("the composer reports the invitation was requested", invitationRequested, deliveryStatus);
    }
  }

  // The Node's delivery authorization is the object the SDK's
  // openCredentialsAudience / nodeInvitationKid predicates run against. The
  // audience remains the credential issuer even though the verified receipt
  // is delivered to the separate email Worker origin.
  const authorization = captured.find((entry) => /openCredentialsAudience/.test(entry.body));
  if (authorization !== undefined) {
    log(`[stage2] delivery authorization from ${authorization.url}`);
    let parsed;
    try {
      parsed = JSON.parse(authorization.body);
    } catch {
      parsed = undefined;
    }
    const value = parsed?.authorization ?? parsed;
    if (value !== undefined) {
      writeFileSync(resolve(RUN_DIR, "delivery-authorization.json"), JSON.stringify(redactValue(parsed), null, 2));
      record("openCredentialsAudience !== nodeAudience", value.openCredentialsAudience !== value.nodeAudience, `${value.openCredentialsAudience} vs ${value.nodeAudience}`);
      record("openCredentialsAudience !== returnOrigin", value.openCredentialsAudience !== value.returnOrigin, `${value.openCredentialsAudience} vs ${value.returnOrigin}`);
      record("openCredentialsAudience === the configured credentialsOrigin", value.openCredentialsAudience === "https://witness.credentials.org", String(value.openCredentialsAudience));
    }
  } else {
    record("the Node returned a delivery authorization", false, "no response body containing openCredentialsAudience was observed");
  }

  // Addressed delivery goes to the email Worker. The credential issuer remains
  // the signed audience because the recipient later acquires the credential
  // there; it is not the network destination for the notification request.
  //
  // Polled, not read once: the `response` handler pushes to `captured` only
  // after `await response.text()` resolves, so reading the array the moment the
  // composer reports "queued" races the capture and finds nothing. The first
  // version of this check did exactly that and reported no POST even though
  // the response arrived immediately afterward.
  const sendDeadline = invitationRequested ? Date.now() + 30_000 : Date.now();
  let sendResponse;
  for (;;) {
    sendResponse = captured.find((entry) => entry.direction !== "request" && /email\.tinycloud\.xyz\/share\/v3/.test(entry.url));
    if (sendResponse !== undefined || Date.now() >= sendDeadline) break;
    await page.waitForTimeout(500);
  }
  record("the email Worker accepted the invitation request", sendResponse?.status === 202, sendResponse === undefined ? "no POST to the email Worker was observed within 30s" : `${sendResponse.status} ${sendResponse.body.slice(0, 300)}`);

  // ---------------------------------------------------------------- mailbox
  let recipientLink = copiedShareUrl;
  // The predicate used to be `() => true`, which accepts ANY message that lands
  // in the inbox — so this proved "an email arrived", not "the invitation for
  // this share arrived", while claiming the latter. Require the document name
  // and a `/s/` link, both of which are known before polling starts. A stray
  // message now keeps the poll running instead of being asserted on and then
  // failing the link check below with a misleading message.
  if (sendResponse?.status === 202) {
    log(`[stage2] polling ${recipient.address}`);
    const isInvitation = (_message, body) => body.includes("stage2-proof.md") && body.includes("/s/");
    const { message, text } = await waitForMessage(recipient.inbox, isInvitation, { timeoutMs: 300_000, log });
    record(
      "the invitation email actually arrived in the Mailinator inbox",
      isInvitation(message, text) && /tinycloud/i.test(String(message.from)),
      `from=${message.from} subject=${JSON.stringify(message.subject)}`,
    );
    writeFileSync(resolve(RUN_DIR, "invitation-email.txt"), redactString(text));

    const links = extractUrls(text).filter((url) => url.includes("/s/"));
    record("the invitation carries a share link", links.length > 0, links.map((url) => url.replace(/#.*/, "#<redacted>")).join(" "));
    if (links.length === 0) throw new Error("no share link in the invitation");
    recipientLink = links[0];
  } else {
    log("[stage2] invitation delivery is unavailable; continuing the recipient proof with the captured private link");
  }

  // -------------------------------------------------------------- recipient
  const recipientContext = await browser.newContext({ acceptDownloads: true });
  const recipientPage = await recipientContext.newPage();
  const recipientOpenKeyRequests = [];
  let recipientRendered = false;
  recipientPage.on("console", (message2) => log(`[recipient console ${message2.type()}] ${message2.text()}`));
  recipientPage.on("pageerror", (error) => log(`[recipient pageerror] ${error.message}`));
  recipientPage.on("response", (response) => {
    if (/registry|\/api\/share\/|node\.tinycloud|credentials\.org|openkey/.test(response.url())) log(`[recipient res ${response.status()}] ${response.request().method()} ${response.url()}`);
  });
  recipientPage.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== OPENKEY_REQUEST_ORIGIN && url.hostname !== "openkey.so" && !url.hostname.endsWith(".openkey.so")) return;
    recipientOpenKeyRequests.push({ phase: recipientRendered ? "after-render" : "before-render", method: request.method(), path: url.pathname });
  });
  recipientPage.on("requestfailed", (request) => log(`[recipient reqfailed] ${request.method()} ${request.url()} — ${request.failure()?.errorText}`));
  await recipientPage.goto(recipientLink, { waitUntil: "domcontentloaded" });

  const acquisitionDeadline = Date.now() + 180_000;
  let acquisitionReady = false;
  let acquisitionFailure = "";
  while (!acquisitionReady && acquisitionFailure.length === 0 && Date.now() < acquisitionDeadline) {
    const state = await recipientPage.evaluate(() => {
      const space = document.querySelector("tinycloud-space-modal")?.shadowRoot;
      const create = space?.querySelector('button[data-action="create"]');
      if (create instanceof HTMLButtonElement) create.click();
      const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
      const ready = root?.querySelector('input[name="otp"]') instanceof HTMLInputElement
        && root.querySelector('button[type="submit"]') instanceof HTMLButtonElement;
      const button = document.querySelector("button.viewer-primary-action");
      const alert = document.querySelector('[role="alert"]');
      return { ready, failed: button instanceof HTMLButtonElement && !button.disabled ? alert?.textContent ?? "credential flow returned to retry" : "" };
    }).catch(() => ({ ready: false, failed: "" }));
    acquisitionReady = state.ready;
    acquisitionFailure = state.failed;
    if (!acquisitionReady && acquisitionFailure.length === 0) await recipientPage.waitForTimeout(1_000);
  }
  record("the SDK embedded credential element rendered in the Share page", acquisitionReady, acquisitionFailure || undefined);
  if (!acquisitionReady) {
    writeFileSync(resolve(RUN_DIR, "recipient-pre-acquisition.txt"), redactString(await recipientPage.evaluate(() => document.body?.innerText ?? "")));
    await recipientPage.screenshot({ path: resolve(RUN_DIR, "recipient-pre-acquisition.png"), fullPage: true });
    throw new Error("embedded credential acquisition controls did not render");
  }
  const saveVisibleBeforeRender = await recipientPage.locator("button.viewer-save-to-tinycloud").isVisible().catch(() => false);

  const otpMail = await waitForMessage(
    recipient.inbox,
    (_message, body) => !body.includes("stage2-proof.md") && extractOtp(body) !== undefined,
    { timeoutMs: 300_000, log },
  );
  const otp = extractOtp(otpMail.text);
  if (otp === undefined) throw new Error("credential verification email did not contain a six-digit OTP");
  const otpSubmitted = await recipientPage.evaluate((value) => {
    const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
    const input = root?.querySelector('input[name="otp"]');
    const submit = root?.querySelector('button[type="submit"]');
    if (!(input instanceof HTMLInputElement) || !(submit instanceof HTMLButtonElement)) return false;
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    submit.click();
    return true;
  }, otp);
  record("the recipient submitted the Mailinator OTP inside the SDK element", otpSubmitted);

  // `section.viewer-content` ships with the document, so waiting for it returned
  // in well under a second while the page still read "Checking…" — the 180s
  // budget never applied and the nonce assertion below ran against a
  // still-loading page. Wait for a terminal state instead: the nonce rendered
  // anywhere (including inside the viewer's frames), or the claim visibly
  // failing. Whichever arrives first is the answer; the timeout is now real.
  const readRendered = async () => {
    const frames = [];
    for (const frame of recipientPage.frames()) frames.push(await frame.evaluate(() => document.body?.innerText ?? "").catch(() => ""));
    return frames.join("\n");
  };
  const deadline = Date.now() + 180_000;
  let rendered = "";
  for (;;) {
    rendered = await readRendered();
    if (rendered.includes(nonce)) break;
    if (/something went wrong|ask the sender for a fresh link|link has expired|no longer available/i.test(rendered)) {
      log("[recipient] the page reached a failure state; not waiting out the rest of the budget");
      break;
    }
    if (Date.now() >= deadline) break;
    await recipientPage.waitForTimeout(2_000);
  }
  record("the recipient reads the exact shared document", rendered.includes(nonce), `nonce ${nonce}`);
  recipientRendered = rendered.includes(nonce);
  record(
    "the accountless receiver made zero OpenKey requests before render",
    recipientOpenKeyRequests.every((request) => request.phase !== "before-render"),
    `${recipientOpenKeyRequests.filter((request) => request.phase === "before-render").length} requests`,
  );
  record("the accountless receiver opened no additional page before render", recipientContext.pages().length === 1, `${recipientContext.pages().length} pages`);
  record(
    "the receiver session key is held in sessionStorage",
    await recipientPage.evaluate(() => sessionStorage.getItem("tinycloud.share.receiver-session.v1") !== null),
  );
  writeFileSync(resolve(RUN_DIR, "recipient-rendered.txt"), redactString(rendered));
  await recipientPage.screenshot({ path: resolve(RUN_DIR, "recipient.png"), fullPage: true });

  const save = recipientPage.locator("button.viewer-save-to-tinycloud");
  const saveVisible = await save.isVisible().catch(() => false);
  record("Save to TinyCloud appears only after render", !saveVisibleBeforeRender && recipientRendered && saveVisible);
  if (!saveVisible) throw new Error("post-render Save to TinyCloud action did not appear");

  const { cdp: recipientCdp, authenticatorId: recipientAuthenticatorId } = await attachVirtualAuthenticator(recipientContext, recipientPage);
  const recipientAccount = loadAccount(RECIPIENT_ACCOUNT_PATH) ?? loadAccount(ACCOUNT_PATH);
  if (recipientAccount === undefined) throw new Error("post-render save requires the OpenKey account created by this run");
  log(`[openkey recipient] reusing account ${recipientAccount.address}`);
  await restoreCredential(recipientCdp, recipientAuthenticatorId, recipientAccount.credential);
  const stopRecipientAutopilot = startOpenKeyAutopilot(recipientPage, log);
  await save.click();

  const saveDeadline = Date.now() + 420_000;
  let saveText = "";
  let saveError = "";
  while (Date.now() < saveDeadline) {
    await recipientPage.evaluate(() => {
      const host = document.querySelector("tinycloud-space-modal");
      const create = host?.shadowRoot?.querySelector('button[data-action="create"]');
      if (create instanceof HTMLButtonElement) create.click();
    }).catch(() => {});
    saveText = (await save.textContent().catch(() => "")) ?? "";
    saveError = (await recipientPage.locator(".viewer-save-status[role=alert]").textContent().catch(() => "")) ?? "";
    if (/Saved to Files for you/i.test(saveText) || saveError.length > 0) break;
    await recipientPage.waitForTimeout(1_000);
  }
  stopRecipientAutopilot();
  record(
    "OpenKey starts only after the explicit Save action",
    recipientOpenKeyRequests.some((request) => request.phase === "after-render")
      && recipientOpenKeyRequests.every((request) => request.phase !== "before-render"),
    `${recipientOpenKeyRequests.filter((request) => request.phase === "after-render").length} post-render requests`,
  );
  record(
    "Save creates and reads back the authenticated Files for you copy",
    /Saved to Files for you/i.test(saveText) && saveError.length === 0,
    saveError || saveText,
  );
  stopAutopilot();
} catch (error) {
  record("stage 2 completed", false, `${error.name}: ${error.message}`);
  log(error.stack ?? String(error));
} finally {
  writeFileSync(resolve(RUN_DIR, "network.json"), JSON.stringify(redactValue(captured), null, 2));
  await browser.close();
}

writeFileSync(resolve(RUN_DIR, "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((entry) => !entry.ok);
log(`\nrecipient address: ${recipient.address}`);
log(`${results.length - failed.length}/${results.length} checks passed. Artifacts in ${RUN_DIR}`);
if (failed.length > 0) process.exit(1);
