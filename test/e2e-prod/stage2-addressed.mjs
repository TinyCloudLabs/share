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
 *   POST {credentialsOrigin}/share/v2 — the actual send
 *   read the Mailinator inbox     — the invitation must really arrive
 *   follow the link, confirm      — the recipient claim
 *   read the exact shared bytes
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
import { attachVirtualAuthenticator, restoreCredential, registerFreshAccount, loadAccount, saveAccount, signInToShare, startOpenKeyAutopilot } from "./lib/openkey.mjs";
import { newInbox, waitForMessage, extractOtp, extractUrls } from "./lib/mailinator.mjs";
import { DEEP_TRACE } from "./lib/deep-trace.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACCOUNT_PATH = resolve(HERE, ".account.json");
const RECIPIENT_ACCOUNT_PATH = resolve(HERE, ".account-recipient.json");
const RUN_DIR = resolve(HERE, "runs", `stage2-${new Date().toISOString().replace(/[:.]/g, "-")}`);
const SHARE_ORIGIN = process.env.SHARE_ORIGIN ?? "https://share.tinycloud.xyz";
const COMPOSER_URL = `${SHARE_ORIGIN}/share#/new`;

mkdirSync(RUN_DIR, { recursive: true });
const lines = [];
const log = (line) => {
  console.log(line);
  lines.push(`${new Date().toISOString()} ${line}`);
  writeFileSync(resolve(RUN_DIR, "run.log"), lines.join("\n"));
};

const results = [];
function record(name, ok, detail) {
  results.push({ name, ok, detail });
  log(`${ok ? "PASS" : "FAIL"}  ${name}${detail === undefined ? "" : ` — ${detail}`}`);
}

const recipient = newInbox("tcshare-rcpt");
if (!recipient.address.endsWith("@mailinator.com")) throw new Error("refusing to run: recipient is not a mailinator address");
log(`[stage2] recipient ${recipient.address}`);
writeFileSync(resolve(RUN_DIR, "recipient.txt"), `${recipient.address}\n`);

const readiness = await fetch("https://api.share.tinycloud.xyz/health/readiness", { cache: "no-store" }).then((response) => response.json());
log(`[stage2] readiness ${JSON.stringify(readiness)}`);
if (readiness.senderReady !== true) log("[stage2] senderReady is false — the POST to the witness is expected to be rejected; everything before it still runs");

const browser = await chromium.launch({ headless: process.env.HEADED !== "1" });
log(`[browser] ${browser.version()}`);

/** Every response body from the Node, the email Worker and the witness, for the proof audit. */
const captured = [];

try {
  const context = await browser.newContext();
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
    if (!/\/share\/v[12]\//.test(request.url())) return;
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
  const markdown = `# Addressed share proof\n\nnonce: ${nonce}\n\nrecipient: ${"<set below>"}\n`;
  await page.setInputFiles('input[name="document"]', { name: "stage2-proof.md", mimeType: "text/markdown", buffer: Buffer.from(new TextEncoder().encode(markdown.replace("<set below>", recipient.address))) });
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

  // Delivery is a second, explicit gesture: the composer creates the link, then
  // offers "Notify recipient". Nothing is requested until it is clicked.
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
      record("the composer reports the invitation was requested", deliveryStatus.startsWith("Invitation requested"), deliveryStatus);
    }
  }

  // The Node's delivery authorization is the object the SDK's
  // openCredentialsAudience / nodeInvitationKid predicates run against.
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
      writeFileSync(resolve(RUN_DIR, "delivery-authorization.json"), JSON.stringify(parsed, null, 2));
      record("openCredentialsAudience !== nodeAudience", value.openCredentialsAudience !== value.nodeAudience, `${value.openCredentialsAudience} vs ${value.nodeAudience}`);
      record("openCredentialsAudience !== returnOrigin", value.openCredentialsAudience !== value.returnOrigin, `${value.openCredentialsAudience} vs ${value.returnOrigin}`);
      record("openCredentialsAudience === the configured credentialsOrigin", value.openCredentialsAudience === "https://witness.credentials.org", String(value.openCredentialsAudience));
    }
  } else {
    record("the Node returned a delivery authorization", false, "no response body containing openCredentialsAudience was observed");
  }

  // Addressed delivery goes to OpenCredentials, which mints the invitation
  // claim material before requesting provider delivery. The legacy Worker
  // cannot own this path because its delivered link contains only `k`.
  //
  // Polled, not read once: the `response` handler pushes to `captured` only
  // after `await response.text()` resolves, so reading the array the moment the
  // composer reports "queued" races the capture and finds nothing. The first
  // version of this check did exactly that and reported no POST even though
  // the response arrived immediately afterward.
  const sendDeadline = Date.now() + 30_000;
  let sendResponse;
  for (;;) {
    sendResponse = captured.find((entry) => entry.direction !== "request" && /witness\.credentials\.org\/share\/v2/.test(entry.url));
    if (sendResponse !== undefined || Date.now() >= sendDeadline) break;
    await page.waitForTimeout(500);
  }
  record("OpenCredentials accepted the invitation request", sendResponse?.status === 202, sendResponse === undefined ? "no POST to OpenCredentials was observed within 30s" : `${sendResponse.status} ${sendResponse.body.slice(0, 300)}`);

  // ---------------------------------------------------------------- mailbox
  log(`[stage2] polling ${recipient.address}`);
  // The predicate used to be `() => true`, which accepts ANY message that lands
  // in the inbox — so this proved "an email arrived", not "the invitation for
  // this share arrived", while claiming the latter. Require the document name
  // and a `/s/` link, both of which are known before polling starts. A stray
  // message now keeps the poll running instead of being asserted on and then
  // failing the link check below with a misleading message.
  const isInvitation = (_message, body) => body.includes("stage2-proof.md") && body.includes("/s/");
  const { message, text } = await waitForMessage(recipient.inbox, isInvitation, { timeoutMs: 300_000, log });
  // Not a hardcoded `true`: `waitForMessage` throws on timeout, but that only
  // proves *something* matched. Re-assert the identity here so the reported
  // check is the one that was actually made.
  record(
    "the invitation email actually arrived in the Mailinator inbox",
    isInvitation(message, text) && /tinycloud/i.test(String(message.from)),
    `from=${message.from} subject=${JSON.stringify(message.subject)}`,
  );
  writeFileSync(resolve(RUN_DIR, "invitation-email.txt"), text);

  const links = extractUrls(text).filter((url) => url.includes("/s/"));
  record("the invitation carries a share link", links.length > 0, links.map((url) => url.replace(/#.*/, "#<redacted>")).join(" "));
  if (links.length === 0) throw new Error("no share link in the invitation");

  // -------------------------------------------------------------- recipient
  const recipientContext = await browser.newContext({ acceptDownloads: true });
  const recipientPage = await recipientContext.newPage();
  recipientPage.on("console", (message2) => log(`[recipient console ${message2.type()}] ${message2.text()}`));
  const { cdp: recipientCdp, authenticatorId: recipientAuthenticatorId } = await attachVirtualAuthenticator(recipientContext, recipientPage);
  let recipientAccount = process.env.FRESH_ACCOUNT === "1" ? undefined : loadAccount(RECIPIENT_ACCOUNT_PATH);
  if (recipientAccount === undefined) {
    recipientAccount = await registerFreshAccount(recipientPage, recipientCdp, recipientAuthenticatorId, log);
    saveAccount(RECIPIENT_ACCOUNT_PATH, recipientAccount);
  } else {
    log(`[openkey recipient] reusing account ${recipientAccount.address}`);
    await restoreCredential(recipientCdp, recipientAuthenticatorId, recipientAccount.credential);
  }
  await recipientPage.goto(links[0], { waitUntil: "domcontentloaded" });

  const verify = recipientPage.getByRole("button", { name: /^confirm email$/i });
  await verify.waitFor({ timeout: 60_000 });
  const stopRecipientAutopilot = startOpenKeyAutopilot(recipientPage, log);
  await verify.click();

  const acquisitionDeadline = Date.now() + 180_000;
  let acquisitionReady = false;
  while (!acquisitionReady && Date.now() < acquisitionDeadline) {
    acquisitionReady = await recipientPage.evaluate(() => {
      const space = document.querySelector("tinycloud-space-modal")?.shadowRoot;
      const create = space?.querySelector('button[data-action="create"]');
      if (create instanceof HTMLButtonElement) create.click();
      const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
      return root?.querySelector('input[name="otp"]') instanceof HTMLInputElement
        && root.querySelector('button[type="submit"]') instanceof HTMLButtonElement;
    }).catch(() => false);
    if (!acquisitionReady) await recipientPage.waitForTimeout(1_000);
  }
  record("the SDK embedded credential element rendered in the Share page", acquisitionReady);
  if (!acquisitionReady) throw new Error("embedded credential acquisition controls did not render");

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
  writeFileSync(resolve(RUN_DIR, "recipient-rendered.txt"), rendered);
  await recipientPage.screenshot({ path: resolve(RUN_DIR, "recipient.png"), fullPage: true });
  stopRecipientAutopilot();
  stopAutopilot();
} catch (error) {
  record("stage 2 completed", false, `${error.name}: ${error.message}`);
  log(error.stack ?? String(error));
} finally {
  writeFileSync(resolve(RUN_DIR, "network.json"), JSON.stringify(captured, null, 2));
  await browser.close();
}

writeFileSync(resolve(RUN_DIR, "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((entry) => !entry.ok);
log(`\nrecipient address: ${recipient.address}`);
log(`${results.length - failed.length}/${results.length} checks passed. Artifacts in ${RUN_DIR}`);
if (failed.length > 0) process.exit(1);
