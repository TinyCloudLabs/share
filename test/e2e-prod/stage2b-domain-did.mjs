/**
 * Production evidence for the two non-email addressed recipient choices.
 *
 * This intentionally does not send mail or mutate deployment configuration. It
 * uses the saved production OpenKey account, creates an email-domain share,
 * opens its private link in a clean context, and then attempts a recipient-DID
 * share with a canonical did:key fixture. Artifacts are written below runs/.
 *
 * Usage: node stage2b-domain-did.mjs
 */
import { chromium } from "playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  attachVirtualAuthenticator,
  loadAccount,
  restoreCredential,
  signInToShare,
  startOpenKeyAutopilot,
} from "./lib/openkey.mjs";
import { redactHeaders, redactJsonText, redactString } from "./lib/redact.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACCOUNT_PATH = resolve(HERE, ".account.json");
const RUN_DIR = resolve(HERE, "runs", `stage2b-domain-did-${new Date().toISOString().replace(/[:.]/g, "-")}`);
const SHARE_ORIGIN = process.env.SHARE_ORIGIN ?? "https://share.tinycloud.xyz";
const COMPOSER_URL = `${SHARE_ORIGIN}/share#/new`;
const DOMAIN = process.env.TEST_DOMAIN ?? "mailinator.com";
// Ed25519 did:key fixture used by the repository's TC-405 authorization vector.
const RECIPIENT_DID = process.env.TEST_RECIPIENT_DID ?? "did:key:z6MkwVDfCg9LbbY6xjH3EZk8YSFQZujV5Y4y1ZWeER9tDiN3";

mkdirSync(RUN_DIR, { recursive: true });
const lines = [];
const log = (line) => {
  const safe = redactString(line);
  console.log(safe);
  lines.push(`${new Date().toISOString()} ${safe}`);
  writeFileSync(resolve(RUN_DIR, "run.log"), `${lines.join("\n")}\n`);
};

const results = [];
function record(name, ok, detail) {
  const row = { name, ok, ...(detail === undefined ? {} : { detail: redactString(detail) }) };
  results.push(row);
  log(`${ok ? "PASS" : "FAIL"}  ${name}${row.detail === undefined ? "" : ` — ${row.detail}`}`);
}

const CLIPBOARD_TAP = () => {
  window.__clipboardWrites = [];
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: async (value) => { window.__clipboardWrites.push(value); },
    },
  });
};

function safeUrl(url) {
  return redactString(url).replace(/#k=[^&#\s]+/i, "#k=<redacted>");
}

function relevant(url) {
  return /tee\.node\.tinycloud|node\.tinycloud|registry|\/api\/share\/|credentials\.org|openkey/.test(url);
}

const network = [];
const pendingBodies = new Set();
let phase = "startup";

function capturePage(page, label) {
  page.on("console", (message) => log(`[${label} console ${message.type()}] ${message.text()}`));
  page.on("pageerror", (error) => log(`[${label} pageerror] ${error.message}`));
  page.on("request", (request) => {
    if (!relevant(request.url())) return;
    const body = request.postData();
    network.push({
      phase,
      page: label,
      direction: "request",
      method: request.method(),
      url: safeUrl(request.url()),
      headers: redactHeaders(request.headers()),
      ...(body === null ? {} : { body: redactJsonText(body).slice(0, 8_000) }),
    });
    log(`[${phase} req] ${request.method()} ${safeUrl(request.url())}`);
  });
  page.on("response", (response) => {
    if (!relevant(response.url())) return;
    const entry = {
      phase,
      page: label,
      direction: "response",
      status: response.status(),
      method: response.request().method(),
      url: safeUrl(response.url()),
      headers: redactHeaders(response.headers()),
      body: "<pending>",
    };
    network.push(entry);
    log(`[${phase} res ${response.status()}] ${response.request().method()} ${safeUrl(response.url())}`);
    const pending = response.text()
      .then((body) => { entry.body = redactJsonText(body).slice(0, 8_000); })
      .catch((error) => { entry.body = `<unreadable: ${redactString(error.message)}>`; })
      .finally(() => { pendingBodies.delete(pending); });
    pendingBodies.add(pending);
  });
  page.on("requestfailed", (request) => {
    if (!relevant(request.url())) return;
    network.push({
      phase,
      page: label,
      direction: "requestfailed",
      method: request.method(),
      url: safeUrl(request.url()),
      error: redactString(request.failure()?.errorText ?? "unknown"),
    });
    log(`[${phase} reqfailed] ${request.method()} ${safeUrl(request.url())} — ${request.failure()?.errorText}`);
  });
}

async function settleComposer(page, timeout = 300_000) {
  const settled = await page.waitForFunction(
    () => {
      const state = document.querySelector("div.composer-status")?.dataset.state ?? "";
      return state === "created" || state.startsWith("error");
    },
    undefined,
    { timeout },
  ).then(() => true).catch(() => false);
  const status = page.locator("div.composer-status");
  return {
    settled,
    state: await status.getAttribute("data-state"),
    text: (await status.innerText().catch(() => "")).replace(/\s*\n\s*/g, " | ").trim(),
  };
}

async function prepareComposer(page) {
  if (await page.locator('div.composer-status[data-state="created"]').count() > 0) {
    await page.getByRole("button", { name: "Share another" }).click();
  } else if (await page.locator("form.composer-form").count() === 0) {
    await page.evaluate(() => { window.location.hash = "#/new"; });
  }
  await page.locator("form.composer-form").waitFor({ timeout: 60_000 });
  await page.locator("div.content-dropzone").waitFor({ state: "visible", timeout: 60_000 });
}

async function attemptShare(page, { kind, value, filename }) {
  await prepareComposer(page);
  await page.evaluate(() => { window.__clipboardWrites = []; });
  const source = `# ${kind} production evidence\n\nnonce: ${crypto.randomUUID()}\n`;
  await page.setInputFiles('input[name="document"]', {
    name: filename,
    mimeType: "text/markdown",
    buffer: Buffer.from(source, "utf8"),
  });
  await page.locator("div.content-chosen").waitFor({ state: "visible", timeout: 30_000 });
  await page.check(`input[name="recipient"][value="${kind}"]`);
  await page.fill('input[name="recipient-value"]', value);
  const uiBeforeSubmit = await page.evaluate(() => ({
    kind: document.querySelector('input[name="recipient"]:checked')?.value ?? null,
    recipientValue: document.querySelector('input[name="recipient-value"]')?.value ?? null,
    recipientLabel: document.querySelector('input[name="recipient-value"]')?.getAttribute("aria-label") ?? null,
    deliveryEmail: document.querySelector('input[name="delivery-email"]')?.value ?? null,
    note: document.querySelector("p.composer-note")?.textContent?.trim() ?? null,
  }));
  await page.locator("button.create-link-button").click();
  const terminal = await settleComposer(page);
  let link;
  if (terminal.state === "created") {
    await page.getByRole("button", { name: /^copy link$/i }).click();
    link = await page.evaluate(() => window.__clipboardWrites?.at(-1));
  }
  return { uiBeforeSubmit, terminal, link };
}

const browser = await chromium.launch({ headless: process.env.HEADED !== "1" });
log(`[browser] ${browser.version()} headless=${process.env.HEADED !== "1"}`);

let stopAutopilot = () => {};
try {
  const account = loadAccount(ACCOUNT_PATH);
  if (account === undefined) throw new Error(`saved OpenKey account is required at ${ACCOUNT_PATH}`);

  const senderContext = await browser.newContext();
  await senderContext.addInitScript(CLIPBOARD_TAP);
  const senderPage = await senderContext.newPage();
  capturePage(senderPage, "sender");
  const { cdp, authenticatorId } = await attachVirtualAuthenticator(senderContext, senderPage);
  await restoreCredential(cdp, authenticatorId, account.credential);
  phase = "sender-sign-in";
  await signInToShare(senderPage, { appUrl: COMPOSER_URL, log });
  record("saved OpenKey account reaches the production composer", await senderPage.locator("form.composer-form").count() > 0, account.address);
  stopAutopilot = startOpenKeyAutopilot(senderPage, log);

  phase = "emailDomain-sender";
  const domain = await attemptShare(senderPage, {
    kind: "emailDomain",
    value: DOMAIN,
    filename: "stage2b-domain-proof.md",
  });
  await senderPage.screenshot({ path: resolve(RUN_DIR, "email-domain-sender.png"), fullPage: true });
  writeFileSync(resolve(RUN_DIR, "email-domain-sender.json"), `${JSON.stringify({ ...domain, link: domain.link === undefined ? undefined : safeUrl(domain.link) }, null, 2)}\n`);
  record("emailDomain selection reaches a terminal composer state", domain.terminal.settled, JSON.stringify(domain.terminal));
  record("emailDomain sender creates a private link", domain.terminal.state === "created" && typeof domain.link === "string", JSON.stringify(domain.terminal));

  if (typeof domain.link === "string") {
    writeFileSync(resolve(RUN_DIR, "email-domain-link.redacted.txt"), `${safeUrl(domain.link)}\n`);
    phase = "emailDomain-receiver";
    const receiverContext = await browser.newContext();
    const receiverPage = await receiverContext.newPage();
    capturePage(receiverPage, "emailDomain-receiver");
    await receiverPage.goto(domain.link, { waitUntil: "domcontentloaded", timeout: 60_000 });
    const receiverSettled = await receiverPage.waitForFunction(
      () => document.querySelector(".viewer-error") !== null || document.querySelector("tinycloud-credential-acquisition") !== null || document.querySelector("main.viewer-content") !== null,
      undefined,
      { timeout: 180_000 },
    ).then(() => true).catch(() => false);
    const receiver = await receiverPage.evaluate(() => {
      const host = document.querySelector("tinycloud-credential-acquisition");
      return {
        settled: document.querySelector(".viewer-error, tinycloud-credential-acquisition, main.viewer-content") !== null,
        title: document.querySelector(".viewer-state-title")?.textContent?.trim() ?? null,
        detail: document.querySelector(".viewer-state-detail")?.textContent?.trim() ?? null,
        bodyText: document.body?.innerText.replace(/\s+/g, " ").trim().slice(0, 2_000) ?? "",
        credentialElementCount: document.querySelectorAll("tinycloud-credential-acquisition").length,
        credentialShadowRootPresent: host?.shadowRoot !== null && host?.shadowRoot !== undefined,
        credentialShadowText: host?.shadowRoot?.textContent?.replace(/\s+/g, " ").trim().slice(0, 1_000) ?? null,
        finalHash: location.hash,
      };
    });
    receiver.settled = receiverSettled && receiver.settled;
    writeFileSync(resolve(RUN_DIR, "email-domain-receiver.json"), `${JSON.stringify(receiver, null, 2)}\n`);
    await receiverPage.screenshot({ path: resolve(RUN_DIR, "email-domain-receiver.png"), fullPage: true });
    record("emailDomain private link reaches a terminal receiver UI", receiver.settled, JSON.stringify(receiver));
    record("emailDomain receiver mounts the embedded credential element", receiver.credentialElementCount > 0 && receiver.credentialShadowRootPresent, JSON.stringify({ count: receiver.credentialElementCount, shadow: receiver.credentialShadowRootPresent }));
    await receiverContext.close();
  } else {
    record("emailDomain receiver flow was exercised", false, "no private link was created");
    record("emailDomain receiver mounts the embedded credential element", false, "no private link was created");
  }

  phase = "recipientDid-sender";
  const did = await attemptShare(senderPage, {
    kind: "recipientDid",
    value: RECIPIENT_DID,
    filename: "stage2b-did-proof.md",
  });
  await senderPage.screenshot({ path: resolve(RUN_DIR, "recipient-did-sender.png"), fullPage: true });
  writeFileSync(resolve(RUN_DIR, "recipient-did-sender.json"), `${JSON.stringify({ ...did, link: did.link === undefined ? undefined : safeUrl(did.link) }, null, 2)}\n`);
  record("recipientDid selection preserves the syntactically valid fixture in the UI", did.uiBeforeSubmit.kind === "recipientDid" && did.uiBeforeSubmit.recipientValue === RECIPIENT_DID, JSON.stringify(did.uiBeforeSubmit));
  record("recipientDid creation reaches a terminal composer state", did.terminal.settled, JSON.stringify(did.terminal));
  record("recipientDid sender creates a private link", did.terminal.state === "created" && typeof did.link === "string", JSON.stringify(did.terminal));
  record("recipientDid creation fails closed instead of producing a private link", did.terminal.state !== "created" && did.link === undefined, JSON.stringify(did.terminal));

  await senderContext.close();
} catch (error) {
  record("harness completed without an unhandled exception", false, error instanceof Error ? `${error.message}\n${error.stack ?? ""}` : String(error));
} finally {
  stopAutopilot();
  await Promise.race([Promise.allSettled([...pendingBodies]), new Promise((resolvePromise) => setTimeout(resolvePromise, 5_000))]);
  writeFileSync(resolve(RUN_DIR, "network.redacted.json"), `${JSON.stringify(network, null, 2)}\n`);
  writeFileSync(resolve(RUN_DIR, "results.json"), `${JSON.stringify({ runDir: RUN_DIR, shareOrigin: SHARE_ORIGIN, domain: DOMAIN, recipientDid: RECIPIENT_DID, results }, null, 2)}\n`);
  await browser.close();
}

const passed = results.filter((result) => result.ok).length;
log(`[summary] ${passed}/${results.length} assertions passed; artifacts ${RUN_DIR}`);
if (passed !== results.length) process.exitCode = 1;
