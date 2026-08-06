/**
 * Production evidence for the two non-email addressed recipient choices.
 *
 * This intentionally does not send mail or mutate deployment configuration. It
 * uses the saved production OpenKey account and proves the incomplete domain
 * and recipient-DID modes are visibly, intentionally unavailable before any
 * share-creation side effects. Artifacts are written below runs/.
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

const browser = await chromium.launch({ headless: process.env.HEADED !== "1" });
log(`[browser] ${browser.version()} headless=${process.env.HEADED !== "1"}`);

let stopAutopilot = () => {};
try {
  const account = loadAccount(ACCOUNT_PATH);
  if (account === undefined) throw new Error(`saved OpenKey account is required at ${ACCOUNT_PATH}`);

  const senderContext = await browser.newContext();
  const senderPage = await senderContext.newPage();
  capturePage(senderPage, "sender");
  const { cdp, authenticatorId } = await attachVirtualAuthenticator(senderContext, senderPage);
  await restoreCredential(cdp, authenticatorId, account.credential);
  phase = "sender-sign-in";
  await signInToShare(senderPage, { appUrl: COMPOSER_URL, log });
  record("saved OpenKey account reaches the production composer", await senderPage.locator("form.composer-form").count() > 0, account.address);
  stopAutopilot = startOpenKeyAutopilot(senderPage, log);

  phase = "unsupported-recipient-contract";
  const addressedRequestsBefore = network.filter((entry) => entry.direction === "request" && /\/share\/v3|\/api\/share\/link-only\/registry|\/api\/share\/bindings/.test(entry.url)).length;
  const availability = await senderPage.evaluate(() => Object.fromEntries(["emailDomain", "recipientDid"].map((kind) => {
    const input = document.querySelector(`input[name="recipient"][value="${kind}"]`);
    const label = input?.closest("label");
    return [kind, {
      present: input instanceof HTMLInputElement,
      disabled: input instanceof HTMLInputElement && input.disabled,
      checked: input instanceof HTMLInputElement && input.checked,
      ariaDisabled: label?.getAttribute("aria-disabled") ?? null,
      copy: label?.textContent?.replace(/\s+/g, " ").trim() ?? "",
    }];
  })));
  await senderPage.screenshot({ path: resolve(RUN_DIR, "unsupported-recipient-options.png"), fullPage: true });
  writeFileSync(resolve(RUN_DIR, "unsupported-recipient-options.json"), `${JSON.stringify(availability, null, 2)}\n`);
  record("emailDomain is visibly and intentionally unavailable", availability.emailDomain?.present === true && availability.emailDomain.disabled === true && availability.emailDomain.checked === false && availability.emailDomain.ariaDisabled === "true" && /not available yet/i.test(availability.emailDomain.copy), JSON.stringify(availability.emailDomain));
  record("recipientDid is visibly and intentionally unavailable", availability.recipientDid?.present === true && availability.recipientDid.disabled === true && availability.recipientDid.checked === false && availability.recipientDid.ariaDisabled === "true" && /not available yet/i.test(availability.recipientDid.copy), JSON.stringify(availability.recipientDid));
  const addressedRequestsAfter = network.filter((entry) => entry.direction === "request" && /\/share\/v3|\/api\/share\/link-only\/registry|\/api\/share\/bindings/.test(entry.url)).length;
  record("unavailable recipient inspection causes no share-authority or registry side effects", addressedRequestsAfter === addressedRequestsBefore, `${addressedRequestsBefore} before, ${addressedRequestsAfter} after`);

  await senderContext.close();
} catch (error) {
  record("harness completed without an unhandled exception", false, error instanceof Error ? `${error.message}\n${error.stack ?? ""}` : String(error));
} finally {
  stopAutopilot();
  await Promise.race([Promise.allSettled([...pendingBodies]), new Promise((resolvePromise) => setTimeout(resolvePromise, 5_000))]);
  writeFileSync(resolve(RUN_DIR, "network.redacted.json"), `${JSON.stringify(network, null, 2)}\n`);
  writeFileSync(resolve(RUN_DIR, "results.json"), `${JSON.stringify({ runDir: RUN_DIR, shareOrigin: SHARE_ORIGIN, results }, null, 2)}\n`);
  await browser.close();
}

const passed = results.filter((result) => result.ok).length;
log(`[summary] ${passed}/${results.length} assertions passed; artifacts ${RUN_DIR}`);
if (passed !== results.length) process.exitCode = 1;
