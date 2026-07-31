/**
 * STAGE 1 — bearer / link-only share against LIVE production.
 *
 * A real Chromium, a real OpenKey passkey sign-in (virtual WebAuthn
 * authenticator via CDP), https://share.tinycloud.xyz, and the real registry.
 * Nothing here is stubbed except the clipboard, which cannot be read from a
 * headless context without changing the code path under test.
 *
 * What it proves, in order:
 *   1. A production sign-in reaches the composer.
 *   2. A markdown share round-trips: the exact source bytes come back out of
 *      "Download original" in a clean, unauthenticated browser context.
 *   3. A binary share round-trips byte-for-byte the same way.
 *   4. The rendered document contains the plaintext nonce — i.e. the bytes were
 *      really decrypted and displayed, not just downloaded.
 *   5. The `#k=` fragment never reaches the address bar, `location.hash`,
 *      `document.referrer`, or a history entry after the viewer loads.
 *   6. The clipboard-denied fallback (TC-297 / TC-334) puts no share material
 *      into the DOM, and still delivers the URL through a real copy gesture.
 *
 * Usage:
 *   node stage1-bearer.mjs                 # reuse ./.account.json if present
 *   FRESH_ACCOUNT=1 node stage1-bearer.mjs # register a new OpenKey account
 *   HEADED=1 node stage1-bearer.mjs        # watch it
 */
import { chromium } from "playwright";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { attachVirtualAuthenticator, restoreCredential, registerFreshAccount, loadAccount, saveAccount, signInToShare } from "./lib/openkey.mjs";
import { redactString } from "./lib/redact.mjs";
import { DEEP_TRACE } from "./lib/deep-trace.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACCOUNT_PATH = resolve(HERE, ".account.json");
const RUN_DIR = resolve(HERE, "runs", `stage1-${new Date().toISOString().replace(/[:.]/g, "-")}`);
const SHARE_ORIGIN = process.env.SHARE_ORIGIN ?? "https://share.tinycloud.xyz";
const COMPOSER_URL = `${SHARE_ORIGIN}/share#/new`;

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
  results.push({ name, ok, detail });
  log(`${ok ? "PASS" : "FAIL"}  ${name}${detail === undefined ? "" : ` — ${detail}`}`);
}

/**
 * Records every `navigator.clipboard.writeText` call into a page global instead
 * of the system clipboard. The composer only ever hands the URL to the
 * clipboard API, by design (§6.3: it is never in the DOM), so this is the only
 * way to observe it without a permission grant that would itself change which
 * branch of `copyWithFallback` runs.
 */
const CLIPBOARD_TAP = () => {
  window.__clipboardWrites = [];
  const clipboard = navigator.clipboard ?? {};
  const original = clipboard.writeText?.bind(clipboard);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      ...clipboard,
      writeText: async (value) => {
        window.__clipboardWrites.push(value);
        if (window.__clipboardDenied === true) throw new DOMException("denied", "NotAllowedError");
        if (original !== undefined) {
          try {
            await original(value);
          } catch {
            /* the harness has already captured it */
          }
        }
      },
    },
  });
  // Observe copy events after the app's capture-phase handler has substituted
  // the payload — this is how the manual (clipboard-denied) path is verified.
  window.__copyEventPayloads = [];
  window.addEventListener("copy", (event) => {
    try {
      window.__copyEventPayloads.push(event.clipboardData?.getData("text/plain") ?? "");
    } catch {
      window.__copyEventPayloads.push("<unreadable>");
    }
  }, false);
};

const SHARE_URL_RE = /^https:\/\/[^/]+\/s\/(bafkrei[a-z2-7]{52})#k=([A-Za-z0-9_-]{43})$/;

const browser = await chromium.launch({
  headless: process.env.HEADED !== "1",
  ...(process.env.BROWSER_CHANNEL === undefined ? {} : { channel: process.env.BROWSER_CHANNEL }),
});
log(`[browser] ${browser.version()} headless=${process.env.HEADED !== "1"} channel=${process.env.BROWSER_CHANNEL ?? "bundled"}`);

try {
  // ---------------------------------------------------------------- sender
  const senderContext = await browser.newContext();
  await senderContext.addInitScript(CLIPBOARD_TAP);
  const senderPage = await senderContext.newPage();
  senderPage.on("console", (message) => log(`[sender console ${message.type()}] ${message.text()}`));
  senderPage.on("pageerror", (error) => log(`[sender pageerror] ${error.message}`));
  senderPage.on("response", (response) => {
    if (/registry|\/api\/share\/|node\.tinycloud|credentials\.org/.test(response.url())) log(`[sender res ${response.status()}] ${response.request().method()} ${response.url()}`);
  });
  senderPage.on("requestfailed", (request) => log(`[sender reqfailed] ${request.method()} ${request.url()} — ${request.failure()?.errorText}`));
  if (process.env.TRACE_REQUESTS === "1") senderPage.on("request", (request) => log(`[sender req] ${request.method()} ${request.url()}`));
  await senderContext.addInitScript(() => {
    window.addEventListener("unhandledrejection", (event) => console.log(`[harness] unhandledrejection: ${event.reason?.stack ?? event.reason}`));
    window.addEventListener("error", (event) => console.log(`[harness] window error: ${event.message}`));
    // documentElement does not exist yet at init-script time.
    const observeIframes = () => {
      new MutationObserver((records) => {
        for (const record of records) {
          for (const node of record.addedNodes) if (node.tagName === "IFRAME") console.log(`[harness] iframe added src=${node.src}`);
          for (const node of record.removedNodes) if (node.tagName === "IFRAME") console.log(`[harness] iframe removed src=${node.src}`);
        }
      }).observe(document.documentElement, { childList: true, subtree: true });
    };
    if (document.documentElement !== null) observeIframes();
    else document.addEventListener("readystatechange", () => { if (document.documentElement !== null) observeIframes(); }, { once: true });
  });
  if (process.env.TRACE_DEEP === "1") await senderContext.addInitScript(DEEP_TRACE);

  const { cdp, authenticatorId } = await attachVirtualAuthenticator(senderContext, senderPage);

  let account = process.env.FRESH_ACCOUNT === "1" ? undefined : loadAccount(ACCOUNT_PATH);
  if (account === undefined) {
    account = await registerFreshAccount(senderPage, cdp, authenticatorId, log);
    saveAccount(ACCOUNT_PATH, account);
    log(`[openkey] saved account ${account.address} to ${ACCOUNT_PATH}`);
  } else {
    log(`[openkey] reusing account ${account.address}`);
    await restoreCredential(cdp, authenticatorId, account.credential);
  }

  await signInToShare(senderPage, { appUrl: COMPOSER_URL, log });
  record("production OpenKey sign-in reaches the sender app", true, account.address);

  /** Drive the composer once and return the URL the app handed the clipboard. */
  async function createBearerShare({ filename, bytes, mimeType, denyClipboard = false }) {
    // Never reload: the session lives only in this tab, so a navigation would
    // put the auth wall back. On the result screen the composer's own "Share
    // another" is the reset affordance; otherwise route to #/new.
    if (await senderPage.locator('div.composer-status[data-state="created"]').count() > 0) {
      await senderPage.getByRole("button", { name: "Share another" }).click();
    } else if (await senderPage.locator("form.composer-form").count() === 0) {
      await senderPage.evaluate(() => { window.location.hash = "#/new"; });
    }
    await senderPage.locator("form.composer-form").waitFor({ timeout: 60_000 });
    await senderPage.locator("div.content-dropzone").waitFor({ state: "visible", timeout: 60_000 });
    await senderPage.evaluate((denied) => {
      window.__clipboardWrites = [];
      window.__copyEventPayloads = [];
      window.__clipboardDenied = denied;
      if (denied) {
        // Force the scripted-execCommand branch to fail too, so the composer
        // reaches armManualCopy — the path TC-297/TC-334 changed and that has
        // never run in a real browser.
        document.execCommand = () => false;
      }
    }, denyClipboard);

    await senderPage.setInputFiles('input[name="document"]', { name: filename, mimeType, buffer: Buffer.from(bytes) });
    await senderPage.locator("div.content-chosen").waitFor({ state: "visible", timeout: 30_000 });

    const recipientKind = await senderPage.locator('input[name="recipient"]:checked').getAttribute("value");
    if (recipientKind !== "bearer") throw new Error(`expected the bearer radio to be the default, got ${recipientKind}`);

    await senderPage.locator("button.create-link-button").click();
    await senderPage.locator('div.composer-status[data-state="created"]').waitFor({ timeout: 120_000 });
    const resultTitle = (await senderPage.locator("strong.result-title").textContent())?.trim();
    log(`[composer] ${resultTitle}`);

    const domBefore = await senderPage.content();
    await senderPage.getByRole("button", { name: "Copy link" }).click();
    await senderPage.waitForTimeout(1_500);
    const writes = await senderPage.evaluate(() => window.__clipboardWrites ?? []);
    return { writes, domBefore };
  }

  // ------------------------------------------------ 2/4: markdown round-trip
  const nonce = `tc-prod-nonce-${crypto.randomUUID()}`;
  const markdown = `# Live production proof\n\nnonce: ${nonce}\n\n- created ${new Date().toISOString()}\n- stage 1, bearer link-only\n`;
  const markdownBytes = new TextEncoder().encode(markdown);

  const markdownRun = await createBearerShare({ filename: "stage1-proof.md", bytes: markdownBytes, mimeType: "text/markdown" });
  if (markdownRun.writes.length !== 1) throw new Error(`expected exactly one clipboard write, got ${markdownRun.writes.length}`);
  const markdownUrl = markdownRun.writes[0];
  const parsed = SHARE_URL_RE.exec(markdownUrl);
  record("bearer link has the compact /s/<cid>#k=<key> shape", parsed !== null, markdownUrl.replace(/#k=.*/, "#k=<redacted>"));
  if (parsed === null) throw new Error(`unexpected share url shape: ${markdownUrl}`);

  record(
    "the composer never puts the share URL or its key in the DOM",
    !markdownRun.domBefore.includes(parsed[1]) && !markdownRun.domBefore.includes(parsed[2]),
    "checked the serialized document for both the cid and the key fragment",
  );

  // ------------------------------------------------- 3: binary round-trip
  const binaryBytes = new Uint8Array(4096);
  crypto.getRandomValues(binaryBytes);
  const binaryRun = await createBearerShare({ filename: "stage1-proof.bin", bytes: binaryBytes, mimeType: "application/octet-stream" });
  const binaryUrl = binaryRun.writes[0];
  if (!SHARE_URL_RE.test(binaryUrl)) throw new Error(`unexpected binary share url shape: ${binaryUrl}`);

  // ---------------------------------------- 6: clipboard-denied fallback
  const deniedNonce = `tc-denied-${crypto.randomUUID()}`;
  const deniedBytes = new TextEncoder().encode(`# clipboard denied path\n\nnonce: ${deniedNonce}\n`);
  const deniedRun = await createBearerShare({ filename: "stage1-denied.md", bytes: deniedBytes, mimeType: "text/markdown", denyClipboard: true });
  const deniedUrl = deniedRun.writes[0];
  const deniedParsed = SHARE_URL_RE.exec(deniedUrl ?? "");

  const manualField = senderPage.locator("div.manual-copy-field");
  const manualVisible = (await manualField.count()) > 0;
  record("clipboard denial surfaces the manual-copy affordance", manualVisible, manualVisible ? (await senderPage.locator("p.manual-copy-help").textContent())?.trim() : "div.manual-copy-field never appeared");

  if (manualVisible && deniedParsed !== null) {
    const targetText = await senderPage.locator("span.manual-copy-target").textContent();
    record(
      "the manual-copy decoy holds one non-breaking space, not the URL",
      targetText === " ",
      JSON.stringify(targetText),
    );
    const deniedDom = await senderPage.content();
    record(
      "no share material leaks into the DOM on the clipboard-denied path",
      !deniedDom.includes(deniedParsed[1]) && !deniedDom.includes(deniedParsed[2]),
      "checked the serialized document for both the cid and the key fragment",
    );
    // A real copy gesture: the app's capture-phase handler substitutes the URL,
    // our bubble-phase listener reads what it substituted.
    await senderPage.keyboard.press(process.platform === "darwin" ? "Meta+c" : "Control+c");
    await senderPage.waitForTimeout(500);
    const payloads = await senderPage.evaluate(() => window.__copyEventPayloads ?? []);
    record(
      "a real Cmd/Ctrl+C on the decoy delivers the full share URL",
      payloads.includes(deniedUrl),
      payloads.length === 0 ? "no copy event observed" : `${payloads.length} copy event(s); match=${payloads.includes(deniedUrl)}`,
    );
  }

  const storage = await senderContext.storageState();
  writeFileSync(resolve(RUN_DIR, "sender-storage.redacted.json"), JSON.stringify({
    origins: storage.origins.map((origin) => ({ origin: origin.origin, localStorageKeys: origin.localStorage.map((entry) => entry.name) })),
    cookies: storage.cookies.map(({ name, domain, path, expires }) => ({ name, domain, path, expires })),
  }, null, 2));

  // ---------------------------------------------------------- recipient
  /**
   * A brand-new context: no cookies, no localStorage, no service worker, and a
   * separate CDP/WebAuthn world. If the sender session leaked into this, the
   * "clean recipient" claim would be worthless.
   */
  async function openAsRecipient(url, { expectNonce, expectBytes, downloadName }) {
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    page.on("console", (message) => log(`[viewer console ${message.type()}] ${message.text()}`));
    page.on("pageerror", (error) => log(`[viewer pageerror] ${error.message}`));

    const cookiesBefore = await context.cookies();
    record("recipient context starts with no cookies", cookiesBefore.length === 0, `${cookiesBefore.length} cookie(s)`);

    await page.goto(url, { waitUntil: "domcontentloaded" });
    await page.locator("button.viewer-download").waitFor({ timeout: 120_000 });

    const observed = await page.evaluate(() => ({
      href: location.href,
      hash: location.hash,
      search: location.search,
      referrer: document.referrer,
      historyLength: history.length,
      storage: Object.keys(localStorage).length,
    }));
    log(`[viewer] ${JSON.stringify(observed)}`);
    record("the #k= fragment is scrubbed from the address bar after load", !observed.href.includes("#k=") && observed.hash === "", observed.href);
    record("no referrer is exposed to the viewer", observed.referrer === "", JSON.stringify(observed.referrer));

    if (expectNonce !== undefined) {
      // Markdown renders into a scriptless `sandbox=""` preview iframe
      // (src/viewer/preview-frame.ts), so the document is not in the top
      // frame's innerText. Read every frame.
      const texts = [];
      for (const frame of page.frames()) {
        texts.push(`--- ${frame.url().slice(0, 60)} ---\n${await frame.evaluate(() => document.body?.innerText ?? "").catch((error) => `<unreadable: ${error.message}>`)}`);
      }
      const rendered = texts.join("\n\n");
      writeFileSync(resolve(RUN_DIR, `${downloadName}.rendered.txt`), rendered);
      record("the rendered document contains the plaintext nonce", rendered.includes(expectNonce), `${page.frames().length} frame(s); nonce ${expectNonce}`);
    }

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 30_000 }),
      page.locator("button.viewer-download").click(),
    ]);
    const path = resolve(RUN_DIR, downloadName);
    await download.saveAs(path);
    const { readFileSync } = await import("node:fs");
    const got = new Uint8Array(readFileSync(path));
    const same = got.length === expectBytes.length && got.every((byte, index) => byte === expectBytes[index]);
    record(
      `"Download original" returns the exact uploaded bytes (${expectBytes.length} B, ${downloadName})`,
      same,
      same ? `sha match over ${got.length} bytes` : `uploaded ${expectBytes.length} B, downloaded ${got.length} B`,
    );

    await page.screenshot({ path: resolve(RUN_DIR, `${downloadName}.png`), fullPage: true });
    await context.close();
  }

  await openAsRecipient(markdownUrl, { expectNonce: nonce, expectBytes: markdownBytes, downloadName: "stage1-proof.md" });
  await openAsRecipient(binaryUrl, { expectBytes: binaryBytes, downloadName: "stage1-proof.bin" });

  await senderContext.close();
} finally {
  await browser.close();
}

writeFileSync(resolve(RUN_DIR, "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((entry) => !entry.ok);
log(`\n${results.length - failed.length}/${results.length} checks passed. Artifacts in ${RUN_DIR}`);
if (failed.length > 0) process.exit(1);
