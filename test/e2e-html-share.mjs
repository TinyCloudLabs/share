/**
 * Browser e2e for single-file HTML shares (TC-542). Renders fixtures through
 * presentShare in real Chromium, with the viewer CSP on the parent and the
 * artifact sandbox document served with its production frame policy. Proves:
 * bearer pages run styled with scripts; addressed HTML never executes; a
 * hostile page cannot read the viewer origin's storage, cookies, fragment or
 * TinyCloud session, navigate the top window, or make fetch/XHR/beacon/image/
 * form requests; the prerender and WebRTC gaps are recorded, not prevented;
 * navigation is refused by the bridge's frame-src
 * (after load the page is closed; before load the frame shows the browser's
 * blocked page); pages are parsed exactly as sent with no main-thread stall;
 * and the verified-bytes download survives every preview failure, including
 * a missing sandbox route.
 */
import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { mkdir } from "node:fs/promises";

import puppeteer from "puppeteer";
import { createServer } from "vite";

const screenshotDir = process.env.HTML_SHARE_SCREENSHOT_DIR ?? ".context";
const probeHits = [];
// Requests the frame is known to be able to send (recorded gaps, see docs).
const gapHits = [];
const server = await createServer({
  configFile: "vite.config.ts",
  logLevel: "error",
  server: { host: "127.0.0.1", port: 43181, strictPort: true, hmr: false },
  plugins: [{
    name: "record-isolation-probes",
    configureServer(dev) {
      // Server-side witness: any probe that leaves the browser lands here.
      dev.middlewares.use((request, response, next) => {
        const url = request.url ?? "";
        if (url.includes("/gap-")) gapHits.push({ url, headers: { ...request.headers } });
        else if (url.includes("/probe-")) probeHits.push({ url, cookie: request.headers.cookie ?? "" });
        else { next(); return; }
        response.statusCode = 204;
        response.end();
      });
    },
  }],
});
await server.listen();
// Stand-in for a sender-controlled STUN server (the recorded WebRTC gap).
const stunPackets = [];
const stun = createSocket("udp4");
stun.on("message", (message, remote) => stunPackets.push({ bytes: message.length, from: remote.address }));
await new Promise((resolve) => stun.bind(0, "127.0.0.1", resolve));
const origin = "http://127.0.0.1:43181";
const harness = `${origin}/test/fixtures/html-share/harness.html`;

async function loadHarness(browser, query, { sandboxStatus } = {}) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  // DevTools reports a request before CSP refuses it, so keep the outcome:
  // only a response means the request actually left the page.
  const requests = [];
  page.on("response", (response) => requests.push({ url: response.url(), outcome: `response ${response.status()}` }));
  page.on("requestfailed", (request) => requests.push({ url: request.url(), outcome: request.failure()?.errorText ?? "failed" }));
  if (sandboxStatus !== undefined) {
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      if (new URL(request.url()).pathname === "/artifact-sandbox.html") void request.respond({ status: sandboxStatus, contentType: "text/plain", body: "Not found" });
      else void request.continue();
    });
  }
  await page.goto(`${harness}?${query}&stun=${stun.address().port}`, { waitUntil: "load" });
  await page.waitForFunction(() => document.documentElement.dataset.ready !== undefined, { timeout: 30_000 });
  assert.equal(await page.evaluate(() => document.documentElement.dataset.ready), "yes", `${query} presented`);
  return { page, requests };
}

async function openFixture(browser, query) {
  const { page, requests } = await loadHarness(browser, query);
  const outerHandle = await page.waitForSelector("iframe.viewer-html-frame");
  assert.equal(await outerHandle.evaluate((node) => node.getAttribute("sandbox")), "allow-scripts");
  const outer = await outerHandle.contentFrame();
  const innerHandle = await outer.waitForSelector("iframe.artifact-document");
  assert.equal(await innerHandle.evaluate((node) => node.getAttribute("sandbox")), "allow-scripts");
  return { page, inner: await innerHandle.contentFrame(), requests };
}

function assertNoProbeLeft(requests, label) {
  const probes = requests.filter((entry) => entry.url.includes("/probe-"));
  assert.deepEqual(probes.filter((entry) => entry.outcome.startsWith("response")), [], `${label}: no probe request received a response`);
  assert.deepEqual(probeHits, [], `${label}: server received no probe request`);
}

async function assertPreviewClosedWithDownload(page, label) {
  await page.waitForFunction(() => document.querySelector("iframe") === null && document.querySelector(".viewer-render-error") !== null, { timeout: 10_000 });
  assert.equal(await page.$eval(".viewer-download", (node) => node.textContent), "Download original", `${label}: download stays available`);
  return page.$eval(".viewer-render-error", (node) => node.textContent);
}

let browser;
try {
  browser = await puppeteer.launch({ headless: true });
  const targets = [];
  browser.on("targetcreated", (target) => { if (target.type() === "page") targets.push(target.url()); });

  // Acceptance 1: a bearer report with CSS and a script renders styled and runs.
  {
    const { page, inner } = await openFixture(browser, "fixture=report");
    assert.equal(await page.$eval(".viewer-filename", (node) => node.textContent), "report.html");
    assert.match(await page.$eval(".viewer-html-notice", (node) => node.textContent), /comes from the sender.*WebRTC/);
    assert.equal(await page.$eval(".viewer-download", (node) => node.textContent), "Download original");
    assert.equal(await inner.$eval("#status", (node) => node.textContent), "Script ran inside the frame.");
    assert.equal(await inner.$eval("h1", (node) => getComputedStyle(node).color), "rgb(42, 86, 246)");
    assert.equal(await inner.$$eval("#metrics tbody tr", (rows) => rows.length), 3);
    await inner.click("#add");
    assert.equal(await inner.$$eval("#metrics tbody tr", (rows) => rows.length), 4);
    assert.equal(await page.content().then((html) => html.includes("Q3 agent report")), false, "page HTML never enters the viewer DOM");
    await mkdir(screenshotDir, { recursive: true });
    await page.screenshot({ path: `${screenshotDir}/html-share-desktop.png`, fullPage: true });
    await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
    await page.screenshot({ path: `${screenshotDir}/html-share-mobile.png`, fullPage: true });
    await page.close();
  }

  // Addressed links never execute HTML, even with a signed text/html type.
  {
    const { page } = await loadHarness(browser, "fixture=report&access=addressed");
    assert.equal(await page.$("iframe"), null, "addressed HTML creates no frame");
    assert.match(await page.$eval(".viewer-file-note", (node) => node.textContent), /Preview isn't available for this link type yet/);
    assert.equal(await page.$eval(".viewer-download", (node) => node.textContent), "Download original");
    await page.close();
  }

  // A missing sandbox route fails the preview but keeps the verified bytes downloadable.
  {
    const { page } = await loadHarness(browser, "fixture=report", { sandboxStatus: 404 });
    assert.match(await assertPreviewClosedWithDownload(page, "sandbox 404"), /couldn't display this document/);
    await page.close();
  }

  // Acceptance 2: the page's own scripts cannot read viewer secrets, navigate
  // the top window, open popups, or make requests as the viewer.
  const pagesBefore = targets.length;
  const { page, inner, requests } = await openFixture(browser, "fixture=hostile");
  const topUrl = page.url();
  await inner.waitForSelector("#results[data-done='yes']", { timeout: 10_000 });
  const results = JSON.parse(await inner.$eval("#results", (node) => node.textContent));
  await new Promise((resolve) => setTimeout(resolve, 1_000));

  assert.deepEqual(results.origin, { ok: true, value: "null" }, "page runs in an opaque origin");
  for (const name of ["sessionStorage", "localStorage", "cookie"]) {
    assert.equal(results[name].ok, false, `${name} is unavailable to the page`);
  }
  for (const name of ["topHash", "topHref", "topDocument", "parentDocument", "topSessionStorage", "topNavigation", "topAssign"]) {
    assert.equal(results[name].ok, false, `${name} is refused to the page`);
  }
  assert.deepEqual(results.popup, { ok: true, value: "null" }, "popups are blocked");
  for (const name of ["fetch", "xhr"]) assert.equal(results[name].ok, false, `${name} is refused`);
  // sendBeacon returns true once queued even when CSP later refuses it; the
  // probe-request witnesses below are the real check for it, the image, and the form.
  assert.deepEqual(results.eval, { ok: true, value: "42" }, "eval is available inside the frame");
  assert.ok(results.rtc !== undefined, "WebRTC probe ran");
  assert.equal(JSON.stringify(results).includes("secret"), false, "no viewer secret is observable");
  assert.equal(page.url(), topUrl, "top window did not navigate");
  assert.match(page.url(), /#tc1=fragment-secret-8c1$/);
  assert.equal(await page.$eval(".viewer-filename", (node) => node.textContent), "hostile.html");
  assert.equal(targets.length, pagesBefore + 1, "only the harness page was created; no popup window");
  assertNoProbeLeft(requests, "hostile");
  console.log(JSON.stringify(results));
  console.log(`KNOWN GAP (WebRTC, not governed by CSP): ${stunPackets.length} STUN packet(s) reached the sender-controlled listener; rtc=${results.rtc.value ?? results.rtc.error}`);

  // KNOWN GAP: <link rel="prerender"> (NoStatePrefetch) ignores the frame CSP
  // and sends a GET with page-chosen query data and the target's SameSite=Lax
  // cookies. Record that it happens; it must carry no TinyCloud credential —
  // no session key/storage value, tc1 fragment, or delegation.
  assert.deepEqual(results.prerender, { ok: true, value: "inserted" });
  const deadline = Date.now() + 10_000;
  while (gapHits.length === 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
  assert.ok(gapHits.length > 0, "prerender GET left the frame (recorded gap; if this stops happening, update docs/html-artifact-sharing.md)");
  for (const hit of gapHits) {
    assert.match(hit.url, /^\/gap-prerender\?data=page-chosen-value$/);
    const exposed = [hit.url, ...Object.values(hit.headers).flat()].join("\n");
    for (const credential of ["session-secret-8c1", "local-secret-8c1", "fragment-secret-8c1", "tc1", "delegation"]) {
      assert.equal(exposed.includes(credential), false, `prerender GET carries no ${credential}`);
    }
  }
  console.log(`KNOWN GAP (prerender, not governed by CSP): ${gapHits.length} GET(s) to ${gapHits[0].url}; purpose=${gapHits[0].headers.purpose ?? gapHits[0].headers["sec-purpose"] ?? "none"}; Lax cookie sent=${(gapHits[0].headers.cookie ?? "").includes("tc_viewer_secret")}`);
  await page.close();

  // Navigation before the first load: frame-src 'none' refuses it, so the
  // frame shows the browser's blocked-content page. Nothing leaves, and the
  // verified bytes stay downloadable.
  {
    const { page: early, requests: earlyRequests } = await loadHarness(browser, "fixture=navigate-early");
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    assert.equal(await early.$eval(".viewer-download", (node) => node.textContent), "Download original", "navigate-early: download stays available");
    assertNoProbeLeft(earlyRequests, "navigate-early");
    console.log(`navigate-early: frame present=${await early.$("iframe.viewer-html-frame") !== null}`);
    await early.close();
  }

  // The page is parsed exactly as sent: explicit <head> attributes survive.
  {
    const { page: app, inner: appInner } = await openFixture(browser, "fixture=head-attributes");
    assert.deepEqual(await appInner.evaluate(() => [document.head.id, document.head.dataset.config, document.documentElement.dataset.theme]), ["app-head", "blue", "report"]);
    assert.equal(await appInner.$eval("#config", (node) => node.textContent), "app-head:blue");
    await app.close();
  }

  // 40 leading comments and no doctype: renders with no main-thread stall over 200 ms.
  {
    const { page: commented, inner: commentedInner } = await openFixture(browser, "fixture=leading-comments");
    assert.equal(await commentedInner.$eval("#status", (node) => node.textContent), "Rendered after 40 leading comments.");
    // srcdoc documents never enter quirks mode, so only the parse result is checked.
    assert.deepEqual(await commentedInner.evaluate(() => [document.head.id, document.head.dataset.config]), ["comment-head", "green"]);
    const longTasks = await commented.evaluate(() => document.documentElement.dataset.longTasks ?? "");
    const stalls = longTasks === "" ? [] : longTasks.split(",").map(Number);
    assert.ok(stalls.every((duration) => duration <= 200), `no main-thread stall over 200 ms (long tasks: ${longTasks || "none"})`);
    await commented.close();
  }

  // Self-navigation after load is refused by the bridge's frame-src 'none'
  // (no request leaves) and the watchdog closes the page.
  {
    const { page: late, inner: lateInner, requests: lateRequests } = await openFixture(browser, "fixture=navigate-late");
    assert.equal(await lateInner.$eval("#loaded", (node) => node.textContent), "Loaded, about to navigate itself");
    assert.match(await assertPreviewClosedWithDownload(late, "navigate-late"), /tried to open another page/);
    assertNoProbeLeft(lateRequests, "navigate-late");
    const blocked = lateRequests.filter((entry) => entry.url.endsWith("/probe-self-navigation"));
    console.log(`navigate-late self-navigation outcome: ${JSON.stringify(blocked)}`);
    await late.close();
  }
  console.log("HTML share browser e2e passed");
} finally {
  await browser?.close();
  await server.close();
  stun.close();
}
