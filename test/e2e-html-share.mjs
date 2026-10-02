/**
 * Browser e2e for single-file HTML shares (TC-542). Renders fixtures through
 * presentShare in real Chromium, with the viewer CSP on the parent and the
 * artifact sandbox document served with its production frame policy, then
 * proves the page runs styled with scripts and cannot reach the viewer
 * origin's storage, cookies, fragment, top window, or network.
 */
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";

import puppeteer from "puppeteer";
import { createServer } from "vite";

const screenshotDir = process.env.HTML_SHARE_SCREENSHOT_DIR ?? ".context";
const probeHits = [];
const server = await createServer({
  configFile: "vite.config.ts",
  logLevel: "error",
  server: { host: "127.0.0.1", port: 43181, strictPort: true, hmr: false },
  plugins: [{
    name: "record-isolation-probes",
    configureServer(dev) {
      // Server-side witness: any probe that leaves the browser lands here.
      dev.middlewares.use((request, response, next) => {
        if (!(request.url ?? "").includes("/probe-")) { next(); return; }
        probeHits.push({ url: request.url, cookie: request.headers.cookie ?? "" });
        response.statusCode = 204;
        response.end();
      });
    },
  }],
});
await server.listen();
const origin = "http://127.0.0.1:43181";
const harness = `${origin}/test/fixtures/html-share/harness.html`;

async function openFixture(browser, query) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  // DevTools reports a request before CSP refuses it, so keep the outcome:
  // only a response means the request actually left the page.
  const requests = [];
  page.on("response", (response) => requests.push({ url: response.url(), outcome: `response ${response.status()}` }));
  page.on("requestfailed", (request) => requests.push({ url: request.url(), outcome: request.failure()?.errorText ?? "failed" }));
  await page.goto(`${harness}?${query}`, { waitUntil: "load" });
  await page.waitForFunction(() => document.documentElement.dataset.ready !== undefined, { timeout: 20_000 });
  assert.equal(await page.evaluate(() => document.documentElement.dataset.ready), "yes", `${query} rendered`);
  const outerHandle = await page.waitForSelector("iframe.viewer-html-frame");
  assert.equal(await outerHandle.evaluate((node) => node.getAttribute("sandbox")), "allow-scripts");
  const outer = await outerHandle.contentFrame();
  const innerHandle = await outer.waitForSelector("iframe.artifact-document");
  assert.equal(await innerHandle.evaluate((node) => node.getAttribute("sandbox")), "allow-scripts");
  return { page, inner: await innerHandle.contentFrame(), requests };
}

let browser;
try {
  browser = await puppeteer.launch({ headless: true });
  const popups = [];
  browser.on("targetcreated", (target) => { if (target.type() === "page") popups.push(target.url()); });

  // Acceptance 1: a report with CSS and a script renders styled and runs, for
  // a bearer link (key extension) and an addressed link (signed text/html).
  for (const access of ["bearer", "addressed"]) {
    const { page, inner } = await openFixture(browser, `fixture=report&access=${access}`);
    assert.equal(await page.$eval(".viewer-filename", (node) => node.textContent), "report.html");
    assert.match(await page.$eval(".viewer-html-notice", (node) => node.textContent), /comes from the sender/);
    assert.equal(await page.$eval(".viewer-download", (node) => node.textContent), "Download original");
    assert.equal(await inner.$eval("#status", (node) => node.textContent), "Script ran inside the frame.");
    assert.equal(await inner.$eval("h1", (node) => getComputedStyle(node).color), "rgb(42, 86, 246)");
    assert.equal(await inner.$$eval("#metrics tbody tr", (rows) => rows.length), 3);
    await inner.click("#add");
    assert.equal(await inner.$$eval("#metrics tbody tr", (rows) => rows.length), 4);
    assert.equal(await page.content().then((html) => html.includes("Q3 agent report")), false, "page HTML never enters the viewer DOM");
    if (access === "bearer") {
      await mkdir(screenshotDir, { recursive: true });
      await page.screenshot({ path: `${screenshotDir}/html-share-desktop.png`, fullPage: true });
      await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
      await page.screenshot({ path: `${screenshotDir}/html-share-mobile.png`, fullPage: true });
    }
    await page.close();
  }

  // Acceptance 2: the page's own scripts cannot read viewer secrets, navigate
  // the top window, open popups, or make requests as the viewer.
  const pagesBefore = popups.length;
  const { page, inner, requests } = await openFixture(browser, "fixture=hostile");
  const topUrl = page.url();
  await inner.waitForSelector("#results[data-done='yes']", { timeout: 10_000 });
  const results = JSON.parse(await inner.$eval("#results", (node) => node.textContent));
  await new Promise((resolve) => setTimeout(resolve, 1_000));

  assert.deepEqual(results.origin, { ok: true, value: "null" }, "page runs in an opaque origin");
  for (const name of ["sessionStorage", "localStorage", "cookie"]) {
    assert.equal(results[name].ok, false, `${name} is unavailable to the page`);
  }
  for (const name of ["topHash", "topHref", "topDocument", "parentDocument", "topSessionStorage"]) {
    assert.equal(results[name].ok, false, `${name} is cross-origin to the page`);
  }
  assert.deepEqual(results.popup, { ok: true, value: "null" }, "popups are blocked");
  for (const name of ["fetch", "xhr"]) assert.equal(results[name].ok, false, `${name} is refused`);
  // sendBeacon returns true once queued even when CSP later refuses it; the
  // probe-request witnesses below are the real check for it, the image, and the form.
  assert.equal(JSON.stringify(results).includes("secret"), false, "no viewer secret is observable");
  assert.equal(page.url(), topUrl, "top window did not navigate");
  assert.match(page.url(), /#tc1=fragment-secret-8c1$/);
  assert.equal(await page.$eval(".viewer-filename", (node) => node.textContent), "hostile.html");
  assert.equal(popups.length, pagesBefore + 1, "only the harness page was created; no popup window");
  const probes = requests.filter((entry) => entry.url.includes("/probe-"));
  assert.deepEqual(probes.filter((entry) => entry.outcome.startsWith("response")), [], "no probe request received a response");
  console.log(JSON.stringify(probes));
  assert.deepEqual(probeHits, [], "server received no probe request");
  console.log(JSON.stringify(results));
  console.log("HTML share browser e2e passed");
} finally {
  await browser?.close();
  await server.close();
}
