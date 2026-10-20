/**
 * Browser e2e for the /apps catalog page, against a production build served
 * with the real public/_headers and public/_redirects. Proves:
 *  - /apps and /apps/ list every catalog entry in cards, each with Install (the install sheets are checked here; the install itself runs in test/e2e-prod/install-gate.mjs);
 *  - the page loads no SDK chunk, makes no request off this origin, and its
 *    only data request is a manifest under /apps/b/<digest>/ after Details is
 *    opened; no CSP or Trusted Types violation fires;
 *  - the detail sheet shows what the app can read and change from the
 *    manifest's descriptions, and shows nothing of a manifest whose bytes do
 *    not match the catalog's sha256;
 *  - Escape closes the sheet and returns focus to Details;
 *  - at 390 and 1440 px, light and dark: no horizontal scroll, 44px targets,
 *    axe WCAG 2.x AA clean on the list and with the sheet open;
 *  - screenshots (APPS_SCREENSHOT_DIR, default .context/apps-page).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";

import puppeteer from "puppeteer";
import { build } from "vite";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";

const screenshotDir = process.env.APPS_SCREENSHOT_DIR ?? ".context/apps-page";
const axeSource = await readFile(new URL("../node_modules/axe-core/axe.min.js", import.meta.url), "utf8");
const catalog = JSON.parse(await readFile(new URL("../apps/catalog.json", import.meta.url), "utf8"));
const rules = parseProductionHeaders(await readFile(new URL("../public/_headers", import.meta.url), "utf8"));
const redirects = (await readFile(new URL("../public/_redirects", import.meta.url), "utf8")).split("\n").filter(Boolean).map((line) => line.split(/\s+/));

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".md": "text/markdown", ".sql": "text/plain" };

/** Builds the site (optionally with a different catalog compiled in) and serves it with the real headers and redirects. */
async function buildAndServe(catalogOverride) {
  const outDir = await mkdtemp(join(tmpdir(), "apps-e2e-"));
  await build({ configFile: "vite.config.ts", logLevel: "error", build: { outDir, emptyOutDir: true }, ...(catalogOverride === undefined ? {} : { resolve: { alias: { "../../apps/catalog.json": catalogOverride } } }) });
  const server = httpServer(async (request, response) => {
    let path = new URL(request.url, "http://x").pathname;
    for (const [from, to, status] of redirects) {
      if (status === "200" && (from === path || (from.endsWith("*") && path.startsWith(from.slice(0, -1))))) { path = to; break; }
    }
    if (path.endsWith("/")) path += "index.html";
    const file = normalize(join(outDir, path));
    try {
      if (!file.startsWith(outDir) || !(await stat(file)).isFile()) throw new Error("not a file");
      response.writeHead(200, { ...productionHeadersForPath(rules, new URL(request.url, "http://x").pathname), "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
      response.end(await readFile(file));
    } catch {
      response.writeHead(404).end("not found");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, close: async () => { await new Promise((resolve) => server.close(resolve)); await rm(outDir, { recursive: true, force: true }); } };
}

const main = await buildAndServe();
const origin = main.origin;

async function axeViolations(page) {
  await page.evaluate(axeSource);
  const result = await page.evaluate(() => globalThis.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } }));
  return result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")} (${violation.help})`);
}

/** A page with violation, request and console recorders installed before any script runs. */
async function open(browser, path, { width, height = 900, scheme, base = origin }) {
  const page = await browser.newPage();
  page.report = { violations: [], requests: [], errors: [] };
  await page.setViewport({ width, height, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
  await page.evaluateOnNewDocument(() => {
    globalThis.__violations = [];
    document.addEventListener("securitypolicyviolation", (event) => globalThis.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  page.on("request", (request) => page.report.requests.push(request.url()));
  page.on("pageerror", (error) => page.report.errors.push(String(error)));
  page.on("console", (message) => { if (message.type() === "error") page.report.errors.push(message.text()); });
  await page.goto(`${base}${path}`, { waitUntil: "networkidle0" });
  return page;
}

async function shoot(page, name) {
  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: `${screenshotDir}/${name}.png` });
}

const sheetOpen = (page) => page.$eval("#apps-sheet", (node) => node.open);

let browser;
try {
  browser = await puppeteer.launch({ headless: true });

  for (const scheme of ["light", "dark"]) {
    for (const width of [390, 1440]) {
      const label = `${width}px ${scheme}`;
      const page = await open(browser, "/apps", { width, scheme });
      assert.equal(await page.title(), "Apps · TinyCloud Sharing");
      assert.equal(await page.$eval("h1", (node) => node.textContent), "Apps for your TinyCloud");

      const cards = await page.$$eval(".apps-card", (nodes) => nodes.map((node) => ({ name: node.querySelector("h2").textContent, install: node.querySelector("button[aria-describedby='install-note']").disabled })));
      assert.deepEqual(cards.map((card) => card.name), catalog.apps.map((app) => app.name), `${label}: one card per catalog entry`);
      assert.ok(cards.every((card) => !card.install), `${label}: Install is enabled`);
      assert.equal(await page.$eval("html", (node) => getComputedStyle(node).colorScheme), scheme, `${label}: follows the OS scheme`);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label}: no horizontal scroll`);
      const small = await page.$$eval(".apps-nav a, .apps-wordmark, .apps-button", (nodes) => nodes.filter((node) => node.getBoundingClientRect().height < 43.5).map((node) => node.textContent));
      assert.deepEqual(small, [], `${label}: 44px targets`);
      assert.deepEqual(await axeViolations(page), [], `${label}: list axe AA`);
      await shoot(page, `apps-list-${width}-${scheme}`);

      // Nothing but this page's own static files so far.
      const before = page.report.requests.map((url) => new URL(url));
      assert.ok(before.every((url) => url.origin === origin), `${label}: same origin only`);
      assert.deepEqual(before.filter((url) => url.pathname.startsWith("/apps/b/")), [], `${label}: no manifest fetched until Details opens`);

      // Details: sheet with the manifest's own words.
      await page.focus(".apps-card .tc-button:not([disabled])");
      await page.keyboard.press("Enter");
      await page.waitForFunction(() => document.querySelector("#apps-sheet [aria-busy]") === null && document.querySelector("#apps-sheet h3") !== null);
      assert.equal(await sheetOpen(page), true, `${label}: sheet opens`);
      const sheetText = await page.$eval("#apps-sheet", (node) => node.innerText);
      for (const expected of ["It can read", "It can change", "Everything the app has stored in its own folder (default grant).", "com.example.notes/*", "See which permissions it has been given", "Where it comes from", catalog.apps[0].bundle.digest, "You'll see what it asks for before anything is saved."]) {
        assert.ok(sheetText.includes(expected), `${label}: sheet shows "${expected}"`);
      }
      assert.equal(await page.$eval("#apps-sheet footer button", (node) => node.disabled), false, `${label}: sheet Install is enabled`);
      assert.ok(await page.evaluate(() => { const s = document.querySelector("#apps-sheet"); return s.scrollWidth <= s.clientWidth; }), `${label}: sheet has no horizontal scroll`);
      assert.deepEqual(await axeViolations(page), [], `${label}: sheet axe AA`);
      await shoot(page, `apps-sheet-${width}-${scheme}`);
      // The lower half: provenance rows and the pinned-file list, expanded.
      await page.click(".apps-files summary");
      await page.$eval(".apps-sheet__body", (node) => { node.scrollTop = node.scrollHeight; });
      assert.deepEqual(await axeViolations(page), [], `${label}: sheet (files expanded) axe AA`);
      await shoot(page, `apps-sheet-bottom-${width}-${scheme}`);

      const manifestRequests = page.report.requests.map((url) => new URL(url)).filter((url) => url.pathname.startsWith("/apps/b/"));
      assert.deepEqual(manifestRequests.map((url) => url.pathname), [`${catalog.apps[0].bundle.root}manifest.json`], `${label}: the only data request is the pinned manifest`);
      assert.ok(page.report.requests.every((url) => new URL(url).origin === origin), `${label}: same origin only after Details`);
      assert.ok(page.report.requests.every((url) => !/sdk|openkey|wasm/i.test(new URL(url).pathname)), `${label}: no SDK or wasm chunk loaded`);

      await page.keyboard.press("Escape");
      assert.equal(await sheetOpen(page), false, `${label}: Escape closes the sheet`);
      assert.equal(await page.evaluate(() => document.activeElement?.textContent), "Details", `${label}: focus returns to Details`);

      // Install: the pre-consent sheet for a plain app, a sample that writes SQL, and a sample that reads another app. Nothing is signed or loaded from the SDK by opening it.
      const installCases = [
        { app: catalog.apps.find((app) => app.app_id === "com.example.notes"), tag: "notes", expect: ["This app can change or delete its own tables.", "What this sign-in allows", "com.example.notes/app/", "com.example.notes/knowledge/", "None of this is granted now.", "Opening installed apps is coming next."], absent: ["Sample app: use throwaway data only."] },
        { app: catalog.apps.find((app) => app.app_id === "xyz.tinycloud.sample.healthlog"), tag: "sample", expect: ["Sample app: use throwaway data only.", "This app can change or delete its own tables."], absent: [] },
        { app: catalog.apps.find((app) => app.app_id === "xyz.tinycloud.sample.recipes"), tag: "cross-app", expect: ["Sample app: use throwaway data only.", "This app can read Health Log (sample)'s database (whole database)."], absent: [] },
      ];
      for (const { app, tag, expect: wanted, absent } of installCases) {
        const index = catalog.apps.indexOf(app);
        await page.evaluate((position) => document.querySelectorAll(".apps-card")[position].querySelectorAll("button")[1].click(), index);
        await page.waitForFunction(() => document.querySelector("#apps-sheet [aria-busy]") === null && [...document.querySelectorAll("#apps-sheet button")].some((button) => button.textContent === "Continue" && !button.disabled)).catch(async (error) => {
          throw new Error(`${label} ${tag}: the install sheet never became ready: ${(await page.$eval("#apps-sheet", (node) => node.innerText).catch(() => "no sheet")).slice(0, 300)} | errors ${JSON.stringify(page.report.errors)} | violations ${JSON.stringify(await page.evaluate(() => globalThis.__violations))}`, { cause: error });
        });
        const installText = await page.$eval("#apps-sheet", (node) => node.innerText);
        assert.ok(installText.includes(`Install ${app.name} to your TinyCloud`), `${label} ${tag}: titled`);
        for (const expected of wanted) assert.ok(installText.includes(expected), `${label} ${tag}: shows "${expected}"`);
        for (const unexpected of absent) assert.ok(!installText.includes(unexpected), `${label} ${tag}: does not show "${unexpected}"`);
        assert.deepEqual(await page.$$eval("#apps-sheet footer button", (nodes) => nodes.map((node) => node.textContent)), ["Continue", "Not now"], `${label} ${tag}: Continue and Not now`);
        assert.ok(await page.evaluate(() => { const s = document.querySelector("#apps-sheet"); return s.scrollWidth <= s.clientWidth; }), `${label} ${tag}: no horizontal scroll`);
        assert.deepEqual(await axeViolations(page), [], `${label} ${tag}: install sheet axe AA`);
        await shoot(page, `install-sheet-${tag}-${width}-${scheme}`);
        await page.click("#apps-sheet .apps-files summary");
        await page.$eval(".apps-sheet__body", (node) => { node.scrollTop = node.scrollHeight; });
        assert.deepEqual(await axeViolations(page), [], `${label} ${tag}: install sheet (account list expanded) axe AA`);
        await shoot(page, `install-sheet-${tag}-bottom-${width}-${scheme}`);
        await page.evaluate(() => document.querySelector("#apps-sheet footer button:last-child").click()); // Not now
        assert.equal(await sheetOpen(page), false, `${label} ${tag}: Not now closes the sheet`);
      }
      assert.ok(page.report.requests.every((url) => new URL(url).origin === origin), `${label}: still same origin only after the install sheets`);
      assert.ok(page.report.requests.every((url) => !/sdk|openkey|wasm/i.test(new URL(url).pathname)), `${label}: opening the install sheet loads no SDK or wasm chunk`);

      assert.deepEqual(await page.evaluate(() => globalThis.__violations), [], `${label}: no CSP or Trusted Types violation`);
      assert.deepEqual(page.report.errors, [], `${label}: no console or page errors`);
      await page.close();
    }
  }

  // The directory form and the landing nav.
  {
    const page = await open(browser, "/apps/", { width: 1440, scheme: "light" });
    assert.equal(await page.$eval("h1", (node) => node.textContent), "Apps for your TinyCloud");
    assert.equal(await page.$eval(".apps-nav a[aria-current='page']", (node) => node.textContent), "apps");
    await page.close();
    const landing = await open(browser, "/", { width: 1440, scheme: "light" });
    assert.equal(await landing.$eval(".primary-nav a[href='/apps/']", (node) => node.textContent), "apps");
    await landing.close();
  }

  // A manifest whose bytes differ from the catalog's sha256 is never shown.
  {
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900 });
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      if (new URL(request.url()).pathname.endsWith("/manifest.json")) {
        request.respond({ status: 200, contentType: "application/json", body: JSON.stringify({ app_id: "com.example.notes", name: "Notes", description: "Tampered.", permissions: [{ service: "tinycloud.kv", path: "x", actions: ["get"], description: "Tampered grant." }] }) });
      } else request.continue();
    });
    await page.goto(`${origin}/apps`, { waitUntil: "networkidle0" });
    await page.click(".apps-card .tc-button:not([disabled])");
    await page.waitForSelector("#apps-sheet [role=alert]");
    const text = await page.$eval("#apps-sheet", (node) => node.innerText);
    assert.ok(text.includes("doesn't match the catalog"), "mismatch is stated");
    assert.ok(!text.includes("Tampered") && !text.includes("It can read"), "none of the tampered manifest is shown");
    await page.close();
  }

  // The kill switch: the same site built with the Health Log entry switched off. Card, sheets, axe and screenshots.
  {
    const switched = structuredClone(catalog);
    const target = switched.apps.find((app) => app.app_id === "xyz.tinycloud.sample.healthlog");
    target.disabled = true;
    target.disabledReason = "Pulled while a problem with saved meals is looked into. Your data is not affected.";
    const file = join(await mkdtemp(join(tmpdir(), "apps-e2e-catalog-")), "catalog.json");
    await writeFile(file, JSON.stringify(switched));
    const off = await buildAndServe(file);
    try {
      for (const scheme of ["light", "dark"]) for (const width of [390, 1440]) {
        const label = `kill switch ${width}px ${scheme}`;
        const page = await open(browser, "/apps", { width, scheme, base: off.origin });
        const index = switched.apps.indexOf(target);
        const card = await page.evaluate((position) => { const node = document.querySelectorAll(".apps-card")[position]; return { text: node.textContent, install: node.querySelectorAll("button")[1].disabled, details: node.querySelectorAll("button")[0].disabled }; }, index);
        assert.ok(card.text.includes("Temporarily unavailable") && card.text.includes(target.disabledReason), `${label}: the card says why`);
        assert.equal(card.install, true, `${label}: Install is disabled`);
        assert.equal(card.details, false, `${label}: Details still opens`);
        assert.equal(await page.$$eval(".apps-card", (nodes) => nodes.filter((node) => node.querySelectorAll("button")[1].disabled).length), 1, `${label}: only that card is off`);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label}: no horizontal scroll`);
        assert.deepEqual(await axeViolations(page), [], `${label}: card axe AA`);
        await shoot(page, `kill-switch-list-${width}-${scheme}`);
        await page.evaluate((position) => document.querySelectorAll(".apps-card")[position].querySelectorAll("button")[0].click(), index);
        await page.waitForFunction(() => document.querySelector("#apps-sheet [aria-busy]") === null && document.querySelector("#apps-sheet h3") !== null);
        const detail = await page.$eval("#apps-sheet", (node) => ({ text: node.innerText, install: [...node.querySelectorAll("footer button")][0].disabled }));
        assert.ok(detail.text.includes("Temporarily unavailable") && detail.install, `${label}: the details sheet says so and Install is disabled`);
        assert.deepEqual(await axeViolations(page), [], `${label}: details sheet axe AA`);
        await shoot(page, `kill-switch-sheet-${width}-${scheme}`);
        assert.ok(page.report.requests.every((url) => !/sdk|openkey|wasm/i.test(new URL(url).pathname)), `${label}: no SDK chunk loaded`);
        assert.deepEqual(await page.evaluate(() => globalThis.__violations), [], `${label}: no CSP or Trusted Types violation`);
        assert.deepEqual(page.report.errors, [], `${label}: no console or page errors`);
        await page.close();
      }
    } finally {
      await off.close();
    }
  }

  console.log(`apps page e2e ok; screenshots in ${screenshotDir}`);
} finally {
  await browser?.close();
  await main.close();
}
