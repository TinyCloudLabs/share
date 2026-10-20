/**
 * Browser e2e: the OpenKey window must be usable while an install runs.
 *
 * The OpenKey SDK appends its window to document.body as a `position: fixed; z-index: 999999` overlay. A modal
 * `<dialog>` (opened with `showModal()`) lives in the browser's TOP LAYER, which no z-index can rise above, so a
 * sheet that stays modal while the window is open sits on top of it: every click lands on the dialog and its
 * backdrop, not on the window. This test drives the real install flow (the real SDK, the real build served with the
 * production headers) against a stand-in OpenKey that waits for a click, and proves:
 *  - after Continue the install sheet is no longer a modal dialog (`:modal` matches nothing, the dialog is not open);
 *  - the OpenKey window is what a hit test returns at its centre, at 390, 1100 and 1440 px;
 *  - a click at its centre reaches the window (the stand-in records it) and does not cancel the install;
 *  - the install's progress and result are shown inline, in a `role=status` panel under the app card, with a visible
 *    Cancel, and the page behind is not inert (a control outside the card can be focused and clicked);
 *  - Cancel and Escape end the install quietly;
 *  - axe (WCAG 2.x AA) is clean on the inline states at 390 and 1440 px, light and dark; screenshots go to
 *    APPS_WIDGET_SHOT_DIR (default .context/apps-widget).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";

import puppeteer from "puppeteer";
import { build } from "vite";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";

const shotDir = process.env.APPS_WIDGET_SHOT_DIR ?? ".context/apps-widget";
const axeSource = await readFile(new URL("../node_modules/axe-core/axe.min.js", import.meta.url), "utf8");
const catalog = JSON.parse(await readFile(new URL("../apps/catalog.json", import.meta.url), "utf8"));
const rules = parseProductionHeaders(await readFile(new URL("../public/_headers", import.meta.url), "utf8"));
const redirects = (await readFile(new URL("../public/_redirects", import.meta.url), "utf8")).split("\n").filter(Boolean).map((line) => line.split(/\s+/));
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".md": "text/markdown", ".sql": "text/plain" };
const APP = "xyz.tinycloud.sample.healthlog";

/** A stand-in for OpenKey's embedded window: ready at once, then one big button that waits for a click. It never answers by itself. */
const STAND_IN = `<!doctype html><meta charset="utf-8"><title>OpenKey stand-in</title>
<body style="margin:0;background:#fff"><button id="approve" style="display:block;width:100%;height:100vh;font:600 22px sans-serif;background:#e9efff;border:0">Approve (stand-in)</button>
<script>
const target = "*";
let asked = false;
parent.postMessage({ type: "openkey:ready" }, target);
addEventListener("message", (event) => { if (event.data?.type === "openkey:auth:request") asked = true; });
document.getElementById("approve").addEventListener("click", () => {
  parent.postMessage({ type: "stand-in:clicked" }, target);
  if (asked) parent.postMessage({ type: "openkey:auth:response", success: true, address: "0x5555555555555555555555555555555555555555", keyId: "stand-in-key", keyType: "MANAGED" }, target);
});
</script>`;

const outDir = await mkdtemp(join(tmpdir(), "apps-widget-e2e-"));
await build({ configFile: "vite.config.ts", logLevel: "error", build: { outDir, emptyOutDir: true } });
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
  } catch { response.writeHead(404).end("not found"); }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

async function axeViolations(page) {
  await page.evaluate(axeSource);
  const result = await page.evaluate(() => globalThis.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } }));
  return result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")}`);
}

async function openPage(browser, { width, height, scheme }) {
  const page = await browser.newPage();
  page.report = { requests: [], errors: [] };
  await page.setViewport({ width, height, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
  await page.evaluateOnNewDocument(() => {
    globalThis.__violations = [];
    globalThis.__standInClicks = 0;
    document.addEventListener("securitypolicyviolation", (event) => globalThis.__violations.push(`${event.violatedDirective} ${event.blockedURI}`));
    addEventListener("message", (event) => { if (event.data?.type === "stand-in:clicked") globalThis.__standInClicks += 1; });
  });
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const url = new URL(request.url());
    page.report.requests.push(url.origin + url.pathname);
    if (url.origin === origin || url.protocol === "data:" || url.protocol === "blob:") { void request.continue(); return; }
    // The stand-in answers for OpenKey; every other host is refused, so nothing here can reach a real service.
    if (url.origin === "https://openkey.so" && url.pathname.startsWith("/widget/")) { void request.respond({ status: 200, contentType: "text/html; charset=utf-8", body: STAND_IN }); return; }
    void request.abort("blockedbyclient");
  });
  page.on("pageerror", (error) => page.report.errors.push(String(error)));
  await page.goto(`${origin}/apps`, { waitUntil: "networkidle0" });
  return page;
}

const cardIndex = catalog.apps.findIndex((app) => app.app_id === APP);

/** Opens the install sheet for the Health Log card and waits until Continue is offered. */
async function openSheet(page) {
  await page.evaluate((index) => document.querySelectorAll(".apps-card")[index].querySelectorAll("button")[1].click(), cardIndex);
  await page.waitForFunction(() => [...document.querySelectorAll("#apps-sheet button")].some((button) => button.textContent === "Continue" && !button.disabled), { timeout: 60_000 });
}

/** Where the OpenKey window's card is: centred on a wide screen, a bottom sheet on a phone (its own layout). */
const windowPoint = (width, height) => (width <= 480 ? [width / 2, height - 120] : [width / 2, height / 2]);

/** What a hit test returns inside the OpenKey window's card, and whether it is the sheet or the OpenKey window's host. */
const hitAtCentre = (page, point) => page.evaluate(([x, y]) => {
  const hit = document.elementFromPoint(x, y);
  const dialog = document.querySelector("#apps-sheet");
  return {
    tag: hit?.tagName ?? null,
    id: hit?.id ?? "",
    inSheet: hit === dialog || dialog?.contains(hit) === true,
    isBodyChild: hit?.parentElement === document.body,
    sheetOpen: dialog?.open === true,
    modal: document.querySelector(":modal")?.id ?? null,
  };
}, point);

async function waitForWidget(page) {
  const found = await page.waitForFunction(() => [...document.body.children].some((child) => child.tagName === "DIV" && child.id === "" && child.attributes.length === 0), { timeout: 60_000 }).then(() => true, () => false);
  assert.ok(found, `the OpenKey window never appeared (requests: ${page.report.requests.filter((url) => /openkey/.test(url)).join(",")}; errors: ${JSON.stringify(page.report.errors)})`);
  // The stand-in's own request is the proof the window is really on the page.
  await page.waitForFunction(() => performance.getEntriesByType("resource").some((entry) => entry.name.startsWith("https://openkey.so/widget/")), { timeout: 30_000 });
}

const statusLine = (page) => page.$eval(".apps-install-panel .apps-install-line", (node) => node.textContent).catch(() => "");

let browser;
const results = {};
try {
  browser = await puppeteer.launch({ headless: true });

  // ---- The window is usable, at three widths: it is what a click reaches, and the click does not cancel the install.
  for (const [width, height] of [[1440, 900], [1100, 800], [390, 844]]) {
    const label = `${width}px`;
    const page = await openPage(browser, { width, height, scheme: "light" });
    await openSheet(page);
    assert.equal((await hitAtCentre(page, windowPoint(width, height))).modal, "apps-sheet", `${label}: the sheet is modal before Continue (the baseline of this test)`);
    await page.evaluate(() => [...document.querySelectorAll("#apps-sheet footer button")].find((button) => button.textContent === "Continue").click());
    await waitForWidget(page);

    const point = windowPoint(width, height);
    const hit = await hitAtCentre(page, point);
    // The hit test is the user's experience: what a click at the window's centre would land on.
    assert.equal(hit.inSheet, false, `${label}: a hit test at the OpenKey window's centre returns the install sheet (${hit.tag}${hit.id === "" ? "" : `#${hit.id}`}), not the window: the window is behind the dialog (modal: ${hit.modal}, sheet open: ${hit.sheetOpen})`);
    assert.equal(hit.isBodyChild, true, `${label}: a hit test at the window's centre returns ${hit.tag}, not the OpenKey window's container`);
    assert.equal(hit.modal, null, `${label}: a modal dialog (${hit.modal}) is still in the top layer, above the OpenKey window`);
    assert.equal(hit.sheetOpen, false, `${label}: the install sheet is still open after Continue`);

    // OpenKey's card slides in (250 ms); a click during the animation would land on its backdrop, not the card.
    await new Promise((done) => setTimeout(done, 900));
    // A click at the centre reaches the window, and nothing about the install is cancelled by it.
    await page.mouse.click(...point);
    await page.waitForFunction(() => globalThis.__standInClicks >= 1, { timeout: 15_000 }).catch(() => undefined);
    assert.ok((await page.evaluate(() => globalThis.__standInClicks)) >= 1, `${label}: a click at the window's centre never reached the window`);
    const after = await statusLine(page);
    assert.ok(!/cancel/i.test(after), `${label}: the click cancelled the install ("${after}")`);
    assert.ok(await page.$(".apps-install-panel"), `${label}: the inline progress panel is gone after the click`);
    await page.close();
    results[label] = { hit: `${hit.tag}`, clicked: true };
  }

  // ---- The inline panel: a live region under the card, a visible Cancel, focus in the panel, the page behind not inert.
  {
    const page = await openPage(browser, { width: 1440, height: 900, scheme: "light" });
    await openSheet(page);
    await page.evaluate(() => [...document.querySelectorAll("#apps-sheet footer button")].find((button) => button.textContent === "Continue").click());
    await waitForWidget(page);
    const panel = await page.evaluate((index) => {
      const card = document.querySelectorAll(".apps-card")[index];
      const node = card.querySelector(".apps-install-panel");
      const status = node?.querySelector(".apps-install-status");
      const cancel = [...(node?.querySelectorAll("button") ?? [])].find((button) => button.textContent === "Cancel");
      return {
        underCard: node !== null && card.contains(node),
        role: node?.getAttribute("role") ?? status?.getAttribute("role") ?? status?.getAttribute("aria-live") ?? null,
        text: node?.querySelector(".apps-install-line")?.textContent ?? "",
        cancelVisible: cancel !== undefined && cancel.getBoundingClientRect().width > 0,
        inert: document.querySelector("main")?.closest("[inert]") !== null,
        outsideFocusable: (() => { const link = document.querySelector(".apps-nav a"); link.focus(); return document.activeElement === link; })(),
      };
    }, cardIndex);
    assert.ok(panel.underCard, "the progress panel is under the app card");
    assert.match(panel.text, /^(Checking|Opening OpenKey|Approve in the OpenKey window to install Health Log \(sample\)\. A new account may ask a few times\.)$/, `the panel shows progress ("${panel.text}")`);
    assert.ok(["status", "polite"].includes(panel.role), `the panel is a status live region (${panel.role})`);
    assert.ok(panel.cancelVisible, "a visible Cancel");
    assert.equal(panel.inert, false, "the page behind is not inert");
    assert.ok(panel.outsideFocusable, "a control outside the card can take focus while the window is up");
    // Cancel ends the install quietly and the panel says so.
    await page.evaluate(() => [...document.querySelectorAll(".apps-install-panel button")].find((button) => button.textContent === "Cancel").click());
    await page.waitForFunction(() => /Install cancelled/.test(document.querySelector(".apps-install-panel .apps-install-line")?.textContent ?? ""), { timeout: 15_000 });
    assert.equal(await page.$$eval(".apps-install-panel [role=alert]", (nodes) => nodes.length), 0, "a cancel is a quiet note, not an alert");
    assert.equal(await page.$eval("#apps-sheet", (dialog) => dialog.open), false);
    results.panel = { text: panel.text, cancelled: true };
    await page.close();
  }

  // ---- Escape cancels from the panel.
  {
    const page = await openPage(browser, { width: 1440, height: 900, scheme: "light" });
    await openSheet(page);
    await page.evaluate(() => [...document.querySelectorAll("#apps-sheet footer button")].find((button) => button.textContent === "Continue").click());
    await waitForWidget(page);
    await page.evaluate(() => document.querySelector(".apps-install-panel").focus());
    await page.keyboard.press("Escape");
    await page.waitForFunction(() => /Install cancelled/.test(document.querySelector(".apps-install-panel .apps-install-line")?.textContent ?? ""), { timeout: 15_000 });
    results.escape = true;
    await page.close();
  }

  // ---- Axe and layout on the inline states, 390 / 1440, light / dark.
  await mkdir(shotDir, { recursive: true });
  for (const scheme of ["light", "dark"]) for (const [width, height] of [[390, 844], [1440, 900]]) {
    const page = await openPage(browser, { width, height, scheme });
    await openSheet(page);
    await page.evaluate(() => [...document.querySelectorAll("#apps-sheet footer button")].find((button) => button.textContent === "Continue").click());
    await waitForWidget(page);
    // Hide the stand-in so the card (and its panel) can be read and shot; the window itself is not what is checked here.
    await page.evaluate(() => { for (const child of document.body.children) if (child.tagName === "DIV" && child.id === "" && child.attributes.length === 0) child.style.display = "none"; });
    await page.waitForFunction(() => document.querySelector(".apps-install-panel .apps-install-line") !== null);
    assert.deepEqual(await axeViolations(page), [], `${width}px ${scheme}: inline progress axe AA`);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${width}px ${scheme}: no horizontal scroll`);
    assert.ok(await page.$$eval(".apps-install-panel button", (nodes) => nodes.every((node) => node.getBoundingClientRect().height >= 43.5)), `${width}px ${scheme}: 44px targets in the panel`);
    await page.$eval(".apps-install-panel", (node) => node.scrollIntoView({ block: "center" }));
    await page.screenshot({ path: join(shotDir, `inline-progress-${width}-${scheme}.png`) });
    await page.evaluate(() => [...document.querySelectorAll(".apps-install-panel button")].find((button) => button.textContent === "Cancel").click());
    await page.waitForFunction(() => /Install cancelled/.test(document.querySelector(".apps-install-panel .apps-install-line")?.textContent ?? ""));
    assert.deepEqual(await axeViolations(page), [], `${width}px ${scheme}: inline cancelled state axe AA`);
    await page.screenshot({ path: join(shotDir, `inline-cancelled-${width}-${scheme}.png`) });
    assert.deepEqual(await page.evaluate(() => globalThis.__violations), [], `${width}px ${scheme}: no CSP or Trusted Types violation`);
    await page.close();
  }
  console.log(`apps widget layer e2e ok ${JSON.stringify(results)}; screenshots in ${shotDir}`);
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
  await rm(outDir, { recursive: true, force: true });
}
