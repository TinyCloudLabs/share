/**
 * Browser e2e: the OpenKey window must be usable while an app opens from its runner page.
 *
 * The runner page (`/apps/run#<app_id>`) shows the first-open disclosure on its start screen, before any sign-in.
 * Continue starts the open: the OpenKey SDK appends its window to document.body as a `position: fixed; z-index:
 * 999999` overlay. A modal `<dialog>` (opened with `showModal()`) lives in the browser's TOP LAYER, which no z-index
 * can rise above, so a dialog left open over the page would sit on top of the window and every click would land on
 * the dialog and its backdrop. The runner shows the open's progress and result inline, in its own `role=status`
 * region with a Cancel, and never opens a dialog. This test drives the real runner flow (the real SDK, the real build
 * served with the production headers) against a stand-in OpenKey that waits for a click, and proves:
 *  - the start screen shows the first-open disclosure, and no OpenKey window or request exists before Continue;
 *  - after Continue no modal dialog is open over the page (`:modal` matches nothing, no dialog is open);
 *  - the OpenKey window is what a hit test returns at its centre, at 390, 1100 and 1440 px;
 *  - a click at its centre reaches the window (the stand-in records it) and does not cancel the open;
 *  - the open's progress is shown inline in a `role=status` region, and the page behind is not inert (a control
 *    outside the stage can be focused and clicked);
 *  - Cancel and Escape end the open quietly (no `role=alert`);
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
/** The first-open disclosure line on the start screen (src/apps/first-open.ts). */
const DISCLOSURE = "If this app isn't in your TinyCloud, we'll save its files as part of opening it.";
/** The status line while the open waits on its first approval (or just before it). */
const PROGRESS = /^(Opening Health Log…|Approve in the OpenKey window \(1 of 2\) so Share can read Health Log from your TinyCloud)/;

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

/** Opens the runner page for the Health Log app, at the start screen. */
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
  await page.goto(`${origin}/apps/run#${APP}`, { waitUntil: "networkidle0" });
  return page;
}

/** Waits for the start screen's Continue button, then presses it. */
async function pressContinue(page) {
  await page.waitForFunction(() => [...document.querySelectorAll(".run-stage button")].some((button) => button.textContent === "Continue" && !button.disabled), { timeout: 60_000 });
  await page.evaluate(() => [...document.querySelectorAll(".run-stage button")].find((button) => button.textContent === "Continue").click());
}

/** Where the OpenKey window's card is: centred on a wide screen, a bottom sheet on a phone (its own layout). */
const windowPoint = (width, height) => (width <= 480 ? [width / 2, height - 120] : [width / 2, height / 2]);

/** What a hit test returns at a point, and whether that is inside the OpenKey window; also whether any dialog is open. */
const hitAtCentre = (page, point) => page.evaluate(([x, y]) => {
  const hit = document.elementFromPoint(x, y);
  const overlay = [...document.body.children].find((child) => child.tagName === "DIV" && child.id === "" && child.attributes.length === 0);
  return {
    tag: hit?.tagName ?? null,
    id: hit?.id ?? "",
    inWindow: overlay !== undefined && hit !== null && (hit === overlay || overlay.contains(hit)),
    dialogOpen: [...document.querySelectorAll("dialog")].some((dialog) => dialog.open),
    modal: document.querySelector(":modal")?.tagName ?? null,
  };
}, point);

/** Hides the stand-in so the page behind (and its status) can be read and shot; the window itself is checked elsewhere. */
const hideWindow = (page) => page.evaluate(() => {
  for (const child of document.body.children) if (child.tagName === "DIV" && child.id === "" && child.attributes.length === 0) child.style.display = "none";
});

async function waitForWidget(page) {
  const found = await page.waitForFunction(() => [...document.body.children].some((child) => child.tagName === "DIV" && child.id === "" && child.attributes.length === 0), { timeout: 60_000 }).then(() => true, () => false);
  assert.ok(found, `the OpenKey window never appeared (requests: ${page.report.requests.filter((url) => /openkey/.test(url)).join(",")}; errors: ${JSON.stringify(page.report.errors)})`);
  // The stand-in's own request is the proof the window is really on the page.
  await page.waitForFunction(() => performance.getEntriesByType("resource").some((entry) => entry.name.startsWith("https://openkey.so/widget/")), { timeout: 30_000 });
}

const statusText = (page) => page.$eval(".run-status-region .run-status-line", (node) => node.textContent).catch(() => "");

let browser;
const results = {};
try {
  browser = await puppeteer.launch({ headless: true });

  // ---- The start screen shows the disclosure and no OpenKey window; after Continue the window is usable, at three widths.
  for (const [width, height] of [[1440, 900], [1100, 800], [390, 844]]) {
    const label = `${width}px`;
    const page = await openPage(browser, { width, height, scheme: "light" });
    await page.waitForFunction(() => document.querySelector(".apps-notes li") !== null, { timeout: 60_000 });
    const notes = await page.$$eval(".apps-notes li", (nodes) => nodes.map((node) => node.textContent ?? ""));
    assert.ok(notes.includes(DISCLOSURE), `${label}: the start screen shows the first-open disclosure (${JSON.stringify(notes)})`);
    assert.equal(await page.evaluate(() => [...document.body.children].some((child) => child.tagName === "DIV" && child.id === "" && child.attributes.length === 0)), false, `${label}: an OpenKey window exists before Continue`);
    assert.equal(page.report.requests.some((url) => url.startsWith("https://openkey.so/")), false, `${label}: OpenKey was contacted before Continue`);

    await pressContinue(page);
    await waitForWidget(page);

    const point = windowPoint(width, height);
    const hit = await hitAtCentre(page, point);
    // The hit test is the user's experience: what a click at the window's centre would land on.
    assert.equal(hit.inWindow, true, `${label}: a hit test at the OpenKey window's centre returns ${hit.tag}${hit.id === "" ? "" : `#${hit.id}`}, not the window (modal: ${hit.modal}, dialog open: ${hit.dialogOpen})`);
    assert.equal(hit.modal, null, `${label}: a modal dialog (${hit.modal}) is in the top layer, above the OpenKey window`);
    assert.equal(hit.dialogOpen, false, `${label}: a dialog is open over the page after Continue`);

    // OpenKey's card slides in (250 ms); a click during the animation would land on its backdrop, not the card.
    await new Promise((done) => setTimeout(done, 900));
    // A click at the centre reaches the window, and nothing about the open is cancelled by it.
    await page.mouse.click(...point);
    await page.waitForFunction(() => globalThis.__standInClicks >= 1, { timeout: 15_000 }).catch(() => undefined);
    assert.ok((await page.evaluate(() => globalThis.__standInClicks)) >= 1, `${label}: a click at the window's centre never reached the window`);
    const after = await statusText(page);
    assert.ok(!/cancel/i.test(after), `${label}: the click cancelled the open ("${after}")`);
    await page.close();
    results[label] = { hit: hit.tag, clicked: true };
  }

  // ---- The inline status: a live region with the progress, and the page behind it is not inert.
  {
    const page = await openPage(browser, { width: 1440, height: 900, scheme: "light" });
    await pressContinue(page);
    await waitForWidget(page);
    const behind = await page.evaluate(() => {
      const region = document.querySelector(".run-status-region");
      const link = [...document.querySelectorAll(".run-actions a")].find((node) => node.textContent === "Open another app");
      if (link === undefined) return null;
      link.addEventListener("click", (event) => { event.preventDefault(); globalThis.__behindClicked = true; });
      link.focus();
      const focused = document.activeElement === link;
      link.click();
      return {
        role: region?.getAttribute("role") ?? null,
        text: region?.textContent ?? "",
        focused,
        clicked: globalThis.__behindClicked === true,
        inert: document.querySelector("[inert]") !== null,
      };
    });
    assert.ok(behind, "a control outside the stage (Open another app) exists");
    assert.equal(behind.role, "status", "the progress is in a role=status region");
    assert.match(behind.text, PROGRESS, "the status region shows the open's progress");
    assert.equal(behind.inert, false, "the page behind is not inert");
    assert.ok(behind.focused, "a control outside the stage can take focus while the window is up");
    assert.ok(behind.clicked, "a control outside the stage can be clicked while the window is up");
    results.status = { text: behind.text };
    await page.close();
  }

  // ---- Axe and layout on the inline progress, 390 / 1440, light / dark.
  await mkdir(shotDir, { recursive: true });
  for (const scheme of ["light", "dark"]) for (const [width, height] of [[390, 844], [1440, 900]]) {
    const label = `${width}px ${scheme}`;
    const page = await openPage(browser, { width, height, scheme });
    await pressContinue(page);
    await waitForWidget(page);
    await hideWindow(page);
    await page.waitForFunction(() => document.querySelector(".run-status-region .run-status") !== null);
    assert.deepEqual(await axeViolations(page), [], `${label}: inline progress axe AA`);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label}: no horizontal scroll`);
    assert.ok(await page.$$eval(".run-actions a, .run-actions button", (nodes) => nodes.length > 0 && nodes.every((node) => node.getBoundingClientRect().height >= 43.5)), `${label}: 44px targets in the app bar`);
    await page.$eval(".run-status-region", (node) => node.scrollIntoView({ block: "center" }));
    await page.screenshot({ path: join(shotDir, `inline-progress-${width}-${scheme}.png`) });
    assert.deepEqual(await page.evaluate(() => globalThis.__violations), [], `${label}: no CSP or Trusted Types violation`);
    await page.close();
  }

  // ---- Cancel and Escape end the open quietly. The runner's Cancel sits beside the status region, not inside it.
  {
    const page = await openPage(browser, { width: 1440, height: 900, scheme: "light" });
    await pressContinue(page);
    await waitForWidget(page);
    const cancel = await page.evaluate(() => {
      const button = [...document.querySelectorAll(".run-status-cancel button")].find((node) => node.textContent === "Cancel");
      return button === undefined ? null : button.getBoundingClientRect().width > 0;
    });
    assert.equal(cancel, true, "a visible Cancel beside the status region while the OpenKey window is open");
    await page.evaluate(() => [...document.querySelectorAll(".run-status-cancel button")].find((button) => button.textContent === "Cancel").click());
    await page.waitForFunction(() => /Sign-in cancelled/.test(document.querySelector(".run-screen__title")?.textContent ?? ""), { timeout: 15_000 });
    assert.equal(await page.$$eval("#runner [role=alert]", (nodes) => nodes.length), 0, "a cancel is a quiet note, not an alert");
    results.cancel = true;
    await page.close();
  }

  // ---- Escape cancels from the status region.
  {
    const page = await openPage(browser, { width: 1440, height: 900, scheme: "light" });
    await pressContinue(page);
    await waitForWidget(page);
    await page.evaluate(() => [...document.querySelectorAll(".run-status-cancel button")].find((button) => button.textContent === "Cancel").focus());
    await page.keyboard.press("Escape");
    await page.waitForFunction(() => /Sign-in cancelled/.test(document.querySelector(".run-screen__title")?.textContent ?? ""), { timeout: 15_000 });
    assert.equal(await page.$$eval("#runner [role=alert]", (nodes) => nodes.length), 0, "an Escape cancel is a quiet note, not an alert");
    results.escape = true;
    await page.close();
  }

  // ---- Axe on the cancelled state, 390 / 1440, light / dark.
  for (const scheme of ["light", "dark"]) for (const [width, height] of [[390, 844], [1440, 900]]) {
    const label = `${width}px ${scheme}`;
    const page = await openPage(browser, { width, height, scheme });
    await pressContinue(page);
    await waitForWidget(page);
    await hideWindow(page);
    await page.evaluate(() => [...document.querySelectorAll(".run-status-cancel button")].find((button) => button.textContent === "Cancel").click());
    await page.waitForFunction(() => /Sign-in cancelled/.test(document.querySelector(".run-screen__title")?.textContent ?? ""), { timeout: 15_000 });
    assert.deepEqual(await axeViolations(page), [], `${label}: cancelled state axe AA`);
    await page.screenshot({ path: join(shotDir, `inline-cancelled-${width}-${scheme}.png`) });
    assert.deepEqual(await page.evaluate(() => globalThis.__violations), [], `${label}: no CSP or Trusted Types violation`);
    await page.close();
  }

  console.log(`apps widget layer e2e ok ${JSON.stringify(results)}; screenshots in ${shotDir}`);
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
  await rm(outDir, { recursive: true, force: true });
}
