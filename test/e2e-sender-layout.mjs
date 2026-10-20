/**
 * Browser e2e for the sender screens (library and composer) in the states a
 * jsdom test cannot judge: layout and contrast. The real screens run against
 * fakes for OpenKey and the node (test/fixtures/sender-layout/harness.ts).
 *
 * For every state below, at 390 and 1440 px, in light and dark:
 *  - the page does not scroll sideways (`scrollWidth <= innerWidth`);
 *  - axe (WCAG 2.x A/AA and best practices) finds nothing.
 * The states are the ones a sender can be left looking at: the revoke approval
 * waiting, slow, cancelled or failed; the status check running, timed out or
 * unconfirmed; a created link with its expiry line; the longest error copy.
 *
 * SENDER_LAYOUT_SCREENSHOT_DIR sets where a screenshot of each state is written
 * (default: none).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import puppeteer from "puppeteer";
import { createServer } from "vite";

const screenshotDir = process.env.SENDER_LAYOUT_SCREENSHOT_DIR;
const axeSource = await readFile(new URL("../node_modules/axe-core/axe.min.js", import.meta.url), "utf8");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

const freePort = async () => {
  const listener = httpServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  return port;
};
const port = Number(process.env.SENDER_LAYOUT_PORT ?? await freePort());
const origin = `http://127.0.0.1:${port}`;
const server = await createServer({ configFile: "vite.config.ts", logLevel: "error", server: { host: "127.0.0.1", port, strictPort: true, hmr: false } });
await server.listen();

const files = await mkdtemp(join(tmpdir(), "sender-layout-"));
const artifact = join(files, "page.html");
await writeFile(artifact, "<h1>hi</h1>");
if (screenshotDir !== undefined) await mkdir(screenshotDir, { recursive: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const click = (page, selector) => page.evaluate((query) => { const node = document.querySelector(query); if (node === null) throw new Error(`missing ${query}`); node.click(); }, selector);
const waitFor = (page, selector, text) => page.waitForFunction((query, expected) => {
  const node = document.querySelector(query);
  return node !== null && !node.hidden && (expected === undefined || node.textContent.includes(expected));
}, { timeout: 10_000 }, selector, text);
const advance = (page, ms) => page.evaluate((delta) => window.__qa.advance(delta), ms);
const revokeHtmlRow = async (page) => { await click(page, 'button[aria-label^="Revoke quarterly"]'); await waitFor(page, ".sender-confirm-dialog"); };
const confirmRevoke = (page) => click(page, ".sender-confirm-dialog .sender-confirm-revoke");
const pickBearerAndFile = async (page) => {
  const input = await page.$("input[type=file]");
  await input.uploadFile(artifact);
  await waitFor(page, ".content-chosen-kind", "Artifact");
  await click(page, "input[name=recipient][value=bearer]");
};
const createLink = (page) => click(page, "button[type=submit]");

/** name, query, and what to do once the harness is ready. */
const STATES = [
  ["library-ready", "screen=library&reader=ok", (page) => waitFor(page, ".sender-freshness", "Statuses confirmed")],
  ["library-expired-by-node", "screen=library&reader=expired", async (page) => {
    await waitFor(page, ".sender-freshness", "Statuses confirmed");
    const text = await page.$eval('button[aria-label^="Revoke quarterly"]', (node) => node.closest("tr").querySelector(".status-expiry").textContent);
    assert.equal(text, "Expired", "a node-expired share shows no saved date");
  }],
  ["library-checking", "screen=library&reader=hang", (page) => waitFor(page, ".sender-freshness", "Checking each share")],
  ["library-status-timeout", "screen=library&reader=hang", async (page) => {
    await waitFor(page, ".sender-freshness", "Checking each share");
    await advance(page, 4000);
    await waitFor(page, ".sender-freshness", "may be out of date");
    assert.equal(await page.$eval(".sender-recheck", (node) => node.textContent), "Check again");
    assert.equal(await page.$eval(".sender-recheck", (node) => node.disabled), false);
  }],
  ["library-unconfirmed", "screen=library&reader=fail", (page) => waitFor(page, ".sender-freshness", "may be out of date")],
  ["library-confirm", "screen=library&reader=ok", async (page) => { await waitFor(page, ".sender-freshness", "Statuses confirmed"); await revokeHtmlRow(page); }],
  ["library-approval", "screen=library&reader=ok&revoke=hang", async (page) => {
    await waitFor(page, ".sender-freshness", "Statuses confirmed");
    await revokeHtmlRow(page); await confirmRevoke(page);
    await waitFor(page, ".sender-approval .sender-row-hint", "Approve in the OpenKey window to revoke");
  }],
  ["library-approval-slow", "screen=library&reader=ok&revoke=hang", async (page) => {
    await waitFor(page, ".sender-freshness", "Statuses confirmed");
    await revokeHtmlRow(page); await confirmRevoke(page);
    await waitFor(page, ".sender-approval");
    await advance(page, 15_000);
    await waitFor(page, ".sender-approval-more", "behind this tab");
  }],
  ["library-approval-cancelled", "screen=library&reader=ok&revoke=hang", async (page) => {
    await waitFor(page, ".sender-freshness", "Statuses confirmed");
    await revokeHtmlRow(page); await confirmRevoke(page);
    await waitFor(page, ".sender-approval");
    await click(page, ".sender-approval-cancel");
    await waitFor(page, ".sender-row-note", "cancelled");
  }],
  ["library-revoke-error", "screen=library&reader=ok&revoke=fail-listing", async (page) => {
    await waitFor(page, ".sender-freshness", "Statuses confirmed");
    await revokeHtmlRow(page); await confirmRevoke(page);
    await waitFor(page, ".sender-row-error", "whole permissions list");
  }],
  ["composer-empty", "screen=composer", (page) => waitFor(page, ".content-dropzone")],
  ["composer-artifact", "screen=composer&create=hang", pickBearerAndFile],
  ["composer-approval", "screen=composer&create=hang", async (page) => {
    await pickBearerAndFile(page); await createLink(page);
    await waitFor(page, ".sender-approval-line", "Approve in the OpenKey window");
  }],
  ["composer-approval-slow", "screen=composer&create=hang", async (page) => {
    await pickBearerAndFile(page); await createLink(page);
    await waitFor(page, ".sender-approval-line");
    await advance(page, 15_000);
    await waitFor(page, ".sender-approval-more", "behind this tab");
  }],
  ["composer-approval-timeout", "screen=composer&create=hang", async (page) => {
    await pickBearerAndFile(page); await createLink(page);
    await waitFor(page, ".sender-approval-line");
    await advance(page, 60_000);
    await waitFor(page, ".sender-approval-more", "still waiting");
  }],
  ["composer-cancelled", "screen=composer&create=hang", async (page) => {
    await pickBearerAndFile(page); await createLink(page);
    await waitFor(page, ".sender-approval-cancel");
    await click(page, ".sender-approval-cancel");
    await waitFor(page, ".sender-status", "Approval cancelled");
  }],
  ["composer-error", "screen=composer&create=fail", async (page) => {
    await pickBearerAndFile(page); await createLink(page);
    await waitFor(page, ".sender-status", "SPACE_NOT_READY");
  }],
  ["composer-result", "screen=composer&create=ok", async (page) => {
    await pickBearerAndFile(page); await createLink(page);
    await waitFor(page, ".result-expiry", "Works until");
  }],
  ["composer-result-domain", "screen=composer&create=ok", async (page) => {
    const input = await page.$("input[type=file]");
    await input.uploadFile(artifact);
    await waitFor(page, ".content-chosen-kind", "Artifact");
    await click(page, "input[name=recipient][value=emailDomain]");
    await page.type(".recipient-value", "a-very-long-company-domain-name.example.invalid");
    await createLink(page);
    await waitFor(page, ".result-expiry", "Works until");
  }],
];

const VIEWPORTS = [[390, 844], [1440, 900]];
const SCHEMES = ["light", "dark"];
const failures = [];

async function check(browser, [width, height], scheme, [name, query, drive]) {
  const label = `${name} ${width}px ${scheme}`;
  const page = await browser.newPage();
  const problems = [];
  page.on("pageerror", (error) => problems.push(`page error: ${String(error?.message ?? error)}`));
  try {
    await page.setViewport({ width, height, deviceScaleFactor: 1 });
    await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
    await page.goto(`${origin}/test/fixtures/sender-layout/harness.html?${query}`, { waitUntil: "load" });
    await page.waitForFunction(() => document.documentElement.dataset.ready === "yes", { timeout: 30_000 });
    await drive(page);
    await sleep(150);
    const sideways = await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth }));
    if (sideways.scrollWidth > sideways.innerWidth) problems.push(`scrolls sideways: scrollWidth ${sideways.scrollWidth} > ${sideways.innerWidth}`);
    await page.evaluate(axeSource);
    const result = await page.evaluate((tags) => globalThis.axe.run(document, { runOnly: { type: "tag", values: tags } }), AXE_TAGS);
    for (const violation of result.violations) problems.push(`axe ${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")} (${violation.help})`);
    if (screenshotDir !== undefined) await page.screenshot({ path: join(screenshotDir, `${name}-${width}-${scheme}.png`), fullPage: true });
  } catch (error) {
    problems.push(`could not reach the state: ${String(error?.message ?? error)}`);
  } finally {
    await page.close();
  }
  for (const problem of problems) failures.push(`${label}: ${problem}`);
}

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
try {
  for (const viewport of VIEWPORTS) for (const scheme of SCHEMES) for (const state of STATES) await check(browser, viewport, scheme, state);
} finally {
  await browser.close();
  await server.close();
  await rm(files, { recursive: true, force: true });
}
assert.deepEqual(failures, [], `sender layout and contrast:\n${failures.join("\n")}`);
console.log(`sender layout: ${STATES.length} states x ${VIEWPORTS.length} widths x ${SCHEMES.length} schemes: no sideways scroll, axe clean`);
