/**
 * Browser e2e for the /courier screens in the states a jsdom test cannot
 * judge: layout, contrast and the rendered markdown frames. The real screens,
 * styles and markdown renderer run against a fake mailbox and a fake sign-in
 * (test/fixtures/courier-layout/harness.ts).
 *
 * For every state below, at 390 and 1440 px, in light and dark:
 *  - the page does not scroll sideways (`scrollWidth <= innerWidth`);
 *  - axe (WCAG 2.x A/AA and best practices) finds nothing;
 *  - a screenshot is written when COURIER_LAYOUT_SCREENSHOT_DIR is set.
 *
 * It also proves the approval flow in a real browser: hostile text stays text,
 * Approve writes one create-only decision file with the request hash, a second
 * click writes nothing, and the thread's markdown arrives in sandboxed frames
 * with the remote image blocked.
 */
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { createServer as httpServer } from "node:http";

import puppeteer from "puppeteer";
import { createServer } from "vite";

const screenshotDir = process.env.COURIER_LAYOUT_SCREENSHOT_DIR;
const axeSource = await readFile(new URL("../node_modules/axe-core/axe.min.js", import.meta.url), "utf8");
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

const freePort = async () => {
  const listener = httpServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  return port;
};
const port = await freePort();
const origin = `http://127.0.0.1:${port}`;
const server = await createServer({ configFile: "vite.config.ts", logLevel: "error", server: { host: "127.0.0.1", port, strictPort: true, hmr: false } });
await server.listen();
if (screenshotDir !== undefined) await mkdir(screenshotDir, { recursive: true });

const click = (page, selector) => page.evaluate((query) => { const node = document.querySelector(query); if (node === null) throw new Error(`missing ${query}`); node.click(); }, selector);
const waitFor = (page, selector, text) => page.waitForFunction((query, expected) => {
  const node = document.querySelector(query);
  return node !== null && !node.hidden && (expected === undefined || node.textContent.includes(expected));
}, { timeout: 15_000 }, selector, text);
const tab = (page, name) => page.evaluate((label) => { [...document.querySelectorAll("[role=tab]")].find((node) => node.textContent.startsWith(label)).click(); }, name);

async function axeViolations(page) {
  await page.evaluate(axeSource);
  const result = await page.evaluate((tags) => globalThis.axe.run(document, { runOnly: { type: "tag", values: tags } }), AXE_TAGS);
  return result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")} (${violation.help})`);
}

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
const problems = [];
const violations = [];
const consoleErrors = [];

async function check(page, name, scheme, width) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  if (overflow > 0) problems.push(`${name} @${width} ${scheme}: scrolls sideways by ${overflow}px`);
  for (const line of await axeViolations(page)) violations.push(`${name} @${width} ${scheme}: ${line}`);
  if (screenshotDir !== undefined) await page.screenshot({ path: `${screenshotDir}/${name}-${width}-${scheme}.png`, fullPage: true });
}

/** Scrolls the whole page so every lazily rendered frame is built, then waits for the frames. */
async function renderAllFrames(page, expected) {
  await page.evaluate(async () => {
    for (let y = 0; y < document.body.scrollHeight; y += 400) { window.scrollTo(0, y); await new Promise((resolve) => setTimeout(resolve, 60)); }
    window.scrollTo(0, 0);
  });
  await page.waitForFunction((count) => document.querySelectorAll(".cr-body iframe").length >= count, { timeout: 20_000 }, expected);
  await new Promise((resolve) => setTimeout(resolve, 800));
}

try {
  for (const scheme of ["light", "dark"]) {
    for (const width of [390, 1440]) {
      const page = await browser.newPage();
      page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`));
      page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
      await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
      await page.setViewport({ width, height: 900 });
      const go = async (state = "full") => {
        await page.goto(`${origin}/test/fixtures/courier-layout/harness.html?state=${state}`, { waitUntil: "networkidle0" });
        await waitFor(page, ".auth-button");
      };
      const signIn = async () => { await click(page, ".auth-button"); await waitFor(page, ".cr-tabs"); await page.waitForFunction(() => document.querySelector(".cr-panel")?.getAttribute("aria-busy") === "false"); };

      await go();
      await check(page, "signed-out", scheme, width);

      await signIn();
      await waitFor(page, ".cr-row-button");
      await check(page, "threads", scheme, width);

      await click(page, ".cr-row-button");
      await waitFor(page, ".cr-thread-content .cr-timeline");
      await renderAllFrames(page, 3);
      const frames = await page.evaluate(() => [...document.querySelectorAll(".cr-body iframe")].map((frame) => ({ sandbox: frame.getAttribute("sandbox"), title: frame.title, html: frame.srcdoc })));
      assert.ok(frames.length >= 3, `the thread's bodies render in frames (${frames.length})`);
      for (const frame of frames) assert.equal(frame.sandbox, "", "every body frame is fully sandboxed");
      const handoff = frames.find((frame) => frame.html.includes("Handoff to Sam"));
      assert.ok(handoff, "the handoff markdown rendered");
      assert.ok(!/<img[^>]+src=["']?https?:/i.test(handoff.html) && handoff.html.includes("viewer-blocked-image"), "the remote image is replaced by the blocked-image notice, never loaded");
      await check(page, "thread", scheme, width);

      await go();
      await signIn();
      await tab(page, "Needs you");
      await waitFor(page, ".cr-request");
      await page.waitForFunction(() => document.querySelector(".cr-approve")?.disabled === false, { timeout: 5_000 });
      const cards = await page.evaluate(() => [...document.querySelectorAll(".cr-request")].map((card) => ({ line: card.querySelector(".cr-consequence")?.textContent ?? null, buttons: card.querySelectorAll("button").length, warning: card.querySelector(".tc-status--warning")?.textContent ?? null })));
      assert.equal(cards.length, 4, "two reviewable and two unreviewable requests are pending");
      const unreviewableCards = cards.filter((card) => card.line === null);
      assert.equal(unreviewableCards.length, 2);
      assert.ok(unreviewableCards.every((card) => card.buttons === 0), "a request that can't be reviewed has no buttons");
      assert.ok(unreviewableCards.some((card) => /doesn't say what it would approve/.test(card.warning)) && unreviewableCards.some((card) => /too long or holds characters you can't see/.test(card.warning)), "each says why");
      const hiddenShown = await page.evaluate(() => document.body.textContent.includes("\u27E6U+E0061\u27E7"));
      assert.ok(hiddenShown, "text that can't be seen is made visible");
      // Nothing a card holds may draw outside it or over its buttons.
      const containment = await page.evaluate(() => { const style = getComputedStyle(document.querySelector(".cr-request")); const quote = getComputedStyle(document.querySelector(".cr-peer-text")); return [style.overflow, style.contain, quote.overflow, quote.contain]; });
      assert.deepEqual([containment[0], containment[2]], ["hidden", "hidden"]);
      assert.ok(containment[1].includes("paint") && containment[3].includes("paint"));
      const rtl = await page.evaluate(() => { const bdi = [...document.querySelectorAll(".cr-consequence bdi")].find((node) => /[\u0590-\u05FF]/.test(node.textContent)); return bdi ? { parent: bdi.parentElement.className, isolate: getComputedStyle(bdi).unicodeBidi, target: getComputedStyle(bdi.parentElement.querySelector("code")).direction } : null; });
      assert.deepEqual(rtl, { parent: "cr-consequence", isolate: "isolate", target: "ltr" }, "right-to-left text sits in its own isolate");
      assert.match(cards.find((card) => card.line?.includes("merge tinycloudlabs/eliza#20")).line, /^Approving lets hunter's agent merge tinycloudlabs\/eliza#20: /, "the card says what is approved, from the structured fields");
      await page.type(".cr-note-input", "Docs only. Go ahead.");
      await check(page, "needs-you", scheme, width);

      if (scheme === "light" && width === 1440) {
        await page.focus(".cr-approve");
        await page.keyboard.press("Enter");
        await page.keyboard.press("Enter");
        await waitFor(page, ".cr-result", "Approved.");
        const written = await page.evaluate(() => window.__qa.approvals);
        assert.equal(written.length, 1, "one decision file, whatever the clicks");
        assert.deepEqual(Object.keys(written[0]).sort(), ["decidedAt", "decision", "note", "requestHash", "requestId"]);
        assert.equal(written[0].decision, "approved");
        assert.match(written[0].requestHash, /^[0-9a-f]{64}$/);
        assert.equal(written[0].note, "Docs only. Go ahead.");
        await check(page, "needs-you-decided", scheme, width);
      }

      await go();
      await signIn();
      await tab(page, "Orders");
      await page.waitForFunction(() => document.querySelector(".cr-orders-input")?.value.includes("Standing orders"));
      await check(page, "orders", scheme, width);

      await go("empty");
      await signIn();
      await check(page, "empty", scheme, width);

      await go("nospace");
      await signIn();
      await waitFor(page, ".tc-status--danger");
      await check(page, "no-mailbox", scheme, width);
      await page.close();
    }
  }
} finally {
  await browser.close();
  await server.close();
}

const real = consoleErrors.filter((line) => !/Failed to load resource.*(404|net::ERR)/.test(line));
for (const line of problems) console.error(line);
for (const line of violations) console.error(line);
for (const line of real) console.error(`console: ${line}`);
assert.deepEqual([...problems, ...violations], [], "layout and accessibility findings");
assert.deepEqual(real, [], "no console errors or page errors");
console.log("courier layout: ok");
