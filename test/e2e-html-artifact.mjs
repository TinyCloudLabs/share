import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";

import puppeteer from "puppeteer";

const port = 43179;
const origin = `http://127.0.0.1:${port}`;
const screenshotDir = process.env.ARTIFACT_SCREENSHOT_DIR ?? ".context";
const server = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", String(port), "--strictPort"], {
  stdio: ["ignore", "pipe", "pipe"],
});

async function waitForServer() {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`Vite exited with ${server.exitCode}`);
    try {
      const response = await fetch(`${origin}/test/fixtures/html-artifact-harness.html`);
      if (response.ok) return;
    } catch {
      // Server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Timed out waiting for the artifact browser harness");
}

let browser;
try {
  await waitForServer();
  browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
  const consoleText = [];
  page.on("console", (message) => consoleText.push(message.text()));
  page.on("pageerror", (error) => consoleText.push(String(error?.message ?? error)));
  await page.goto(`${origin}/test/fixtures/html-artifact-harness.html`, { waitUntil: "networkidle0" });
  await page.waitForFunction(() => document.documentElement.dataset.ready === "yes");

  const outer = await page.waitForSelector("iframe.viewer-artifact-frame");
  const outerFrame = await outer.contentFrame();
  assert(outerFrame, "outer sandbox frame should exist");
  await outerFrame.waitForSelector("iframe.artifact-document");
  const innerHandle = await outerFrame.$("iframe.artifact-document");
  const inner = await innerHandle.contentFrame();
  assert(inner, "inner opaque-origin artifact frame should exist");

  assert.equal(await inner.$eval("h1", (node) => node.textContent), "Small signals, shared safely.");
  assert.equal(await inner.$eval("#isolation", (node) => node.textContent), "Sandbox isolation confirmed.");
  assert.ok(await inner.$eval(".mark", (node) => node instanceof HTMLImageElement && node.complete && node.naturalWidth > 0));
  await inner.click("#count");
  assert.equal(await inner.$eval("#count span", (node) => node.textContent), "1");
  assert.equal(await inner.evaluate(async () => {
    try {
      await fetch("https://example.com/network-must-be-blocked");
      return false;
    } catch {
      return true;
    }
  }), true);
  assert.equal(await inner.evaluate(() => {
    try {
      void parent.document.body;
      return false;
    } catch {
      return true;
    }
  }), true);

  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), false);
  // The fake link secret planted by the harness lives only in the Copy link closure.
  await page.click(".artifact-chrome-button:not(.artifact-chrome-hide)");
  await page.waitForFunction(() => window.__copied === 1);
  const SECRET = "FAKE-LINK-SECRET-8c1";
  const surfaces = {
    "page HTML and attributes": await page.content(),
    "outer frame HTML and attributes": await outerFrame.content(),
    "title": await page.title(),
    "address bar": page.url(),
    "history state": JSON.stringify(await page.evaluate(() => history.state)),
    "storage": JSON.stringify(await page.evaluate(() => ({ ...localStorage, ...sessionStorage }))),
    "frame URLs": [page.url(), outerFrame.url(), inner.url()].join("\n"),
    "console": consoleText.join("\n"),
  };
  for (const [name, text] of Object.entries(surfaces)) assert.equal(text.includes(SECRET) || text.includes("tc1=FAKE"), false, `the link secret appears in the ${name}`);
  assert.equal(await page.evaluate(() => location.hash), "", "the harness scrubbed the fragment like main.ts");
  await page.click(".artifact-chrome-hide");
  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), true);
  assert.equal(await page.$eval(".artifact-chrome-pill", (node) => node.hidden), false, "the recall pill replaces the bar");
  // The page has no channel from the artifact to the bar: a chord pressed inside
  // the sandboxed frame does nothing; the pill and the page's own chord restore it.
  await inner.click("#count");
  await inner.evaluate(() => {
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", altKey: true, shiftKey: true, bubbles: true, cancelable: true }));
  });
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), true, "a key chord inside the artifact does not touch the bar");
  await page.click(".artifact-chrome-pill");
  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), false, "the pill brings the bar back");
  await page.click(".artifact-chrome-hide");
  await page.keyboard.down("Alt"); await page.keyboard.down("Shift"); await page.keyboard.press("KeyC"); await page.keyboard.up("Shift"); await page.keyboard.up("Alt");
  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), false, "Alt+Shift+C on the page brings the bar back");
  assert.equal(await page.$eval(".artifact-chrome-pill", (node) => node.hidden), true);

  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: `${screenshotDir}/html-artifact-desktop.png`, fullPage: true });
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await page.screenshot({ path: `${screenshotDir}/html-artifact-mobile.png`, fullPage: true });
  console.log("HTML artifact browser e2e passed");
} finally {
  await browser?.close();
  server.kill("SIGTERM");
}
