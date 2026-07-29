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

  assert.equal(await page.$eval(".artifact-chrome-panel", (node) => node.hidden), false);
  assert.equal(await page.content().then((html) => html.includes("browser-secret")), false);
  await page.click(".artifact-chrome-button");
  assert.equal(await page.$eval(".artifact-chrome-cloud", (node) => node.hidden), false);
  await page.click(".artifact-chrome-cloud");
  await page.click(".artifact-chrome-hide");
  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), true);
  await page.keyboard.down("Alt");
  await page.keyboard.down("Shift");
  await page.keyboard.press("KeyC");
  await page.keyboard.up("Shift");
  await page.keyboard.up("Alt");
  assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), false);

  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: `${screenshotDir}/html-artifact-desktop.png`, fullPage: true });
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 });
  await page.screenshot({ path: `${screenshotDir}/html-artifact-mobile.png`, fullPage: true });
  console.log("HTML artifact browser e2e passed");
} finally {
  await browser?.close();
  server.kill("SIGTERM");
}
