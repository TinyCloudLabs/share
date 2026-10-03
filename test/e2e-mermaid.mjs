/**
 * Browser e2e for Mermaid diagrams in Markdown shares (TC-546). Renders a
 * flowchart through presentShare in real Chromium, with the viewer CSP on the
 * parent and the Mermaid sandbox document served with its production frame
 * policy (checked against public/_headers). Proves the diagram reaches the
 * scriptless preview frame with visible labels and styled — not solid black —
 * nodes, and that no stylesheet, HTML label, or script crosses into it.
 */
import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";

import puppeteer from "puppeteer";
import { createServer } from "vite";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";

const screenshotDir = process.env.MERMAID_SCREENSHOT_DIR ?? ".context";
const LABELS = ["Draft notes", "Peer review", "Publish share", "Archive copy", "approved", "changes"];
const rules = parseProductionHeaders(await readFile(new URL("../public/_headers", import.meta.url), "utf8"));
const server = await createServer({
  configFile: "vite.config.ts",
  logLevel: "error",
  server: { host: "127.0.0.1", port: 43183, strictPort: true, hmr: false },
});
await server.listen();
const harness = "http://127.0.0.1:43183/test/fixtures/markdown-share/harness.html";

/**
 * Pixel statistics for page-coordinate rectangles of a PNG screenshot, read
 * back through a canvas in a blank page (no image decoder dependency).
 * `dark` counts near-black pixels; `ink` counts pixels clearly darker than
 * the rectangle's lightest pixel (text strokes against a label background).
 */
async function pixelStats(browser, png, rects) {
  const page = await browser.newPage();
  try {
    return await page.evaluate(async (dataUrl, regions) => {
      const image = new Image();
      image.src = dataUrl;
      await image.decode();
      const canvas = document.createElement("canvas");
      canvas.width = image.width;
      canvas.height = image.height;
      const context = canvas.getContext("2d");
      context.drawImage(image, 0, 0);
      return regions.map(({ x, y, width, height }) => {
        const { data } = context.getImageData(Math.round(x), Math.round(y), Math.max(1, Math.round(width)), Math.max(1, Math.round(height)));
        const luma = [];
        for (let index = 0; index < data.length; index += 4) luma.push(0.2126 * data[index] + 0.7152 * data[index + 1] + 0.0722 * data[index + 2]);
        const lightest = Math.max(...luma);
        return {
          dark: luma.filter((value) => value < 40).length / luma.length,
          ink: luma.filter((value) => value < lightest - 90).length,
          lightest,
        };
      });
    }, `data:image/png;base64,${png}`, rects);
  } finally {
    await page.close();
  }
}

async function renderFlowchart(browser, colorScheme) {
  const page = await browser.newPage();
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: colorScheme }]);
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  const sandboxResponses = [];
  page.on("response", (response) => {
    if (new URL(response.url()).pathname === "/mermaid-sandbox.html") sandboxResponses.push(response.headers());
  });
  await page.goto(harness, { waitUntil: "load" });
  await page.waitForFunction(() => document.documentElement.dataset.ready !== undefined, { timeout: 30_000 });
  assert.equal(await page.evaluate(() => document.documentElement.dataset.ready), "yes", `${colorScheme}: presented`);

  // The sandbox ran under exactly the production frame policy.
  assert.equal(sandboxResponses.length, 1, `${colorScheme}: one sandbox document load`);
  const production = productionHeadersForPath(rules, "/mermaid-sandbox.html");
  assert.equal(sandboxResponses[0]["content-security-policy"], production["content-security-policy"]);
  assert.equal(sandboxResponses[0]["x-frame-options"], production["x-frame-options"]);

  const frameHandle = await page.waitForSelector("iframe.viewer-preview-frame");
  assert.equal(await frameHandle.evaluate((node) => node.getAttribute("sandbox")), "", "preview frame grants nothing");
  const frame = await frameHandle.contentFrame();
  await frame.waitForSelector(".viewer-mermaid svg", { timeout: 10_000 });
  assert.equal(await frame.$("pre > code.language-mermaid"), null, `${colorScheme}: no source fallback`);

  const diagram = await frame.evaluate((labels) => {
    const svg = document.querySelector(".viewer-mermaid svg");
    const box = (node) => {
      const { x, y, width, height } = node.getBoundingClientRect();
      return { x, y, width, height };
    };
    const texts = [...svg.querySelectorAll("text")];
    return {
      forbidden: svg.querySelectorAll("style, foreignObject, script").length,
      labels: labels.map((label) => {
        const text = texts.find((node) => node.textContent.replace(/\s+/g, " ").trim() === label);
        if (text === undefined) return { label, found: false };
        const style = getComputedStyle(text);
        return { label, found: true, fill: style.fill, visibility: style.visibility, opacity: style.opacity, box: box(text) };
      }),
      // The node outline: a shape element, or (rough-drawn shapes) a group
      // of paths. Every geometry element in it is checked.
      shapes: [...svg.querySelectorAll(".node")].map((node) => {
        const container = node.querySelector(".label-container");
        const geometry = [container, ...container.querySelectorAll("*")]
          .filter((element) => ["rect", "polygon", "path", "circle", "ellipse"].includes(element.localName));
        const paints = geometry.map((element) => {
          const style = getComputedStyle(element);
          return { fill: style.fill, stroke: style.stroke };
        });
        return { id: node.id, paints, box: box(container) };
      }),
    };
  }, LABELS);

  assert.equal(diagram.forbidden, 0, `${colorScheme}: no <style>, foreignObject, or script reaches the preview`);
  for (const label of diagram.labels) {
    assert.ok(label.found, `${colorScheme}: label "${label.label}" is SVG text`);
    assert.equal(label.visibility, "visible", `${colorScheme}: "${label.label}" visible`);
    assert.equal(label.opacity, "1", `${colorScheme}: "${label.label}" opaque`);
    assert.notEqual(label.fill, "none", `${colorScheme}: "${label.label}" painted`);
    assert.ok(label.box.width > 10 && label.box.height > 8, `${colorScheme}: "${label.label}" has layout`);
  }
  assert.equal(diagram.shapes.length, 4, `${colorScheme}: four nodes`);
  for (const shape of diagram.shapes) {
    assert.ok(shape.paints.length > 0, `${colorScheme}: ${shape.id} has geometry`);
    for (const paint of shape.paints) assert.notEqual(paint.fill, "rgb(0, 0, 0)", `${colorScheme}: ${shape.id} is not filled black`);
    assert.ok(shape.paints.some((paint) => paint.fill !== "none"), `${colorScheme}: ${shape.id} is filled`);
    assert.ok(shape.paints.some((paint) => paint.stroke !== "none"), `${colorScheme}: ${shape.id} is outlined`);
  }

  // What the reader sees: node fills are not solid black, and every label
  // has ink against its background.
  const offset = await frameHandle.evaluate((node) => {
    const { x, y } = node.getBoundingClientRect();
    return { x: x + node.clientLeft, y: y + node.clientTop };
  });
  const toPage = ({ x, y, width, height }) => ({ x: x + offset.x, y: y + offset.y, width, height });
  const png = await page.screenshot({ encoding: "base64", type: "png" });
  // A patch inside each shape, above its centred label: the shape's own fill.
  const fillPatches = diagram.shapes.map(({ box }) => toPage({ x: box.x + box.width / 2 - 4, y: box.y + box.height * 0.2, width: 8, height: 4 }));
  const shapeStats = await pixelStats(page.browser(), png, fillPatches);
  diagram.shapes.forEach((shape, index) => {
    assert.ok(shapeStats[index].dark < 0.2, `${colorScheme}: ${shape.id} is not a black box (${(shapeStats[index].dark * 100).toFixed(1)}% near-black)`);
  });
  const labelStats = await pixelStats(page.browser(), png, diagram.labels.map((label) => toPage(label.box)));
  diagram.labels.forEach((label, index) => {
    assert.ok(labelStats[index].ink >= 20, `${colorScheme}: "${label.label}" shows ink (${labelStats[index].ink} px)`);
  });

  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: `${screenshotDir}/mermaid-flowchart-${colorScheme}.png` });
  await page.close();
}

let browser;
try {
  browser = await puppeteer.launch({ headless: true });
  await renderFlowchart(browser, "light");
  await renderFlowchart(browser, "dark");
  console.log("Mermaid browser e2e passed");
} finally {
  await browser?.close();
  await server.close();
}
