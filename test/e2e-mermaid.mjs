/**
 * Browser e2e for Mermaid diagrams in Markdown shares (TC-546). Renders
 * Markdown fixtures through presentShare in real Chromium, in light and dark
 * colour schemes, with the viewer CSP on the parent and the Mermaid sandbox
 * served with its production frame policy. Proves:
 *  - both sandbox routes answer with the frame headers public/_headers
 *    resolves for them (dev parity locally; the deployed contract remotely);
 *  - diagrams reach the scriptless preview frame with every label as SVG
 *    text, readable (WCAG contrast >= 4.5) wherever it sits — on node fills,
 *    on edges, on the diagram background — and with nodes not filled black;
 *  - diagrams keep their natural size on the card (drawn scale ~1); at phone
 *    width a wide one stops at half size and its card scrolls sideways;
 *  - an A4 print (page.pdf) contains every diagram label, including all
 *    steps of a diagram taller than the printed preview frame;
 *  - an init directive or frontmatter config cannot switch HTML labels back
 *    on or switch to a dark theme; no <style>, foreignObject, or script
 *    crosses into the preview.
 *
 * Local (default): starts Vite and renders test/fixtures/markdown-share/
 * through its harness.
 *
 * Deployed: MERMAID_E2E_ORIGIN=https://<origin> checks the sandbox route
 * headers there. Rendering checks run for each fixture whose bearer share
 * link is given as MERMAID_E2E_URL_<FIXTURE> (e.g. MERMAID_E2E_URL_FLOWCHART,
 * MERMAID_E2E_URL_THEME_INIT); share the fixture file unchanged. Fixtures
 * without a link are skipped and reported. A deployed run that renders no
 * fixture fails unless MERMAID_E2E_HEADERS_ONLY=1 asks for headers only.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import puppeteer from "puppeteer";
import { createServer } from "vite";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";
import { pdfPageTexts } from "./pdf-text.mjs";

const screenshotDir = process.env.MERMAID_SCREENSHOT_DIR ?? ".context";
const SANDBOX_ROUTES = ["/mermaid-sandbox", "/mermaid-sandbox.html"];
const MIN_CONTRAST = 4.5;
const FLOWCHART_LABELS = ["Draft notes", "Peer review", "Publish share", "Archive copy", "approved", "changes"];
const SEQUENCE_LABELS = ["Sender", "Viewer", "Open share link", "Render diagram text", "Labels stay readable"];
const FLOWCHART = { diagrams: 1, nodes: 4, labels: FLOWCHART_LABELS };
// Both diagrams ask for Mermaid's dark theme (plus darkMode and dark theme
// variables); every label must still read on the light card.
const DARK_THEME_REQUEST = { diagrams: 2, nodes: 4, labels: [...SEQUENCE_LABELS, ...FLOWCHART_LABELS] };
/** "<Name> step 0" … "<Name> step <count - 1>" for each name. */
function steps(names, count) {
  return names.flatMap((name) => Array.from({ length: count }, (_, step) => `${name} step ${step}`));
}
const SCENARIOS = [
  { fixture: "flowchart", ...FLOWCHART },
  { fixture: "flowchart-init", ...FLOWCHART },
  { fixture: "flowchart-frontmatter", ...FLOWCHART },
  { fixture: "sequence", diagrams: 2, nodes: 0, axis: true, labels: [...SEQUENCE_LABELS, "Release plan", "Sandbox fix", "Deploy"] },
  { fixture: "state", diagrams: 1, labels: ["Idle", "Rendering", "Shown", "open", "done"] },
  { fixture: "theme-init", ...DARK_THEME_REQUEST },
  { fixture: "theme-frontmatter", ...DARK_THEME_REQUEST },
  // Taller than the printed preview frame at natural size, alone or together:
  // print must still show every step of every diagram.
  { fixture: "print", diagrams: 1, nodes: 8, labels: steps(["Print"], 8) },
  { fixture: "print-two", diagrams: 2, nodes: 8, labels: steps(["First", "Next"], 4) },
  { fixture: "print-three", diagrams: 3, nodes: 12, labels: steps(["First", "Next", "Last"], 4) },
];
// A diagram narrower than the page must render at its own size, not shrunk
// by the card around it (ratio to the expected scale).
const MIN_SCALE = 0.98;
// On screen a wide diagram shrinks to the page but not below half size; past
// that its card scrolls sideways.
const MIN_DRAWN_SCALE = 0.5;
const PHONE = { width: 390, height: 844, deviceScaleFactor: 1 };
const rules = parseProductionHeaders(await readFile(new URL("../public/_headers", import.meta.url), "utf8"));

const deployedOrigin = process.env.MERMAID_E2E_ORIGIN;
const server = deployedOrigin === undefined
  ? await createServer({
    configFile: "vite.config.ts",
    logLevel: "error",
    server: { host: "127.0.0.1", port: 43183, strictPort: true, hmr: false },
  })
  : undefined;
await server?.listen();
const origin = deployedOrigin ?? "http://127.0.0.1:43183";

function scenarioUrl(fixture) {
  if (deployedOrigin === undefined) return `${origin}/test/fixtures/markdown-share/harness.html?fixture=${fixture}`;
  return process.env[`MERMAID_E2E_URL_${fixture.toUpperCase().replaceAll("-", "_")}`];
}

/** Assert a sandbox response carries the headers public/_headers resolves for its path. */
function assertFrameHeaders(pathname, headers, label) {
  const expected = productionHeadersForPath(rules, pathname);
  assert.equal(headers["content-security-policy"], expected["content-security-policy"], `${label}: frame CSP`);
  assert.equal(headers["x-frame-options"], expected["x-frame-options"], `${label}: X-Frame-Options`);
}

async function checkSandboxRoutes() {
  for (const route of SANDBOX_ROUTES) {
    // Production redirects the .html form to the extensionless path; judge
    // the document actually served.
    const response = await fetch(new URL(route, origin), { redirect: "follow" });
    assert.equal(response.status, 200, `${route}: served`);
    assert.match(await response.text(), /self\.origin !== "null"/, `${route}: serves the sandbox document`);
    assertFrameHeaders(new URL(response.url).pathname, Object.fromEntries(response.headers), route);
  }
}

/**
 * Pixel statistics for a PNG, read back through a canvas in a blank page (no
 * image decoder dependency). `dark` is the share of near-black pixels;
 * `contrast` is the WCAG ratio between the median pixel (the background) and
 * the pixel furthest from it (the text strokes).
 */
async function pixelStats(browser, png) {
  const page = await browser.newPage();
  try {
    return await page.evaluate(async (dataUrl) => {
      const image = new Image();
      image.src = dataUrl;
      await image.decode();
      const canvas = document.createElement("canvas");
      canvas.width = image.width;
      canvas.height = image.height;
      const context = canvas.getContext("2d");
      context.drawImage(image, 0, 0);
      const { data } = context.getImageData(0, 0, image.width, image.height);
      const channel = (value) => {
        const unit = value / 255;
        return unit <= 0.04045 ? unit / 12.92 : ((unit + 0.055) / 1.055) ** 2.4;
      };
      const luminance = [];
      for (let index = 0; index < data.length; index += 4) {
        luminance.push(0.2126 * channel(data[index]) + 0.7152 * channel(data[index + 1]) + 0.0722 * channel(data[index + 2]));
      }
      const sorted = [...luminance].sort((a, b) => a - b);
      const background = sorted[Math.floor(sorted.length / 2)];
      const furthest = Math.abs(sorted[0] - background) > Math.abs(sorted[sorted.length - 1] - background) ? sorted[0] : sorted[sorted.length - 1];
      return {
        dark: luminance.filter((value) => value < 0.021).length / luminance.length,
        contrast: (Math.max(background, furthest) + 0.05) / (Math.min(background, furthest) + 0.05),
      };
    }, `data:image/png;base64,${png}`);
  } finally {
    await page.close();
  }
}

/**
 * Screenshot a region (as boundingBox() reports it) and measure it. Capture
 * stays within the viewport: capturing beyond it resizes the viewport, which
 * resizes the 75vh preview frame and moves its scrolled content.
 */
async function measure(page, clip) {
  const png = await page.screenshot({ encoding: "base64", type: "png", clip, captureBeyondViewport: false });
  return pixelStats(page.browser(), png);
}

/** Open a fixture's share and wait for its diagrams in the preview frame. */
async function openFixture(browser, scenario, { colorScheme, viewport, label }) {
  const page = await browser.newPage();
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: colorScheme }]);
  await page.setViewport(viewport);
  const sandboxResponses = [];
  page.on("response", (response) => {
    const { pathname } = new URL(response.url());
    if (SANDBOX_ROUTES.includes(pathname) && response.status() === 200) sandboxResponses.push({ pathname, headers: response.headers() });
  });
  await page.goto(scenarioUrl(scenario.fixture), { waitUntil: "load" });
  const frameHandle = await page.waitForSelector("iframe.viewer-preview-frame", { timeout: 60_000 });
  if (deployedOrigin === undefined) {
    assert.equal(await page.evaluate(() => document.documentElement.dataset.ready), "yes", `${label}: presented`);
  }
  const frame = await frameHandle.contentFrame();
  await frame.waitForFunction(
    (count) => document.querySelectorAll(".viewer-mermaid svg").length === count,
    { timeout: 15_000 },
    scenario.diagrams,
  ).catch(() => undefined);
  return { page, frameHandle, frame, sandboxResponses };
}

/**
 * Each diagram is drawn at its natural scale (1 user unit = 1 CSS px) unless
 * the page is narrower, then at the page width but never below half size;
 * the card's padding and border must not shrink it. The screen CTM is the
 * scale the drawing actually gets. Returns each card's horizontal overflow.
 */
async function assertDrawnScales(frame, label) {
  const sizes = await frame.$$eval(".viewer-mermaid svg", (svgs) => svgs.map((svg) => {
    const card = svg.parentElement;
    const cardStyle = getComputedStyle(card);
    const body = getComputedStyle(document.body);
    const chrome = (style, side) => Number.parseFloat(style[`padding${side}`]) + Number.parseFloat(style[`border${side}Width`]);
    return {
      natural: svg.viewBox.baseVal.width,
      drawn: svg.getScreenCTM().a,
      room: document.body.clientWidth - chrome(body, "Left") - chrome(body, "Right") - chrome(cardStyle, "Left") - chrome(cardStyle, "Right"),
      scrolls: card.scrollWidth > card.clientWidth,
      pageScrolls: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    };
  }));
  for (const [index, size] of sizes.entries()) {
    const expected = Math.max(MIN_DRAWN_SCALE, Math.min(1, size.room / size.natural));
    const ratio = size.drawn / expected;
    assert.ok(
      ratio >= MIN_SCALE && ratio <= 1.02,
      `${label}: diagram ${index} is drawn at scale ${size.drawn.toFixed(3)}, expected ${expected.toFixed(3)} (${size.natural.toFixed(0)}px wide)`,
    );
    assert.equal(size.pageScrolls, false, `${label}: the preview page itself never scrolls sideways`);
  }
  return sizes;
}

async function renderScenario(browser, scenario, colorScheme) {
  const label = `${scenario.fixture}/${colorScheme}`;
  const { page, frameHandle, frame, sandboxResponses } = await openFixture(browser, scenario, {
    colorScheme,
    viewport: { width: 1280, height: 1400, deviceScaleFactor: 1 },
    label,
  });
  assert.equal(await frameHandle.evaluate((node) => node.getAttribute("sandbox")), "", `${label}: preview frame grants nothing`);

  // The sandbox document ran under the production frame policy.
  assert.equal(sandboxResponses.length, 1, `${label}: one sandbox document load`);
  assertFrameHeaders(sandboxResponses[0].pathname, sandboxResponses[0].headers, `${label} sandbox load`);

  // Every diagram rendered: none fell back to its source.
  assert.equal(await frame.$$eval("pre > code.language-mermaid", (nodes) => nodes.length), 0, `${label}: no source fallback`);
  assert.equal(await frame.$$eval(".viewer-mermaid svg", (nodes) => nodes.length), scenario.diagrams, `${label}: every diagram rendered`);
  assert.equal(
    await frame.$$eval(".viewer-mermaid svg", (svgs) => svgs.reduce((count, svg) => count + svg.querySelectorAll("style, foreignObject, script").length, 0)),
    0,
    `${label}: no <style>, foreignObject, or script reaches the preview`,
  );
  await assertDrawnScales(frame, label);

  // Tag what to measure, then read each target through the frame boundary.
  const targets = await frame.evaluate(({ labels, axis }) => {
    const texts = [...document.querySelectorAll(".viewer-mermaid svg text")];
    const found = [];
    const tag = (element, entry) => {
      element.setAttribute("data-e2e-target", String(found.length));
      found.push(entry);
    };
    for (const text of labels) {
      const node = texts.find((candidate) => candidate.textContent.replace(/\s+/g, " ").trim() === text);
      if (node === undefined) {
        found.push({ kind: "label", text, missing: true });
        continue;
      }
      const style = getComputedStyle(node);
      tag(node, { kind: "label", text, fill: style.fill, visibility: style.visibility, opacity: style.opacity });
    }
    if (axis) {
      const tick = document.querySelector(".viewer-mermaid .tick text");
      if (tick === null) found.push({ kind: "label", text: "axis tick", missing: true });
      else tag(tick, { kind: "label", text: `axis tick "${tick.textContent}"`, fill: getComputedStyle(tick).fill, visibility: "visible", opacity: "1" });
    }
    for (const node of document.querySelectorAll(".viewer-mermaid .node")) {
      // The outline is a shape element or (rough-drawn shapes) a group of
      // paths; start/end markers (state diagrams) have no label container.
      const container = node.querySelector(".label-container");
      if (container === null) continue;
      const paints = [container, ...container.querySelectorAll("*")]
        .filter((element) => ["rect", "polygon", "path", "circle", "ellipse"].includes(element.localName))
        .map((element) => ({ fill: getComputedStyle(element).fill, stroke: getComputedStyle(element).stroke }));
      tag(container, { kind: "node", text: node.id, paints });
    }
    return found;
  }, scenario);

  if (scenario.nodes !== undefined) {
    assert.equal(targets.filter((target) => target.kind === "node").length, scenario.nodes, `${label}: node count`);
  }
  for (const [index, target] of targets.entries()) {
    assert.ok(!target.missing, `${label}: "${target.text}" is SVG text`);
    const handle = await frame.$(`[data-e2e-target="${index}"]`);
    await handle.scrollIntoView();
    const box = await handle.boundingBox();
    if (target.kind === "label") {
      assert.equal(target.visibility, "visible", `${label}: "${target.text}" visible`);
      assert.equal(target.opacity, "1", `${label}: "${target.text}" opaque`);
      assert.notEqual(target.fill, "none", `${label}: "${target.text}" painted`);
      assert.ok(box.width > 10 && box.height > 8, `${label}: "${target.text}" has layout`);
      const { contrast } = await measure(page, box);
      assert.ok(contrast >= MIN_CONTRAST, `${label}: "${target.text}" readable (contrast ${contrast.toFixed(2)}:1)`);
    } else {
      assert.ok(target.paints.length > 0, `${label}: ${target.text} has geometry`);
      for (const paint of target.paints) assert.notEqual(paint.fill, "rgb(0, 0, 0)", `${label}: ${target.text} is not filled black`);
      assert.ok(target.paints.some((paint) => paint.fill !== "none"), `${label}: ${target.text} is filled`);
      assert.ok(target.paints.some((paint) => paint.stroke !== "none"), `${label}: ${target.text} is outlined`);
      // A patch inside the shape, above its centred label: the shape's own fill.
      const { dark } = await measure(page, { x: box.x + box.width / 2 - 4, y: box.y + box.height * 0.2, width: 8, height: 4 });
      assert.ok(dark < 0.2, `${label}: ${target.text} is not a black box (${(dark * 100).toFixed(1)}% near-black)`);
    }
  }

  await (await frame.$(".viewer-mermaid")).scrollIntoView();
  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: `${screenshotDir}/mermaid-${scenario.fixture}-${colorScheme}.png` });

  // Print (A4): every diagram label is in the PDF's text. Print shows only
  // the preview frame's viewport, so a diagram cut off there loses labels.
  const pdf = await page.pdf({ format: "A4" });
  if (colorScheme === "light") await writeFile(`${screenshotDir}/mermaid-${scenario.fixture}.pdf`, pdf);
  const printed = pdfPageTexts(pdf).join("\n").replace(/\s+/g, " ");
  for (const text of scenario.labels) assert.ok(printed.includes(text), `${label}: "${text}" prints`);
  await page.close();
}

/**
 * Phone width: a wide diagram stops shrinking at half size and its card
 * scrolls sideways; a narrow one keeps its natural size. The page itself
 * never scrolls sideways.
 */
async function renderOnPhone(browser, scenario, cardScrolls) {
  const label = `${scenario.fixture}/phone`;
  const { page, frame } = await openFixture(browser, scenario, { colorScheme: "light", viewport: PHONE, label });
  const sizes = await assertDrawnScales(frame, label);
  assert.equal(sizes[0].scrolls, cardScrolls, `${label}: card ${cardScrolls ? "scrolls" : "fits"}`);
  await page.screenshot({ path: `${screenshotDir}/mermaid-${scenario.fixture}-phone.png` });
  await page.close();
}

let browser;
try {
  await checkSandboxRoutes();
  browser = await puppeteer.launch({ headless: true });
  let rendered = 0;
  for (const scenario of SCENARIOS) {
    if (scenarioUrl(scenario.fixture) === undefined) {
      console.log(`skipped ${scenario.fixture}: no MERMAID_E2E_URL_${scenario.fixture.toUpperCase().replaceAll("-", "_")}`);
      continue;
    }
    for (const colorScheme of ["light", "dark"]) await renderScenario(browser, scenario, colorScheme);
    if (scenario.fixture === "flowchart") await renderOnPhone(browser, scenario, true);
    if (scenario.fixture === "print") await renderOnPhone(browser, scenario, false);
    rendered += 1;
  }

  // Headers alone say nothing about rendering: a run that drew no diagram
  // only passes when it explicitly asked for headers only.
  const headersOnly = process.env.MERMAID_E2E_HEADERS_ONLY === "1";
  assert.ok(
    rendered > 0 || headersOnly,
    "no fixture rendered: pass MERMAID_E2E_URL_<FIXTURE> share links, or set MERMAID_E2E_HEADERS_ONLY=1 for a headers-only check",
  );
  console.log(`Mermaid browser e2e passed against ${origin}: ${rendered} fixture(s) rendered${rendered === 0 ? " (headers only)" : ""}`);
} finally {
  await browser?.close();
  await server?.close();
}
