/**
 * Browser e2e for the sandboxed JSX renderer. Runs the real content pipeline
 * (renderSafeContent → lazy jsx-render → sandbox bridge → srcdoc child) in
 * Chromium against the Vite dev server, which serves the bridge with the same
 * headers as production, and a loopback "beacon" server that must see NOTHING.
 *
 * Defensive checks only: a benign self-check fixture and a viewer-privacy
 * fixture try operations an artifact must not be able to do and the test
 * asserts every one of them failed.
 */
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import dgram from "node:dgram";
import { createServer } from "node:http";

import puppeteer from "puppeteer";

const port = 43180;
const origin = `http://127.0.0.1:${port}`;
const screenshotDir = process.env.ARTIFACT_SCREENSHOT_DIR ?? ".context";

// Anything that reaches this server is a remote load that got through. Every
// page gets a fresh server on a fresh port: Chromium's loading predictor
// otherwise pre-connects to origins it has seen, which would blame a probe for
// an earlier page's connection.
let beacon;
let beaconOrigin;
async function freshBeacon() {
  beacon?.server.closeAllConnections();
  beacon?.server.close();
  beacon?.udp.close();
  const state = { requests: [], connections: 0, upgrades: 0, udpPackets: 0 };
  state.server = createServer((request, response) => {
    state.requests.push(request.url);
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("seen");
  });
  state.server.on("connection", () => { state.connections += 1; });
  state.server.on("upgrade", (_request, socket) => { state.upgrades += 1; socket.destroy(); });
  await new Promise((resolve) => state.server.listen(0, "127.0.0.1", resolve));
  // A STUN server on the same port number, to see what WebRTC ICE gathering sends.
  state.udp = dgram.createSocket("udp4");
  state.udp.on("message", () => { state.udpPackets += 1; });
  await new Promise((resolve) => state.udp.bind(state.server.address().port, "127.0.0.1", resolve));
  beacon = state;
  beaconOrigin = `http://127.0.0.1:${state.server.address().port}`;
}
await freshBeacon();

const server = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", String(port), "--strictPort"], {
  stdio: ["ignore", "pipe", "pipe"],
});
async function waitForServer() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error(`Vite exited with ${server.exitCode}`);
    try { if ((await fetch(`${origin}/test/fixtures/jsx-harness.html`)).ok) return; } catch { /* still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Timed out waiting for the JSX browser harness");
}

let browser;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function open(fixture, { scheme = "light", query = "", width = 1100, height = 720 } = {}) {
  await freshBeacon();
  const page = await browser.newPage();
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
  await page.setViewport({ width, height });
  const requests = [];
  page.on("request", (request) => requests.push({ url: request.url(), frame: request.frame()?.url() ?? "" }));
  const consoleErrors = [];
  page.on("pageerror", (error) => consoleErrors.push(error.message));
  await page.goto(`${origin}/test/fixtures/jsx-harness.html?f=${fixture}&beacon=${encodeURIComponent(beaconOrigin)}${query}`, { waitUntil: "load" });
  await page.waitForFunction(() => document.documentElement.dataset.ready, { timeout: 30_000 });
  return { page, requests, consoleErrors };
}

async function childFrame(page, { timeout = 20_000 } = {}) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const frame = page.frames().find((candidate) => candidate.url() === "about:srcdoc");
    if (frame !== undefined) return frame;
    await sleep(100);
  }
  throw new Error("child frame never appeared");
}

/** The viewer itself may fetch only same-origin runtime files; the frame fetches nothing. */
function assertNoRemoteLoads(label, { requests }) {
  const foreign = requests.filter((request) => !request.url.startsWith(origin) && !request.url.startsWith("data:") && !request.url.startsWith("blob:") && request.url !== "about:srcdoc");
  assert.deepEqual(foreign, [], `${label}: requests left the origin`);
  const fromChild = requests.filter((request) => request.frame === "about:srcdoc");
  assert.deepEqual(fromChild, [], `${label}: the artifact frame made network requests`);
  assert.deepEqual(beacon.requests, [], `${label}: loopback beacon saw requests`);
  assert.equal(beacon.connections, 0, `${label}: loopback beacon saw connections`);
  assert.equal(beacon.upgrades, 0, `${label}: loopback beacon saw upgrades`);
  assert.equal(beacon.udpPackets, 0, `${label}: loopback beacon saw UDP packets`);
}

async function shot(page, name) {
  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: `${screenshotDir}/${name}.png` });
}

try {
  await waitForServer();
  browser = await puppeteer.launch({ headless: true });

  // --- Fixtures render, are interactive, and load nothing remote -----------
  {
    const run = await open("counter.jsx");
    const frame = await childFrame(run.page);
    const outer = run.page.frames().find((candidate) => candidate.url().includes("/jsx-sandbox.html"));
    assert.ok(outer, "bridge frame exists");
    await frame.waitForSelector("[data-testid=count]");
    assert.equal(await frame.$eval("[data-testid=count]", (node) => node.textContent), "0");
    // The bridge drops the nonce from its own URL, so the child cannot read it through baseURI.
    assert.equal(await frame.evaluate(() => document.baseURI.includes("#")), false, "the child's baseURI carries no fragment");
    await frame.click("[data-testid=increment]");
    await frame.click("[data-testid=increment]");
    assert.equal(await frame.$eval("[data-testid=count]", (node) => node.textContent), "2");
    // Tailwind built CSS from the classes, and the TinyCloud tokens reached it.
    const styled = await frame.evaluate(() => {
      const button = document.querySelector("[data-testid=increment]");
      const root = getComputedStyle(document.documentElement);
      return { display: getComputedStyle(document.querySelector("main")).display, background: getComputedStyle(button).backgroundColor, accent: root.getPropertyValue("--tc-color-accent").trim(), radius: getComputedStyle(button).borderRadius };
    });
    assert.equal(styled.display, "grid");
    assert.equal(styled.accent, "#2a56f6");
    assert.equal(styled.background, "rgb(42, 86, 246)");
    // Sandbox attributes as the browser sees them.
    const iframeAttrs = await run.page.$eval("iframe.viewer-html-frame", (node) => ({ sandbox: node.getAttribute("sandbox"), allow: node.getAttribute("allow"), referrer: node.getAttribute("referrerpolicy") }));
    assert.deepEqual(iframeAttrs, { sandbox: "allow-scripts", allow: "", referrer: "no-referrer" });
    const childSandbox = await outer.$eval("iframe", (node) => node.getAttribute("sandbox"));
    assert.equal(childSandbox, "allow-scripts");
    await sleep(500);
    await shot(run.page, "jsx-counter-light");
    assertNoRemoteLoads("counter", run);
    await run.page.close();

    const dark = await open("counter.jsx", { scheme: "dark" });
    const darkFrame = await childFrame(dark.page);
    await darkFrame.waitForSelector("[data-testid=count]");
    assert.equal(await darkFrame.evaluate(() => getComputedStyle(document.querySelector("main")).backgroundColor), "rgb(11, 14, 20)");
    await shot(dark.page, "jsx-counter-dark");
    await dark.page.close();
  }

  {
    const run = await open("chart.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("[data-testid=chart] svg.recharts-surface path.recharts-area-curve", { timeout: 20_000 });
    await sleep(1200);
    await shot(run.page, "jsx-chart-light");
    assertNoRemoteLoads("recharts", run);
    await run.page.close();
    const dark = await open("chart.jsx", { scheme: "dark" });
    await (await childFrame(dark.page)).waitForSelector("svg.recharts-surface path.recharts-area-curve", { timeout: 20_000 });
    await sleep(1200);
    await shot(dark.page, "jsx-chart-dark");
    await dark.page.close();
  }

  {
    const run = await open("icons.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("[data-testid=icons] svg.lucide");
    assert.equal(await frame.$$eval("[data-testid=icons] svg.lucide", (nodes) => nodes.length), 8);
    await shot(run.page, "jsx-icons-light");
    assertNoRemoteLoads("lucide", run);
    await run.page.close();
  }

  {
    const run = await open("diagram.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("[data-testid=diagram] svg", { timeout: 30_000 });
    const labels = await frame.$$eval("[data-testid=diagram] svg", (nodes) => nodes[0].textContent);
    assert.match(labels, /Agent writes app\.jsx/);
    await sleep(500);
    await shot(run.page, "jsx-mermaid-light");
    assertNoRemoteLoads("mermaid", run);
    await run.page.close();
    const dark = await open("diagram.jsx", { scheme: "dark" });
    await (await childFrame(dark.page)).waitForSelector("[data-testid=diagram] svg", { timeout: 30_000 });
    await sleep(500);
    await shot(dark.page, "jsx-mermaid-dark");
    await dark.page.close();
  }

  {
    const run = await open("card.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("article");
    const card = await frame.$eval("article", (node) => { const style = getComputedStyle(node); return { radius: style.borderRadius, overflow: style.overflow, width: node.getBoundingClientRect().width }; });
    assert.notEqual(card.radius, "0px");
    assert.ok(card.width > 300 && card.width <= 448 + 2, `card width ${card.width}`);
    await shot(run.page, "jsx-card-light");
    assertNoRemoteLoads("tailwind card", run);
    await run.page.close();
    const dark = await open("card.jsx", { scheme: "dark" });
    await (await childFrame(dark.page)).waitForSelector("article");
    await shot(dark.page, "jsx-card-dark");
    await dark.page.close();
    const phone = await open("card.jsx", { width: 390, height: 844 });
    await (await childFrame(phone.page)).waitForSelector("article");
    await shot(phone.page, "jsx-card-390");
    await phone.page.close();
  }

  // --- Error panels --------------------------------------------------------
  {
    const run = await open("unknown-import.jsx");
    const panel = await run.page.$eval(".viewer-jsx-panel", (node) => node.textContent);
    assert.match(panel, /needs a library that isn't available[\s\S]*Import from the file: canvas-confetti/);
    assert.match(panel, /Available: react, react-dom, react-dom\/client, react\/jsx-runtime, lucide-react, recharts, d3, mermaid/);
    assert.equal(await run.page.$("iframe"), null, "no frame left after an import error");
    await shot(run.page, "jsx-unknown-import");
    await run.page.close();

    const syntax = await open("syntax-error.jsx", { scheme: "dark" });
    const text = await syntax.page.$eval(".viewer-jsx-panel", (node) => node.textContent);
    assert.match(text, /syntax error/);
    assert.match(text, /Line 5/);
    assert.equal(await syntax.page.$("iframe"), null);
    assert.equal(await syntax.page.$eval(".viewer-jsx-panel a[download]", (node) => node.getAttribute("download")), "syntax-error.jsx");
    await shot(syntax.page, "jsx-syntax-error-dark");
    await syntax.page.close();
  }

  // --- Loading state: never a blank area while libraries load or the page starts ---
  {
    await freshBeacon();
    const page = await browser.newPage();
    await page.setViewport({ width: 1100, height: 720 });
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      // Hold the largest library back, as a slow connection would.
      if (/\/assets\/jsx-runtime\/|\/\.vite\/|mermaid/.test(request.url()) && /mermaid/.test(request.url()) && request.resourceType() === "fetch") {
        setTimeout(() => request.continue().catch(() => undefined), 3000);
      } else {
        request.continue().catch(() => undefined);
      }
    });
    await page.goto(`${origin}/test/fixtures/jsx-harness.html?f=diagram.jsx&beacon=${encodeURIComponent(beaconOrigin)}`, { waitUntil: "domcontentloaded" });
    await page.waitForSelector(".viewer-jsx-loading", { timeout: 20_000 });
    await sleep(600);
    const cover = await page.evaluate(() => {
      const node = document.querySelector(".viewer-jsx-loading");
      const box = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      const bar = node.querySelector(".viewer-jsx-skeleton-bar");
      return {
        role: node.getAttribute("role"),
        text: node.textContent,
        height: box.height,
        width: box.width,
        background: style.backgroundColor,
        stageState: node.parentElement.dataset.state,
        animation: getComputedStyle(bar, "::after").animationName,
        hit: document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) !== null && node.contains(document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2)),
      };
    });
    assert.equal(cover.role, "status");
    assert.match(cover.text, /Loading the page…/);
    assert.ok(cover.height >= 400, `the cover fills the area (height ${cover.height})`);
    assert.notEqual(cover.background, "rgba(0, 0, 0, 0)");
    assert.equal(cover.stageState, "loading");
    assert.equal(cover.animation, "viewer-jsx-skeleton");
    assert.ok(cover.hit, "the cover is the topmost element over the area");
    await shot(page, "jsx-loading-light");
    await page.waitForFunction(() => document.documentElement.dataset.ready, { timeout: 40_000 });
    await childFrame(page);
    assert.equal(await page.$(".viewer-jsx-loading"), null, "the cover is gone once the page is ready");
    await page.close();

    // Reduced motion: the skeleton does not animate.
    const calm = await browser.newPage();
    await calm.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }, { name: "prefers-color-scheme", value: "dark" }]);
    await calm.setViewport({ width: 390, height: 844 });
    await calm.setRequestInterception(true);
    calm.on("request", (request) => {
      if (/mermaid/.test(request.url()) && request.resourceType() === "fetch") setTimeout(() => request.continue().catch(() => undefined), 3000);
      else request.continue().catch(() => undefined);
    });
    await calm.goto(`${origin}/test/fixtures/jsx-harness.html?f=diagram.jsx&beacon=${encodeURIComponent(beaconOrigin)}`, { waitUntil: "domcontentloaded" });
    await calm.waitForSelector(".viewer-jsx-loading", { timeout: 20_000 });
    await sleep(400);
    assert.equal(await calm.evaluate(() => getComputedStyle(document.querySelector(".viewer-jsx-skeleton-bar"), "::after").animationName), "none");
    // Dark: the cover is dark, not a light card.
    const dark = await calm.evaluate(() => getComputedStyle(document.querySelector(".viewer-jsx-loading")).backgroundColor);
    assert.equal(dark, "rgb(11, 14, 20)", "dark cover uses the dark page token");
    await shot(calm, "jsx-loading-dark-390");
    await calm.close();
  }

  // --- Chrome follows the OS theme at phone and desktop widths ---
  for (const [scheme, width] of [["light", 1440], ["dark", 1440], ["light", 390], ["dark", 390]]) {
    const run = await open("syntax-error.jsx", { scheme, width, height: width === 390 ? 844 : 900 });
    const colors = await run.page.evaluate(() => {
      const notice = document.querySelector(".viewer-artifact-notice");
      const panel = document.querySelector(".viewer-jsx-panel");
      return {
        notice: getComputedStyle(notice).backgroundColor,
        noticeText: getComputedStyle(notice).color,
        noticeHeight: notice.getBoundingClientRect().height,
        panel: getComputedStyle(panel).backgroundColor,
        panelText: getComputedStyle(panel).color,
        overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });
    const dark = scheme === "dark";
    assert.equal(colors.panel, dark ? "rgb(18, 21, 30)" : "rgb(255, 255, 255)", `${scheme} ${width}: panel surface`);
    assert.equal(colors.notice, dark ? "rgb(22, 25, 34)" : "rgb(241, 245, 249)", `${scheme} ${width}: notice surface`);
    assert.equal(colors.panelText, dark ? "rgb(226, 232, 240)" : "rgb(26, 28, 33)", `${scheme} ${width}: panel text`);
    assert.ok(colors.overflowX <= 0, `${scheme} ${width}: no horizontal scroll`);
    // The notice plus its one-line "What the sender can learn" row (the detail itself starts closed on a phone).
    if (width === 390) assert.ok(colors.noticeHeight <= 104, `390px notice height ${colors.noticeHeight}`);
    await shot(run.page, `jsx-chrome-${scheme}-${width}`);
    await run.page.close();
  }

  // --- Addressed links get a download, never a frame -----------------------
  {
    const run = await open("counter.jsx", { query: "&access=policy" });
    assert.equal(await run.page.$("iframe"), null);
    assert.match(await run.page.$eval("#harness", (node) => node.textContent), /Preview isn't available for this link type yet/);
    await run.page.close();
  }

  // --- Benign sandbox self-check -------------------------------------------
  {
    await freshBeacon();
    const run = await open("self-check.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 20_000 });
    const { result, violations } = JSON.parse(await frame.$eval("#report", (node) => node.textContent));
    const failed = (probe) => assert.equal(result[probe].ok, false, `${probe} should have failed: ${JSON.stringify(result[probe])}`);
    for (const probe of ["parentDocument", "topDocument", "localStorage", "sessionStorage", "indexedDB", "fetchRemote", "fetchSameOrigin", "worker"]) failed(probe);
    assert.equal(result.parentDocument.name, "SecurityError");
    assert.equal(result.topDocument.name, "SecurityError");
    assert.equal(result.localStorage.name, "SecurityError");
    assert.equal(result.sessionStorage.name, "SecurityError");
    assert.ok(result.cookie.ok === false || result.cookie.value === "", "document.cookie must be empty or throw");
    assert.equal(result.windowOpen.value, "null", "window.open must return null");
    assert.equal(result.origin.value, "null", "the artifact origin must be opaque");
    assert.ok(violations.some((directive) => directive.startsWith("connect-src")), `expected a connect-src violation, got ${violations}`);
    assert.ok(violations.some((directive) => directive.startsWith("worker-src") || directive.startsWith("script-src") || directive.startsWith("child-src")), `expected a worker block, got ${violations}`);
    assert.equal(new URL(run.page.url()).origin, origin, "top navigation must not have moved the viewer");
    assert.equal(new URL(run.page.url()).pathname, "/test/fixtures/jsx-harness.html");
    await sleep(500);
    assert.deepEqual(beacon.requests, [], "self-check reached the beacon");
    assert.equal(beacon.connections, 0);
    await shot(run.page, "jsx-self-check");
    await run.page.close();
  }

  // --- The viewer chrome cannot be hidden, covered, trapped or dismissed by the artifact ---
  // The same hostile page, as a JSX app and as a single-file HTML artifact.
  for (const kind of ["jsx", "html"]) {
    const run = await open(kind === "jsx" ? "hostile-chrome.jsx" : "hostile-chrome.html");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 20_000 });
    await sleep(600);
    const { results } = JSON.parse(await frame.$eval("#report", (node) => node.textContent));
    const label = (text) => `${kind}: ${text}`;
    // No fullscreen, no Picture-in-Picture: the sandbox documents' Permissions-Policy forbids both.
    assert.equal(results.fullscreenEnabled, false, label("fullscreen must be unavailable inside the frame"));
    assert.equal(results.pictureInPictureEnabled, false, label("Picture-in-Picture must be unavailable inside the frame"));
    assert.ok(/^(?:rejected|threw)/.test(results.fullscreenRequest) || results.fullscreenRequest === "pending", label(`fullscreen request: ${results.fullscreenRequest}`));
    assert.equal(await run.page.evaluate(() => document.fullscreenElement), null);

    // The notice is where the viewer put it, above the frame, and nothing draws over it.
    const geometry = await run.page.evaluate(() => {
      const notice = document.querySelector(".viewer-artifact-notice");
      const frameElement = document.querySelector("iframe.viewer-html-frame");
      const rect = (element) => { const box = element.getBoundingClientRect(); return { x: box.x, y: box.y, w: box.width, h: box.height }; };
      const center = (element) => { const box = element.getBoundingClientRect(); return [box.x + box.width / 2, box.y + box.height / 2]; };
      const hit = (element) => { const [x, y] = center(element); const found = document.elementFromPoint(x, y); return found === element || element.contains(found); };
      const dismiss = notice.querySelector(".viewer-artifact-notice-dismiss");
      return {
        noticeVisible: notice.getBoundingClientRect().height > 0 && getComputedStyle(notice).visibility === "visible",
        noticeRect: rect(notice),
        frameRect: rect(frameElement),
        noticeHit: hit(notice.querySelector(".viewer-artifact-notice-text")),
        dismissHit: hit(dismiss),
        frameHit: (() => { const [x, y] = center(frameElement); return document.elementFromPoint(x, y) === frameElement; })(),
        frameStyle: (() => { const style = getComputedStyle(frameElement); return { overflow: style.overflow, isolation: style.isolation, contain: style.contain, zIndex: style.zIndex }; })(),
        noticeZ: getComputedStyle(notice).zIndex,
        allowAttr: frameElement.getAttribute("allow"),
        allowFullscreenAttr: frameElement.hasAttribute("allowfullscreen"),
        sandbox: frameElement.getAttribute("sandbox"),
      };
    });
    assert.ok(geometry.noticeVisible, label("the notice is visible"));
    assert.ok(geometry.noticeHit, label("elementFromPoint at the notice text returns the notice"));
    assert.ok(geometry.dismissHit, label("elementFromPoint at the dismiss button returns the button"));
    assert.ok(geometry.frameHit, label("the frame is still the topmost thing over its own box"));
    assert.ok(geometry.noticeRect.y + geometry.noticeRect.h <= geometry.frameRect.y + 0.5, label("the notice and the frame do not overlap"));
    assert.ok(["hidden", "clip"].includes(geometry.frameStyle.overflow), label(`frame overflow ${geometry.frameStyle.overflow}`));
    assert.equal(geometry.frameStyle.isolation, "isolate");
    assert.ok(Number(geometry.noticeZ) > Number(geometry.frameStyle.zIndex), label("the notice stacks above the frame"));
    assert.equal(geometry.allowAttr, "", label("no permissions delegated to the frame"));
    assert.equal(geometry.allowFullscreenAttr, false);
    assert.equal(geometry.sandbox, "allow-scripts");
    assert.match(await run.page.$eval(".viewer-artifact-notice-text", (node) => node.textContent), /^This page runs the sender's code\. The sender can tell that you opened it\.$/);

    const state = () => run.page.$eval(".viewer-artifact-notice", (node) => node.dataset.state);
    const activeClass = () => run.page.evaluate(() => document.activeElement?.className ?? "");

    // Keyboard: the notice's own button is the first thing Tab reaches, before the frame.
    await frame.evaluate(() => window.__stopStealing());
    await run.page.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur());
    await run.page.keyboard.press("Tab");
    assert.equal(await activeClass(), "viewer-artifact-notice-dismiss", label("Tab reaches the notice first"));

    // KNOWN LIMIT, recorded: a page that loops focus() and swallows Tab can keep keyboard focus
    // inside its own frame (any iframe can). The person can still click the chrome, and for JSX the
    // recall shortcut below brings focus to the notice. What the page cannot do is dismiss it.
    await frame.evaluate(() => { window.__startStealing(); document.getElementById("thief").focus(); });
    for (let press = 0; press < 3; press += 1) await run.page.keyboard.press("Tab");
    console.log(`KNOWN-LIMIT (${kind}): keyboard focus held by a focus-looping frame: active=${await activeClass()}`);

    // Forged messages from INSIDE the frame, through the bridge and straight at the top window,
    // then the keys a person might press next. Nothing may dismiss the notice.
    await frame.evaluate(() => window.__stopStealing());
    await frame.evaluate(() => window.__forgeMessages());
    await sleep(400);
    assert.equal(await state(), "open", label("a message from the frame must not dismiss the notice"));
    if (kind === "jsx") {
      // The bridge passes a bare restore-controls on; the viewer moves focus to the notice itself, never a button.
      assert.equal(await activeClass(), "viewer-artifact-notice", label("a frame-triggered reveal focuses the notice, not a button"));
    }
    assert.notEqual(await run.page.evaluate(() => document.activeElement?.tagName), "BUTTON", label("focus is not on a button after a frame message"));
    for (const key of ["Space", "Enter", "Space"]) {
      await run.page.keyboard.press(key);
      await sleep(100);
    }
    assert.equal(await state(), "open", label("Space/Enter after a forged frame message must not dismiss the notice"));
    // A burst is limited to one reveal a second and never dismisses.
    for (let burst = 0; burst < 5; burst += 1) await frame.evaluate(() => window.__forgeMessages());
    await sleep(300);
    for (const key of ["Space", "Enter"]) await run.page.keyboard.press(key);
    assert.equal(await state(), "open", label("a burst of forged messages must not dismiss the notice"));

    // The person's own Tab then Space is what dismisses it. (An HTML page has no reveal path, so
    // focus is still in its frame: the person clicks out of it first.)
    if (kind === "html") await run.page.click(".viewer-artifact-notice-text");
    await run.page.keyboard.press("Tab");
    assert.equal(await activeClass(), "viewer-artifact-notice-dismiss", label("Tab from the notice reaches the button"));
    await run.page.keyboard.press("Space");
    assert.equal(await state(), "collapsed", label("a deliberate key press on the button dismisses it"));
    assert.ok(await run.page.$eval(".viewer-artifact-notice-recall", (node) => node.getBoundingClientRect().height >= 44 && !node.hidden), label("still reachable after dismissal"));
    await sleep(1100);
    await frame.evaluate(() => window.__forgeMessages());
    await sleep(300);
    assert.notEqual(await run.page.evaluate(() => document.activeElement?.className), "viewer-artifact-notice-dismiss", label("no frame path focuses the dismiss button"));

    if (kind === "jsx") {
      // The recall shortcut, typed with focus in the frame, is captured before any artifact
      // listener and brings the person to the notice (not to a button).
      await run.page.keyboard.press("Tab");
      await frame.evaluate(() => document.getElementById("thief").focus());
      await sleep(1100);
      await run.page.keyboard.down("Alt");
      await run.page.keyboard.down("Shift");
      await run.page.keyboard.press("KeyC");
      await run.page.keyboard.up("Shift");
      await run.page.keyboard.up("Alt");
      await run.page.waitForFunction(() => document.activeElement?.className === "viewer-artifact-notice", { timeout: 5_000 });
      assert.equal(await state(), "open");
    }
    await run.page.click(".viewer-artifact-notice-recall").catch(() => undefined);
    await shot(run.page, `${kind}-hostile-chrome`);
    await run.page.close();
  }

  // --- Viewer privacy: nothing remote may load -----------------------------
  const staying = ["img", "imageConstructor", "video", "audio", "cssUrl", "cssImport", "fontFace", "linkStylesheet", "linkPrefetch", "sendBeacon", "xhr", "webSocket", "eventSource"];
  {
    await freshBeacon();
    const run = await open("privacy.jsx", { query: `&probes=${staying.join(",")}` });
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 40_000 });
    const { outcomes, violations } = JSON.parse(await frame.$eval("#report", (node) => node.textContent));
    for (const probe of ["img", "imageConstructor", "video", "audio", "linkStylesheet", "linkPrefetch", "xhr", "webSocket", "eventSource"]) {
      assert.notEqual(outcomes[probe], "load", `${probe} loaded a remote resource`);
      assert.notEqual(outcomes[probe], "open", `${probe} opened a remote connection`);
      assert.notEqual(outcomes[probe], "loadedmetadata", `${probe} loaded remote media`);
    }
    // sendBeacon returns true when it queues the request; CSP refuses the send itself (connect-src, below).
    for (const directive of ["img-src", "media-src", "style-src", "font-src", "connect-src"]) {
      assert.ok(violations.some((entry) => entry.startsWith(directive)), `no ${directive} violation reported: ${violations}`);
    }
    await sleep(800);
    console.log("privacy probes (staying):", JSON.stringify(outcomes));
    console.log("privacy violations:", JSON.stringify(violations));
    assert.deepEqual(beacon.requests, [], "a remote load reached the loopback beacon");
    assert.equal(beacon.connections, 0, "a connection reached the loopback beacon (preconnect?)");
    assert.equal(beacon.upgrades, 0);
    assert.equal(beacon.udpPackets, 0);
    await run.page.close();
  }

  // --- Leak vectors: NOTHING may reach the loopback listener ------------------
  // Every browser-initiated request the frame's CSP does not govern (prerender, prefetch, preconnect, dns-prefetch,
  // modulepreload, <a ping>, <img>, <form>, <meta refresh>, window.open, WebRTC, fetch, import(), CSS url()/@import/image-set),
  // through React elements and through every DOM insertion path the page has. The frame's runtime refuses them
  // (src/artifact/jsx-runtime/url-guard.ts); the listener saw nothing at all: no request, no connection, no UDP packet.
  {
    await freshBeacon();
    const run = await open("leak-vectors.jsx");
    const lastVectors = [];
    run.page.on("console", (message) => { if (message.text().startsWith("leak-vector ")) lastVectors.push(message.text()); });
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 90_000 }).catch((error) => { throw new Error(`the leak-vector page stopped after ${lastVectors.slice(-3).join(" | ")}: ${error.message}`); });
    const { outcomes, violations } = JSON.parse(await frame.$eval("#report", (node) => node.textContent));
    await sleep(1500);
    assert.equal(outcomes.webrtc, "removed", "WebRTC is still there");
    for (const name of ["fetch", "xhr", "import", "sendBeacon"]) assert.notEqual(outcomes[name], "loaded", name);
    // The declared elements: none that fetches is in the document.
    const declared = await frame.$$eval("#declared *", (nodes) => nodes.map((node) => `${node.localName} ${node.getAttribute("href") ?? node.getAttribute("src") ?? node.getAttribute("data") ?? node.getAttribute("action") ?? node.getAttribute("ping") ?? ""}`).filter((text) => /127\.0\.0\.1/.test(text)));
    assert.deepEqual(declared, [], "a JSX element that names the listener is in the document");
    const inHead = await frame.evaluate(() => [...document.querySelectorAll("link, meta[http-equiv], base, iframe, object, embed")].map((node) => `${node.localName} ${node.getAttribute("href") ?? node.getAttribute("src") ?? ""}`).filter((text) => /127\.0\.0\.1/.test(text)));
    assert.deepEqual(inHead, [], "an element that names the listener is still in the document");
    console.log(`leak vectors: ${Object.keys(outcomes).length} DOM vectors, ${violations.length} CSP violation kinds (${violations.join(",")}); listener: requests=${beacon.requests.length} tcp=${beacon.connections} upgrades=${beacon.upgrades} udp=${beacon.udpPackets}`);
    assert.deepEqual(beacon.requests, [], `a vector reached the listener: ${JSON.stringify(beacon.requests)}`);
    assert.equal(beacon.connections, 0, "a vector opened a connection to the listener (preconnect?)");
    assert.equal(beacon.upgrades, 0);
    assert.equal(beacon.udpPackets, 0, "a vector sent UDP to the listener (WebRTC?)");
    await run.page.close();
  }
  // Chromium caps the speculative loads (prerender, preconnect) it starts per page, so a few leaks in one page can hide the rest:
  // the DOM-path vectors also run in groups, one fresh page and one fresh listener each, and every group must see nothing.
  for (const group of ["x-cd,x-comment,x-doctype", "x-attr,x-set", "x-link,x-toggle,x-xhtml,x-createElementNS", "x-replace,x-insert,x-range,x-fragment,x-template,x-import,x-adopt,x-clone", "x-outer,x-inner,x-setHTML,x-create,x-exec", "x-shadow", "x-dsd,x-document,x-custom,x-move", "x-xslt,x-observer,x-spec,x-web,x-adopted"]) {
    await freshBeacon();
    const run = await open("leak-vectors.jsx", { query: `&probes=only:${group}` });
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 60_000 }).catch((error) => { throw new Error(`leak vectors ${group}: the page stopped: ${error.message}`); });
    await sleep(1200);
    assert.deepEqual(beacon.requests, [], `vectors ${group}: reached the listener: ${JSON.stringify(beacon.requests)}`);
    assert.equal(beacon.connections, 0, `vectors ${group}: opened a connection to the listener`);
    assert.equal(beacon.upgrades + beacon.udpPackets, 0, `vectors ${group}: upgrade or UDP`);
    await run.page.close();
  }
  // The one class still measured to leak: the page tries to navigate itself.
  {
    await freshBeacon();
    const run = await open("leak-vectors.jsx", { query: "&probes=navigation" });
    await sleep(6000);
    console.log(`KNOWN-LEAK (navigation attempts; not blockable from inside the frame): http requests=${JSON.stringify(beacon.requests)} tcp connections=${beacon.connections} udp packets=${beacon.udpPackets}`);
    assert.deepEqual(beacon.requests, [], "a navigation attempt sent an HTTP request");
    assert.equal(beacon.udpPackets, 0);
    await run.page.close();
  }

  for (const probe of ["object", "embed"]) {
    await freshBeacon();
    const run = await open("privacy.jsx", { query: `&probes=${probe}` });
    await sleep(3500);
    assert.deepEqual(beacon.requests, [], `${probe}: reached the loopback beacon`);
    assert.equal(beacon.connections, 0, `${probe}: connected to the loopback beacon`);
    assert.equal(new URL(run.page.url()).pathname, "/test/fixtures/jsx-harness.html");
    await run.page.close();
  }

  // Documented known leaks (docs/jsx-artifact-sharing.md). CSP does not
  // govern resource hints, and Chromium opens a TCP connection for a frame
  // navigation attempt before the frame-src block applies; the navigation
  // itself is refused, so no HTTP request arrives. Connection counts are
  // observed and printed, not asserted, so a browser change in either
  // direction does not break the suite. What IS asserted: no HTTP request
  // reaches the beacon, except the prerender hint's GET (NoStatePrefetch).
  for (const probe of ["iframe", "metaRefresh", "locationAssign", "linkPreconnect", "linkDnsPrefetch", "linkPrerender", "webrtc"]) {
    const run = await open("privacy.jsx", { query: `&probes=${probe}` });
    await sleep(3500);
    console.log(`KNOWN-LEAK (observed; CSP does not stop it) ${probe}: http requests=${JSON.stringify(beacon.requests)} tcp connections=${beacon.connections} udp packets=${beacon.udpPackets}`);
    if (probe !== "linkPrerender") assert.deepEqual(beacon.requests, [], `${probe}: an HTTP request reached the beacon`);
    // A prerender can send an HTTP GET to the author's address with author-chosen data; nothing else may.
    else assert.ok(beacon.requests.every((url) => url === "/link-prerender?data=author-chosen-value"), `prerender: unexpected requests ${JSON.stringify(beacon.requests)}`);
    assert.equal(new URL(run.page.url()).pathname, "/test/fixtures/jsx-harness.html");
    await run.page.close();
  }

  console.log("JSX artifact browser e2e passed");
} finally {
  await browser?.close();
  server.kill("SIGTERM");
  beacon.server.closeAllConnections();
  beacon.server.close();
  beacon.udp.close();
}
