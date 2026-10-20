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
    assert.match(panel, /canvas-confetti isn't available/);
    assert.match(panel, /Available: react, react-dom, react-dom\/client, react\/jsx-runtime, lucide-react, recharts, d3, mermaid/);
    assert.equal(await run.page.$("iframe"), null, "no frame left after an import error");
    await shot(run.page, "jsx-unknown-import");
    await run.page.close();

    const syntax = await open("syntax-error.jsx", { scheme: "dark" });
    const text = await syntax.page.$eval(".viewer-jsx-panel", (node) => node.textContent);
    assert.match(text, /syntax error/);
    assert.match(text, /Line 5/);
    assert.equal(await syntax.page.$("iframe"), null);
    assert.equal(await syntax.page.$eval(".viewer-jsx-panel-download", (node) => node.getAttribute("download")), "syntax-error.jsx");
    await shot(syntax.page, "jsx-syntax-error-dark");
    await syntax.page.close();
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
  {
    const run = await open("hostile-chrome.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 20_000 });
    await sleep(600);
    const { results } = JSON.parse(await frame.$eval("#report", (node) => node.textContent));
    // No fullscreen, no Picture-in-Picture: the sandbox documents' Permissions-Policy forbids both.
    assert.equal(results.fullscreenEnabled, false, "fullscreen must be unavailable inside the frame");
    assert.equal(results.pictureInPictureEnabled, false, "Picture-in-Picture must be unavailable inside the frame");
    assert.ok(/^(?:rejected|threw)/.test(results.fullscreenRequest) || results.fullscreenRequest === "pending", `fullscreen request: ${results.fullscreenRequest}`);
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
    assert.ok(geometry.noticeVisible, "the notice is visible");
    assert.ok(geometry.noticeHit, "elementFromPoint at the notice text returns the notice");
    assert.ok(geometry.dismissHit, "elementFromPoint at the dismiss button returns the button");
    assert.ok(geometry.frameHit, "the frame is still the topmost thing over its own box");
    assert.ok(geometry.noticeRect.y + geometry.noticeRect.h <= geometry.frameRect.y + 0.5, "the notice and the frame do not overlap");
    assert.ok(["hidden", "clip"].includes(geometry.frameStyle.overflow), `frame overflow ${geometry.frameStyle.overflow}`);
    assert.equal(geometry.frameStyle.isolation, "isolate");
    assert.ok(Number(geometry.noticeZ) > Number(geometry.frameStyle.zIndex), "the notice stacks above the frame");
    assert.equal(geometry.allowAttr, "");
    assert.equal(geometry.allowFullscreenAttr, false);
    assert.equal(geometry.sandbox, "allow-scripts");
    assert.match(await run.page.$eval(".viewer-artifact-notice-text", (node) => node.textContent), /^This page runs the sender's code\. The sender can tell that you opened it\.$/);

    // Keyboard: the notice is the first thing Tab reaches, before the frame.
    await run.page.evaluate(() => document.activeElement instanceof HTMLElement && document.activeElement.blur());
    await run.page.keyboard.press("Tab");
    assert.equal(await run.page.evaluate(() => document.activeElement.className), "viewer-artifact-notice-dismiss");

    // A frame that swallows Tab and steals focus cannot keep the user from the chrome:
    // the recall shortcut is captured first and only reveals the notice and focuses it.
    await frame.click("#thief").catch(() => undefined);
    await frame.evaluate(() => document.getElementById("thief").focus());
    for (let press = 0; press < 3; press += 1) await run.page.keyboard.press("Tab");
    assert.notEqual(await run.page.evaluate(() => document.activeElement?.className), "viewer-artifact-notice-dismiss", "the frame trapped Tab (the test's premise)");
    await run.page.keyboard.down("Alt");
    await run.page.keyboard.down("Shift");
    await run.page.keyboard.press("KeyC");
    await run.page.keyboard.up("Shift");
    await run.page.keyboard.up("Alt");
    await run.page.waitForFunction(() => document.activeElement?.className === "viewer-artifact-notice-dismiss", { timeout: 5_000 });

    // Only a user's click dismisses it; messages from the frame cannot.
    await frame.evaluate(() => {
      for (const data of [{ v: 1, type: "dismiss" }, { v: 1, type: "restore-controls", nonce: "0".repeat(32) }, { type: "restore-controls" }]) window.top.postMessage(data, "*");
    });
    await run.page.mouse.click(geometry.noticeRect.x + 5, geometry.noticeRect.y + geometry.noticeRect.h / 2);
    await run.page.click(".viewer-artifact-notice-dismiss");
    assert.equal(await run.page.$eval(".viewer-artifact-notice", (node) => node.dataset.state), "collapsed");
    await frame.evaluate(() => {
      for (const data of [{ v: 1, type: "restore-controls", nonce: "0".repeat(32) }, { type: "restore-controls" }, { v: 1, type: "bridge-ready" }]) window.top.postMessage(data, "*");
    });
    await sleep(300);
    assert.equal(await run.page.$eval(".viewer-artifact-notice", (node) => node.dataset.state), "collapsed", "a forged message from the frame must not touch the notice");
    // Still reachable after dismissal.
    assert.ok(await run.page.$eval(".viewer-artifact-notice-recall", (node) => node.getBoundingClientRect().height >= 44 && !node.hidden));
    await run.page.click(".viewer-artifact-notice-recall");
    assert.equal(await run.page.$eval(".viewer-artifact-notice", (node) => node.dataset.state), "open");
    await shot(run.page, "jsx-hostile-chrome");
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
    console.log(`KNOWN-LEAK (observed, not blocked by CSP) ${probe}: http requests=${JSON.stringify(beacon.requests)} tcp connections=${beacon.connections} udp packets=${beacon.udpPackets}`);
    if (probe !== "linkPrerender") assert.deepEqual(beacon.requests, [], `${probe}: an HTTP request reached the beacon`);
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
