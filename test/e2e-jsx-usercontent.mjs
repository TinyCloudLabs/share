/**
 * Browser e2e for the SEPARATE user-content origin deployment.
 *
 * Builds dist-usercontent (viewer origin = the harness origin), serves it from a
 * second loopback origin with its own `_headers` applied (same parser as the
 * production-origin gate), and runs the viewer harness with
 * VITE_USER_CONTENT_ORIGIN pointing at it. The harness response carries the
 * viewer's real `frame-src` and `connect-src` for that origin. Proves: frames
 * and library files come from the user-content origin, CORS is scoped to the
 * viewer, a foreign page can neither frame the documents nor read the files,
 * the host sets no cookie, and the sandbox is still opaque ("null") and
 * network-less from there.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";

import puppeteer from "puppeteer";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";

async function freePort() {
  const probe = createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}
const viewerPort = await freePort();
const contentPort = await freePort();
const viewerOrigin = `http://127.0.0.1:${viewerPort}`;
const contentOrigin = `http://127.0.0.1:${contentPort}`;
const root = await mkdtemp(join(tmpdir(), "usercontent-e2e-"));

// 1. Build the deployment under test with the viewer origin it will be framed by.
await new Promise((resolve, reject) => {
  const build = spawn("npx", ["tsx", "scripts/build-usercontent.mts"], {
    env: { ...process.env, USER_CONTENT_VIEWER_ORIGIN: viewerOrigin },
    stdio: ["ignore", "inherit", "inherit"],
  });
  build.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`build:usercontent exited ${code}`))));
});

// 2. Serve it as Pages would: static files, `_headers` applied, nothing else, no cookies.
const rules = parseProductionHeaders(await readFile("dist-usercontent/_headers", "utf8"));
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json" };
const contentLog = [];
const contentServer = createServer(async (request, response) => {
  const url = new URL(request.url, contentOrigin);
  contentLog.push({ path: url.pathname, origin: request.headers.origin ?? null, cookie: request.headers.cookie ?? null });
  const headers = productionHeadersForPath(rules, url.pathname);
  try {
    if (request.method !== "GET" || url.pathname.includes("..") || url.pathname === "/_headers") throw new Error("not served");
    const body = await readFile(join("dist-usercontent", url.pathname));
    response.writeHead(200, { ...headers, "content-type": TYPES[extname(url.pathname)] ?? "text/plain" });
    response.end(body);
  } catch {
    response.writeHead(404, headers);
    response.end("not found");
  }
});
await new Promise((resolve) => contentServer.listen(contentPort, "127.0.0.1", resolve));

// A third origin: a hostile page that tries to frame the documents and read the files.
const foreignServer = createServer((request, response) => {
  response.writeHead(200, { "content-type": "text/html" });
  response.end(`<!doctype html><iframe id="f" src="${contentOrigin}/jsx-sandbox.html#${"0".repeat(32)}"></iframe>`);
});
await new Promise((resolve) => foreignServer.listen(0, "127.0.0.1", resolve));
const foreignOrigin = `http://127.0.0.1:${foreignServer.address().port}`;

// 3. The viewer harness, built for that origin.
const vitePort = await freePort();
const vite = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", String(vitePort), "--strictPort"], {
  env: { ...process.env, VITE_USER_CONTENT_ORIGIN: contentOrigin },
  stdio: ["ignore", "pipe", "pipe"],
});
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
for (let tries = 0; tries < 200; tries += 1) {
  try { if ((await fetch(`http://127.0.0.1:${vitePort}/test/fixtures/jsx-harness.html`)).ok) break; } catch { /* starting */ }
  await sleep(150);
}
// The viewer origin: the dev server behind a proxy that gives the harness document the
// viewer's real frame-src/connect-src for the user-content origin (same function the build uses).
const { withUserContentOrigin } = await import("../src/artifact/user-content/headers.ts");
const siteWideCsp = /Content-Security-Policy: (.*)/.exec(await readFile("public/_headers", "utf8"))[1];
const directives = withUserContentOrigin(siteWideCsp, contentOrigin).split("; ").filter((part) => /^(?:frame-src|connect-src) /.test(part));
const viewerServer = createServer(async (request, response) => {
  const upstream = await fetch(`http://127.0.0.1:${vitePort}${request.url}`, { headers: { accept: request.headers.accept ?? "*/*" } });
  const headers = Object.fromEntries([...upstream.headers].filter(([name]) => !["content-encoding", "content-length", "transfer-encoding"].includes(name)));
  if (new URL(request.url, viewerOrigin).pathname === "/test/fixtures/jsx-harness.html") headers["content-security-policy"] = directives.join("; ");
  response.writeHead(upstream.status, headers);
  response.end(Buffer.from(await upstream.arrayBuffer()));
});
await new Promise((resolve) => viewerServer.listen(viewerPort, "127.0.0.1", resolve));

let browser;
try {
  browser = await puppeteer.launch({ headless: true });

  async function open(fixture, query = "") {
    const page = await browser.newPage();
    await page.setViewport({ width: 1100, height: 720 });
    const responses = [];
    const requests = [];
    page.on("request", (request) => requests.push({ url: request.url(), frame: request.frame()?.url() ?? "" }));
    page.on("response", (response) => responses.push({ url: response.url(), headers: response.headers() }));
    await page.goto(`${viewerOrigin}/test/fixtures/jsx-harness.html?f=${fixture}${query}`, { waitUntil: "load" });
    await page.waitForFunction(() => document.documentElement.dataset.ready, { timeout: 40_000 });
    return { page, requests, responses };
  }
  async function childFrame(page) {
    for (let tries = 0; tries < 200; tries += 1) {
      const frame = page.frames().find((candidate) => candidate.url() === "about:srcdoc");
      if (frame !== undefined) return frame;
      await sleep(100);
    }
    throw new Error("child frame never appeared");
  }

  // The artifact runs from the user-content origin, interactive and styled.
  {
    const run = await open("counter.jsx");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("[data-testid=count]");
    await frame.click("[data-testid=increment]");
    assert.equal(await frame.$eval("[data-testid=count]", (node) => node.textContent), "1");
    assert.equal(await frame.evaluate(() => getComputedStyle(document.querySelector("[data-testid=increment]")).backgroundColor), "rgb(42, 86, 246)");
    const bridge = run.page.frames().find((candidate) => candidate.url().startsWith(`${contentOrigin}/jsx-sandbox.html`));
    assert.ok(bridge, "the bridge frame is served by the user-content origin");
    assert.equal(await run.page.$eval("iframe.viewer-html-frame", (node) => node.getAttribute("sandbox")), "allow-scripts");
    // Opaque origin even though the host is a real one: sandbox without allow-same-origin.
    assert.equal(await bridge.evaluate(() => self.origin), "null");
    assert.equal(await frame.evaluate(() => self.origin), "null");
    // Library files: from the user-content origin, CORS names the viewer only.
    const files = run.responses.filter((entry) => entry.url.startsWith(`${contentOrigin}/assets/jsx-runtime/`));
    assert.ok(files.length >= 5, `expected library files from the user-content origin, saw ${files.length}`);
    for (const entry of files) {
      assert.equal(entry.headers["access-control-allow-origin"], viewerOrigin);
      assert.match(entry.headers["cache-control"], /immutable/);
    }
    // The viewer origin itself serves no sandbox document or library file.
    assert.deepEqual(run.requests.filter((entry) => entry.url.startsWith(viewerOrigin) && /\/jsx-sandbox(?:\.html)?(?:[#?]|$)|\/assets\/jsx-runtime\//.test(entry.url)), []);
    // The host never set a cookie, and the viewer never sent one.
    for (const entry of run.responses.filter((candidate) => candidate.url.startsWith(contentOrigin))) assert.equal(entry.headers["set-cookie"], undefined);
    assert.deepEqual((await run.page.cookies(contentOrigin)), []);
    assert.ok(contentLog.every((entry) => entry.cookie === null), "the viewer sent a cookie to the user-content origin");
    // Nothing the frame did touched the network.
    assert.deepEqual(run.requests.filter((entry) => entry.frame === "about:srcdoc"), []);
    await run.page.close();
  }

  // Mermaid is the largest file: proves the digest check and CORS fetch at full size.
  {
    const run = await open("diagram.jsx");
    await (await childFrame(run.page)).waitForSelector("[data-testid=diagram] svg", { timeout: 40_000 });
    await run.page.close();
  }

  // The self-check holds from the separate origin too.
  {
    const run = await open("self-check.jsx", "&beacon=http://127.0.0.1:9");
    const frame = await childFrame(run.page);
    await frame.waitForSelector("#report[data-done=yes]", { timeout: 20_000 });
    const { result } = JSON.parse(await frame.$eval("#report", (node) => node.textContent));
    for (const probe of ["parentDocument", "topDocument", "localStorage", "sessionStorage", "indexedDB", "fetchRemote", "fetchSameOrigin", "worker"]) assert.equal(result[probe].ok, false, probe);
    assert.equal(result.origin.value, "null");
    await run.page.close();
  }

  // Error panels are unchanged.
  {
    const run = await open("unknown-import.jsx");
    assert.match(await run.page.$eval(".viewer-jsx-panel", (node) => node.textContent), /canvas-confetti isn't available/);
    await run.page.close();
  }

  // A foreign page cannot frame the documents (frame-ancestors) nor read the files (CORS).
  {
    const page = await browser.newPage();
    const refusals = [];
    page.on("console", (message) => refusals.push(message.text()));
    await page.goto(foreignOrigin, { waitUntil: "load" });
    await sleep(1500);
    assert.ok(refusals.some((text) => /frame-ancestors|Refused to frame|blocked/i.test(text)), `expected a frame-ancestors refusal, got ${JSON.stringify(refusals)}`);
    const manifest = JSON.parse(await readFile("dist-usercontent/manifest.json", "utf8"));
    const url = `${contentOrigin}${manifest.files.react.url}`;
    const readable = await page.evaluate(async (target) => {
      try { return (await fetch(target, { mode: "cors", credentials: "omit" })).ok; } catch { return "blocked"; }
    }, url);
    assert.equal(readable, "blocked", "a foreign origin must not be able to read library files");
    const viewerPage = await browser.newPage();
    await viewerPage.goto(`${viewerOrigin}/test/fixtures/jsx-harness.html?f=card.jsx`, { waitUntil: "load" });
    const fromViewer = await viewerPage.evaluate(async (target) => { try { return (await fetch(target, { mode: "cors", credentials: "omit" })).ok; } catch { return "blocked"; } }, url);
    assert.equal(fromViewer, true, "the viewer origin must be able to read library files");
    await page.close();
    await viewerPage.close();
  }

  console.log("JSX user-content origin browser e2e passed");
} finally {
  await browser?.close();
  vite.kill("SIGTERM");
  viewerServer.close();
  contentServer.close();
  foreignServer.close();
  await rm(root, { recursive: true, force: true });
}
