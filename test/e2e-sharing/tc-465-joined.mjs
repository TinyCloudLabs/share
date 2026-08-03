#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";
import { privateKeyToAccount } from "viem/accounts";

const shareRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/skgbafa/tc-470-holder-credential-admission");
const sdkRoot = process.env.TINYCLOUD_JS_SDK_WORKTREE ?? join(workspaceRoot, "worktrees/js-sdk/skgbafa/tc-470-policy-credential-presentation");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? join(workspaceRoot, "worktrees/opencredentials/skgbafa/tc-462-credential-flow-opencredentials-785732297208");
const credentialsManifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
const credentialsApp = join(credentialsRoot, "apps/open-credentials");
const canonical = { share: "https://share.tinycloud.xyz", node: "https://node.tinycloud.xyz", witness: "https://witness.credentials.org", interaction: "https://credentials.org", openKey: "https://openkey.so" };
const expectedContent = await readFile(join(shareRoot, "test/e2e-sharing/fixture.md"), "utf8");
const wallet = privateKeyToAccount(`0x${"55".repeat(32)}`);
const requests = [];
const installedPages = new WeakSet();
let integration;
let fixture;
let browser;

function run(command, args, cwd, env = {}) {
  execFileSync(command, args, { cwd, env: { ...process.env, ...env }, stdio: "inherit" });
}

async function waitForFile(path, child, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { await stat(path); return; } catch (error) { if (error?.code !== "ENOENT") throw error; }
    if (child.exitCode !== null) throw new Error(`composition exited before ${path} was published (${child.exitCode})`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`timed out waiting for ${path}`);
}

function headersForFetch(request, forwardedHttps = false) {
  const headers = new Headers(request.headers());
  for (const name of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"]) headers.delete(name);
  if (forwardedHttps) headers.set("x-forwarded-proto", "https");
  return headers;
}

async function proxy(request, targetOrigin, options = {}) {
  const original = new URL(request.url());
  const target = new URL(`${original.pathname}${original.search}`, targetOrigin);
  const method = request.method();
  const response = await fetch(target, {
    method,
    headers: headersForFetch(request, options.forwardedHttps),
    redirect: "manual",
    ...(method === "GET" || method === "HEAD" ? {} : { body: request.postDataBuffer() }),
  });
  const headers = Object.fromEntries(response.headers.entries());
  const setCookie = response.headers.getSetCookie?.()[0] ?? response.headers.get("set-cookie");
  if (setCookie !== null && setCookie !== undefined) headers["set-cookie"] = setCookie;
  if (options.cors) {
    const origin = request.headers().origin;
    if (origin === canonical.share || origin === canonical.interaction) {
      headers["access-control-allow-origin"] = origin;
      headers["access-control-allow-credentials"] = "true";
      headers["access-control-allow-methods"] = "GET, POST, OPTIONS";
      headers["access-control-allow-headers"] = "authorization, content-type";
      headers.vary = "Origin";
    }
  }
  await request.respond({ status: response.status, headers, body: Buffer.from(await response.arrayBuffer()) });
}

const contentTypes = { ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".wasm": "application/wasm", ".png": "image/png", ".ico": "image/x-icon" };

async function serveCredentialsApp(request) {
  const path = new URL(request.url()).pathname;
  const requested = path === "/" ? "index.html" : path.slice(1);
  const file = requested.startsWith("assets/") || extname(requested) !== "" ? join(credentialsApp, "dist", requested) : join(credentialsApp, "dist/index.html");
  let body;
  try { body = await readFile(file); } catch { body = await readFile(join(credentialsApp, "dist/index.html")); }
  await request.respond({ status: 200, headers: { "content-type": contentTypes[extname(file)] ?? "text/html; charset=utf-8", "cache-control": "no-store" }, body });
}

async function installInterception(page, services, fixtureOrigin) {
  if (installedPages.has(page)) return;
  installedPages.add(page);
  await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    if (url.origin === canonical.share && url.pathname === "/__tc465/wallet/sign") return proxy(request, services.walletOrigin);
    if (url.origin === canonical.share) return proxy(request, services.shareOrigin, { forwardedHttps: true });
    if (url.origin === canonical.node) return proxy(request, services.nodeOrigin);
    if (url.origin === canonical.witness) {
      if (request.method() === "OPTIONS") return request.respond({ status: 204, headers: { "access-control-allow-origin": request.headers().origin ?? canonical.share, "access-control-allow-credentials": "true", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "authorization, content-type", vary: "Origin" } });
      return proxy(request, fixtureOrigin, { cors: true });
    }
    if (url.origin === canonical.interaction) return serveCredentialsApp(request);
    if (url.origin === canonical.openKey) return proxy(request, services.openKeyOrigin);
    if (url.protocol === "data:" || url.protocol === "blob:" || url.origin === "null") return request.continue();
    throw new Error(`unexpected browser destination ${url.origin}${url.pathname}`);
  })().catch((error) => request.abort("blockedbyclient").finally(() => { console.error(error instanceof Error ? error.message : String(error)); })); });
  page.on("response", (response) => {
    const url = new URL(response.url());
    requests.push({ method: response.request().method(), origin: url.origin, path: url.pathname, status: response.status() });
  });
  await page.evaluateOnNewDocument((address, shareOrigin) => {
    const originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function attachShadow(init) { return originalAttachShadow.call(this, { ...init, mode: "open" }); };
    const provider = {
      selectedAddress: address, chainId: "0x1",
      request: async ({ method, params }) => {
        if (method === "eth_accounts" || method === "eth_requestAccounts") return [address];
        if (method === "eth_chainId") return "0x1";
        if (method === "wallet_getPermissions" || method === "wallet_requestPermissions") return [{ parentCapability: "eth_accounts" }];
        if (method === "personal_sign") {
          const raw = String(params?.[0] ?? "");
          const bytes = raw.startsWith("0x") ? Uint8Array.from((raw.slice(2).match(/.{1,2}/g) ?? []).map((value) => Number.parseInt(value, 16))) : undefined;
          const message = bytes === undefined ? raw : new TextDecoder().decode(bytes);
          const response = await fetch(`${shareOrigin}/__tc465/wallet/sign`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message }) });
          return (await response.json()).signature;
        }
        return null;
      },
      on: () => provider, removeListener: () => provider, isConnected: () => true,
    };
    const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" }, provider } }));
    Object.defineProperty(window, "ethereum", { configurable: true, value: provider });
    window.addEventListener("eip6963:requestProvider", announce);
    setTimeout(announce, 0);
  }, wallet.address, canonical.share);
}

async function text(page) { return page.evaluate(() => document.body?.innerText ?? ""); }
async function waitForText(page, value, timeout = 180_000) { await page.waitForFunction((expected) => document.body?.innerText.includes(expected), { timeout }, value); }
async function clickText(page, value, optional = false) {
  const clicked = await page.evaluate((expected) => {
    const visit = (root) => {
      for (const element of root.querySelectorAll("button,[role=button],a")) {
        if ((element.textContent ?? "").trim().includes(expected) && !element.disabled) { element.click(); return true; }
        if (element.shadowRoot && visit(element.shadowRoot)) return true;
      }
      return false;
    };
    return visit(document);
  }, value);
  if (!clicked && !optional) throw new Error(`action not found: ${value}`);
  return clicked;
}

async function main() {
  const control = await mkdtemp(join(tmpdir(), "tinycloud-tc465-"));
  await chmod(control, 0o700);
  try {
    run("npm", ["run", "link:web-sdk"], shareRoot, { TINYCLOUD_JS_SDK_WORKTREE: sdkRoot });
    run("npm", ["run", "build"], credentialsApp, { VITE_WITNESS_URL: canonical.witness });
    run("cargo", ["build", "--quiet", "--manifest-path", credentialsManifest, "--features", "email-claim-fixture", "--bin", "credential-acquisition-fixture"], credentialsRoot);
    fixture = spawn(join(credentialsRoot, "rust/opencredentials_witness/target/debug/credential-acquisition-fixture"), [], { cwd: credentialsRoot, stdio: ["ignore", "pipe", "inherit"] });
    const fixtureOrigin = await new Promise((resolveOrigin, reject) => {
      let output = "";
      fixture.stdout.on("data", (chunk) => { output += String(chunk); const line = output.split("\n").find((candidate) => candidate.trim().startsWith("{")); if (line) resolveOrigin(JSON.parse(line).url); });
      fixture.once("exit", (code) => reject(new Error(`credential fixture exited (${code})`)));
      setTimeout(() => reject(new Error("credential fixture readiness timeout")), 30_000);
    });
    const compositionEnv = {
      ...process.env,
      SHARING_E2E_TC465_JOINED: "1",
      SHARING_E2E_LOCAL_UNPUSHED: "1",
      SHARING_E2E_EXTERNAL_CONTROL_DIR: control,
      SHARING_E2E_ARTIFACT_PATH: process.env.SHARING_E2E_ARTIFACT_PATH ?? join(workspaceRoot, ".context/tc-465-joined.json"),
      TINYCLOUD_NODE_WORKTREE: nodeRoot,
      TINYCLOUD_JS_SDK_WORKTREE: sdkRoot,
      OPENCREDENTIALS_WORKTREE: credentialsRoot,
    };
    integration = spawn(process.execPath, [join(shareRoot, "test/e2e-sharing/integration.mjs")], { cwd: shareRoot, env: compositionEnv, stdio: ["ignore", "inherit", "inherit"] });
    await waitForFile(join(control, "services.json"), integration, 600_000);
    const services = JSON.parse(await readFile(join(control, "services.json"), "utf8"));

    browser = await puppeteer.launch({ headless: true, args: ["--disable-popup-blocking", "--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1,MAP node.tinycloud.xyz 127.0.0.1,MAP witness.credentials.org 127.0.0.1,MAP credentials.org 127.0.0.1,MAP openkey.so 127.0.0.1"] });
    browser.on("targetcreated", (target) => { void target.page().then((page) => page === null ? undefined : installInterception(page, services, fixtureOrigin)).catch(() => undefined); });
    const page = await browser.newPage();
    await installInterception(page, services, fixtureOrigin);
    await page.goto(`${canonical.share}/share.html`, { waitUntil: "networkidle2", timeout: 180_000 });
    await clickText(page, "Sign in");
    await new Promise((resolveWait) => setTimeout(resolveWait, 800));
    await clickText(page, "TinyCloud E2E Wallet");
    await waitForText(page, "Shared by me.");
    await clickText(page, "New share");
    await waitForText(page, "Share a file");
    await page.evaluate(() => { window.__tc465Copied = null; Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (value) => { window.__tc465Copied = value; return Promise.resolve(); } } }); });
    await page.click("input[value=exactEmail]");
    await page.type("input[name=recipient-value]", "sam@tinycloud.xyz");
    const upload = await page.$("input[name=document]");
    assert(upload, "share upload control is missing");
    await upload.uploadFile(join(shareRoot, "test/e2e-sharing/fixture.md"));
    await page.click("button.create-link-button");
    await waitForText(page, "Your private link is ready");
    await clickText(page, "Copy link");
    const shareUrl = await page.evaluate(() => window.__tc465Copied);
    assert.match(shareUrl, /^https:\/\/share\.tinycloud\.xyz\/s\/bafkrei[a-z2-7]{52}/);
    const shareCid = new URL(shareUrl).pathname.split("/").at(-1);
    const binding = await page.evaluate(async (cid) => { const response = await fetch(`/.well-known/tinycloud-share/bindings/${cid}.json`, { cache: "no-store" }); return { status: response.status, body: await response.json() }; }, shareCid);
    assert.equal(binding.status, 200);
    assert.equal(binding.body.version, 3);
    assert.equal(binding.body.shareCid, shareCid);

    const popupTarget = browser.waitForTarget((target) => target.url().startsWith(`${canonical.interaction}/credentials/acquire/`), { timeout: 180_000 });
    await page.goto(shareUrl, { waitUntil: "networkidle2", timeout: 180_000 });
    await waitForText(page, "Confirm your email to open this");
    await page.click("button.viewer-primary-action");
    await new Promise((resolveWait) => setTimeout(resolveWait, 800));
    await clickText(page, "TinyCloud E2E Wallet", true);
    const target = await popupTarget;
    const popup = await target.page();
    assert(popup, "credential popup page is missing");
    await installInterception(popup, services, fixtureOrigin);
    const popupUrl = target.url();
    if (!popupUrl.startsWith(`${canonical.interaction}/credentials/acquire/`) || (await text(popup)).length === 0) await popup.goto(popupUrl, { waitUntil: "networkidle2" });
    const acquisitionCookies = await browser.defaultBrowserContext().cookies(canonical.witness);
    const requestCookie = acquisitionCookies.find((cookie) => cookie.name === "oc_acquisition");
    assert(requestCookie?.httpOnly && requestCookie.secure && requestCookie.sameSite === "None" && requestCookie.domain === "witness.credentials.org", "acquisition cookie did not retain canonical HttpOnly/Secure/SameSite=None semantics");
    await popup.waitForSelector("input[name=otp]", { timeout: 60_000 });
    await popup.type("input[name=otp]", "246810");
    await popup.click("button[type=submit]");

    const renderedNeedle = "This file is a deterministic hermetic upload fixture.";
    await page.waitForFunction((needle) => document.body?.innerText.includes(needle) || [...document.querySelectorAll("iframe")].some((frame) => frame.contentDocument?.body?.innerText.includes(needle)), { timeout: 180_000 }, renderedNeedle);
    const rendered = await page.evaluate((needle) => document.body?.innerText.includes(needle) || [...document.querySelectorAll("iframe")].some((frame) => frame.contentDocument?.body?.innerText.includes(needle)), renderedNeedle);
    assert.equal(rendered, true, `final rendered content was missing: ${(await text(page)).slice(-1000)}`);

    const successful = (path) => requests.some((entry) => (typeof path === "string" ? entry.path === path : path.test(entry.path)) && entry.status >= 200 && entry.status < 300);
    const statuses = {
      policyV3Mint: successful("/share/v3/policy/delegations"),
      delegate: successful("/delegate"),
      invoke: successful("/invoke"),
      decrypt: successful(/^\/encryption\/networks\/[^/]+\/decrypt$/),
      rendered,
    };
    assert.deepEqual(statuses, { policyV3Mint: true, delegate: true, invoke: true, decrypt: true, rendered: true });
    const evidence = { type: "tinycloud.share/tc-465-joined-evidence/v1", renderedSha256: createHash("sha256").update(expectedContent).digest("hex"), statuses };
    await writeFile(join(control, "tc465-result.json"), JSON.stringify(evidence), { flag: "wx", mode: 0o600 });
    await writeFile(join(control, "release"), "ok\n", { flag: "wx", mode: 0o600 });
    const exitCode = await new Promise((resolveExit) => integration.once("exit", resolveExit));
    assert.equal(exitCode, 0, "production-shaped TC-465 composition failed after browser completion");
    console.error(`TC-465 joined exact-email receiver: PASS ${JSON.stringify(evidence)}`);
  } finally {
    await browser?.close().catch(() => undefined);
    if (fixture?.exitCode === null) fixture.kill("SIGTERM");
    if (integration?.exitCode === null) integration.kill("SIGTERM");
    await rm(control, { recursive: true, force: true });
  }
}

await main();
