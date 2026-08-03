#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";
import { Cbor } from "ox";
import { privateKeyToAccount } from "viem/accounts";

const shareRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/skgbafa/tc-470-holder-credential-admission");
const sdkRoot = process.env.TINYCLOUD_JS_SDK_WORKTREE ?? join(workspaceRoot, "worktrees/js-sdk/skgbafa/tc-470-policy-credential-presentation");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? join(workspaceRoot, "worktrees/opencredentials/skgbafa/tc-462-credential-flow-opencredentials-785732297208");
const credentialsManifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
const credentialsApp = join(credentialsRoot, "apps/open-credentials");
const canonical = { share: "https://share.tinycloud.xyz", node: "https://node.tinycloud.xyz", witness: "https://witness.credentials.org", interaction: "https://credentials.org", openKey: "https://openkey.so" };
const expectedBytes = await readFile(join(shareRoot, "test/e2e-sharing/fixture.md"));
const wallet = privateKeyToAccount(`0x${"55".repeat(32)}`);
const receiverRequests = [];
const requestEntries = new WeakMap();
const installedPages = new WeakMap();
let receiverJourneyStarted = false;
let receiverSequence = 0;
let integration;
let fixture;
let browser;
const browserErrors = [];

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
  const target = new URL(`${options.path ?? original.pathname}${original.search}`, targetOrigin);
  const method = request.method();
  const response = await fetch(target, {
    method,
    headers: headersForFetch(request, options.forwardedHttps),
    redirect: "manual",
    ...(method === "GET" || method === "HEAD" ? {} : { body: await request.fetchPostData() }),
  });
  let responseBytes = Buffer.from(await response.arrayBuffer());
  if (options.rewriteNodeCsp === true && response.headers.get("content-type")?.includes("text/html")) {
    responseBytes = Buffer.from(responseBytes.toString("utf8").replaceAll("https://tee.node.tinycloud.xyz", canonical.node));
  }
  if (options.entry !== undefined) {
    options.entry.status = response.status;
    try { options.entry.responseBody = JSON.parse(responseBytes.toString("utf8")); } catch { /* response validation remains with the product client */ }
  }
  if (response.status >= 400) {
    const raw = responseBytes.toString("utf8");
    let code = raw.slice(0, 300)
      .replace(/0x[a-fA-F0-9]{40,}/g, "<address>")
      .replace(/(?:did|tinycloud):[^\s\"']+/g, "<identifier>")
      .replace(/[A-Za-z0-9_-]{32,}/g, "<opaque>");
    try { code = JSON.parse(raw)?.error?.code ?? "json_without_error_code"; } catch { /* sanitized text is useful for local product failures */ }
    browserErrors.push(`response: ${request.method()} ${original.origin}${original.pathname} ${response.status} ${code}`);
  }
  const headers = Object.fromEntries(response.headers.entries());
  for (const name of ["connection", "content-encoding", "content-length", "keep-alive", "transfer-encoding"]) delete headers[name];
  const setCookie = response.headers.getSetCookie?.()[0] ?? response.headers.get("set-cookie");
  if (setCookie !== null && setCookie !== undefined) headers["set-cookie"] = setCookie;
  if (options.cors) {
    const origin = request.headers().origin;
    if (origin === canonical.share || origin === canonical.interaction) {
      headers["access-control-allow-origin"] = origin;
      headers["access-control-allow-credentials"] = "true";
      headers["access-control-allow-methods"] = "GET, POST, OPTIONS";
      headers["access-control-allow-headers"] = request.headers()["access-control-request-headers"] ?? "authorization, content-type";
      headers.vary = "Origin";
    }
  }
  await request.respond({ status: response.status, headers, body: responseBytes });
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
  const existing = installedPages.get(page);
  if (existing !== undefined) return existing;
  let resolveInstallation;
  let rejectInstallation;
  const installation = new Promise((resolveInstall, rejectInstall) => {
    resolveInstallation = resolveInstall;
    rejectInstallation = rejectInstall;
  });
  installedPages.set(page, installation);
  try {
    await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    const headers = request.headers();
    const entry = receiverJourneyStarted ? {
      sequence: ++receiverSequence,
      method: request.method(),
      origin: url.origin,
      path: url.pathname,
      status: undefined,
      body: (() => { const body = request.postData(); if (body === undefined) return undefined; try { return JSON.parse(body); } catch { return body; } })(),
      authorization: headers.authorization,
    } : undefined;
    if (entry !== undefined) { receiverRequests.push(entry); requestEntries.set(request, entry); }
    if (url.origin === canonical.share && url.pathname === "/__tc465/wallet/sign") return proxy(request, services.walletOrigin, { entry, path: "/sign" });
    if (url.origin === canonical.share) return proxy(request, services.shareOrigin, { forwardedHttps: true, entry, rewriteNodeCsp: true });
    if (url.origin === canonical.node) return proxy(request, services.nodeOrigin, { cors: true, entry });
    if (url.origin === canonical.witness) {
      if (request.method() === "OPTIONS") return request.respond({ status: 204, headers: { "access-control-allow-origin": request.headers().origin ?? canonical.share, "access-control-allow-credentials": "true", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "authorization, content-type", vary: "Origin" } });
      return proxy(request, fixtureOrigin, { cors: true, entry });
    }
    if (url.origin === canonical.interaction) return serveCredentialsApp(request);
    if (url.origin === canonical.openKey) return proxy(request, services.openKeyOrigin, { entry });
    if (url.protocol === "data:" || url.protocol === "blob:" || url.origin === "null") return request.continue();
    throw new Error(`unexpected browser destination ${url.origin}${url.pathname}`);
  })().catch((error) => request.abort("blockedbyclient").finally(() => { console.error(error instanceof Error ? error.message : String(error)); })); });
  page.on("response", (response) => { const entry = requestEntries.get(response.request()); if (entry !== undefined) entry.status = response.status(); });
    await page.evaluateOnNewDocument((address, shareOrigin) => {
    window.__tc465Diagnostics = { messages: [], walletAnnouncements: 0, walletRequests: 0 };
    window.addEventListener("message", (event) => window.__tc465Diagnostics.messages.push({ origin: event.origin, type: event.data?.type ?? null }));
    const originalDecode = TextDecoder.prototype.decode;
    TextDecoder.prototype.decode = function decode(input, options) {
      const value = originalDecode.call(this, input, options);
      if (value.includes("This file is a deterministic hermetic upload fixture.") && input !== undefined) {
        const bytes = ArrayBuffer.isView(input)
          ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
          : new Uint8Array(input);
        window.__tc465RenderedBytes = Array.from(bytes);
      }
      return value;
    };
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
    const announce = () => {
      window.__tc465Diagnostics.walletAnnouncements += 1;
      window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" }, provider } }));
    };
    Object.defineProperty(window, "ethereum", { configurable: true, writable: true, value: provider });
    window.addEventListener("eip6963:requestProvider", () => { window.__tc465Diagnostics.walletRequests += 1; announce(); });
    setTimeout(announce, 10_000);
    }, wallet.address, canonical.share);
    resolveInstallation();
  } catch (error) {
    installedPages.delete(page);
    rejectInstallation(error);
    throw error;
  }
  return installation;
}

async function text(page) { return page.evaluate(() => document.body?.innerText ?? ""); }
async function waitForText(page, value, timeout = 180_000) {
  try {
    await page.waitForFunction((expected) => document.body?.innerText.includes(expected), { timeout }, value);
  } catch (error) {
    const state = await page.evaluate(() => ({
      text: (document.body?.innerText ?? "").slice(-1_500),
      authError: window.__tinycloudAuthError instanceof Error ? window.__tinycloudAuthError.message : String(window.__tinycloudAuthError ?? ""),
      diagnostics: window.__tc465Diagnostics ?? null,
    })).catch(() => null);
    throw new Error(`timed out waiting for text ${JSON.stringify(value)}; state=${JSON.stringify(state)}; browserErrors=${JSON.stringify(browserErrors.slice(-30))}`, { cause: error });
  }
}
async function announceWallet(page) {
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: {
    info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" },
    provider: window.ethereum,
  } })));
}
async function clickText(page, value, optional = false) {
  let clicked = false;
  const deadline = Date.now() + (optional ? 10_000 : 30_000);
  while (!clicked && Date.now() < deadline) {
    for (const frame of page.frames()) {
      clicked = await frame.evaluate((expected) => {
        const visit = (root) => {
          for (const element of root.querySelectorAll("button,[role=button],a")) {
            if ((element.textContent ?? "").trim().includes(expected) && !element.disabled) { element.click(); return true; }
            if (element.shadowRoot && visit(element.shadowRoot)) return true;
          }
          for (const element of root.querySelectorAll("*")) {
            if (element.shadowRoot && visit(element.shadowRoot)) return true;
            if ((element.textContent ?? "").trim() === expected && element instanceof HTMLElement) { element.click(); return true; }
          }
          return false;
        };
        return visit(document);
      }, value).catch(() => false);
      if (clicked) break;
    }
    if (!clicked) await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  if (!clicked && !optional) {
    const surfaces = await Promise.all(page.frames().map(async (frame) => ({
      origin: (() => { try { return new URL(frame.url()).origin; } catch { return "invalid"; } })(),
      actions: await frame.evaluate(() => {
        const values = [];
        const visit = (root) => {
          for (const element of root.querySelectorAll("button,[role=button],a")) {
            const value = (element.textContent ?? "").trim();
            if (value) values.push(value);
          }
          for (const element of root.querySelectorAll("*")) if (element.shadowRoot) visit(element.shadowRoot);
        };
        visit(document);
        return values.slice(0, 30);
      }).catch(() => []),
      status: await frame.evaluate(() => document.querySelector(".auth-status,[role=alert]")?.textContent?.trim() ?? null).catch(() => null),
      diagnostics: await frame.evaluate(() => window.__tc465Diagnostics ?? null).catch(() => null),
    })));
    throw new Error(`action not found: ${value}; surfaces=${JSON.stringify(surfaces)}; browserErrors=${JSON.stringify(browserErrors.slice(-10))}`);
  }
  return clicked;
}

function successful(entry) { return entry.status >= 200 && entry.status < 300; }

function authorizationValue(authorization) {
  const encoded = authorization?.replace(/^Bearer\s+/i, "");
  if (encoded === undefined || encoded.length === 0) return undefined;
  try {
    const parts = encoded.split(".");
    if (parts.length === 3) return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return Cbor.decode(Buffer.from(encoded, "base64url"));
  } catch { return undefined; }
}

function stringsIn(value, found = []) {
  if (typeof value === "string") found.push(value);
  else if (Array.isArray(value)) for (const item of value) stringsIn(item, found);
  else if (value instanceof Map) for (const [key, item] of value) { stringsIn(key, found); stringsIn(item, found); }
  else if (value !== null && typeof value === "object") for (const [key, item] of Object.entries(value)) { found.push(key); stringsIn(item, found); }
  return found;
}

function authorizationNames(entry) { return stringsIn(authorizationValue(entry.authorization)); }

function routeAfter(label, after, predicate) {
  const entry = receiverRequests.find((candidate) => candidate.sequence > after && successful(candidate) && predicate(candidate));
  assert(entry, `${label} was not observed after receiver sequence ${after}`);
  return entry;
}

function escaped(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

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
    page.on("console", (message) => { if (["error", "warning"].includes(message.type())) browserErrors.push(`${message.type()}: ${message.text()}`.slice(0, 500)); });
    page.on("pageerror", (error) => { browserErrors.push(`pageerror: ${error.message}`.slice(0, 500)); });
    page.on("requestfailed", (request) => { browserErrors.push(`requestfailed: ${new URL(request.url()).origin}${new URL(request.url()).pathname} ${request.failure()?.errorText ?? "unknown"}`.slice(0, 500)); });
    await installInterception(page, services, fixtureOrigin);
    await page.goto(`${canonical.share}/share.html`, { waitUntil: "networkidle2", timeout: 180_000 });
    await page.waitForFunction(() => { const button = document.querySelector("button.auth-button"); return button !== null && !button.disabled; }, { timeout: 60_000 });
    await page.click("button.auth-button");
    await new Promise((resolveWait) => setTimeout(resolveWait, 800));
    await announceWallet(page);
    await clickText(page, "TinyCloud E2E Wallet");
    await clickText(page, "Create TinyCloud Space", true);
    await waitForText(page, "Shared by me.", 60_000);
    await clickText(page, "New share");
    await page.waitForSelector('input[name="recipient"][value="exactEmail"]', { timeout: 60_000 });
    await page.evaluate(() => { window.__tc465Copied = null; Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (value) => { window.__tc465Copied = value; return Promise.resolve(); } } }); });
    await page.click('input[name="recipient"][value="exactEmail"]');
    await page.type("input[name=recipient-value]", "sam@tinycloud.xyz");
    const upload = await page.$("input[name=document]");
    assert(upload, "share upload control is missing");
    await upload.uploadFile(join(shareRoot, "test/e2e-sharing/fixture.md"));
    await page.click("button.create-link-button");
    await waitForText(page, "Your private link is ready", 60_000);
    await clickText(page, "Copy link");
    const shareUrl = await page.evaluate(() => window.__tc465Copied);
    assert.match(shareUrl, /^https:\/\/share\.tinycloud\.xyz\/s\/bafkrei[a-z2-7]{52}/);
    const shareCid = new URL(shareUrl).pathname.split("/").at(-1);
    const binding = await page.evaluate(async (cid) => { const response = await fetch(`/.well-known/tinycloud-share/bindings/${cid}.json`, { cache: "no-store" }); return { status: response.status, body: await response.json() }; }, shareCid);
    assert.equal(binding.status, 200);
    assert.equal(binding.body.version, 3);
    assert.equal(binding.body.shareCid, shareCid);

    const popupTarget = browser.waitForTarget((target) => target.url().startsWith(`${canonical.interaction}/credentials/acquire/`), { timeout: 180_000 });
    receiverJourneyStarted = true;
    await page.goto(shareUrl, { waitUntil: "networkidle2", timeout: 180_000 });
    await waitForText(page, "Confirm your email to open this");
    await page.click("button.viewer-primary-action");
    await new Promise((resolveWait) => setTimeout(resolveWait, 800));
    await announceWallet(page);
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
    const renderedBytes = Buffer.from(await page.evaluate(() => window.__tc465RenderedBytes ?? []));
    assert(renderedBytes.length > 0, "the renderer did not expose the decrypted byte slice it decoded");
    assert.deepEqual(renderedBytes, expectedBytes, "the decrypted bytes passed to the renderer differ from the fixture");

    const create = routeAfter("credential acquisition create", 0, (entry) => entry.method === "POST" && entry.origin === canonical.witness && entry.path === "/v1/acquisitions");
    const acquisitionId = create.responseBody?.requestId;
    assert.match(acquisitionId, /^[A-Za-z0-9_-]{16,128}$/, "credential acquisition create did not return a canonical request id");
    const acquisitionPath = new RegExp(`^/v1/acquisitions/${escaped(acquisitionId)}/`);
    const state = routeAfter("credential acquisition state", create.sequence, (entry) => entry.method === "GET" && acquisitionPath.test(entry.path) && entry.path.endsWith("/state"));
    const challenge = routeAfter("credential acquisition OTP challenge", state.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/challenge") && entry.body?.step === "mailbox_otp");
    const proof = routeAfter("credential acquisition OTP proof", challenge.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/proof") && entry.body?.step === "mailbox_otp");
    const holderBinding = routeAfter("credential acquisition holder binding", proof.sequence, (entry) => entry.method === "GET" && acquisitionPath.test(entry.path) && entry.path.endsWith("/holder-binding"));
    const holderSignature = routeAfter("credential acquisition holder signature", holderBinding.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/holder-signature"));
    const issue = routeAfter("credential acquisition issue", holderSignature.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/issue"));
    const result = routeAfter("credential acquisition result", issue.sequence, (entry) => entry.method === "GET" && acquisitionPath.test(entry.path) && entry.path.endsWith("/result"));

    const credentialWrite = routeAfter("durable credential-space write", result.sequence, (entry) => entry.path === "/invoke" && Array.isArray(entry.responseBody?.written) && entry.responseBody.written.some((key) => typeof key === "string" && key.startsWith("v1/records/")));
    const credentialRecord = credentialWrite.responseBody.written.find((key) => key.startsWith("v1/records/"));
    const credentialWriteAuth = authorizationNames(credentialWrite);
    assert(credentialWrite.authorization && credentialWriteAuth.includes(credentialRecord), "credential-space write was not authenticated for the exact record");
    const credentialRead = routeAfter("authenticated credential-space readback", credentialWrite.sequence, (entry) => entry.path === "/invoke" && entry.responseBody?.type === "TinyCloudStoredCredential" && `v1/records/${entry.responseBody.recordId}` === credentialRecord);
    assert(credentialRead.authorization && authorizationNames(credentialRead).includes(credentialRecord), "credential-space readback was not authenticated for the exact record");

    const policyChallenge = routeAfter("Policy/v3 challenge", credentialRead.sequence, (entry) => entry.path === "/share/v3/policy/challenges" && entry.method === "POST");
    const policyCid = policyChallenge.body?.policyCid;
    assert.equal(policyCid, binding.body.policyCid, "Policy/v3 challenge did not bind the published policy CID");
    const requestedKv = policyChallenge.body?.requestedCapabilities?.find((capability) => capability?.kind === "kv");
    assert(requestedKv?.resource?.startsWith("tinycloud://"), "Policy/v3 challenge did not request one exact TinyCloud KV resource");
    assert.equal(requestedKv.selector, "exact");
    assert.deepEqual(requestedKv.actions, ["tinycloud.kv/get"]);
    const kvResource = requestedKv.resource;
    const resource = kvResource.split("/kv/")[1];
    assert(resource, "Policy/v3 challenge KV resource path is missing");

    const policyMint = routeAfter("Policy/v3 delegation mint", policyChallenge.sequence, (entry) => entry.path === "/share/v3/policy/delegations" && entry.method === "POST" && entry.body?.policyCid === policyCid && entry.body?.challengeId === policyChallenge.responseBody?.challengeId);
    const credentialSpaceId = policyMint.body?.credentialSpaceId;
    assert.equal(typeof credentialSpaceId, "string", "Policy/v3 mint omitted the recipient credentials space");
    assert.equal(policyMint.body?.presentation?.credentialSpaceOwnerDid, credentialRead.responseBody.ownerDid, "Policy/v3 presentation did not bind the durable credential owner");
    assert.deepEqual(policyMint.body?.presentation?.requestedCapabilities, policyChallenge.body.requestedCapabilities, "Policy/v3 mint substituted the challenged capability slice");

    const delegate = routeAfter("ordinary delegation activation", policyMint.sequence, (entry) => entry.path === "/delegate" && entry.method === "POST");
    assert.equal(delegate.authorization, policyMint.responseBody?.authorization, "ordinary /delegate did not activate the freshly minted policy authorization");
    const invoke = routeAfter("ordinary exact-resource invocation", delegate.sequence, (entry) => entry.path === "/invoke" && entry.method === "POST" && authorizationNames(entry).includes(resource));
    const decrypt = routeAfter("ordinary delegated decrypt", invoke.sequence, (entry) => /^\/encryption\/networks\/[^/]+\/decrypt$/.test(entry.path) && entry.method === "POST");
    assert(!receiverRequests.some((entry) => entry.path === "/share/v2/policy/session"), "receiver journey used the legacy /share/v2/policy/session route");
    const allowedOrigins = new Set([...Object.values(canonical), "null"]);
    const external = receiverRequests.filter((entry) => !allowedOrigins.has(entry.origin));
    assert.deepEqual(external.map((entry) => `${entry.method} ${entry.origin}${entry.path}`), [], "receiver journey attempted an external destination");

    const chain = [
      "acquisition:create", "acquisition:state", "acquisition:otp-challenge", "acquisition:otp-proof", "acquisition:holder-binding", "acquisition:holder-signature", "acquisition:issue", "acquisition:result",
      "credentials:durable-write", "credentials:authenticated-readback", "policy-v3:challenge", "policy-v3:mint", "delegate", `invoke:${kvResource}`, "decrypt", "render",
    ];
    const statuses = {
      acquisition: result.sequence > create.sequence,
      durableCredential: credentialRead.sequence > credentialWrite.sequence,
      policyV3Challenge: policyChallenge.sequence > credentialRead.sequence,
      policyV3Mint: policyMint.sequence > policyChallenge.sequence,
      delegate: delegate.sequence > policyMint.sequence,
      invoke: invoke.sequence > delegate.sequence,
      decrypt: decrypt.sequence > invoke.sequence,
      rendered,
      legacyPolicySessionAbsent: true,
      zeroExternalDestinations: true,
    };
    assert(Object.values(statuses).every((value) => value === true), "receiver chain status is incomplete");
    const evidence = {
      type: "tinycloud.share/tc-465-joined-evidence/v2",
      renderedSha256: createHash("sha256").update(renderedBytes).digest("hex"),
      statuses,
      chain,
      slice: {
        shareCid,
        policyCid,
        resource,
        credentialSpaceId,
        credentialRecord,
        acquisitionIdSha256: createHash("sha256").update(acquisitionId).digest("hex"),
      },
    };
    assert.equal(evidence.renderedSha256, createHash("sha256").update(expectedBytes).digest("hex"), "rendered bytes digest does not match the fixture digest");
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
