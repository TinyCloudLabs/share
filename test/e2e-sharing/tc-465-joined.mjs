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
import { ed25519 } from "@noble/curves/ed25519";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalize, computeCid, ed25519PublicKeyFromDidKey, fromBase64Url, open, parseShareUrl, shareEnvelopeV3Schema, verifyEnvelopeV3, verifyEnvelopeV3SignatureOnly } from "@tinycloud/share-envelope";
import { parseCompactUcanAuthorization } from "@tinycloud/sdk-core/policy";

const shareRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const tc500 = process.argv.includes("--tc-500");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, tc500 ? "worktrees/tinycloud-node/skgbafa/tc-500-embedded-policy-runtime" : "worktrees/tinycloud-node/skgbafa/tc-470-holder-credential-admission");
const sdkRoot = process.env.TINYCLOUD_JS_SDK_WORKTREE ?? join(workspaceRoot, tc500 ? "worktrees/js-sdk/skgbafa/tc-500-embedded-policy-access" : "worktrees/js-sdk/skgbafa/tc-470-policy-credential-presentation");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? join(workspaceRoot, tc500 ? "worktrees/opencredentials/tc-500-remove-policy-dns" : "worktrees/opencredentials/skgbafa/tc-462-credential-flow-opencredentials-785732297208");
const credentialsManifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
const credentialsApp = join(credentialsRoot, "apps/open-credentials");
const canonical = { share: "https://share.tinycloud.xyz", node: "https://node.tinycloud.xyz", witness: "https://witness.credentials.org", interaction: "https://credentials.org", openKey: "https://openkey.so", openKeyApi: "https://api.openkey.so" };
const expectedBytes = await readFile(join(shareRoot, "test/e2e-sharing/fixture.md"));
const wallet = privateKeyToAccount(`0x${"55".repeat(32)}`);
const receiverRequests = [];
const browserTraffic = [];
const requestEntries = new WeakMap();
const installedPages = new WeakMap();
let receiverJourneyStarted = false;
let receiverSequence = 0;
const receiverTargets = [];
let receiverTargetBaseline = new Set();
let integration;
let fixture;
let browser;
const browserErrors = [];
let invitationDeliveryRequest;

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

function diagnosticReceiverTraffic() {
  return receiverRequests.slice(-50).map((entry) => ({
    sequence: entry.sequence,
    method: entry.method,
    origin: entry.origin,
    path: entry.path,
    status: entry.status,
    authenticated: typeof entry.authorization === "string",
    ...(entry.body !== undefined && typeof entry.body === "object" && entry.body !== null ? { bodyKeys: Object.keys(entry.body).sort() } : {}),
    ...(entry.responseBody !== undefined && typeof entry.responseBody === "object" && entry.responseBody !== null ? { responseKeys: Object.keys(entry.responseBody).sort() } : {}),
  }));
}

async function proxy(request, targetOrigin, options = {}) {
  const original = new URL(request.url());
  const target = new URL(`${options.path ?? original.pathname}${original.search}`, targetOrigin);
  const method = request.method();
  const body = method === "GET" || method === "HEAD"
    ? undefined
    : original.pathname === "/api/share/link-only/registry/blobs"
      ? Buffer.from(await options.page.evaluate(() => window.__tc465BinaryBodies.shift() ?? []))
      : original.origin === canonical.node && original.pathname === "/invoke" && request.headers()["content-type"]?.startsWith("application/vnd.tinycloud.sealed")
        ? Buffer.from(await options.page.evaluate(() => window.__tc465NodeBinaryBodies.shift() ?? []))
      : await request.fetchPostData();
  const response = await fetch(target, {
    method,
    headers: headersForFetch(request, options.forwardedHttps),
    redirect: "manual",
    ...(body === undefined ? {} : { body }),
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
    try {
      const parsed = JSON.parse(raw);
      const candidate = typeof parsed === "string" ? parsed : parsed?.error?.code ?? parsed?.code ?? (typeof parsed?.error === "string" ? parsed.error : undefined);
      code = typeof candidate === "string" && /^[A-Za-z][A-Za-z0-9 _:.\/-]{0,160}$/.test(candidate) ? candidate : `json_keys:${Object.keys(parsed ?? {}).sort().join(",")}`;
    } catch {
      const candidate = raw.trim();
      if (/^[a-z][a-z0-9-]{0,160}$/.test(candidate)) code = candidate;
    }
    browserErrors.push(`response: ${request.method()} ${original.origin}${original.pathname} ${response.status} ${code}`);
  }
  browserTraffic.push(`${request.method()} ${original.origin}${original.pathname} ${response.status}`);
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
  const origin = request.headers().origin;
  await request.respond({ status: 200, headers: {
    "content-type": contentTypes[extname(file)] ?? "text/html; charset=utf-8",
    "cache-control": "no-store",
    ...(origin === canonical.share || origin === canonical.interaction ? { "access-control-allow-origin": origin, vary: "Origin" } : {}),
  }, body });
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
    page.on("console", (message) => {
      if (["error", "warning"].includes(message.type()) || message.text().startsWith("tinycloud share:")) {
        browserErrors.push(`${message.type()}: ${message.text()}`.replace(/[A-Za-z0-9_-]{32,}/g, "<opaque>").slice(0, 500));
      }
    });
    page.on("pageerror", (error) => { browserErrors.push(`pageerror: ${error.message}`.replace(/[A-Za-z0-9_-]{32,}/g, "<opaque>").slice(0, 500)); });
    await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    const headers = request.headers();
    if (tc500 && url.origin === canonical.witness && url.pathname === "/v1/credential-invitations" && request.method() === "POST") {
      invitationDeliveryRequest = request.postData();
    }
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
    if (url.origin === canonical.share) return proxy(request, services.shareOrigin, { forwardedHttps: true, entry, rewriteNodeCsp: true, page });
    if (url.origin === canonical.node) return proxy(request, services.nodeOrigin, { cors: true, entry, page });
    if (url.origin === canonical.witness) {
      if (request.method() === "OPTIONS") return request.respond({ status: 204, headers: { "access-control-allow-origin": request.headers().origin ?? canonical.share, "access-control-allow-credentials": "true", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "authorization, content-type", vary: "Origin" } });
      if (tc500) return proxy(request, services.credentialsOrigin, { cors: true, entry });
      if (!tc500 && url.pathname === "/share/v3") return proxy(request, services.credentialsOrigin, { cors: true, entry });
      return proxy(request, fixtureOrigin, { cors: true, entry });
    }
    if (url.origin === canonical.interaction) return serveCredentialsApp(request);
    if (url.origin === canonical.openKey) return proxy(request, services.openKeyOrigin, { entry });
    if (url.origin === canonical.openKeyApi) return proxy(request, services.openKeyOrigin, { cors: true, entry });
    if (url.protocol === "data:" || url.protocol === "blob:" || url.origin === "null") return request.continue();
    throw new Error(`unexpected browser destination ${url.origin}${url.pathname}`);
  })().catch((error) => request.abort("blockedbyclient").finally(() => { console.error(error instanceof Error ? error.message : String(error)); })); });
  page.on("response", (response) => { const entry = requestEntries.get(response.request()); if (entry !== undefined) entry.status = response.status(); });
    await page.evaluateOnNewDocument((address, shareOrigin, nodeOrigin, accountlessReceiver) => {
    window.__tc465Diagnostics = { messages: [], walletAnnouncements: 0, walletRequests: 0, windowOpenCalls: 0 };
    window.__tc465BinaryBodies = [];
    window.__tc465NodeBinaryBodies = [];
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url, location.href);
      const body = init?.body;
      if (url.pathname === "/api/share/link-only/registry/blobs" && (body instanceof ArrayBuffer || ArrayBuffer.isView(body))) {
        const bytes = body instanceof ArrayBuffer
          ? new Uint8Array(body)
          : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
        window.__tc465BinaryBodies.push(Array.from(bytes));
      }
      if (url.origin === nodeOrigin && url.pathname === "/invoke" && body instanceof Blob && body.type.startsWith("application/vnd.tinycloud.sealed")) {
        window.__tc465NodeBinaryBodies.push(Array.from(new Uint8Array(await body.arrayBuffer())));
      }
      return originalFetch(input, init);
    };
    const originalOpen = window.open.bind(window);
    window.open = (url, target, features) => {
      window.__tc465Diagnostics.windowOpenCalls += 1;
      return originalOpen(url, target, features);
    };
    window.addEventListener("message", (event) => window.__tc465Diagnostics.messages.push({ origin: event.origin, type: event.data?.type ?? null }));
    const originalDebug = console.debug;
    console.debug = (...args) => {
      if (String(args[0] ?? "").startsWith("tinycloud share:")) {
        const messages = [];
        let current = args[1];
        if (current instanceof Error && typeof current.stack === "string") {
          window.__tc465Diagnostics.productErrorStack = current.stack;
        }
        for (let depth = 0; depth < 4 && current !== undefined && current !== null; depth += 1) {
          messages.push(String(current?.message ?? current));
          current = current?.cause;
        }
        window.__tc465Diagnostics.productError = messages.join(" <- ");
      }
      originalDebug(...args);
    };
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
    Element.prototype.attachShadow = function attachShadow(init) {
      const options = init || {};
      // OpenKey's fixture-only wallet selector uses a closed root, while this
      // browser test drives the deterministic wallet through its public UI.
      // Do not alter the acquisition element: its public open-root contract
      // is exercised directly by the OTP interaction below.
      return originalAttachShadow.call(this, this.localName === "div" && options.mode === "closed" ? { ...options, mode: "open" } : options);
    };
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
    if (!accountlessReceiver) setTimeout(announce, 10_000);
    }, wallet.address, canonical.share, canonical.node, tc500);
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
    throw new Error(`timed out waiting for text ${JSON.stringify(value)}; state=${JSON.stringify(state)}; traffic=${JSON.stringify(browserTraffic.slice(-50))}; browserErrors=${JSON.stringify(browserErrors.slice(-30))}`, { cause: error });
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
      try {
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
        }, value);
      } catch {
        // Embedded sign-in surfaces navigate while this loop is running. A frame
        // captured by page.frames() can detach before evaluate() is invoked.
        clicked = false;
      }
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

function hexDigest(domain, value) {
  return createHash("sha256").update(domain).update(canonicalize(value)).digest("hex");
}

function base32Lower(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let output = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) { output += alphabet[(buffer >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}

async function auditV3Envelope(envelope) {
  const policy = envelope.policy;
  const unsignedPolicy = { ...policy };
  delete unsignedPolicy.policyId;
  delete unsignedPolicy.signature;
  const policyDomain = policy.schema === "xyz.tinycloud.policy/policy/v2" ? "xyz.tinycloud.policy/policy/v2\0" : "xyz.tinycloud.policy/policy/v1\0";
  const policyDigest = createHash("sha256").update(policyDomain).update(canonicalize(unsignedPolicy)).digest();
  const policyRoot = parseCompactUcanAuthorization(envelope.policyRoot.authorization, envelope.policyRoot.cid);
  const enforcementRoot = parseCompactUcanAuthorization(envelope.enforcementRoot.authorization, envelope.enforcementRoot.cid);
  const policyFact = policyRoot.payload.fct[0];
  const enforcementFact = enforcementRoot.payload.fct[0];
  const capabilities = [...policy.capabilityCeiling].sort((left, right) => canonicalize(left).localeCompare(canonicalize(right)));
  const projection = capabilities.map((capability) => capability.kind === "encryption"
    ? { service: "tinycloud.encryption", space: capability.resource, path: capability.resource, actions: [capability.action] }
    : { service: "tinycloud.kv", space: capability.resource.slice(0, capability.resource.indexOf("/kv/")), path: capability.resource.split("/kv/")[1], actions: [...capability.actions], caveat: { type: "xyz.tinycloud.resource/selector", kind: capability.selector, value: capability.resource } })
    .sort((left, right) => canonicalize(left).localeCompare(canonicalize(right)));
  const attenuation = Object.fromEntries(capabilities.map((capability) => capability.kind === "encryption"
    ? [capability.resource, { [capability.action]: [{}] }]
    : [capability.resource, Object.fromEntries(capability.actions.map((action) => [action, [{ kind: capability.selector, type: "xyz.tinycloud.resource/selector", value: capability.resource }]]))]));
  const binding = envelope.attestedEnforcerBinding;
  const { signature: bindingSignature, ...unsignedBinding } = binding;
  const bindingDigest = createHash("sha256").update("xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0").update(canonicalize(unsignedBinding)).digest();
  return {
    envelopeSignature: verifyEnvelopeV3SignatureOnly(envelope),
    policySignature: ed25519.verify(fromBase64Url(policy.signature.value), policyDigest, ed25519PublicKeyFromDidKey(policy.ownerDid), { zip215: false }),
    policyId: policy.policyId === `pol_${base32Lower(policyDigest)}`,
    policyCid: await computeCid(new TextEncoder().encode(canonicalize(policy))) === envelope.policyCid,
    contentSourceDigest: hexDigest("xyz.tinycloud.policy/ContentSource/v1\0", policy.contentSource) === envelope.contentSourceDigestHex,
    capabilityHash: policyFact.capabilityCeilingHashHex === hexDigest("xyz.tinycloud.policy/PolicyCapability/v1\0", capabilities),
    nativeProjectionHash: policyFact.nativeProjectionHashHex === hexDigest("xyz.tinycloud.policy/NativeProjection/v1\0", projection),
    bindingDigest: binding.attestationBindingDigestHex === hexDigest("", { enforcerDid: binding.enforcerDid, nodeAudience: binding.nodeAudience }),
    bindingSignature: ed25519.verify(fromBase64Url(bindingSignature.value), bindingDigest, ed25519PublicKeyFromDidKey(binding.nodeAudience), { zip215: false }),
    rootAttenuation: canonicalize(policyRoot.payload.att) === canonicalize(attenuation) && canonicalize(enforcementRoot.payload.att) === canonicalize(attenuation),
    rootFacts: policyFact.policyDigestHex === policyDigest.toString("hex") && enforcementFact.policyDigestHex === policyDigest.toString("hex") && policyFact.nodeAudience === binding.nodeAudience && enforcementFact.nodeAudience === binding.nodeAudience,
    fullVerification: await verifyEnvelopeV3(envelope, { expectedSignerDid: policy.ownerDid }),
  };
}

function routeAfter(label, after, predicate) {
  const entry = receiverRequests.find((candidate) => candidate.sequence > after && successful(candidate) && predicate(candidate));
  assert(entry, `${label} was not observed after receiver sequence ${after}`);
  return entry;
}

function escaped(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function shareUrlFromMail(message) {
  const values = stringsIn(message).flatMap((candidate) => [...candidate.matchAll(/https:\/\/share\.tinycloud\.xyz\/s\/[^\s"'<>]+/g)].map((match) => match[0]));
  const value = values.sort((left, right) => Number(right.includes("?i=") && right.includes("#k=")) - Number(left.includes("?i=") && left.includes("#k=")) || right.length - left.length)[0];
  if (value === undefined) throw new Error("captured mail did not contain the generated Share invitation URL");
  return value.replaceAll("&amp;", "&");
}

async function main() {
  const control = await mkdtemp(join(tmpdir(), tc500 ? "tinycloud-tc500-" : "tinycloud-tc465-"));
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
      [tc500 ? "SHARING_E2E_TC500_JOINED" : "SHARING_E2E_TC465_JOINED"]: "1",
      SHARING_E2E_EXTERNAL_CONTROL_DIR: control,
      SHARING_E2E_ARTIFACT_PATH: process.env.SHARING_E2E_ARTIFACT_PATH ?? join(workspaceRoot, tc500 ? ".context/tc-500-joined.json" : ".context/tc-465-joined.json"),
      TINYCLOUD_NODE_WORKTREE: nodeRoot,
      TINYCLOUD_JS_SDK_WORKTREE: sdkRoot,
      OPENCREDENTIALS_WORKTREE: credentialsRoot,
    };
    integration = spawn(process.execPath, [join(shareRoot, "test/e2e-sharing/integration.mjs")], { cwd: shareRoot, env: compositionEnv, stdio: ["ignore", "inherit", "inherit"] });
    await waitForFile(join(control, "services.json"), integration, 20 * 60_000);
    const services = JSON.parse(await readFile(join(control, "services.json"), "utf8"));

    browser = await puppeteer.launch({ headless: true, args: ["--disable-popup-blocking", "--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1,MAP node.tinycloud.xyz 127.0.0.1,MAP witness.credentials.org 127.0.0.1,MAP credentials.org 127.0.0.1,MAP openkey.so 127.0.0.1,MAP api.openkey.so 127.0.0.1"] });
    browser.on("targetcreated", (target) => {
      if (receiverJourneyStarted && !receiverTargetBaseline.has(target) && target.type() === "page") receiverTargets.push(target.url());
      void target.page().then((page) => page === null ? undefined : installInterception(page, services, fixtureOrigin)).catch(() => undefined);
    });
    let page = await browser.newPage();
    page.on("console", (message) => {
      if (["error", "warning"].includes(message.type()) || message.text().startsWith("tinycloud share:")) {
        browserErrors.push(`${message.type()}: ${message.text()}`.replace(/[A-Za-z0-9_-]{32,}/g, "<opaque>").slice(0, 500));
      }
    });
    page.on("pageerror", (error) => { browserErrors.push(`pageerror: ${error.message}`.slice(0, 500)); });
    page.on("requestfailed", (request) => { browserErrors.push(`requestfailed: ${new URL(request.url()).origin}${new URL(request.url()).pathname} ${request.failure()?.errorText ?? "unknown"}`.slice(0, 500)); });
    await installInterception(page, services, fixtureOrigin);
    await page.goto(`${canonical.share}/share.html`, { waitUntil: "networkidle2", timeout: 180_000 });
    await page.waitForFunction(() => { const button = document.querySelector("button.auth-button"); return button !== null && !button.disabled; }, { timeout: 60_000 });
    await page.click("button.auth-button");
    await clickText(page, "Create TinyCloud Space", true);
    await waitForText(page, "Shared by me.", 60_000);
    await clickText(page, "New share");
    await page.waitForSelector('input[name="recipient"][value="exactEmail"]', { timeout: 60_000 });
    const recipientEmail = "sam@tinycloud.xyz";
    await fetch(`${services.mailOrigin}/emails/reset`, { method: "POST" });
    await page.evaluate(() => { window.__tc465Copied = null; Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (value) => { window.__tc465Copied = value; return Promise.resolve(); } } }); });
    await page.click('input[name="recipient"][value="exactEmail"]');
    await page.type("input[name=recipient-value]", recipientEmail);
    const upload = await page.$("input[name=document]");
    assert(upload, "share upload control is missing");
    await upload.uploadFile(join(shareRoot, "test/e2e-sharing/fixture.md"));
    await page.click("button.create-link-button");
    await waitForText(page, "Your encrypted link is ready", 30_000);
    await clickText(page, "Copy link");
    const shareUrl = await page.evaluate(() => window.__tc465Copied);
    assert.match(shareUrl, /^https:\/\/share\.tinycloud\.xyz\/s\/bafkrei[a-z2-7]{52}/);
    const shareCid = new URL(shareUrl).pathname.split("/").at(-1);
    const sealedEnvelopeBytes = Uint8Array.from(await page.evaluate(async (cid) => {
      const response = await fetch(`/registry/ipfs/${cid}?format=raw`, { cache: "no-store" });
      if (!response.ok) throw new Error(`registry envelope read failed (${response.status})`);
      return Array.from(new Uint8Array(await response.arrayBuffer()));
    }, shareCid));
    const parsedLink = parseShareUrl(shareUrl, { expectedOrigin: canonical.share });
    const envelopeBytes = await open(sealedEnvelopeBytes, parsedLink.key32);
    parsedLink.key32.fill(0);
    const envelopeValue = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(envelopeBytes));
    const envelopeValidation = shareEnvelopeV3Schema.safeParse(envelopeValue);
    assert(envelopeValidation.success, `published v3 envelope is invalid: ${envelopeValidation.error?.issues.map((issue) => `${issue.path.join(".")}:${issue.code}:${issue.message}`).join("; ")}`);
    const publishedEnvelope = envelopeValidation.data;
    if (tc500) {
      assert.equal(verifyEnvelopeV3SignatureOnly(publishedEnvelope), true, "accountless envelope owner signature is invalid");
      assert.equal(JSON.stringify(publishedEnvelope).includes("This file is a deterministic hermetic upload fixture."), false, "registry envelope contained document payload");
      assert.equal(Object.hasOwn(publishedEnvelope, "documentPayload"), false, "registry envelope exposed a document payload field");
    } else {
      const envelopeAudit = await auditV3Envelope(publishedEnvelope);
      assert.deepEqual(envelopeAudit, Object.fromEntries(Object.keys(envelopeAudit).map((key) => [key, true])), `published v3 envelope verification audit failed: ${JSON.stringify(envelopeAudit)}`);
      const policyRoot = parseCompactUcanAuthorization(publishedEnvelope.policyRoot.authorization, publishedEnvelope.policyRoot.cid);
      const enforcementRoot = parseCompactUcanAuthorization(publishedEnvelope.enforcementRoot.authorization, publishedEnvelope.enforcementRoot.cid);
      assert.equal(policyRoot.payload.fct[0]?.nodeAudience, publishedEnvelope.attestedEnforcerBinding.nodeAudience, "policy root collapsed the Node audience into the enforcement DID");
      assert.equal(enforcementRoot.payload.fct[0]?.nodeAudience, publishedEnvelope.attestedEnforcerBinding.nodeAudience, "enforcement root collapsed the Node audience into the enforcement DID");
      assert.equal(enforcementRoot.payload.aud, publishedEnvelope.attestedEnforcerBinding.enforcerDid, "enforcement root audience does not match the attested enforcement DID");
      assert.equal(enforcementRoot.payload.fct[0]?.enforcerDid, publishedEnvelope.attestedEnforcerBinding.enforcerDid, "enforcement root fact does not match the attested enforcement DID");
    }
    const exactKvResource = publishedEnvelope.contentSource.kvResource;
    const binding = await page.evaluate(async (cid) => { const response = await fetch(`/.well-known/tinycloud-share/bindings/${cid}.json`, { cache: "no-store" }); return { status: response.status, body: await response.json() }; }, shareCid);
    assert.equal(binding.status, 200);
    assert.equal(binding.body.version, 3);
    assert.equal(binding.body.shareCid, shareCid);

    await page.click("button.confirm-notification");
    await waitForText(page, "Invitation requested", 30_000);
    const mailDeadline = Date.now() + 30_000;
    let deliveredMail;
    while (Date.now() < mailDeadline) {
      const state = await (await fetch(`${services.mailOrigin}/emails`, { cache: "no-store" })).json();
      deliveredMail = state.messages?.find((message) => stringsIn(message?.payload).includes(recipientEmail));
      if (deliveredMail !== undefined) break;
      await new Promise((resolveWait) => setTimeout(resolveWait, 150));
    }
    assert(deliveredMail !== undefined, "exact-email notification was not captured by the mail fixture");
    if (tc500) {
      assert.equal(typeof invitationDeliveryRequest, "string", "generic invitation delivery request was not captured");
      const deliveryContract = JSON.parse(invitationDeliveryRequest);
      assert.equal(deliveryContract.request.policyId, binding.body.policyCid, "invitation policy binding changed after admission");
      assert.equal(deliveryContract.request.recipient, recipientEmail, "invitation recipient binding changed after admission");
      assert.equal(deliveryContract.request.resource, exactKvResource, "invitation resource binding changed after admission");
      assert.equal(deliveryContract.request.credentialType, "opencredentials.email/v1", "invitation credential type changed after admission");
      assert.equal(deliveryContract.request.envelopeRef, shareCid, "invitation envelope binding changed after admission");
      assert.equal(deliveryContract.request.audience, canonical.witness, "invitation audience changed after admission");
      assert.equal(deliveryContract.admission.recipient, deliveryContract.request.recipient, "admission and invitation recipients differ");
      assert.equal(deliveryContract.admission.resource, deliveryContract.request.resource, "admission and invitation resources differ");
      assert.deepEqual(deliveryContract.admission.actions, ["tinycloud.kv/get"], "delivery admission was not read-only");
      assert.equal(deliveryContract.admission.senderKeyDid, deliveryContract.proof.kid, "delivery proof did not use the admitted sender key");
      assert.equal(deliveryContract.admission.returnLink, deliveryContract.request.returnLink, "admission and invitation return links differ");
      assert.equal(deliveryContract.admission.expiresAt, deliveryContract.request.expiresAt, "admission and invitation expiries differ");
      const invitationTtl = (Date.parse(deliveryContract.request.expiresAt) - Date.parse(deliveryContract.request.issuedAt)) / 1_000;
      assert(invitationTtl > 0 && invitationTtl <= 900, "invitation expiry was not positively bounded to fifteen minutes");
      const beforeReplay = (await (await fetch(`${services.mailOrigin}/emails`)).json()).messages.length;
      const replay = await fetch(`${services.credentialsOrigin}/v1/credential-invitations`, { method: "POST", headers: { "content-type": "application/json", origin: canonical.share }, body: invitationDeliveryRequest });
      assert.equal(replay.status, 202, "identical invitation replay was not idempotently accepted");
      const afterReplay = (await (await fetch(`${services.mailOrigin}/emails`)).json()).messages.length;
      assert.equal(afterReplay, beforeReplay, "idempotent invitation replay sent a second email");
      const rebound = JSON.parse(invitationDeliveryRequest);
      rebound.request.nonce = "AQEBAQEBAQEBAQEBAQEBAQ";
      const rejectedReplay = await fetch(`${services.credentialsOrigin}/v1/credential-invitations`, { method: "POST", headers: { "content-type": "application/json", origin: canonical.share }, body: JSON.stringify(rebound) });
      assert.equal(rejectedReplay.status, 400, "nonce-rebound invitation replay was accepted");
    }
    const deliveredShareUrl = shareUrlFromMail(deliveredMail.payload);
    assert.equal(new URL(deliveredShareUrl).pathname, new URL(shareUrl).pathname, "delivered invitation changed the Share CID");
    assert.match(deliveredShareUrl, tc500 ? /#k=[A-Za-z0-9_-]+$/ : /\?i=[A-Za-z0-9_-]+#k=[A-Za-z0-9_-]+$/, "delivered invitation omitted decryption material");
    await page.click("button.composer-back");
    await waitForText(page, "All shares", 30_000);
    await page.waitForSelector(".sender-history-row", { timeout: 30_000 });
    assert.equal(await page.$$eval(".sender-history-row", (rows) => rows.length), 1, "delivered share was not retained in sender history");

    if (tc500) {
      const receiverContext = await browser.createBrowserContext();
      const receiverPage = await receiverContext.newPage();
      await installInterception(receiverPage, services, fixtureOrigin);
      await page.close();
      page = receiverPage;
    }
    receiverTargetBaseline = new Set(browser.targets());
    receiverJourneyStarted = true;
    await page.goto(deliveredShareUrl, { waitUntil: "networkidle2", timeout: 180_000 });
    if (!tc500) {
      await waitForText(page, "Confirm your email to open this");
      await page.click("button.viewer-primary-action");
      await new Promise((resolveWait) => setTimeout(resolveWait, 800));
      await announceWallet(page);
      await clickText(page, "TinyCloud E2E Wallet", true);
    }
    let otpSubmitted;
    try {
      if (tc500) {
        await page.waitForFunction(() => {
          const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
          return root?.querySelector('input[name="otp"]') instanceof HTMLInputElement
            && root?.querySelector('button[type="submit"]') instanceof HTMLButtonElement;
        }, { timeout: 60_000 });
        const otpDeadline = Date.now() + 30_000;
        let code;
        while (Date.now() < otpDeadline && code === undefined) {
          const state = await (await fetch(`${services.mailOrigin}/emails`, { cache: "no-store" })).json();
          const otpMail = state.messages?.find((message) => message.id !== deliveredMail.id && stringsIn(message?.payload).includes(recipientEmail));
          code = otpMail === undefined ? undefined : stringsIn(otpMail.payload).flatMap((value) => value.match(/\b\d{6}\b/g) ?? [])[0];
          if (code === undefined) await new Promise((resolveWait) => setTimeout(resolveWait, 150));
        }
        assert.match(code ?? "", /^\d{6}$/, "OpenCredentials OTP email did not contain a six-digit code");
        await page.evaluate((otp) => {
          const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
          const input = root?.querySelector('input[name="otp"]');
          const submit = root?.querySelector('button[type="submit"]');
          if (!(input instanceof HTMLInputElement) || !(submit instanceof HTMLButtonElement)) throw new Error("embedded OTP controls disappeared");
          input.value = otp;
          submit.click();
        }, code);
        otpSubmitted = { jsonValue: async () => true };
      } else {
        otpSubmitted = await page.waitForFunction(() => {
          const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
          const input = root?.querySelector("input[name=otp]");
          const submit = root?.querySelector("button[type=submit]");
          if (input?.tagName !== "INPUT" || submit?.tagName !== "BUTTON") return false;
          input.value = "246810";
          submit.click();
          return true;
        }, { timeout: 60_000 });
      }
    } catch (error) {
      const receiverState = await page.evaluate(() => ({ text: (document.body?.innerText ?? "").slice(-1_500), credentialElement: document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.innerHTML ?? null, diagnostics: window.__tc465Diagnostics ?? null })).catch(() => null);
      throw new Error(`embedded credential acquisition did not render; state=${JSON.stringify(receiverState)}; receiverTraffic=${JSON.stringify(diagnosticReceiverTraffic())}; browserErrors=${JSON.stringify(browserErrors.slice(-30))}`, { cause: error });
    }
    assert.equal(await otpSubmitted.jsonValue(), true, "embedded OTP controls are missing");
    const acquisitionCookies = await page.browserContext().cookies(canonical.witness);
    const requestCookie = acquisitionCookies.find((cookie) => cookie.name === "oc_acquisition");
    assert.equal(requestCookie, undefined, "embedded SDK acquisition must not depend on a browser cookie");

    const renderedNeedle = "This file is a deterministic hermetic upload fixture.";
    try {
      const deadline = Date.now() + 180_000;
      let renderedInIsolatedFrame = false;
      while (!renderedInIsolatedFrame && Date.now() < deadline) {
        assert.equal(typeof await page.evaluate(() => window.__tc465Diagnostics?.productError), "undefined", "receiver reported a terminal product error before rendering");
        for (const frame of page.frames()) {
          if (await frame.evaluate((needle) => document.body?.innerText.includes(needle) ?? false, renderedNeedle).catch(() => false)) {
            renderedInIsolatedFrame = true;
            break;
          }
        }
        if (!renderedInIsolatedFrame) await new Promise((resolveWait) => setTimeout(resolveWait, 100));
      }
      assert.equal(renderedInIsolatedFrame, true, "decrypted document did not render in the isolated preview frame");
    } catch (error) {
      const receiverState = await page.evaluate(() => ({ text: (document.body?.innerText ?? "").slice(-1_500), diagnostics: window.__tc465Diagnostics ?? null })).catch(() => null);
      throw new Error(`credential receiver did not render the decrypted document; receiverState=${JSON.stringify(receiverState)}; receiverTraffic=${JSON.stringify(diagnosticReceiverTraffic())}; browserErrors=${JSON.stringify(browserErrors.slice(-30))}`, { cause: error });
    }
    const rendered = (await Promise.all(page.frames().map((frame) => frame.evaluate((needle) => document.body?.innerText.includes(needle) ?? false, renderedNeedle).catch(() => false)))).some(Boolean);
    assert.equal(rendered, true, `final rendered content was missing: ${(await text(page)).slice(-1000)}`);
    const renderedBytes = Buffer.from(await page.evaluate(() => window.__tc465RenderedBytes ?? []));
    assert(renderedBytes.length > 0, "the renderer did not expose the decrypted byte slice it decoded");
    assert.deepEqual(renderedBytes, expectedBytes, "the decrypted bytes passed to the renderer differ from the fixture");

    const create = routeAfter("credential acquisition create", 0, (entry) => entry.method === "POST" && entry.origin === canonical.witness && entry.path === "/v1/acquisitions");
    const acquisitionId = create.responseBody?.requestId;
    assert.match(acquisitionId, /^[A-Za-z0-9_-]{16,128}$/, "credential acquisition create did not return a canonical request id");
    const acquisitionPath = new RegExp(`^/v1/acquisitions/${escaped(acquisitionId)}/`);
    const state = receiverRequests.find((entry) => entry.sequence > create.sequence && successful(entry) && entry.method === "GET" && acquisitionPath.test(entry.path) && entry.path.endsWith("/state")) ?? create;
    const challenge = routeAfter("credential acquisition OTP challenge", state.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/challenge") && entry.body?.step === "mailbox_otp");
    const proof = routeAfter("credential acquisition OTP proof", challenge.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/proof") && entry.body?.step === "mailbox_otp");
    const holderBinding = routeAfter("credential acquisition holder binding", proof.sequence, (entry) => entry.method === "GET" && acquisitionPath.test(entry.path) && entry.path.endsWith("/holder-binding"));
    const holderSignature = routeAfter("credential acquisition holder signature", holderBinding.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/holder-signature"));
    const issue = routeAfter("credential acquisition issue", holderSignature.sequence, (entry) => entry.method === "POST" && acquisitionPath.test(entry.path) && entry.path.endsWith("/issue"));
    const result = routeAfter("credential acquisition result", issue.sequence, (entry) => entry.method === "GET" && acquisitionPath.test(entry.path) && entry.path.endsWith("/result"));

    let credentialRecord;
    let credentialSpaceId;
    let policyStartSequence = result.sequence;
    if (!tc500) {
      const credentialWrite = routeAfter("durable credential-space write", result.sequence, (entry) => entry.path === "/invoke" && Array.isArray(entry.responseBody?.written) && entry.responseBody.written.some((key) => typeof key === "string" && key.startsWith("v1/records/")));
      credentialRecord = credentialWrite.responseBody.written.find((key) => key.startsWith("v1/records/"));
      assert(credentialWrite.authorization?.length > 0, "credential-space write was not authenticated");
      const credentialRead = routeAfter("authenticated credential-space readback", credentialWrite.sequence, (entry) => entry.path === "/invoke" && entry.responseBody?.type === "TinyCloudStoredCredential" && `v1/records/${entry.responseBody.recordId}` === credentialRecord);
      assert(credentialRead.authorization?.length > 0, "credential-space readback was not authenticated");
      policyStartSequence = credentialRead.sequence;
      credentialSpaceId = credentialRead.responseBody.ownerDid;
    }

    const policyChallenge = routeAfter("embedded Node Policy/v3 challenge", policyStartSequence, (entry) => entry.origin === canonical.node && entry.path === "/policy/v3/challenges" && entry.method === "POST");
    if (tc500) {
      assert.equal(receiverRequests.some((entry) => entry.sequence > result.sequence && entry.sequence < policyChallenge.sequence && entry.path === "/invoke"), false, "accountless credential custody touched TinyCloud account storage");
    }
    const policyCid = policyChallenge.body?.policyCid;
    assert.equal(policyCid, binding.body.policyCid, "Policy/v3 challenge did not bind the published policy CID");
    const policyMint = routeAfter("embedded Node Policy/v3 delegation mint", policyChallenge.sequence, (entry) => entry.origin === canonical.node && entry.path === "/policy/v3/delegations" && entry.method === "POST" && entry.body?.policyCid === policyCid && entry.body?.challengeId === policyChallenge.responseBody?.challengeId);
    const requestedKv = policyChallenge.body?.requestedCapabilities?.find((capability) => capability?.kind === "kv");
    const kvResource = requestedKv?.resource;
    assert.equal(kvResource, exactKvResource, "policy presentation did not request the envelope's exact TinyCloud KV resource");
    assert(requestedKv.actions.includes("tinycloud.kv/get") && !requestedKv.actions.some((action) => action === "tinycloud.kv/put" || action === "tinycloud.kv/list"), "policy presentation was not read-only");

    const receiverDid = policyChallenge.body?.recipientDid;
    if (tc500) {
      assert.match(receiverDid, /^did:key:z/, "accountless challenge recipient is not the receiver session key");
      assert.equal(policyMint.body?.presentation?.schema, "xyz.tinycloud.policy/presentation/v4");
      assert.equal(policyMint.body?.presentation?.holderDid, receiverDid);
      const minted = parseCompactUcanAuthorization(policyMint.responseBody?.authorization, policyMint.responseBody?.sessionCid);
      assert.equal(minted.payload.aud, receiverDid, "delegation audience was not the proven ephemeral holder");
      assert.equal(minted.payload.iss, publishedEnvelope.attestedEnforcerBinding.nodeAudience, "delegation issuer did not match the embedded Node audience");
      const encryptionCapability = publishedEnvelope.policy.capabilityCeiling.find((capability) => capability.kind === "encryption");
      assert(encryptionCapability, "published policy omitted its exact encryption resource");
      assert.deepEqual(Object.keys(minted.payload.att).sort(), [kvResource, encryptionCapability.resource].sort(), "delegation was not exact-resource scoped");
      const delegatedKvActions = Object.keys(minted.payload.att[kvResource]).sort();
      assert(delegatedKvActions.includes("tinycloud.kv/get") && delegatedKvActions.every((action) => ["tinycloud.kv/get", "tinycloud.kv/metadata"].includes(action)), "delegation was not read-only");
      assert.deepEqual(Object.keys(minted.payload.att[encryptionCapability.resource]), ["tinycloud.encryption/decrypt"], "delegation did not limit key unwrap to the exact encryption network");
      assert(minted.payload.exp > minted.payload.nbf && minted.payload.exp - minted.payload.nbf <= 900, "delegation lifetime was not short-lived");
      assert.equal(minted.payload.fct[0]?.policyCid, policyCid, "delegation policy fact did not match the presented policy");
      assert.equal(minted.payload.fct[0]?.profile, "policy-session-ucan/v1", "delegation was not an ordinary policy session");
    } else {
      credentialSpaceId = policyMint.body?.credentialSpaceId;
      assert.equal(typeof credentialSpaceId, "string", "Policy/v3 mint omitted the recipient credentials space");
      assert.equal(policyMint.body?.presentation?.credentialSpaceOwnerDid, credentialSpaceId, "Policy/v3 presentation did not bind the durable credential owner");
    }
    if (!tc500) assert.deepEqual(policyMint.body?.presentation?.requestedCapabilities, policyChallenge.body.requestedCapabilities, "Policy/v3 mint substituted the challenged capability slice");

    const delegate = routeAfter("ordinary delegation activation", policyMint.sequence, (entry) => entry.path === "/delegate" && entry.method === "POST");
    assert.equal(delegate.authorization, policyMint.responseBody?.authorization, "ordinary /delegate did not activate the freshly minted policy authorization");
    const invoke = routeAfter("ordinary exact-resource invocation", delegate.sequence, (entry) => entry.path === "/invoke" && entry.method === "POST" && authorizationNames(entry).includes(kvResource));
    const decrypt = tc500
      ? routeAfter("ordinary generic decrypt invocation", invoke.sequence, (entry) => entry.method === "POST" && entry.path === "/invoke" && entry.body?.type === "tinycloud.encryption.decrypt/v1")
      : routeAfter("ordinary delegated decrypt", invoke.sequence, (entry) => entry.method === "POST" && /^\/encryption\/networks\/[^/]+\/decrypt$/.test(entry.path));
    if (tc500) assert.equal(receiverRequests.some((entry) => entry.sequence > invoke.sequence && /^\/encryption\/networks\/[^/]+\/decrypt$/.test(entry.path)), false, "accountless receiver used a specialized decrypt route");
    assert(!receiverRequests.some((entry) => entry.path === "/share/v2/policy/session"), "receiver journey used the legacy /share/v2/policy/session route");
    if (tc500) assert.equal(receiverRequests.some((entry) => entry.origin === canonical.node && entry.path.startsWith("/share/")), false, "accountless receiver used a Node /share/* route");
    assert.equal(receiverTargets.length, 0, `embedded credential acquisition created browser targets: ${JSON.stringify(receiverTargets)}`);
    const diagnostics = await page.evaluate(() => window.__tc465Diagnostics);
    assert.equal(diagnostics.windowOpenCalls, 0, "embedded credential acquisition called window.open");
    if (tc500) {
      assert.equal(receiverRequests.some((entry) => entry.origin === canonical.openKey), false, "accountless receive contacted OpenKey before render");
      assert.equal(diagnostics.walletRequests, 0, "accountless receive requested a wallet provider before render");
    }
    assert.equal(receiverRequests.some((entry) => entry.origin === canonical.interaction), false, "embedded credential acquisition navigated to credentials.org");
    const allowedOrigins = new Set([canonical.share, canonical.node, canonical.witness, canonical.openKey, "null"]);
    const external = receiverRequests.filter((entry) => !allowedOrigins.has(entry.origin));
    assert.deepEqual(external.map((entry) => `${entry.method} ${entry.origin}${entry.path}`), [], "receiver journey attempted an external destination");

    const chain = [
      "delivery:email", "sender-history:reload",
      "acquisition:create", "acquisition:state", "acquisition:otp-challenge", "acquisition:otp-proof", "acquisition:holder-binding", "acquisition:holder-signature", "acquisition:issue", "acquisition:result",
      ...(tc500 ? ["credential:session-custody", "policy-v3:challenge", "policy-v3:mint"] : ["credentials:durable-write", "credentials:authenticated-readback", "policy-v3:challenge", "policy-v3:mint"]),
      "delegate", `invoke:${kvResource}`, tc500 ? "invoke:decrypt" : "decrypt", "decrypt:local", "render",
    ];
    const statuses = tc500 ? {
      delivery: deliveredMail !== undefined,
      senderLibrary: true,
      acquisition: result.sequence > create.sequence,
      sessionCredential: policyChallenge.sequence > result.sequence,
      policyV3: policyMint.sequence > policyChallenge.sequence,
      delegate: delegate.sequence > policyMint.sequence,
      invoke: invoke.sequence > delegate.sequence,
      genericDecrypt: decrypt.sequence > invoke.sequence,
      localDecrypt: rendered,
      rendered,
      legacyPolicySessionAbsent: true,
      zeroOpenKeyBeforeRender: true,
      zeroExternalDestinations: true,
      registryMetadataOnly: true,
      exactInvitationBindings: true,
      invitationReplayIdempotent: true,
      invitationNonceRebindingRejected: true,
      browserCors: true,
      exactDelegationBindings: true,
      zeroNodeShareRoutes: true,
    } : {
      acquisition: result.sequence > create.sequence,
      durableCredential: policyChallenge.sequence > result.sequence,
      policyV3Challenge: policyChallenge.sequence > result.sequence,
      policyV3Mint: policyMint.sequence > policyChallenge.sequence,
      delegate: delegate.sequence > policyMint.sequence,
      invoke: invoke.sequence > delegate.sequence,
      decrypt: decrypt.sequence > invoke.sequence,
      rendered,
      legacyPolicySessionAbsent: true,
      zeroExternalDestinations: true,
      noPopupOrNavigation: true,
    };
    assert(Object.values(statuses).every((value) => value === true), "receiver chain status is incomplete");
    const evidence = {
      type: tc500 ? "tinycloud.policy-access/delivered-email-evidence/v1" : "tinycloud.share/tc-465-joined-evidence/v2",
      renderedSha256: createHash("sha256").update(renderedBytes).digest("hex"),
      statuses,
      chain,
      slice: tc500 ? {
        shareCid,
        policyCid,
        resource: kvResource,
        receiverDid,
        delegationCid: policyMint.responseBody.delegation.delegationId,
        acquisitionIdSha256: createHash("sha256").update(acquisitionId).digest("hex"),
        deliveredMailIdSha256: createHash("sha256").update(String(deliveredMail.id)).digest("hex"),
      } : {
        shareCid,
        policyCid,
        resource: kvResource,
        credentialSpaceId,
        credentialRecord,
        acquisitionIdSha256: createHash("sha256").update(acquisitionId).digest("hex"),
      },
    };
    assert.equal(evidence.renderedSha256, createHash("sha256").update(expectedBytes).digest("hex"), "rendered bytes digest does not match the fixture digest");
    await writeFile(join(control, "tc465-result.json"), JSON.stringify(evidence), { flag: "wx", mode: 0o600 });
    await writeFile(join(control, "release"), "ok\n", { flag: "wx", mode: 0o600 });
    const exitCode = await new Promise((resolveExit) => integration.once("exit", resolveExit));
    assert.equal(exitCode, 0, `production-shaped ${tc500 ? "TC-500" : "TC-465"} composition failed after browser completion`);
    console.error(`${tc500 ? "TC-500 accountless" : "TC-465"} joined exact-email receiver: PASS ${JSON.stringify(evidence)}`);
  } finally {
    await browser?.close().catch(() => undefined);
    if (fixture?.exitCode === null) fixture.kill("SIGTERM");
    if (integration?.exitCode === null) integration.kill("SIGTERM");
    await rm(control, { recursive: true, force: true });
  }
}

await main();
