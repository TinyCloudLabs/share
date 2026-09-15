#!/usr/bin/env node

/**
 * TC-500 target-architecture joined gate.
 *
 * The Share origin is static. Every authority and byte transfer is made by
 * the browser directly to a signed Location Registry record, the discovered
 * owner Node, or OpenCredentials. There is intentionally no Share API,
 * Share registry, same-origin proxy, or Node /share/* route in this process.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { startCandidateServer } from "./candidate-server.mjs";
import { credentialOtpFromMail, isCredentialOtpMail, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/skgbafa/tc-500-node-1.17.1");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-d43839e";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const outputPath = resolve(process.env.TC500_E2E_ARTIFACT ?? join(workspaceRoot, ".context/tc-500-native-joined.json"));
const fixture = Buffer.concat([Buffer.from("TC-500 native joined fixture\n", "utf8"), Buffer.from([0, 0x80, 0xff, 0x0a])]);
const fixtureDigest = createHash("sha256").update(fixture).digest("hex");
const trace = [];
const consoleCounts = {};
let phase = "sender";
let journeyStage = "setup";
let failureReported = false;

function fail(stage) {
  if (!failureReported) console.error(`[tc500] joined gate failed at ${stage}; sensitive details withheld`);
  failureReported = true;
  process.exitCode = 1;
}
process.on("uncaughtException", () => fail("uncaught"));
process.on("unhandledRejection", () => fail("unhandled"));

function stringsIn(value, output = []) {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) for (const item of value) stringsIn(item, output);
  else if (value !== null && typeof value === "object") for (const [key, item] of Object.entries(value)) { output.push(key); stringsIn(item, output); }
  return output;
}

function parseBody(body) {
  if (typeof body !== "string" || body.length === 0) return undefined;
  try { return JSON.parse(body); } catch { return undefined; }
}

function findMail(messages, predicate) {
  return messages.find((entry) => predicate(stringsIn(entry.payload)));
}

function invitationFromMail(message) {
  return stringsIn(message?.payload).flatMap((value) => [...value.matchAll(/https:\/\/share\.tinycloud\.xyz\/s\/inline#[^\s"'<>]+/g)].map((match) => match[0].replaceAll("&amp;", "&")))[0];
}

async function waitUntil(check, timeout = 180_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  return undefined;
}

function recordRequest(request) {
  const url = new URL(request.url());
  if (!url.protocol.startsWith("http")) return undefined;
  const entry = { sequence: trace.length + 1, phase, method: request.method(), origin: url.origin, path: url.pathname, status: undefined, body: parseBody(request.postData()), authorization: request.headers().authorization };
  trace.push(entry);
  return entry;
}

function headerSubset(request) {
  const headers = new Headers(request.headers());
  for (const key of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"]) headers.delete(key);
  return headers;
}

async function installRouting(page, stack) {
  await page.evaluateOnNewDocument(() => {
    window.__tc500BinaryBodies = [];
    window.__tc500Clipboard = [];
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url, location.href);
      const body = init?.body;
      if (url.pathname === "/invoke" && (body instanceof Blob || body instanceof ArrayBuffer || ArrayBuffer.isView(body))) {
        const bytes = body instanceof Blob ? new Uint8Array(await body.arrayBuffer()) : body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
        window.__tc500BinaryBodies.push(Array.from(bytes));
      }
      return originalFetch(input, init);
    };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value) => { window.__tc500Clipboard.push(value); } } });
  });
  page.on("console", (message) => { consoleCounts[message.type()] = (consoleCounts[message.type()] ?? 0) + 1; });
  page.on("pageerror", () => { consoleCounts.pageerror = (consoleCounts.pageerror ?? 0) + 1; });
  await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    const entry = recordRequest(request);
    if (url.origin === stack.canonical.share || url.protocol === "data:" || url.protocol === "blob:") { await request.continue(); return; }
    const targets = new Map([
      [stack.canonical.node, stack.services.nodeOrigin],
      [stack.canonical.credentials, stack.services.credentialsOrigin],
      [stack.canonical.registry, stack.services.registryOrigin],
      ["https://openkey.so", stack.services.openKeyOrigin],
      ["https://api.openkey.so", stack.services.openKeyOrigin],
    ]);
    const targetOrigin = targets.get(url.origin);
    if (targetOrigin === undefined) { await request.abort("blockedbyclient"); return; }
    if (request.method() === "OPTIONS" && url.origin === "https://api.openkey.so") {
      await request.respond({ status: 204, headers: { "access-control-allow-origin": stack.canonical.share, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "authorization, content-type", vary: "Origin" } }); return;
    }
    let body;
    if (!new Set(["GET", "HEAD"]).has(request.method())) {
      if (url.pathname === "/invoke" && request.headers()["content-type"]?.startsWith("application/vnd.tinycloud.sealed")) body = Buffer.from(await page.evaluate(() => window.__tc500BinaryBodies.shift() ?? []));
      else body = request.postData();
    }
    const response = await fetch(new URL(`${url.pathname}${url.search}`, targetOrigin), { method: request.method(), headers: headerSubset(request), redirect: "manual", ...(body === undefined ? {} : { body }) });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (entry !== undefined) { entry.status = response.status; try { entry.response = JSON.parse(bytes.toString("utf8")); } catch {} }
    const headers = Object.fromEntries(response.headers.entries());
    for (const key of ["connection", "content-encoding", "content-length", "keep-alive", "transfer-encoding"]) delete headers[key];
    if (url.origin !== "https://openkey.so") {
      headers["access-control-allow-origin"] = request.headers().origin ?? stack.canonical.share;
      headers["access-control-allow-credentials"] = "true";
      headers["access-control-allow-methods"] = "GET, PUT, POST, OPTIONS";
      headers["access-control-allow-headers"] = request.headers()["access-control-request-headers"] ?? "authorization, content-type";
      headers.vary = "Origin";
    }
    await request.respond({ status: response.status, headers, body: bytes });
  })().catch(() => request.abort("failed").catch(() => undefined)); });
}

async function clickText(page, value, timeout = 60_000) {
  const found = await waitUntil(async () => {
    for (const frame of page.frames()) {
      const clicked = await frame.evaluate((label) => {
        const visit = (root) => {
          for (const button of root.querySelectorAll("button,[role=button],a")) {
            if ((button.textContent ?? "").trim().includes(label) && !button.disabled) { button.click(); return true; }
          }
          for (const child of root.querySelectorAll("*")) if (child.shadowRoot && visit(child.shadowRoot)) return true;
          return false;
        };
        return visit(document);
      }, value).catch(() => false);
      if (clicked) return true;
    }
    return false;
  }, timeout);
  assert.equal(found, true, `required ${value} action did not become available`);
}

async function submitCredentialValue(page, value, expectedType) {
  const filled = await waitUntil(() => page.evaluate(({ value, expectedType }) => {
    const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
    const input = root?.querySelector("input");
    if (!(input instanceof HTMLInputElement)) return false;
    if (expectedType === "otp" && input.type !== "text" && input.inputMode !== "numeric" && input.name !== "otp") return false;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    if (setter === undefined) return false;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    return true;
  }, { value, expectedType }).catch(() => false), 90_000);
  if (!filled) return false;
  await page.evaluate(() => new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame))));
  return waitUntil(() => page.evaluate(({ value, expectedType }) => {
    const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
    const input = root?.querySelector("input");
    const button = [...(root?.querySelectorAll("button") ?? [])].find((candidate) => !candidate.disabled);
    if (!(input instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement) || input.value !== value) return false;
    if (expectedType === "otp" && input.type !== "text" && input.inputMode !== "numeric" && input.name !== "otp") return false;
    button.click(); return true;
  }, { value, expectedType }).catch(() => false), 10_000);
}

async function downloadExact(page, temporary) {
  await page.waitForSelector(".viewer-download", { timeout: 180_000 });
  const cdp = await page.createCDPSession(); await cdp.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: temporary });
  await page.click(".viewer-download");
  return waitUntil(async () => {
    const { readdir } = await import("node:fs/promises");
    for (const name of await readdir(temporary)) {
      if (name.endsWith(".pem") || name.endsWith(".key") || name.endsWith(".json")) continue;
      const bytes = await readFile(join(temporary, name)).catch(() => undefined);
      if (bytes?.equals(fixture)) return true;
    }
    return false;
  }, 30_000);
}

function traceAudit(stack) {
  const at = (p, origin, path, method) => trace.find((entry) => entry.phase === p && entry.origin === origin && entry.path === path && (method === undefined || entry.method === method) && entry.status >= 200 && entry.status < 300);
  const accountLocationPath = "/v1/locations/" + encodeURIComponent(`did:pkh:eip155:1:${stack.walletAddress.toLowerCase()}`);
  assert(trace.some((entry) => entry.phase === "sender" && entry.origin === stack.canonical.registry && entry.path === accountLocationPath && entry.method === "GET" && entry.status === 404), "fresh sender did not prove the missing-location bootstrap case");
  const publishedLocation = trace.find((entry) => entry.phase === "sender" && entry.origin === stack.canonical.registry && entry.path.startsWith("/v1/locations/") && entry.method === "PUT" && entry.status >= 200 && entry.status < 300);
  const ownerDid = publishedLocation?.body?.subject;
  assert.match(ownerDid ?? "", /^did:key:z/);
  assert.equal(publishedLocation?.path, `/v1/locations/${encodeURIComponent(ownerDid)}`, "sender published location under the wrong subject");
  assert(at("sender", stack.canonical.node, "/policy/v3/policies", "POST"), "sender did not register embedded Node policy");
  assert(at("sender", stack.canonical.node, "/policy/v3/deliveries/authorize", "POST"), "sender did not authorize delivery at owner Node");
  assert(at("sender", stack.canonical.credentials, "/v1/credential-invitations", "POST"), "sender did not send generic credential invitation");
  assert(at("recipient", stack.canonical.credentials, "/v1/acquisitions", "POST"), "recipient did not acquire email credential");
  assert(at("recipient", stack.canonical.registry, `/v1/locations/${encodeURIComponent(ownerDid)}`, "GET"), "recipient did not discover the sender's published owner Node");
  const challenge = at("recipient", stack.canonical.node, "/policy/v3/challenges", "POST");
  const delegation = at("recipient", stack.canonical.node, "/policy/v3/delegations", "POST");
  assert(challenge && delegation, "recipient did not present credential to embedded Node policy");
  assert.equal(delegation.body?.presentation?.holderDid, challenge.body?.recipientDid, "recipient changed ephemeral did:key between acquisition and policy presentation");
  assert.match(challenge.body?.recipientDid ?? "", /^did:key:z/);
  assert(at("recipient", stack.canonical.node, "/delegate", "POST"), "recipient did not import scoped delegation");
  assert(trace.filter((entry) => entry.phase === "recipient" && entry.origin === stack.canonical.node && entry.path === "/invoke" && entry.status >= 200 && entry.status < 300).length >= 2, "recipient did not read ciphertext and decrypt through ordinary invoke");
  assert(!trace.some((entry) => entry.phase === "recipient" && /openkey/i.test(entry.origin)), "recipient contacted OpenKey before render");
  assert(!trace.some((entry) => entry.path.startsWith("/share/") || /api\.share/.test(entry.origin) || (entry.origin === stack.canonical.registry && !entry.path.startsWith("/v1/locations/"))), "journey used a prohibited Share or registry data plane");
  return { ownerDidSha256: createHash("sha256").update(ownerDid).digest("hex"), receiverDidSha256: createHash("sha256").update(challenge.body.recipientDid).digest("hex"), nodeInvokeCount: trace.filter((entry) => entry.phase === "recipient" && entry.path === "/invoke").length };
}

const temporary = await mkdtemp(join(tmpdir(), "tc500-native-joined-"));
const fixturePath = join(temporary, "native-fixture.bin"); await writeFile(fixturePath, fixture, { flag: "wx", mode: 0o600 });
let stack; let candidate; let browser;
try {
  journeyStage = "share-build";
  execFileSync("npm", ["run", "build"], { cwd: shareRoot, stdio: "ignore" });
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore" });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8" }).trim();
  candidate = await startCandidateServer({ root: resolve(shareRoot, "dist"), key: await readFile(key), cert: await readFile(cert) });
  journeyStage = "native-stack-readiness";
  stack = await startNativeStack({ root: temporary, nodeRoot, credentialsRoot, registryRoot });
  journeyStage = "browser-launch";
  browser = await puppeteer.launch({ headless: process.env.HEADED !== "1", args: [`--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${candidate.port}`, `--ignore-certificate-errors-spki-list=${spki}`, "--disable-quic", "--no-proxy-server"] });

  const sender = await browser.newPage(); await installRouting(sender, stack);
  journeyStage = "sender-navigation";
  await sender.goto(`${stack.canonical.share}/share#/new`, { waitUntil: "domcontentloaded", timeout: 180_000 });
  journeyStage = "sender-authentication";
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 }); await sender.click("button.auth-button");
  await clickText(sender, "Create TinyCloud Space", 10_000).catch(() => undefined);
  await sender.waitForSelector("form.composer-form", { timeout: 180_000 });
  journeyStage = "sender-composition";
  await sender.$eval('input[name="recipient"][value="exactEmail"]', (input) => input.click());
  const recipientEmail = `tc500-native-${Date.now()}@mailinator.com`;
  await sender.type('input[name="recipient-value"]', recipientEmail);
  const upload = await sender.$('input[name="document"]'); assert(upload); await upload.uploadFile(fixturePath);
  journeyStage = "sender-publication";
  await sender.click("button.create-link-button");
  await sender.waitForFunction(() => document.querySelector(".composer-status")?.dataset.state === "created", { timeout: 300_000 });
  await clickText(sender, "Copy link");
  const shareUrl = await sender.evaluate(() => window.__tc500Clipboard.at(-1));
  assert.match(shareUrl ?? "", /^https:\/\/share\.tinycloud\.xyz\/s\/inline#v=2&p=/);
  journeyStage = "sender-delivery";
  await clickText(sender, "Notify recipient");
  const invitationMail = await waitUntil(() => findMail(stack.mail, (values) => values.some((value) => value.includes("/s/inline#"))), 60_000);
  const invitation = invitationFromMail(invitationMail); assert.equal(typeof invitation, "string");

  phase = "recipient";
  journeyStage = "recipient-navigation";
  const recipientContext = await browser.createBrowserContext(); const recipient = await recipientContext.newPage(); await installRouting(recipient, stack);
  await recipient.goto(invitation, { waitUntil: "domcontentloaded", timeout: 180_000 });
  journeyStage = "recipient-email";
  assert.equal(await submitCredentialValue(recipient, recipientEmail, "email"), true);
  const otpMail = await waitUntil(() => stack.mail.find((message) => isCredentialOtpMail(message, recipientEmail)), 60_000);
  const otp = credentialOtpFromMail(otpMail); assert.match(otp ?? "", /^\d{6}$/);
  journeyStage = "recipient-otp";
  assert.equal(await submitCredentialValue(recipient, otp, "otp"), true);
  journeyStage = "recipient-decrypt-render";
  assert.equal(await downloadExact(recipient, temporary), true);
  journeyStage = "traffic-audit";
  const audit = traceAudit(stack);

  const artifact = { type: "tinycloud.share/native-joined-e2e/v1", result: "passed", fixtureSha256: fixtureDigest, provenance: stack.provenance, ...audit, consoleCounts, prohibitedShareDataPlaneRequests: 0 };
  await writeFile(outputPath, JSON.stringify(artifact, null, 2), { mode: 0o600 });
  console.log(JSON.stringify(artifact, null, 2));
} catch {
  const pageState = await browser?.pages().then(async (pages) => {
    const page = pages.find((candidatePage) => candidatePage.url().startsWith(stack?.canonical.share ?? "https://share.tinycloud.xyz"));
    return page?.evaluate(() => {
      const status = document.querySelector(".composer-status");
      return status === null ? undefined : { state: (status instanceof HTMLElement ? status.dataset.state : undefined), text: status.textContent?.trim().slice(0, 240) };
    }).catch(() => undefined);
  }).catch(() => undefined);
  await writeFile(outputPath, JSON.stringify({
    type: "tinycloud.share/native-joined-e2e/v1",
    result: "failed",
    stage: journeyStage,
    requests: trace.map(({ phase: requestPhase, method, origin, path, status, response }) => ({
      phase: requestPhase,
      method,
      origin,
      path,
      status,
      code: typeof response?.error?.code === "string" ? response.error.code : typeof response?.code === "string" ? response.code : undefined,
    })),
    pageState,
    consoleCounts,
  }, null, 2), { mode: 0o600 }).catch(() => undefined);
  fail(journeyStage);
} finally {
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  console.log(`[tc500] artifacts retained under ${temporary.replace(/[^/]+$/, "<redacted>")}`);
}
