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
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { signCompactUcanAuthorization, toBase64Url, verifyCompactUcanAuthorization } from "@tinycloud/share-envelope";
import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { credentialOtpFromMail, isCredentialOtpMail, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/skgbafa/tc-500-node-1.17.1");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const outputPath = resolve(process.env.TC500_E2E_ARTIFACT ?? join(workspaceRoot, ".context/tc-500-native-joined.json"));
const fixture = Buffer.concat([Buffer.from("TC-500 native joined fixture\n", "utf8"), Buffer.from([0, 0x80, 0xff, 0x0a])]);
const fixtureDigest = createHash("sha256").update(fixture).digest("hex");
const publishedPackages = Object.freeze([
  "@tinycloud/node-sdk",
  "@tinycloud/sdk-core",
  "@tinycloud/sdk-services",
  "@tinycloud/web-sdk",
  "@tinycloud/share-sdk",
  "@tinycloud/share-envelope",
]);
const trace = [];
const consoleCounts = {};
const consoleDiagnostics = [];
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

async function digestDirectory(root, relative = "") {
  const digest = createHash("sha256");
  const directory = join(root, relative);
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((left, right) => left.name.localeCompare(right.name))) {
    const path = relative === "" ? entry.name : `${relative}/${entry.name}`;
    if (entry.isDirectory()) digest.update(`directory:${path}\0`).update(await digestDirectory(root, path));
    else if (entry.isFile()) digest.update(`file:${path}\0`).update(await readFile(join(root, path)));
  }
  return digest.digest("hex");
}

async function shareProvenance() {
  const git = (args) => execFileSync("git", args, { cwd: shareRoot, encoding: "utf8" }).trim();
  const lock = JSON.parse(await readFile(join(shareRoot, "package-lock.json"), "utf8"));
  const packages = Object.fromEntries(publishedPackages.map((name) => {
    const packageLock = lock.packages?.[`node_modules/${name}`];
    assert.equal(typeof packageLock?.version, "string", `package lock has no version for ${name}`);
    assert.match(packageLock.integrity ?? "", /^sha512-/, `package lock has no npm integrity for ${name}`);
    return [name, { version: packageLock.version, integrity: packageLock.integrity }];
  }));
  return {
    shareCommit: git(["rev-parse", "HEAD"]),
    shareTree: git(["rev-parse", "HEAD^{tree}"]),
    bundleSha256: await digestDirectory(join(shareRoot, "dist")),
    publishedPackages: packages,
  };
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
  for (const key of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-tc500-binary-id"]) headers.delete(key);
  return headers;
}

async function installRouting(page, stack) {
  await page.evaluateOnNewDocument(installBrowserInstrumentation);
  page.on("console", (message) => {
    consoleCounts[message.type()] = (consoleCounts[message.type()] ?? 0) + 1;
    if (message.type() === "error" || message.type() === "warn") consoleDiagnostics.push({ type: message.type(), text: message.text().replaceAll(/https:\/\/[^\s#]+(?:#[^\s]*)?/g, "<url>").replaceAll(/[A-Za-z0-9_-]{80,}/g, "<redacted>").slice(0, 240) });
  });
  page.on("pageerror", (error) => {
    consoleCounts.pageerror = (consoleCounts.pageerror ?? 0) + 1;
    consoleDiagnostics.push({ type: "pageerror", text: String(error?.message ?? "page error").replaceAll(/[A-Za-z0-9_-]{80,}/g, "<redacted>").slice(0, 240) });
  });
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
      const binaryId = request.headers()["x-tc500-binary-id"];
      if (url.pathname === "/invoke" && binaryId !== undefined) {
        assert.match(binaryId, /^\d+$/, "binary browser request has an invalid captured body id");
        const captured = await page.evaluate((id) => {
          const bytes = window.__tc500BinaryBodies[id];
          delete window.__tc500BinaryBodies[id];
          return bytes;
        }, binaryId);
        assert(Array.isArray(captured), "binary browser request body was not captured");
        body = Buffer.from(captured);
      }
      else body = await request.fetchPostData();
    }
    if (entry !== undefined && Buffer.isBuffer(body)) {
      entry.requestByteLength = body.byteLength;
      entry.requestSha256 = createHash("sha256").update(body).digest("hex");
    }
    const response = await fetch(new URL(`${url.pathname}${url.search}`, targetOrigin), { method: request.method(), headers: headerSubset(request), redirect: "manual", ...(body === undefined ? {} : { body }) });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (entry !== undefined) {
      entry.status = response.status;
      entry.responseByteLength = bytes.byteLength;
      entry.responseSha256 = createHash("sha256").update(bytes).digest("hex");
      entry.responseContentType = response.headers.get("content-type") ?? undefined;
      try { entry.response = JSON.parse(bytes.toString("utf8")); } catch {}
    }
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
  const input = await waitUntil(async () => {
    const handle = await page.evaluateHandle((expectedType) => {
      const candidate = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input");
      if (!(candidate instanceof HTMLInputElement)) return null;
      if (expectedType === "otp" && candidate.type !== "text" && candidate.inputMode !== "numeric" && candidate.name !== "otp") return null;
      return candidate;
    }, expectedType).catch(() => undefined);
    return handle?.asElement() ?? undefined;
  }, 90_000);
  if (input === undefined) return false;
  await input.click({ clickCount: 3 });
  await page.keyboard.press("Backspace");
  await input.type(value);
  // The SDK view submits itself once all eight digits are entered; an older
  // view waits for its submit button.
  const autoSubmitted = await page.evaluate((expected) => {
    const candidate = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input");
    return candidate instanceof HTMLInputElement && candidate.readOnly && candidate.value === expected;
  }, value).catch(() => false);
  if (autoSubmitted) return true;
  const button = await waitUntil(async () => {
    const handle = await page.evaluateHandle(({ value, expectedType }) => {
      const root = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot;
      const candidateInput = root?.querySelector("input");
      const candidateButton = [...(root?.querySelectorAll("button[type=submit]") ?? [])].find((candidate) => !candidate.disabled);
      if (!(candidateInput instanceof HTMLInputElement) || !(candidateButton instanceof HTMLButtonElement) || candidateInput.value !== value) return null;
      if (expectedType === "otp" && candidateInput.type !== "text" && candidateInput.inputMode !== "numeric" && candidateInput.name !== "otp") return null;
      return candidateButton;
    }, { value, expectedType }).catch(() => undefined);
    return handle?.asElement() ?? undefined;
  }, 10_000);
  if (button === undefined) return false;
  await button.click();
  return true;
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

function successfulRequest(entry) {
  return entry.status >= 200 && entry.status < 300;
}

function assertBearerDidNotAuthorize(stack) {
  const prohibitedBeforeProof = trace.filter((entry) => entry.phase === "recipient" && (
    /openkey/i.test(entry.origin)
    || (entry.origin === stack.canonical.node && (
      entry.path === "/policy/v3/delegations"
      || entry.path === "/delegate"
      || entry.path === "/invoke"
    ))
  ));
  assert.equal(prohibitedBeforeProof.length, 0, "invitation bearer authorized recipient access before mailbox proof");
}

async function credentialInputReady(page, expectedType) {
  return waitUntil(() => page.evaluate((expectedType) => {
    const candidate = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input");
    if (!(candidate instanceof HTMLInputElement)) return false;
    return expectedType !== "otp" || candidate.type === "text" || candidate.inputMode === "numeric" || candidate.name === "otp";
  }, expectedType).catch(() => false), 90_000);
}

function auditBrowserDiagnostics(stack) {
  const failedRequests = trace.filter((entry) => typeof entry.status === "number" && entry.status >= 400);
  const locationBootstrapMisses = failedRequests.filter((entry) => entry.phase === "sender" && entry.origin === stack.canonical.registry && entry.method === "GET" && entry.path.startsWith("/v1/locations/") && entry.status === 404);
  const ownerStateBootstrapMisses = failedRequests.filter((entry) => entry.phase === "sender" && entry.origin === stack.canonical.node && entry.status === 404 && (
    (entry.method === "GET" && entry.path.startsWith("/encryption/networks/"))
    || (entry.method === "POST" && entry.path === "/invoke")
  ));
  const bootstrapMisses = new Set([...locationBootstrapMisses, ...ownerStateBootstrapMisses]);
  const expectedEnforcement = new Map([
    ["negative-sibling", 403],
    ["negative-write", 403],
    ["negative-tamper", 401],
    ["negative-revoked", 403],
    ["domain-negative-sibling", 403],
    ["domain-negative-write", 403],
    ["domain-negative-tamper", 401],
  ]);
  const admittedRequestReplayRejections = failedRequests.filter((entry) => entry.phase === "domain-replay" && entry.method === "POST" && entry.path === "/policy/v3/delegations" && entry.status >= 400 && entry.status < 500);
  const unexpectedRequests = failedRequests.filter((entry) => !bootstrapMisses.has(entry) && !admittedRequestReplayRejections.includes(entry) && !(entry.method === "POST" && entry.path === "/invoke" && expectedEnforcement.get(entry.phase) === entry.status));
  assert.equal(unexpectedRequests.length, 0, "browser observed an unexpected failed network request");
  const errors = consoleDiagnostics.filter((entry) => entry.type === "error");
  const warnings = consoleDiagnostics.filter((entry) => entry.type === "warn");
  const pageErrors = consoleDiagnostics.filter((entry) => entry.type === "pageerror");
  assert.equal(pageErrors.length, 0, "browser raised an unexpected page error");
  assert(errors.every((entry) => /^Failed to load resource: the server responded with a status of (400|401|403|404|409) \((?:Bad Request|Unauthorized|Forbidden|Not Found|Conflict)\)$/.test(entry.text)), "browser emitted an unexpected console error");
  assert.equal(errors.length, failedRequests.length, "browser console/network failure accounting diverged");
  assert(locationBootstrapMisses.length > 0, "fresh sender did not observe the expected missing-location bootstrap response");
  assert(ownerStateBootstrapMisses.length > 0, "fresh sender did not observe expected uninitialized owner state");
  assert.equal(warnings.length, 1, "browser emitted an unexpected number of warnings");
  assert.match(warnings[0].text, /^TinyCloud account registry sync failed after retries/, "browser emitted an unexpected warning");
  return {
    unexpectedConsoleErrors: 0,
    unexpectedPageErrors: 0,
    expectedLocationBootstrap404s: locationBootstrapMisses.length,
    expectedOwnerStateBootstrap404s: ownerStateBootstrapMisses.length,
    expectedPolicyDenials: Object.fromEntries(expectedEnforcement),
    admittedRequestReplayRejections: admittedRequestReplayRejections.map((entry) => entry.status),
    expectedBootstrapWarnings: warnings.length,
  };
}

async function recipientSigningMaterial(page) {
  const record = await page.evaluate(() => {
    const raw = sessionStorage.getItem("tinycloud.share.receiver-session.v1");
    return raw === null ? undefined : JSON.parse(raw);
  });
  assert.equal(record?.type, "TinyCloudShareReceiverSession", "recipient session key record is missing");
  assert.equal(record?.version, 1, "recipient session key record version is invalid");
  assert.match(record?.holderDid ?? "", /^did:key:z/, "recipient session holder DID is invalid");
  assert.equal(record?.jwk?.kty, "OKP", "recipient session key is not Ed25519");
  const privateKey = await crypto.subtle.importKey("jwk", record.jwk, { name: "Ed25519" }, false, ["sign"]);
  return {
    holderDid: record.holderDid,
    sign: async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, bytes)),
  };
}

async function signedPolicyInvocation({ authorization, holderDid, sign, nodeAudience, policyCid, action, resource }) {
  const session = verifyCompactUcanAuthorization(authorization);
  const now = Math.floor(Date.now() / 1000);
  assert(session.payload.exp > now, "policy session expired before negative enforcement checks");
  return signCompactUcanAuthorization({
    issuerDid: holderDid,
    audienceDid: nodeAudience,
    attenuation: { [resource]: { [action]: [{ type: "xyz.tinycloud.resource/selector", kind: "exact", value: resource }] } },
    facts: [{ type: "tinycloud.policy.invocation/v1", policyCid, sessionCid: session.cid }],
    proofs: [session.cid],
    notBefore: now,
    expiresAt: Math.min(now + 60, session.payload.exp),
    nonce: toBase64Url(randomBytes(16)),
    sign,
  });
}

async function invokeFromBrowser(page, nodeOrigin, authorization, body) {
  return page.evaluate(async ({ nodeOrigin, authorization, body }) => {
    const headers = new Headers({ accept: "application/json", Authorization: authorization });
    let requestBody;
    if (body !== undefined) {
      headers.set("content-type", "application/octet-stream");
      requestBody = Uint8Array.from(body);
    }
    const response = await fetch(new URL("/invoke", nodeOrigin), { method: "POST", headers, ...(requestBody === undefined ? {} : { body: requestBody }) });
    await response.arrayBuffer();
    return response.status;
  }, { nodeOrigin, authorization, body });
}

async function verifyNegativeEnforcement({ sender, recipient, stack, recipientPhase = "recipient", prefix = "", revoke = true }) {
  const challenge = trace.find((entry) => entry.phase === recipientPhase && entry.method === "POST" && entry.path === "/policy/v3/challenges" && successfulRequest(entry));
  const delegation = trace.find((entry) => entry.phase === recipientPhase && entry.method === "POST" && entry.path === "/policy/v3/delegations" && successfulRequest(entry));
  const imported = trace.find((entry) => entry.phase === recipientPhase && entry.method === "POST" && entry.path === "/delegate" && successfulRequest(entry));
  assert(challenge && delegation && imported?.authorization, "policy session evidence is missing for negative enforcement checks");
  const session = verifyCompactUcanAuthorization(imported.authorization);
  const kvCapability = challenge.body?.requestedCapabilities?.find((candidate) => candidate?.kind === "kv");
  const kvResource = kvCapability?.resource;
  assert.equal(typeof kvResource, "string", "policy session KV resource is missing");
  const nodeAudience = session.payload.iss.split("#", 1)[0];
  assert.match(nodeAudience ?? "", /^did:key:z/, "policy session node audience is invalid");
  const material = await recipientSigningMaterial(recipient);
  assert.equal(material.holderDid, challenge.body.recipientDid, "negative checks did not use the admitted ephemeral recipient DID");
  const base = { authorization: imported.authorization, holderDid: material.holderDid, sign: material.sign, nodeAudience, policyCid: challenge.body.policyCid };

  const sibling = `${kvResource}.sibling`;
  const siblingInvocation = await signedPolicyInvocation({ ...base, action: "tinycloud.kv/get", resource: sibling });
  phase = `${prefix}negative-sibling`;
  const siblingReadStatus = await invokeFromBrowser(recipient, stack.canonical.node, siblingInvocation.authorization);
  assert.equal(siblingReadStatus, 403, "policy session allowed a sibling KV read");

  const writeInvocation = await signedPolicyInvocation({ ...base, action: "tinycloud.kv/put", resource: kvResource });
  phase = `${prefix}negative-write`;
  const writeEscalationStatus = await invokeFromBrowser(recipient, stack.canonical.node, writeInvocation.authorization, [1, 2, 3]);
  assert.equal(writeEscalationStatus, 403, "policy session allowed KV write escalation");

  const tamperInvocation = await signedPolicyInvocation({ ...base, action: "tinycloud.kv/get", resource: kvResource });
  const last = tamperInvocation.authorization.at(-1);
  const tampered = `${tamperInvocation.authorization.slice(0, -1)}${last === "A" ? "B" : "A"}`;
  phase = `${prefix}negative-tamper`;
  const tamperStatus = await invokeFromBrowser(recipient, stack.canonical.node, tampered);
  assert.equal(tamperStatus, 401, "Node admitted a tampered recipient invocation");

  if (!revoke) return { siblingReadStatus, writeEscalationStatus, tamperStatus };
  const revokedInvocation = await signedPolicyInvocation({ ...base, action: "tinycloud.kv/get", resource: kvResource });
  phase = "sender-revocation";
  await sender.evaluate(() => { window.location.hash = "#/library"; });
  await sender.waitForSelector(".sender-revoke:not([disabled])", { timeout: 180_000 });
  sender.once("dialog", (dialog) => void dialog.accept());
  await sender.click(".sender-revoke:not([disabled])");
  await sender.waitForFunction(() => document.body.textContent?.includes("Share revoked."), { timeout: 180_000 });
  phase = "negative-revoked";
  const revokedReadStatus = await invokeFromBrowser(recipient, stack.canonical.node, revokedInvocation.authorization);
  assert.equal(revokedReadStatus, 403, "revoked policy root still authorized a KV read");

  return { bearerWithoutOtp: true, siblingReadStatus, writeEscalationStatus, tamperStatus, revokedReadStatus };
}

/**
 * Bearer regression on the same stack: a link-only share opens in a fresh
 * context through native `tc1` delegation, with no credential acquisition,
 * no Policy/v3 admission, and no OpenKey before render.
 */
async function verifyBearerRegression({ browser, sender, stack }) {
  phase = "bearer-sender";
  await sender.evaluate(() => { window.location.hash = "#/new"; });
  await sender.waitForSelector("form.composer-form", { timeout: 180_000 });
  await sender.$eval('input[name="recipient"][value="bearer"]', (input) => input.click());
  const upload = await sender.$('input[name="document"]'); assert(upload); await upload.uploadFile(fixturePath);
  await sender.click("button.create-link-button");
  await sender.waitForFunction(() => document.querySelector(".composer-status")?.dataset.state === "created", { timeout: 300_000 });
  const copied = await sender.evaluate(() => window.__tc500Clipboard.length);
  await clickText(sender, "Copy link");
  const bearerUrl = await waitUntil(() => sender.evaluate((count) => window.__tc500Clipboard.length > count ? window.__tc500Clipboard.at(-1) : undefined, copied), 10_000);
  assert.match(bearerUrl ?? "", /^https:\/\/share\.tinycloud\.xyz\/viewer#tc1=/, "bearer share did not produce a native tc1 link");
  phase = "bearer-recipient";
  const context = await browser.createBrowserContext(); const reader = await context.newPage(); await installRouting(reader, stack);
  await reader.goto(bearerUrl, { waitUntil: "domcontentloaded", timeout: 180_000 });
  const bearerTemporary = await mkdtemp(join(tmpdir(), "tc500-bearer-"));
  assert.equal(await downloadExact(reader, bearerTemporary), true, "bearer recipient did not render the exact bytes");
  const bearerTrace = trace.filter((entry) => entry.phase === "bearer-recipient");
  assert(!bearerTrace.some((entry) => /openkey/i.test(entry.origin)), "bearer recipient contacted OpenKey");
  assert(!bearerTrace.some((entry) => entry.origin === stack.canonical.credentials || entry.path.startsWith("/policy/v3/")), "bearer recipient ran a credential or policy ceremony");
  const invokes = bearerTrace.filter((entry) => entry.origin === stack.canonical.node && entry.path === "/invoke" && successfulRequest(entry));
  assert(invokes.length >= 1, "bearer recipient did not read through ordinary invoke");
  await context.close();
  return { bearerRendered: true, bearerInvokeCount: invokes.length, bearerOpenKeyRequests: 0, bearerCredentialRequests: 0 };
}

async function mailboxEntry(page) {
  return waitUntil(async () => {
    const handle = await page.evaluateHandle(() => document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input#mailbox") ?? null).catch(() => undefined);
    return handle?.asElement() ?? undefined;
  }, 90_000);
}

async function enterMailbox(page, mailbox) {
  const input = await mailboxEntry(page);
  assert(input, "domain recipient mailbox entry did not appear");
  await input.click({ clickCount: 3 }); await page.keyboard.press("Backspace");
  await input.type(mailbox);
  await page.evaluate(() => document.querySelector("tinycloud-credential-acquisition").shadowRoot.querySelector("button[type=submit]").click());
}

/**
 * Domain-addressed share on the same stack: any mailbox whose issuer-derived
 * domain is exactly the invited one can claim it; look-alikes never start an
 * acquisition; the Node enforces the signed domain claim and read-only scope.
 */
async function verifyDomainJourney({ browser, sender, stack }) {
  const domain = "tinycloud.test";
  phase = "domain-sender";
  // The bearer leg left the composer on its result screen.
  await clickText(sender, "Share another");
  await sender.waitForSelector('form.composer-form input[name="recipient"][value="emailDomain"]', { visible: true, timeout: 180_000 });
  await sender.$eval('input[name="recipient"][value="emailDomain"]', (input) => input.click());
  await sender.type('input[name="recipient-value"]', domain);
  const upload = await sender.$('input[name="document"]'); assert(upload); await upload.uploadFile(fixturePath);
  await sender.click("button.create-link-button");
  await sender.waitForFunction(() => document.querySelector(".composer-status")?.dataset.state === "created", { timeout: 300_000 });
  const offersNotify = await sender.evaluate(() => [...document.querySelectorAll(".composer-status button")].some((button) => /Notify recipient/.test(button.textContent ?? "")));
  assert.equal(offersNotify, false, "a domain share offered to email recipients");
  const copied = await sender.evaluate(() => window.__tc500Clipboard.length);
  await clickText(sender, "Copy link");
  const domainUrl = await waitUntil(() => sender.evaluate((count) => window.__tc500Clipboard.length > count ? window.__tc500Clipboard.at(-1) : undefined, copied), 10_000);
  assert.match(domainUrl ?? "", /^https:\/\/share\.tinycloud\.xyz\/s\/inline#v=2&p=/, "domain share did not produce a sealed inline link");
  const mailBefore = stack.mail.length;

  // Look-alike and subdomain mailboxes are refused before any acquisition.
  phase = "domain-lookalike";
  const lookalikeContext = await browser.createBrowserContext(); const lookalike = await lookalikeContext.newPage(); await installRouting(lookalike, stack);
  await lookalike.goto(domainUrl, { waitUntil: "domcontentloaded", timeout: 180_000 });
  for (const mailbox of [`reader@sub.${domain}`, `reader@${domain}.evil`, `reader@evil${domain}`]) {
    await enterMailbox(lookalike, mailbox);
    const refused = await waitUntil(() => lookalike.evaluate(() => document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("#mailbox-error:not([hidden])")?.textContent ?? undefined), 10_000);
    assert.match(refused ?? "", /is a different domain/, "look-alike mailbox was not refused");
  }
  assert.equal(trace.filter((entry) => entry.phase === "domain-lookalike" && entry.origin === stack.canonical.credentials && entry.method === "POST").length, 0, "a look-alike mailbox reached OpenCredentials");
  assert.equal(stack.mail.length, mailBefore, "a look-alike mailbox was emailed");
  await lookalikeContext.close();

  phase = "domain-recipient";
  const mailbox = `reader-${Date.now()}@${domain}`;
  const context = await browser.createBrowserContext(); const reader = await context.newPage(); await installRouting(reader, stack);
  await reader.goto(domainUrl, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await mailboxEntry(reader);
  // Holding the sealed link alone authorizes nothing before mailbox proof.
  assert.equal(trace.filter((entry) => entry.phase === "domain-recipient" && (/openkey/i.test(entry.origin) || (entry.origin === stack.canonical.node && ["/policy/v3/delegations", "/delegate", "/invoke"].includes(entry.path)))).length, 0, "domain link authorized access before mailbox proof");
  const claimCopy = await reader.evaluate(() => document.querySelector(".claim-lede")?.textContent ?? "");
  assert.match(claimCopy, /anyone with an email address at @tinycloud\.test/, "claim page did not present the invited domain");
  await enterMailbox(reader, mailbox);
  const otpMail = await waitUntil(() => stack.mail.find((message) => isCredentialOtpMail(message, mailbox)), 60_000);
  const code = credentialOtpFromMail(otpMail); assert.match(code ?? "", /^\d{8}$/);
  assert.equal(await submitCredentialValue(reader, code, "otp"), true);
  const domainTemporary = await mkdtemp(join(tmpdir(), "tc500-domain-"));
  assert.equal(await downloadExact(reader, domainTemporary), true, "domain recipient did not render the exact bytes");
  const verifiedMailbox = await reader.evaluate(() => document.querySelector(".viewer-download") !== null);
  assert.equal(verifiedMailbox, true);

  const phaseTrace = trace.filter((entry) => entry.phase === "domain-recipient");
  const create = phaseTrace.find((entry) => entry.origin === stack.canonical.credentials && entry.method === "POST" && entry.path === "/v1/acquisitions" && successfulRequest(entry));
  assert.equal(create?.body?.profile, "tinycloud.email-domain-proof/v1", "domain recipient used the wrong credential profile");
  assert.deepEqual(Object.keys(create?.body?.inputs ?? {}), ["email"], "domain acquisition carried a caller-asserted claim");
  for (const path of ["/policy/v3/challenges", "/policy/v3/delegations", "/delegate"]) {
    assert(phaseTrace.some((entry) => entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === path && successfulRequest(entry)), `domain recipient did not complete ${path}`);
  }
  const invokes = phaseTrace.filter((entry) => entry.origin === stack.canonical.node && entry.path === "/invoke" && successfulRequest(entry));
  assert(invokes.length >= 2, "domain recipient did not read and decrypt through ordinary invoke");
  assert(!phaseTrace.some((entry) => /openkey/i.test(entry.origin)), "domain recipient contacted OpenKey");

  const negatives = await verifyNegativeEnforcement({ sender, recipient: reader, stack, recipientPhase: "domain-recipient", prefix: "domain-", revoke: false });

  // Replaying the admitted request (its consumed challenge and presentation)
  // must not mint another policy session.
  const admitted = phaseTrace.find((entry) => entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === "/policy/v3/delegations" && successfulRequest(entry));
  phase = "domain-replay";
  const replayStatus = await reader.evaluate(async ({ nodeOrigin, body }) => {
    const response = await fetch(new URL("/policy/v3/delegations", nodeOrigin), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    await response.arrayBuffer();
    return response.status;
  }, { nodeOrigin: stack.canonical.node, body: admitted.body });
  assert(replayStatus >= 400 && replayStatus < 500, "Node accepted a replay of an admitted policy request");
  await context.close();
  return { domainRendered: true, lookalikesRefusedBeforeAcquisition: 3, acquisitionInputKeys: ["email"], domainInvokeCount: invokes.length, ...Object.fromEntries(Object.entries(negatives).map(([key, value]) => [`domain${key[0].toUpperCase()}${key.slice(1)}`, value])), admittedRequestReplayStatus: replayStatus };
}

function traceAudit(stack) {
  const at = (p, origin, path, method) => trace.find((entry) => entry.phase === p && entry.origin === origin && entry.path === path && (method === undefined || entry.method === method) && entry.status >= 200 && entry.status < 300);
  const accountLocationPath = "/v1/locations/" + encodeURIComponent(`did:pkh:eip155:1:${stack.walletAddress}`);
  assert(trace.some((entry) => entry.phase === "sender" && entry.origin === stack.canonical.registry && entry.path === accountLocationPath && entry.method === "GET" && entry.status === 404), "fresh sender did not prove the missing-location bootstrap case");
  const publishedLocation = trace.find((entry) => entry.phase === "sender" && entry.origin === stack.canonical.registry && entry.path.startsWith("/v1/locations/") && entry.method === "PUT" && entry.status >= 200 && entry.status < 300);
  const ownerDid = publishedLocation?.body?.subject;
  assert.match(ownerDid ?? "", /^did:key:z/, "published location owner DID is invalid");
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
  assert.match(challenge.body?.recipientDid ?? "", /^did:key:z/, "policy challenge recipient DID is invalid");
  assert(at("recipient", stack.canonical.node, "/delegate", "POST"), "recipient did not import scoped delegation");
  const positiveInvokes = trace.filter((entry) => entry.phase === "recipient" && entry.origin === stack.canonical.node && entry.path === "/invoke" && entry.method === "POST" && entry.status >= 200 && entry.status < 300);
  assert(positiveInvokes.length >= 2, "recipient did not read ciphertext and decrypt through ordinary invoke");
  assert(!trace.some((entry) => entry.phase === "recipient" && /openkey/i.test(entry.origin)), "recipient contacted OpenKey before render");
  assert(!trace.some((entry) => entry.path.startsWith("/share/") || /api\.share/.test(entry.origin) || (entry.origin === stack.canonical.registry && !entry.path.startsWith("/v1/locations/"))), "journey used a prohibited Share or registry data plane");
  return { ownerDidSha256: createHash("sha256").update(ownerDid).digest("hex"), receiverDidSha256: createHash("sha256").update(challenge.body.recipientDid).digest("hex"), nodeInvokeCount: positiveInvokes.length };
}

const temporary = await mkdtemp(join(tmpdir(), "tc500-native-joined-"));
const fixturePath = join(temporary, "native-fixture.bin"); await writeFile(fixturePath, fixture, { flag: "wx", mode: 0o600 });
let stack; let candidate; let browser; let recipientEmail; let selectedOtp;
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
  recipientEmail = `tc500-native-${Date.now()}@mailinator.com`;
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
  journeyStage = "recipient-otp-delivery";
  const otpMail = await waitUntil(() => stack.mail.find((message) => isCredentialOtpMail(message, recipientEmail)), 60_000);
  selectedOtp = credentialOtpFromMail(otpMail); assert.match(selectedOtp ?? "", /^\d{8}$/);
  assert.equal(await credentialInputReady(recipient, "otp"), true, "recipient OTP input did not become stable");
  assertBearerDidNotAuthorize(stack);
  journeyStage = "recipient-otp";
  assert.equal(await submitCredentialValue(recipient, selectedOtp, "otp"), true);
  journeyStage = "recipient-decrypt-render";
  assert.equal(await downloadExact(recipient, temporary), true);
  journeyStage = "traffic-audit";
  const audit = traceAudit(stack);
  journeyStage = "negative-enforcement";
  const negativeGates = await verifyNegativeEnforcement({ sender, recipient, stack });
  traceAudit(stack);
  journeyStage = "bearer-regression";
  const bearerRegression = await verifyBearerRegression({ browser, sender, stack });
  journeyStage = "domain-journey";
  const domainJourney = await verifyDomainJourney({ browser, sender, stack });
  const browserDiagnostics = auditBrowserDiagnostics(stack);

  const artifact = { type: "tinycloud.share/native-joined-e2e/v1", result: "passed", fixtureSha256: fixtureDigest, provenance: { ...stack.provenance, ...(await shareProvenance()) }, ...audit, negativeGates, bearerRegression, domainJourney, browserDiagnostics, prohibitedShareDataPlaneRequests: 0 };
  await writeFile(outputPath, JSON.stringify(artifact, null, 2), { mode: 0o600 });
  console.log(JSON.stringify(artifact, null, 2));
} catch (error) {
  const submittedProofs = trace.filter((entry) => entry.phase === "recipient" && entry.method === "POST" && /\/v1\/acquisitions\/[^/]+\/proof$/.test(entry.path));
  const submittedOtp = submittedProofs.at(-1)?.body?.proof?.otp;
  const senderCiphertexts = trace.filter((entry) => entry.phase === "sender" && entry.path === "/invoke" && entry.status >= 200 && entry.status < 300 && entry.requestByteLength !== undefined);
  const recipientInvokes = trace.filter((entry) => entry.phase === "recipient" && entry.path === "/invoke" && entry.status >= 200 && entry.status < 300);
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
    credentialDiagnostics: {
      verificationMailCount: stack?.mail.filter((message) => isCredentialOtpMail(message, recipientEmail)).length,
      submittedProofCount: submittedProofs.length,
      submittedOtpLength: typeof submittedOtp === "string" ? submittedOtp.length : undefined,
      submittedOtpMatchedSelected: typeof submittedOtp === "string" && submittedOtp === selectedOtp,
    },
    auditDiagnostic: journeyStage === "traffic-audit" && error?.code === "ERR_ASSERTION" ? error.message : undefined,
    negativeDiagnostic: journeyStage === "negative-enforcement" ? String(error?.message ?? "negative enforcement failed").slice(0, 240) : undefined,
    journeyDiagnostic: ["bearer-regression", "domain-journey"].includes(journeyStage) && error?.code === "ERR_ASSERTION" ? String(error.message).slice(0, 240) : undefined,
    dataPlaneDiagnostics: recipientInvokes.map((entry) => ({
      responseByteLength: entry.responseByteLength,
      responseContentType: entry.responseContentType,
      matchesSenderCiphertext: senderCiphertexts.some((senderEntry) => senderEntry.requestSha256 === entry.responseSha256),
      matchingSenderCiphertextByteLength: senderCiphertexts.find((senderEntry) => senderEntry.requestSha256 === entry.responseSha256)?.requestByteLength,
    })),
  }, null, 2), { mode: 0o600 }).catch(() => undefined);
  fail(journeyStage);
} finally {
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  console.log(`[tc500] artifacts retained under ${temporary.replace(/[^/]+$/, "<redacted>")}`);
}
