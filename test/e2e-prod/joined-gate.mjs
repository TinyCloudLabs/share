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
import { execFileSync, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { signCompactUcanAuthorization, toBase64Url, verifyCompactUcanAuthorization } from "@tinycloud/share-envelope";
import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { credentialOtpFromMail, gateResult, isCredentialOtpMail, runBoundedStep, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/v1.21.0");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
// The `tc` CLI used as the agent-style sender: an installed @tinycloud/cli package root.
const cliPackage = resolve(process.env.TC500_CLI_PACKAGE ?? "/tmp/tc500-cli/node_modules/@tinycloud/cli");
const outputPath = resolve(process.env.TC500_E2E_ARTIFACT ?? join(workspaceRoot, ".context/tc-500-native-joined.json"));
// Once the stack is up, the whole browser + CLI journey must finish within this budget.
const journeyTimeoutMs = Number(process.env.TC500_JOURNEY_TIMEOUT_MS ?? 15 * 60_000);
const fixture = Buffer.concat([Buffer.from("TC-500 native joined fixture\n", "utf8"), Buffer.from([0, 0x80, 0xff, 0x0a])]);
const fixtureDigest = createHash("sha256").update(fixture).digest("hex");
const cliFixture = Buffer.from(`# TC-500 CLI email share\n\n${randomBytes(8).toString("hex")}\n`, "utf8");
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
// The link-only share the bearer stage made: later stages check it survives another share's revoke, then revoke it from a new sign-in.
let bearerLink;
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

async function installRouting(page, stack, { openKeyOrigin = stack.services.openKeyOrigin } = {}) {
  await page.evaluateOnNewDocument(installBrowserInstrumentation);
  page.on("console", (message) => {
    consoleCounts[message.type()] = (consoleCounts[message.type()] ?? 0) + 1;
    if (message.type() === "error" || message.type() === "warn") consoleDiagnostics.push({ phase, type: message.type(), text: message.text().replaceAll(/https:\/\/[^\s#]+(?:#[^\s]*)?/g, "<url>").replaceAll(/[A-Za-z0-9_-]{80,}/g, "<redacted>").slice(0, 240) });
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
      ["https://openkey.so", openKeyOrigin],
      ["https://api.openkey.so", openKeyOrigin],
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
      // A fresh account's SQL migration probe reads the migrations table before
      // it exists; the SDK treats this exact Node answer as "table missing" and
      // creates it (sdk-services SQL `applyMigrationsOnDbUnlocked`).
      entry.migrationsTableProbe = response.status === 400 && bytes.byteLength < 200 && bytes.toString("utf8").trim() === "SQLite error: no such table: __tinycloud_sql_migrations";
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

async function downloadExact(page, temporary, expected = fixture) {
  await page.waitForSelector(".viewer-download", { timeout: 180_000 });
  const cdp = await page.createCDPSession(); await cdp.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: temporary });
  await page.click(".viewer-download");
  return waitUntil(async () => {
    const { readdir } = await import("node:fs/promises");
    for (const name of await readdir(temporary)) {
      if (name.endsWith(".pem") || name.endsWith(".key") || name.endsWith(".json")) continue;
      const bytes = await readFile(join(temporary, name)).catch(() => undefined);
      if (bytes?.equals(expected)) return true;
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
  // No location record is ever published for the recipient who saves a copy (it does not share from its own node), so each of its sign-ins asks the registry and is told so.
  const locationBootstrapMisses = failedRequests.filter((entry) => ["sender", "sender-relogin", "domain-delivery-sender", "save-recipient-one", "save-recipient-two", "save-revoked-recipient"].includes(entry.phase) && entry.origin === stack.canonical.registry && entry.method === "GET" && entry.path.startsWith("/v1/locations/") && entry.status === 404);
  const ownerStateBootstrapMisses = failedRequests.filter((entry) => ["sender", "save-recipient-one"].includes(entry.phase) && entry.origin === stack.canonical.node && (
    (entry.status === 404 && entry.method === "GET" && entry.path.startsWith("/encryption/networks/"))
    || (entry.status === 404 && entry.method === "POST" && entry.path === "/invoke")
    // Fresh-account SQL migration probe; only this exact Node answer is accepted.
    || (entry.status === 400 && entry.method === "POST" && entry.path === "/invoke" && entry.migrationsTableProbe === true)
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
    ["domain-negative-revoked", 403],
    ["revoked-bearer-recipient", 401],
    // The second save of a name: the create-only write meets the first copy and moves on to the next name.
    ["save-recipient-two", 412],
    // A revoked link-only share, and the read-back of the copies after it.
    ["save-revoked-recipient", 401],
  ]);
  const admittedRequestReplayRejections = failedRequests.filter((entry) => entry.phase === "domain-replay" && entry.method === "POST" && entry.path === "/policy/v3/delegations" && entry.status >= 400 && entry.status < 500);
  const unexpectedRequests = failedRequests.filter((entry) => !bootstrapMisses.has(entry) && !admittedRequestReplayRejections.includes(entry) && !(entry.method === "POST" && entry.path === "/invoke" && expectedEnforcement.get(entry.phase) === entry.status));
  assert.equal(unexpectedRequests.length, 0, "browser observed an unexpected failed network request");
  const errors = consoleDiagnostics.filter((entry) => entry.type === "error");
  const warnings = consoleDiagnostics.filter((entry) => entry.type === "warn");
  const pageErrors = consoleDiagnostics.filter((entry) => entry.type === "pageerror");
  assert.equal(pageErrors.length, 0, "browser raised an unexpected page error");
  assert(errors.every((entry) => /^Failed to load resource: the server responded with a status of (400|401|403|404|409|412) \((?:Bad Request|Unauthorized|Forbidden|Not Found|Conflict|Precondition Failed)\)$/.test(entry.text)), "browser emitted an unexpected console error");
  assert.equal(errors.length, failedRequests.length, "browser console/network failure accounting diverged");
  assert(locationBootstrapMisses.length > 0, "fresh sender did not observe the expected missing-location bootstrap response");
  assert(ownerStateBootstrapMisses.length > 0, "fresh sender did not observe expected uninitialized owner state");
  // At most one migrations probe per account-registry sync attempt (the SDK makes three).
  assert(ownerStateBootstrapMisses.filter((entry) => entry.status === 400).length <= 3, "fresh sender repeated the migrations-table probe");
  // A fresh sender's background account-registry sync logs one bootstrap
  // warning: older Nodes exhaust the registry retries; Node 1.21 reports the
  // account index (SQL) as not yet created (404 SQL_DATABASE_NOT_FOUND) and continues.
  const bootstrapWarnings = [/^TinyCloud account registry sync failed after retries/, /^TinyCloud account index initialization failed; continuing registry sync/];
  // The fresh recipient who saves a copy is a fresh account too: its first sign-in logs the same bootstrap warning, once.
  const senderWarnings = warnings.filter((entry) => entry.phase === "sender");
  const saveWarnings = warnings.filter((entry) => entry.phase === "save-recipient-one");
  assert(senderWarnings.length >= 1 && senderWarnings.length <= bootstrapWarnings.length, "browser emitted an unexpected number of warnings");
  assert.equal(warnings.length, senderWarnings.length + saveWarnings.length, "browser emitted a warning outside sender and fresh-recipient bootstrap");
  for (const group of [senderWarnings, saveWarnings]) {
    assert(group.length <= bootstrapWarnings.length, "browser emitted an unexpected number of warnings");
    assert(bootstrapWarnings.every((pattern) => group.filter((entry) => pattern.test(entry.text)).length <= 1), "browser repeated a bootstrap warning");
    assert(group.every((entry) => bootstrapWarnings.some((pattern) => pattern.test(entry.text))), "browser emitted an unexpected warning");
  }
  return {
    unexpectedConsoleErrors: 0,
    unexpectedPageErrors: 0,
    expectedLocationBootstrap404s: locationBootstrapMisses.length,
    expectedOwnerStateBootstrap404s: ownerStateBootstrapMisses.filter((entry) => entry.status === 404).length,
    expectedMigrationsTableProbe400s: ownerStateBootstrapMisses.filter((entry) => entry.status === 400).length,
    expectedPolicyDenials: Object.fromEntries(expectedEnforcement),
    admittedRequestReplayRejections: admittedRequestReplayRejections.map((entry) => entry.status),
    expectedBootstrapWarnings: warnings.length,
  };
}

/** Reads the page's stored receiver key handle: its DID and whether the private key can be exported. */
async function recipientKeyHandle(page) {
  return page.evaluate(async () => {
    const database = await new Promise((resolve, reject) => {
      const open = indexedDB.open("tinycloud.share.receiver-keys");
      open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);
    });
    const record = await new Promise((resolve, reject) => {
      const read = database.transaction("keys").objectStore("keys").get(location.origin);
      read.onsuccess = () => resolve(read.result); read.onerror = () => reject(read.error);
    });
    database.close();
    if (record === undefined) return undefined;
    const exportRejected = await Promise.all(["pkcs8", "jwk"].map((format) => crypto.subtle.exportKey(format, record.privateKey).then(() => false, () => true)));
    return { holderDid: record.holderDid, extractable: record.privateKey.extractable, exportRejected: exportRejected.every(Boolean) };
  });
}

/**
 * The recipient key is a non-extractable handle in the page's IndexedDB. The
 * gate signs through that handle inside the page and never holds the key.
 */
async function recipientSigningMaterial(page) {
  const handle = await recipientKeyHandle(page);
  assert.match(handle?.holderDid ?? "", /^did:key:z/, "recipient key handle is missing");
  assert.equal(handle.extractable, false, "recipient key is extractable");
  return {
    holderDid: handle.holderDid,
    sign: async (bytes) => Uint8Array.from(await page.evaluate(async (data) => {
      const database = await new Promise((resolve, reject) => {
        const open = indexedDB.open("tinycloud.share.receiver-keys");
        open.onsuccess = () => resolve(open.result); open.onerror = () => reject(open.error);
      });
      const record = await new Promise((resolve, reject) => {
        const read = database.transaction("keys").objectStore("keys").get(location.origin);
        read.onsuccess = () => resolve(read.result); read.onerror = () => reject(read.error);
      });
      database.close();
      return [...new Uint8Array(await crypto.subtle.sign("Ed25519", record.privateKey, Uint8Array.from(data)))];
    }, [...bytes])),
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

async function verifyNegativeEnforcement({ sender, recipient, stack, recipientPhase = "recipient", prefix = "", revoke = true, relogin = false }) {
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
  const revocation = await revokeFromLibrary(sender, { relogin });
  phase = `${prefix}negative-revoked`;
  const revokedReadStatus = await invokeFromBrowser(recipient, stack.canonical.node, revokedInvocation.authorization);
  assert.equal(revokedReadStatus, 403, "revoked policy root still authorized a KV read");

  return { bearerWithoutOtp: true, siblingReadStatus, writeEscalationStatus, tamperStatus, revokedReadStatus, ...(relogin ? { revokedAfterRelogin: revocation } : {}) };
}

/**
 * A new sign-in of the same account. The share app keeps no session across a
 * load (`persistSession: false`), so a reload and a fresh OpenKey approval
 * make a new session key: the key that signed every earlier share is gone.
 */
async function signInAgain(sender) {
  phase = "sender-relogin";
  await sender.evaluate(() => { window.location.hash = "#/library"; });
  await sender.reload({ waitUntil: "domcontentloaded", timeout: 180_000 });
  await sender.waitForSelector("button.auth-button", { timeout: 60_000 }); await sender.click("button.auth-button");
  await sender.waitForSelector(".sender-history-row", { timeout: 180_000 });
}

/**
 * Revoke one share from the library. With `relogin`, the page is signed in
 * again first, so the share was made by a session key this page no longer
 * holds: the revoke must go to the node as the owner wallet's own revocation
 * of that one delegation (a generic `/revoke` with an authorization header and
 * no JSON body), never as a session-signed root revocation.
 */
async function revokeFromLibrary(sender, { relogin = false, recipientText } = {}) {
  if (relogin) await signInAgain(sender);
  phase = "sender-revocation";
  await sender.evaluate(() => { window.location.hash = "#/library"; });
  await sender.waitForSelector(".sender-revoke:not([disabled])", { timeout: 180_000 });
  const before = trace.length;
  if (recipientText === undefined) await sender.click(".sender-revoke:not([disabled])");
  else {
    const clicked = await sender.evaluate((text) => {
      for (const row of document.querySelectorAll(".sender-history-row")) {
        const button = row.querySelector(".sender-revoke:not([disabled])");
        if (button !== null && (row.textContent ?? "").includes(text)) { button.click(); return true; }
      }
      return false;
    }, recipientText);
    assert.equal(clicked, true, `no revocable share row for ${recipientText}`);
  }
  await sender.waitForSelector(".sender-confirm-revoke", { timeout: 10_000 });
  await sender.click(".sender-confirm-revoke");
  await sender.waitForFunction(() => document.body.textContent?.includes("Share revoked."), { timeout: 180_000 });
  const revokes = trace.slice(before).filter((entry) => entry.phase === "sender-revocation" && entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === "/revoke");
  assert.equal(revokes.length, 1, "revoking one share sent a number of /revoke requests other than one");
  const [revoke] = revokes;
  assert.equal(revoke.status, 200, "the Node refused the revocation");
  if (!relogin) return { wallet: false };
  assert.equal(revoke.body, undefined, "a re-login revocation used the session-signed JSON route");
  assert.match(revoke.authorization ?? "", /\S/, "a re-login revocation carried no owner authorization");
  assert.equal(typeof revoke.response?.cid, "string", "the Node's revocation receipt names no delegation");
  // The share is gone from the library for good: a reload still shows it revoked.
  return { wallet: true, revokeRequests: revokes.length, receiptNamesDelegation: true };
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
  bearerLink = bearerUrl;
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

  const negatives = await verifyNegativeEnforcement({ sender, recipient: reader, stack, recipientPhase: "domain-recipient", prefix: "domain-", relogin: true });

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

/**
 * TC-530: one domain link, with edit access, emailed to two mailboxes at the
 * domain. The owner's Node authorizes each address in its own signed
 * admission, OpenCredentials emails each one, and a recipient opens the link
 * from their email after proving that mailbox.
 */
async function verifyDomainDelivery({ browser, sender, stack }) {
  const domain = "tinycloud.test";
  phase = "domain-delivery-sender";
  // The previous stage ended on the library after a re-login, not on the composer result screen.
  const onResult = await sender.evaluate(() => [...document.querySelectorAll("button")].some((button) => /Share another/.test(button.textContent ?? "")));
  if (onResult) await clickText(sender, "Share another"); else await sender.evaluate(() => { window.location.hash = "#/new"; });
  await sender.waitForSelector('form.composer-form input[name="recipient"][value="emailDomain"]', { visible: true, timeout: 180_000 });
  await sender.$eval('input[name="recipient"][value="emailDomain"]', (input) => input.click());
  await sender.type('input[name="recipient-value"]', domain);
  const stamp = Date.now();
  const recipients = [`alice-${stamp}@${domain}`, `bob-${stamp}@${domain}`];
  await sender.type('textarea[name="delivery-emails"]', recipients.join(", "));
  await sender.$eval('input[name="permission"][value="edit"]', (input) => { if (!input.checked) input.click(); });
  const upload = await sender.$('input[name="document"]'); assert(upload); await upload.uploadFile(fixturePath);
  await sender.click("button.create-link-button");
  await sender.waitForFunction(() => document.querySelector(".composer-status")?.dataset.state === "created", { timeout: 300_000 });
  const mailBefore = stack.mail.length;
  await clickText(sender, "Notify 2 recipients");
  const invitedTo = (recipient) => stack.mail.slice(mailBefore).find((message) => {
    const to = Array.isArray(message?.payload?.to) ? message.payload.to : [message?.payload?.to];
    return to.includes(recipient) && stringsIn(message.payload).some((value) => value.includes("/s/inline#"));
  });
  const invitations = await waitUntil(() => recipients.every((recipient) => invitedTo(recipient) !== undefined) ? recipients.map(invitedTo) : undefined, 90_000);
  assert(invitations, "each domain address was not emailed an invitation");
  const links = invitations.map(invitationFromMail);
  assert.equal(new Set(links).size, 1, "domain invitations did not carry the same link");
  assert.equal(await waitUntil(() => sender.evaluate(() => document.querySelector(".notification-status")?.textContent === "Invitations requested." || undefined), 30_000), true, "sender did not confirm both invitations");
  const authorized = trace.filter((entry) => entry.phase === "domain-delivery-sender" && entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === "/policy/v3/deliveries/authorize" && successfulRequest(entry));
  assert.deepEqual(authorized.map((entry) => entry.body?.recipientEmail).sort(), [...recipients].sort(), "the owner's Node did not authorize each address separately");
  assert.equal(new Set(authorized.map((entry) => entry.body?.jti)).size, recipients.length, "domain deliveries shared a JTI");
  // Edit access is in the policy the owner's Node registered, not only in the form.
  const registered = trace.find((entry) => entry.phase === "domain-delivery-sender" && entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === "/policy/v3/policies" && successfulRequest(entry));
  const editAccessPublished = registered?.body?.policy?.capabilityCeiling?.some((capability) => capability?.kind === "kv" && capability.actions?.includes("tinycloud.kv/put")) === true;
  assert.equal(editAccessPublished, true, "the domain share's registered policy does not grant edit access");

  phase = "domain-delivery-recipient";
  const context = await browser.createBrowserContext(); const reader = await context.newPage(); await installRouting(reader, stack);
  await reader.goto(links[0], { waitUntil: "domcontentloaded", timeout: 180_000 });
  await enterMailbox(reader, recipients[1]);
  const otpMail = await waitUntil(() => stack.mail.find((message) => isCredentialOtpMail(message, recipients[1])), 60_000);
  const code = credentialOtpFromMail(otpMail); assert.match(code ?? "", /^\d{8}$/);
  assert.equal(await submitCredentialValue(reader, code, "otp"), true);
  const temporary = await mkdtemp(join(tmpdir(), "tc530-domain-delivery-"));
  assert.equal(await downloadExact(reader, temporary), true, "an emailed domain recipient did not render the exact bytes");
  // TC-531: the recipient asked its owner's Node for a session as long as the share.
  const mint = trace.find((entry) => entry.phase === "domain-delivery-recipient" && entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === "/policy/v3/delegations" && successfulRequest(entry));
  assert.equal(typeof mint?.body?.requestedExpiresAt, "string", "the recipient did not request a durable session");
  await context.close();
  return { invitationsSent: recipients.length, nodeAuthorizations: authorized.length, sameLinkForEveryAddress: true, editAccessPublished, emailedRecipientRendered: true, durableSessionRequested: true };
}

/**
 * Another share of the same owner must not notice a revoke: after the domain
 * share was revoked from a new sign-in, the link-only share made earlier still
 * opens for a fresh reader. (A cascade that reached the owner's own session,
 * space or other delegations would break it.)
 */
async function verifyOtherShareSurvives({ browser, stack }) {
  phase = "survivor-recipient";
  assert.equal(typeof bearerLink, "string", "the bearer stage did not keep its link");
  const context = await browser.createBrowserContext(); const reader = await context.newPage(); await installRouting(reader, stack);
  await reader.goto(bearerLink, { waitUntil: "domcontentloaded", timeout: 180_000 });
  const survivorTemporary = await mkdtemp(join(tmpdir(), "tc500-survivor-"));
  assert.equal(await downloadExact(reader, survivorTemporary), true, "another share of the owner stopped working after a revoke");
  await context.close();
  return { otherShareStillOpens: true };
}

/**
 * Link-only share, revoked from a new sign-in: one owner-wallet revocation of
 * that share's own delegation, and the link then fails closed for a new reader.
 */
async function verifyBearerRevokeAfterRelogin({ browser, sender, stack }) {
  const revocation = await revokeFromLibrary(sender, { relogin: true, recipientText: "Anyone with link" });
  phase = "revoked-bearer-recipient";
  const context = await browser.createBrowserContext(); const reader = await context.newPage(); await installRouting(reader, stack);
  await reader.goto(bearerLink, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await reader.waitForSelector(".viewer-state", { timeout: 180_000 });
  assert.equal(await reader.$(".viewer-download"), null, "a revoked link-only share still rendered");
  await context.close();
  // The owner's own access is untouched: the library still lists and offers the other shares.
  const stillListed = await sender.evaluate(() => document.querySelectorAll(".sender-history-row").length);
  assert(stillListed >= 2, "the owner's library lost shares after a revoke");
  return { ...revocation, revokedLinkFailsClosed: true, libraryRowsAfter: stillListed };
}

// A markdown file with a table, multi-byte text and a per-run marker: the bytes a recipient saves must be exactly these.
const saveCopyName = "save-copy-fixture.md";
const saveCopyFixture = Buffer.from(`# Save a copy fixture\n\nCafé ✓ — 日本語\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n${randomBytes(8).toString("hex")}\n`, "utf8");
const saveCopyDigest = createHash("sha256").update(saveCopyFixture).digest("hex");

/**
 * Reads the recipient's private copies back through the product's own sign-in
 * helper, in the page that saved them (the account chunk is already loaded
 * there). Returns each copy's key, SHA-256 and stored media type.
 */
async function readBackCopies(page) {
  return page.evaluate(async () => {
    const chunk = performance.getEntriesByType("resource").map((entry) => entry.name).find((name) => /\/assets\/openkey-session-[^/]+\.js$/.test(new URL(name).pathname));
    if (chunk === undefined) throw new Error("the account chunk was never loaded");
    const chunkExports = await import(chunk);
    // The build minifies this chunk's export names, but one export is the module's own namespace object, which
    // keeps the real names: that is where the two helpers are.
    const session = Object.values(chunkExports).find((value) => typeof value === "object" && value !== null && typeof value.signInWithManifest === "function");
    if (session === undefined) throw new Error("the account chunk does not carry the sign-in helpers");
    const { signInWithManifest, saveCopyManifest, SAVE_COPY_MANIFEST_SCOPE } = session;
    const config = await (await fetch("/.well-known/tinycloud-share/config.json")).json();
    const signedIn = await signInWithManifest({ manifest: saveCopyManifest(), ...SAVE_COPY_MANIFEST_SCOPE, config, hostSpaces: ["files-for-you"] });
    const { tinycloud, spaces } = signedIn;
    const kv = tinycloud.kvForSpace(spaces["files-for-you"]);
    const listed = await kv.list({ prefix: "v1/" });
    if (!listed.ok) throw new Error(`list failed: ${listed.error?.code}`);
    const copies = [];
    for (const key of [...listed.data.keys].sort()) {
      const got = await kv.get(key, { binary: true });
      if (!got.ok) throw new Error(`get failed: ${got.error?.code}`);
      const digest = await crypto.subtle.digest("SHA-256", got.data.data);
      copies.push({ key, sha256: [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join(""), contentType: got.data.headers.contentType ?? null, byteLength: got.data.data.byteLength });
    }
    // The helper's own teardown, against the real SDK: it must not throw.
    await signedIn.dispose();
    return { copies };
  });
}

/** A link-only markdown share, from the signed-in sender page. Returns its link. */
async function shareSaveCopyFixture(sender) {
  phase = "save-sender";
  await sender.evaluate(() => { window.location.hash = "#/new"; });
  await sender.waitForSelector("form.composer-form", { timeout: 180_000 });
  await sender.$eval('input[name="recipient"][value="bearer"]', (input) => input.click());
  const upload = await sender.$('input[name="document"]'); assert(upload);
  const path = join(temporary, saveCopyName); await writeFile(path, saveCopyFixture, { flag: "w", mode: 0o600 });
  await upload.uploadFile(path);
  await sender.click("button.create-link-button");
  await sender.waitForFunction(() => document.querySelector(".composer-status")?.dataset.state === "created", { timeout: 300_000 });
  const copied = await sender.evaluate(() => window.__tc500Clipboard.length);
  await clickText(sender, "Copy link");
  const url = await waitUntil(() => sender.evaluate((count) => window.__tc500Clipboard.length > count ? window.__tc500Clipboard.at(-1) : undefined, copied), 10_000);
  assert.match(url ?? "", /^https:\/\/share\.tinycloud\.xyz\/viewer#tc1=/, "the markdown share did not produce a native tc1 link");
  return url;
}

/** Opens `url` as a recipient with their own OpenKey account, clicks Save a copy, and waits for Saved. */
async function saveFromRecipient({ browser, stack, url, label, expectedName }) {
  phase = `save-recipient-${label}`;
  const context = await browser.createBrowserContext(); const reader = await context.newPage();
  await installRouting(reader, stack, { openKeyOrigin: stack.services.recipientOpenKeyOrigin });
  await reader.goto(url, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await reader.waitForSelector(".viewer-save-to-tinycloud", { timeout: 180_000 });
  await reader.waitForSelector(".viewer-preview-frame", { timeout: 60_000 });
  // Account-free until the click: opening the file touched neither OpenKey nor the recipient's account.
  const before = trace.filter((entry) => entry.phase === phase);
  assert(!before.some((entry) => /openkey/i.test(entry.origin)), "the recipient contacted OpenKey before clicking Save");
  assert(!before.some((entry) => entry.origin === stack.canonical.credentials || entry.path.startsWith("/policy/v3/")), "a bearer recipient ran a credential or policy ceremony");
  const clickedAt = trace.length;
  // Record what the live region says, in order, from before the click.
  await reader.evaluate(() => {
    window.__toastLog = [];
    const toast = document.querySelector(".artifact-chrome-toast--job");
    new MutationObserver(() => window.__toastLog.push({ role: toast.getAttribute("role"), live: toast.getAttribute("aria-live"), text: toast.textContent })).observe(toast, { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ["role"] });
  });
  await reader.click(".viewer-save-to-tinycloud");
  await reader.waitForFunction(() => /^(Saved to your TinyCloud files|Sign-in cancelled|OpenKey didn't answer|Another OpenKey|That approval came|We couldn't save)/.test(document.querySelector(".artifact-chrome-toast--job")?.textContent ?? ""), { timeout: 300_000 });
  // The bar's own copy is fixed UI text (never a response body), so it is safe to report.
  const outcome = await reader.$eval(".artifact-chrome-toast--job", (node) => node.textContent);
  assert(outcome.startsWith("Saved to your TinyCloud files as"), `Save did not finish: the bar said "${outcome}"`);
  const toastLog = await reader.evaluate(() => window.__toastLog);
  const spoken = toastLog.map((entry) => entry.text);
  assert(spoken.includes("Saving a copy to your TinyCloud…"), "the pending state was never announced");
  // One hint per signature, counted in order, with the same words each time.
  const hints = spoken.filter((text) => /^Approval \d+ of up to \d+\. Approve in the OpenKey window to save a copy$/.test(text));
  assert(hints.length >= 1, "the OpenKey approval hint never appeared");
  hints.forEach((text, index) => assert(text.startsWith(`Approval ${index + 1} of up to`), `approval hints were not counted in order: ${JSON.stringify(hints)}`));
  assert.equal(spoken.at(-1), `Saved to your TinyCloud files as “${expectedName}”.`, "the page did not end on Saved, naming the copy");
  assert(toastLog.every((entry) => entry.live === "polite" || entry.role === "alert"), "a toast message was not in a live region");
  assert.equal(await reader.$(".artifact-chrome-toasts a"), null, "the Saved message links to a library that does not list copies");
  const after = trace.slice(clickedAt).filter((entry) => entry.phase === phase);
  assert(after.some((entry) => /openkey/i.test(entry.origin)), "Save never opened OpenKey");
  // The bytes that left the page for the node are the fixture's.
  const puts = after.filter((entry) => entry.origin === stack.canonical.node && entry.path === "/invoke" && entry.requestSha256 === saveCopyDigest && successfulRequest(entry));
  assert.equal(puts.length, 1, "the exact fixture bytes were not written once to the owner's node");
  // Nothing is kept by the page: no localStorage, sessionStorage or cookie entry at all, so none holds key or session material.
  const stored = await reader.evaluate(() => ({ entries: [...Object.entries(localStorage), ...Object.entries(sessionStorage), ...document.cookie.split(";").map((cookie) => cookie.trim()).filter((cookie) => cookie !== "").map((cookie) => cookie.split("="))] }));
  assert.deepEqual(stored.entries, [], "the page stored something while saving a copy");
  const databases = await reader.evaluate(async () => (await indexedDB.databases()).map((database) => database.name ?? ""));
  assert.deepEqual(databases, [], `the page created an IndexedDB database while saving a copy: ${databases.join(",")}`);
  // A fresh account's first sign-in meets "not found" answers and one bootstrap warning while its space and records do not exist yet; a second save of the same name meets the node's
  // "precondition failed" for the taken name (counted in auditBrowserDiagnostics). Nothing else is logged.
  const unexpectedLogs = consoleDiagnostics.filter((entry) => entry.phase === phase && !(
    (entry.type === "error" && /^Failed to load resource: the server responded with a status of (?:404 \(Not Found\)|412 \(Precondition Failed\))$/.test(entry.text))
    || (entry.type === "warn" && /^TinyCloud account (?:registry sync failed after retries|index initialization failed; continuing registry sync)/.test(entry.text))
  ));
  assert.equal(unexpectedLogs.length, 0, "the Save path logged something other than the account bootstrap and the taken-name answer");
  // Every OpenKey approval is one signature the widget was asked for; the first Save on a new account asks several (documented), a later one fewer.
  const approvals = after.filter((entry) => /openkey/i.test(entry.origin) && entry.method === "POST" && entry.path === "/sign").length;
  return { context, reader, storageEntries: stored.entries.length, announced: spoken.length, approvals, hints: hints.length };
}

/**
 * Save a copy, on the same stack: a recipient with their own OpenKey account
 * opens a link-only markdown share and clicks Save. The copy appears under
 * `files-for-you/v1/` in THEIR account with the exact bytes, a second Save
 * keeps both (a numbered name, never an overwrite), and revoking the original
 * share leaves every copy readable.
 */
async function verifySaveCopy({ browser, sender, stack }) {
  // Keys are stored percent-encoded (the node refuses a raw space or non-ASCII character); decoded, they are the names.
  const decoded = (copies) => copies.map((copy) => decodeURIComponent(copy.key.slice("v1/".length))).sort();
  const url = await shareSaveCopyFixture(sender);
  const first = await saveFromRecipient({ browser, stack, url, label: "one", expectedName: saveCopyName });
  const afterFirst = await readBackCopies(first.reader);
  assert.deepEqual(decoded(afterFirst.copies), [saveCopyName], "the first save is not the recipient's only copy");
  assert.equal(afterFirst.copies[0].sha256, saveCopyDigest, "the saved bytes differ from the original");
  assert.equal(afterFirst.copies[0].byteLength, saveCopyFixture.byteLength);
  assert.match(afterFirst.copies[0].contentType ?? "", /^text\/markdown/, "the copy is not stored as markdown");
  const second = await saveFromRecipient({ browser, stack, url, label: "two", expectedName: saveCopyName.replace(".md", " (2).md") });
  const afterSecond = await readBackCopies(second.reader);
  assert.deepEqual(decoded(afterSecond.copies), [saveCopyName, saveCopyName.replace(".md", " (2).md")].sort(), "a second save did not keep both copies");
  assert(afterSecond.copies.every((copy) => copy.sha256 === saveCopyDigest), "a saved copy differs from the original");

  // The original share is revoked by its owner; the recipient's copies are theirs and stay.
  const revocation = await revokeFromLibrary(sender, { relogin: true, recipientText: saveCopyName });
  phase = "save-revoked-recipient";
  const context = await browser.createBrowserContext(); const revoked = await context.newPage(); await installRouting(revoked, stack);
  await revoked.goto(url, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await revoked.waitForSelector(".viewer-state", { timeout: 180_000 });
  assert.equal(await revoked.$(".viewer-save-to-tinycloud"), null, "a revoked share still offered Save");
  assert.equal(await revoked.$(".viewer-download"), null, "a revoked share still rendered");
  await context.close();
  const afterRevoke = await readBackCopies(first.reader);
  assert.deepEqual(afterRevoke.copies, afterSecond.copies, "revoking the original share changed the recipient's copies");
  await first.context.close(); await second.context.close();
  return {
    savedOnce: true, savedTwice: true,
    copyKeys: afterRevoke.copies.map((copy) => copy.key),
    copySha256: saveCopyDigest, copiesEqualOriginal: true, copyContentType: afterRevoke.copies[0].contentType,
    openKeyBeforeClick: 0, openKeyApprovals: [first.approvals, second.approvals], approvalHints: [first.hints, second.hints], pendingAnnounced: true, approvalHintShown: true, savedAnnounced: true,
    storageEntriesAfterSave: first.storageEntries + second.storageEntries,
    revokedOriginalOffersNoSave: true, copiesSurviveRevoke: true, revocationWallet: revocation.wallet,
  };
}

/**
 * Agent-style sender on the same stack: the `tc` CLI publishes an exact-email
 * share and asks the owner's Node and OpenCredentials to email it
 * (`tc share publish <file> --to email:<addr> --notify`). The CLI keeps every
 * canonical origin it signs and validates; `cli-transport.mjs` only remaps
 * transport to this stack and refuses any other host. A fresh browser context
 * then claims the mailed link exactly as in the composer journey.
 */
let cliDiagnostic;
// The CLI bundle keeps @tinycloud/node-sdk external, so record the copy Node's
// resolver would load for it as well; the CLI dist alone does not pin behavior.
async function resolvedCliDependency(name) {
  for (let directory = cliPackage; ; directory = dirname(directory)) {
    const root = join(directory, "node_modules", name);
    const manifest = await readFile(join(root, "package.json"), "utf8").catch(() => undefined);
    if (manifest !== undefined) return { version: JSON.parse(manifest).version, distSha256: await digestDirectory(join(await realpath(root), "dist")) };
    if (dirname(directory) === directory) return undefined;
  }
}
async function verifyCliSenderJourney({ browser, stack, temporary }) {
  phase = "cli-sender";
  const cliManifest = JSON.parse(await readFile(join(cliPackage, "package.json"), "utf8"));
  assert.equal(cliManifest.name, "@tinycloud/cli", "TC500_CLI_PACKAGE is not an @tinycloud/cli package root");
  const nodeSdk = await resolvedCliDependency("@tinycloud/node-sdk");
  assert(nodeSdk, "the CLI's @tinycloud/node-sdk dependency is not installed");
  const cliProvenance = { version: cliManifest.version, distSha256: await digestDirectory(join(cliPackage, "dist")), nodeSdk };
  const tcHome = join(temporary, "cli-home");
  const profileDir = join(tcHome, ".tinycloud/profiles/owner");
  await mkdir(profileDir, { recursive: true, mode: 0o700 });
  await writeFile(join(tcHome, ".tinycloud/config.json"), JSON.stringify({ defaultProfile: "owner", version: 1 }), { mode: 0o600 });
  // A local owner key profile: the CLI signs in to the stack's Node itself.
  await writeFile(join(profileDir, "profile.json"), JSON.stringify({ name: "owner", host: stack.canonical.node, chainId: 1, spaceName: "default", authMethod: "local", posture: "local-owner-key", privateKey: randomBytes(32).toString("hex"), createdAt: new Date().toISOString() }), { mode: 0o600 });
  const inputPath = join(temporary, "cli-fixture.md"); await writeFile(inputPath, cliFixture, { flag: "wx", mode: 0o600 });
  const routeLog = join(temporary, "cli-routes.jsonl");
  const recipient = `tc500-cli-${Date.now()}@mailinator.com`;
  const mailBefore = stack.mail.length;
  const cli = await new Promise((resolveCli) => {
    // Asynchronous on purpose: the mail sink runs in this process.
    const child = spawn(process.execPath, ["--import", resolve(import.meta.dirname, "cli-transport.mjs"), join(cliPackage, "bin/tc"), "--profile", "owner", "share", "publish", inputPath, "--to", `email:${recipient}`, "--notify", "--json"], {
      env: {
        ...process.env, TC_HOME: tcHome, TC_HOST: stack.canonical.node, NO_COLOR: "1",
        TC500_CLI_ROUTES: JSON.stringify({ [stack.canonical.node]: stack.services.nodeOrigin, [stack.canonical.credentials]: stack.services.credentialsOrigin, [stack.canonical.registry]: stack.services.registryOrigin }),
        TC500_CLI_SHARE_CONFIG: join(shareRoot, "dist/.well-known/tinycloud-share/config.json"), TC500_CLI_ROUTE_LOG: routeLog,
      },
      stdio: ["ignore", "pipe", "ignore"],
    });
    let stdout = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 5 * 60_000);
    child.on("close", (status) => { clearTimeout(timer); resolveCli({ status, stdout }); });
  });
  let published; try { published = JSON.parse(cli.stdout); } catch {}
  const routes = (await readFile(routeLog, "utf8").catch(() => "")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const witnessStages = stack.credentialsLog().split("\n").filter((line) => /^credential invitation stage=/.test(line)).slice(-6);
  // Fixed labels and counts only; no link, mailbox, receipt, or body.
  cliDiagnostic = { cli: cliProvenance, exitCode: cli.status, notificationState: published?.notification?.state, notificationAttempts: published?.notification?.attempts, deliveryAuthorizations: routes.filter((entry) => entry.path === "/policy/v3/deliveries/authorize").map((entry) => entry.status), credentialInvitations: routes.filter((entry) => entry.path === "/v1/credential-invitations").map((entry) => entry.status), refusedHosts: routes.filter((entry) => entry.refused !== undefined).length, witnessStages };
  assert.equal(cliDiagnostic.refusedHosts, 0, "the CLI tried to reach a host outside the stack");
  assert.equal(cli.status, 0, "tc share publish --notify did not exit cleanly");
  assert.equal(published?.notification?.state, "delivered", "tc share publish --notify did not deliver the invitation");
  assert.deepEqual(cliDiagnostic.credentialInvitations, [202], "OpenCredentials did not accept exactly one CLI invitation");
  const invitationMail = await waitUntil(() => stack.mail.slice(mailBefore).find((message) => {
    const to = Array.isArray(message?.payload?.to) ? message.payload.to : [message?.payload?.to];
    return to.includes(recipient) && stringsIn(message.payload).some((value) => value.includes("/s/inline#"));
  }), 60_000);
  const link = invitationFromMail(invitationMail);
  assert.equal(typeof link, "string", "the CLI invitation was not mailed to the recipient");

  phase = "cli-recipient";
  const context = await browser.createBrowserContext(); const reader = await context.newPage(); await installRouting(reader, stack);
  await reader.goto(link, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await (await waitUntil(async () => (await reader.$(".claim-request-code")) ?? undefined, 90_000)).click();
  const otpMail = await waitUntil(() => stack.mail.find((message) => isCredentialOtpMail(message, recipient)), 60_000);
  const code = credentialOtpFromMail(otpMail); assert.match(code ?? "", /^\d{8}$/);
  assert.equal(await credentialInputReady(reader, "otp"), true, "CLI recipient OTP input did not become stable");
  assert.equal(await submitCredentialValue(reader, code, "otp"), true);
  const cliTemporary = await mkdtemp(join(tmpdir(), "tc500-cli-recipient-"));
  assert.equal(await downloadExact(reader, cliTemporary, cliFixture), true, "CLI recipient did not render the exact bytes");
  const phaseTrace = trace.filter((entry) => entry.phase === "cli-recipient");
  assert(phaseTrace.some((entry) => entry.origin === stack.canonical.credentials && entry.method === "POST" && entry.path === "/v1/acquisitions" && successfulRequest(entry)), "CLI recipient did not acquire an email credential");
  for (const path of ["/policy/v3/challenges", "/policy/v3/delegations", "/delegate"]) {
    assert(phaseTrace.some((entry) => entry.origin === stack.canonical.node && entry.method === "POST" && entry.path === path && successfulRequest(entry)), `CLI recipient did not complete ${path}`);
  }
  const invokes = phaseTrace.filter((entry) => entry.origin === stack.canonical.node && entry.path === "/invoke" && successfulRequest(entry));
  assert(invokes.length >= 2, "CLI recipient did not read and decrypt through ordinary invoke");
  assert(!phaseTrace.some((entry) => /openkey/i.test(entry.origin)), "CLI recipient contacted OpenKey");
  await context.close();
  return { cli: cliProvenance, notificationState: "delivered", deliveryAuthorizations: cliDiagnostic.deliveryAuthorizations.length, credentialInvitations: 1, recipientRendered: true, recipientInvokeCount: invokes.length, fixtureSha256: createHash("sha256").update(cliFixture).digest("hex") };
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

/**
 * TC-1582. The first email share was revoked by the negative-enforcement stage.
 * Its invitation link must now show the "no longer available" screen without
 * offering or requesting a code: no OpenCredentials request, no node challenge,
 * no mail. Also probes the real node (not the gate's rewriting proxy) for the
 * CORS headers the browser needs on the public status route.
 */
async function verifyRevokedEmailShare({ browser, stack, invitation, recipientEmail }) {
  const mailBefore = stack.mail.length;
  const codesBefore = stack.mail.filter((message) => isCredentialOtpMail(message, recipientEmail)).length;
  phase = "revoked-email-recipient";
  const from = trace.length;
  const context = await browser.createBrowserContext(); const page = await context.newPage(); await installRouting(page, stack);
  await page.goto(invitation, { waitUntil: "domcontentloaded", timeout: 180_000 });
  await page.waitForSelector(".recipient-unavailable", { timeout: 90_000 });
  const screen = await page.evaluate(() => ({
    title: document.querySelector("h1")?.textContent,
    detail: document.querySelector(".recipient-detail")?.textContent,
    role: document.querySelector(".recipient-unavailable")?.getAttribute("role"),
    requestButtons: document.querySelectorAll(".claim-request-code").length,
    mentionsVerify: /Verify your email|Email me a code/.test(document.body.textContent ?? ""),
    focused: document.activeElement?.id,
  }));
  assert.equal(screen.title, "This share is no longer available");
  assert.equal(screen.detail, "The sender may have revoked it, or it has expired.");
  assert.equal(screen.role, "alert");
  assert.equal(screen.requestButtons, 0, "a revoked share still offered a code request");
  assert.equal(screen.mentionsVerify, false, "a revoked share still asked the recipient to verify an email");
  assert.equal(screen.focused, "viewer", "focus did not move to the unavailable screen");
  // Give any late request a moment to show up before reading the trace.
  await new Promise((done) => setTimeout(done, 2_000));
  const mine = trace.slice(from).filter((entry) => entry.phase === phase);
  const statusReads = mine.filter((entry) => entry.origin === stack.canonical.node && entry.method === "GET" && entry.path.startsWith("/policy/v3/status/"));
  assert(statusReads.length >= 1 && statusReads.some((entry) => entry.status === 200 && entry.response?.state === "revoked"), "the page did not read a revoked status from the node");
  assert.equal(mine.filter((entry) => entry.origin === stack.canonical.credentials).length, 0, "a revoked share contacted OpenCredentials");
  assert.equal(mine.filter((entry) => entry.origin === stack.canonical.node && entry.method === "POST").length, 0, "a revoked share made a node POST (challenge, delegation or invoke)");
  assert.equal(mine.filter((entry) => /openkey/i.test(entry.origin)).length, 0, "a revoked share contacted OpenKey");
  assert.equal(stack.mail.length, mailBefore, "mail was sent for a revoked share");
  assert.equal(stack.mail.filter((message) => isCredentialOtpMail(message, recipientEmail)).length, codesBefore, "a code was emailed for a revoked share");
  const stored = await page.evaluate(async () => ({ session: Object.keys(sessionStorage).length, local: Object.keys(localStorage).length, databases: (await indexedDB.databases()).map((database) => database.name ?? "") }));
  assert.deepEqual(stored, { session: 0, local: 0, databases: [] }, "a revoked share left receiver state in the browser");
  const revokedRoot = statusReads.find((entry) => entry.response?.state === "revoked");
  const direct = await fetch(new URL(revokedRoot.path, stack.services.nodeOrigin), { headers: { origin: stack.canonical.share, accept: "application/json" } });
  assert.equal(direct.status, 200);
  assert.equal(direct.headers.get("access-control-allow-origin"), stack.canonical.share, "the node does not allow the Share origin to read policy status");
  const directBody = await direct.json();
  assert.equal(directBody.state, "revoked");
  assert.equal(directBody.rootCid, decodeURIComponent(revokedRoot.path.split("/").at(-1)));
  // A root the node has never seen is a plain 404, which the page reads as "not revoked".
  const unknown = await fetch(new URL("/policy/v3/status/bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", stack.services.nodeOrigin), { headers: { origin: stack.canonical.share } });
  assert.equal(unknown.status, 404);
  const shots = process.env.TC1582_SHOT_DIR;
  const axeSource = await readFile(join(shareRoot, "node_modules/axe-core/axe.min.js"), "utf8");
  const axe = {};
  for (const [width, height] of [[390, 844], [1440, 900]]) for (const scheme of ["light", "dark"]) {
    await page.setViewport({ width, height }); await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
    // The theme switch transitions colours; axe must read the settled values.
    await new Promise((done) => setTimeout(done, 800));
    await page.evaluate(axeSource);
    const result = await page.evaluate(() => globalThis.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } }));
    axe[`${width}-${scheme}`] = result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => `${node.target.join(" ")} ${JSON.stringify(node.any[0]?.data ?? {})}`).join("; ")}`);
    assert.deepEqual(axe[`${width}-${scheme}`], [], `${width}px ${scheme}: axe AA on the unavailable screen`);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    assert(overflow <= 0, `${width}px ${scheme}: the unavailable screen scrolls sideways`);
    if (shots !== undefined) await page.screenshot({ path: join(shots, `unavailable-${width}-${scheme}.png`) });
  }
  await context.close();
  return { screenShown: true, codeRequests: 0, mailSent: 0, statusReads: statusReads.length, corsAllowsShareOrigin: true, unknownRootStatus: unknown.status, axe };
}

const temporary = await mkdtemp(join(tmpdir(), "tc500-native-joined-"));
const fixturePath = join(temporary, "native-fixture.bin"); await writeFile(fixturePath, fixture, { flag: "wx", mode: 0o600 });
let stack; let candidate; let browser; let recipientEmail; let selectedOtp; let watchdog;
try {
  journeyStage = "share-build";
  await runBoundedStep("npm", ["run", "build"], shareRoot, {}, 10 * 60_000);
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore", timeout: 60_000 });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8", timeout: 30_000 }).trim();
  candidate = await startCandidateServer({ root: resolve(shareRoot, "dist"), key: await readFile(key), cert: await readFile(cert) });
  journeyStage = "native-stack-readiness";
  stack = await startNativeStack({ root: temporary, nodeRoot, credentialsRoot, registryRoot });
  // A hung journey fails and exits (fixture processes are killed on exit)
  // instead of holding the host until someone notices.
  watchdog = setTimeout(() => { fail(`${journeyStage} (journey timeout)`); process.exit(1); }, journeyTimeoutMs);
  watchdog.unref();
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
  journeyStage = "recipient-code-request";
  const requestCode = await waitUntil(async () => (await recipient.$(".claim-request-code")) ?? undefined, 90_000);
  assert(requestCode, "recipient code request button did not appear");
  // Opening the link (as a mail scanner would) must not reach OpenCredentials or send a code.
  assert.equal(trace.filter((entry) => entry.phase === "recipient" && entry.origin === stack.canonical.credentials && entry.method === "POST").length, 0, "the invitation page contacted OpenCredentials before a click");
  assert.equal(stack.mail.filter((message) => isCredentialOtpMail(message, recipientEmail)).length, 0, "a code was emailed before a click");
  // Both policy roots are checked before the button is offered; a live share's status reads all answer 200.
  const liveStatusReads = trace.filter((entry) => entry.phase === "recipient" && entry.origin === stack.canonical.node && entry.method === "GET" && entry.path.startsWith("/policy/v3/status/"));
  assert(liveStatusReads.length >= 2 && liveStatusReads.every((entry) => entry.status === 200 && entry.response?.state === "active"), "the page did not read an active status for each root of a live share");
  // A double click sends one code.
  await recipient.$eval(".claim-request-code", (button) => { button.click(); button.click(); });
  journeyStage = "recipient-otp-delivery";
  const otpMail = await waitUntil(() => stack.mail.find((message) => isCredentialOtpMail(message, recipientEmail)), 60_000);
  selectedOtp = credentialOtpFromMail(otpMail); assert.match(selectedOtp ?? "", /^\d{8}$/);
  assert.equal(await credentialInputReady(recipient, "otp"), true, "recipient OTP input did not become stable");
  assertBearerDidNotAuthorize(stack);
  journeyStage = "recipient-otp";
  assert.equal(await submitCredentialValue(recipient, selectedOtp, "otp"), true);
  journeyStage = "recipient-decrypt-render";
  assert.equal(await downloadExact(recipient, temporary), true);
  assert.equal(stack.mail.filter((message) => isCredentialOtpMail(message, recipientEmail)).length, 1, "one click did not send exactly one code");
  journeyStage = "traffic-audit";
  const audit = traceAudit(stack);
  journeyStage = "negative-enforcement";
  const negativeGates = await verifyNegativeEnforcement({ sender, recipient, stack });
  traceAudit(stack);
  journeyStage = "recipient-storage";
  // After a full claim the key is a non-extractable IndexedDB handle, and no
  // private key material sits in session storage, local storage or cookies.
  const keyHandle = await recipientKeyHandle(recipient);
  assert.equal(keyHandle?.extractable, false, "recipient key handle is missing or extractable");
  assert.equal(keyHandle.exportRejected, true, "recipient private key could be exported");
  const stored = await recipient.evaluate(async () => ({
    entries: [...Object.entries(sessionStorage), ...Object.entries(localStorage), ...document.cookie.split(";").map((cookie) => cookie.trim().split("="))],
    databases: (await indexedDB.databases()).map((database) => database.name ?? ""),
  }));
  for (const [key = "", value = ""] of stored.entries) {
    assert(!/receiver-session/.test(key), "a legacy receiver session record was left in browser storage");
    assert(!/"d"\s*:|"jwk"|privateKey|pkcs8/i.test(value), "private key material was left in browser storage");
  }
  assert.deepEqual(stored.databases.filter((name) => /receiver|share/i.test(name)), ["tinycloud.share.receiver-keys"], "an unexpected receiver database is in IndexedDB");
  journeyStage = "revoked-email-share";
  const revokedEmailShare = await verifyRevokedEmailShare({ browser, stack, invitation, recipientEmail });
  journeyStage = "bearer-regression";
  const bearerRegression = await verifyBearerRegression({ browser, sender, stack });
  journeyStage = "domain-journey";
  const domainJourney = await verifyDomainJourney({ browser, sender, stack });
  journeyStage = "domain-delivery";
  const domainDelivery = await verifyDomainDelivery({ browser, sender, stack });
  journeyStage = "other-share-survives";
  const otherShare = await verifyOtherShareSurvives({ browser, stack });
  journeyStage = "bearer-revoke-after-relogin";
  const bearerRevoke = await verifyBearerRevokeAfterRelogin({ browser, sender, stack });
  journeyStage = "save-copy";
  const saveCopy = await verifySaveCopy({ browser, sender, stack });
  journeyStage = "cli-sender";
  // TC500_SKIP_CLI_SENDER=1 runs every browser stage without the `tc` CLI leg (no CLI is installed); such a run is never the release gate.
  const cliSkipped = process.env.TC500_SKIP_CLI_SENDER === "1";
  const cliSender = cliSkipped ? { skipped: true } : await verifyCliSenderJourney({ browser, stack, temporary });
  journeyStage = "browser-diagnostics";
  const browserDiagnostics = auditBrowserDiagnostics(stack);

  const artifact = { type: "tinycloud.share/native-joined-e2e/v1", result: cliSkipped ? "partial-passed" : gateResult(stack.provenance), fixtureSha256: fixtureDigest, provenance: { ...stack.provenance, ...(await shareProvenance()) }, ...audit, negativeGates, bearerRegression, domainJourney, domainDelivery, otherShare, bearerRevoke, cliSender, revokeRequests: trace.filter((entry) => entry.path === "/revoke").map((entry) => ({ sequence: entry.sequence, phase: entry.phase, origin: entry.origin === stack.canonical.node ? "node" : "other", status: entry.status, jsonBody: entry.body !== undefined, authorizationHeader: typeof entry.authorization === "string" && entry.authorization.length > 0, receiptCidReturned: typeof entry.response?.cid === "string" })), browserDiagnostics, prohibitedShareDataPlaneRequests: 0 };
  artifact.revokedEmailShare = revokedEmailShare;
  artifact.saveCopy = saveCopy;
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
    nativeStackStage: typeof error?.nativeStage === "string" ? error.nativeStage : undefined,
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
    journeyDiagnostic: ["revoked-email-share", "bearer-regression", "domain-journey", "domain-delivery", "other-share-survives", "bearer-revoke-after-relogin", "save-copy", "cli-sender", "browser-diagnostics"].includes(journeyStage) && error?.code === "ERR_ASSERTION" ? String(error.message).slice(0, 240) : undefined,
    cliDiagnostic: journeyStage === "cli-sender" ? cliDiagnostic : undefined,
    dataPlaneDiagnostics: recipientInvokes.map((entry) => ({
      responseByteLength: entry.responseByteLength,
      responseContentType: entry.responseContentType,
      matchesSenderCiphertext: senderCiphertexts.some((senderEntry) => senderEntry.requestSha256 === entry.responseSha256),
      matchingSenderCiphertextByteLength: senderCiphertexts.find((senderEntry) => senderEntry.requestSha256 === entry.responseSha256)?.requestByteLength,
    })),
  }, null, 2), { mode: 0o600 }).catch(() => undefined);
  fail(journeyStage);
} finally {
  clearTimeout(watchdog);
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  console.log(`[tc500] artifacts retained under ${temporary.replace(/[^/]+$/, "<redacted>")}`);
  // Exit explicitly: a lingering handle must never keep a finished run alive.
  process.exit();
}
