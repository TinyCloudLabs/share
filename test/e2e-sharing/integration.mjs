#!/usr/bin/env node

/*
 * Hermetic sharing gate.
 *
 * This file intentionally drives the shipped production Share pages with the
 * agent-browser CLI.  The only browser-side test seam is the external-wallet
 * shape described in the browser E2E guide: OpenKey's external widget is
 * intercepted before it can leave the loopback composition, while the wallet
 * signs the real SIWE message through a deterministic loopback signer.  The
 * Share host, registry, and native services remain real processes.
 */

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer as httpServer } from "node:http";
import { createConnection, createServer as netServer } from "node:net";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "multiformats/bases/base58";
import { privateKeyToAccount } from "viem/accounts";
import { buildNodeLaunchEnv } from "./node-launch-env.mjs";
import { buildShareHostLaunchEnv } from "./share-launch-env.mjs";
import { buildShareBrowserBuildEnv } from "./share-browser-build-env.mjs";
import { verifyReleaseInputRepository } from "./preflight.mjs";
import { assertWebSdkLink, resolveJsSdkWorktree } from "./web-sdk-link.mjs";
import { GATE_SLICES, gateSummary, gateVerdict, parseRequiredSlices, summarizeSlices } from "./gate-slices.mjs";
import { findSurvivingOwnedProcesses, parsePsLines } from "./process-groups.mjs";
import { buildCredentialsLaunchEnv, buildMigrationEnv } from "./credentials-launch-env.mjs";
import { assertCredentialsReadinessBody, redactSecrets } from "./credentials-readiness.mjs";
import { buildDstackResponsePayload, ed25519PublicKey, parseDstackRequest, formatHttpResponse } from "./dstack-issuer.mjs";
import { nodeEnforcerAudienceFromTrustBundle } from "./node-enforcer-audience.mjs";
import { assertNodeShareV2Capability } from "./node-capability.mjs";
import { POSTGRES_TLS_HOSTNAME, postgresConnectionUrl, postgresServerCertExtensionFile } from "./postgres-tls-config.mjs";
import { safeFailedTelemetry } from "./failure-diagnostic.mjs";
import { routeTelemetryFetchArgs, normalizeTelemetryFetchArgs } from "./browser-telemetry-route.mjs";
import { assertRoutingShimInstalled, loopbackTransportAbortPatterns } from "./loopback-transport.mjs";
import { OPENSSL_OVERRIDE_ENV, duplicateCertificateExtensions, resolveOpensslBinary, tlsMaterialDiagnostic } from "./openssl-toolchain.mjs";
import { OPENKEY_TEST_SESSION_TOKEN, openKeyApiCors, openKeyWidgetHtml } from "./openkey-fixture.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");

// The composer infers what is being shared from what the sender does: there
// is no content-mode control to drive. These helpers exercise the three real
// entry points (paste, file picker, library) and the Advanced disclosure.
const pasteIntoDropzone = (text) => ["eval", `(()=>{const transfer=new DataTransfer();transfer.setData('text/plain',${JSON.stringify(text)});const zone=document.querySelector('.content-dropzone');if(!zone)throw new Error('content drop zone is not present');zone.dispatchEvent(new ClipboardEvent('paste',{clipboardData:transfer,bubbles:true,cancelable:true}));return true;})()`];
const openAdvancedSettings = ["eval", "(()=>{const drawer=document.querySelector('details.composer-advanced');if(!drawer)throw new Error('advanced settings are not present');drawer.open=true;return true;})()"];
const pickFromLibrary = ["eval", "(()=>{const link=document.querySelector('.content-dropzone .dropzone-library');if(!link)throw new Error('library picker is not present');link.click();return true;})()"];
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/feat/sharing-production-live");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? join(workspaceRoot, "worktrees/opencredentials/feat/sharing-production-live");
const policyEngineRoot = process.env.POLICY_ENGINE_WORKTREE ?? join(workspaceRoot, "worktrees/policy-engine/feat-plaintext-exact-email-share");
const credentialsManifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
const artifactPath = process.env.SHARING_E2E_ARTIFACT_PATH ?? join(workspaceRoot, ".context/sharing-experience-e2e-result.json");
const lockPath = join(tmpdir(), "tinycloud-sharing-e2e.lock");
const canonical = Object.freeze({
  share: "https://share.tinycloud.xyz",
  node: "https://node.tinycloud.xyz",
  credentials: "https://witness.credentials.org",
  registry: "https://registry.tinycloud.xyz",
  policy: "https://policy.tinycloud.xyz",
});
const tc500Joined = process.env.SHARING_E2E_TC500_JOINED === "1";
const tc465Joined = process.env.SHARING_E2E_TC465_JOINED === "1" || tc500Joined;
const walletPrivateKey = `0x${"55".repeat(32)}`;
const issuerSeed = Buffer.alloc(32, tc465Joined ? 67 : 0x47);
const issuerPublicKey = ed25519PublicKey(issuerSeed).toString("base64url");
const policyGrantSeed = Buffer.alloc(32, 91);
const policyGrantPublicKey = ed25519.getPublicKey(policyGrantSeed);
const policyGrantIssuerDid = `did:key:${base58btc.encode(Uint8Array.from([0xed, 0x01, ...policyGrantPublicKey]))}`;
const registryUploadSeed = Buffer.alloc(32, 7);
const registryUploadPublicKey = Buffer.from(ed25519.getPublicKey(registryUploadSeed)).toString("base64url");
const nodeKeysSecret = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const wallet = privateKeyToAccount(walletPrivateKey);
const agentBrowser = process.env.AGENT_BROWSER_BIN ?? "agent-browser";
const postgresBin = process.env.SHARING_E2E_POSTGRES_BIN ?? execFileSync("pg_config", ["--bindir"], { encoding: "utf8" }).trim();
const postgresUser = process.env.SHARING_E2E_POSTGRES_USER ?? process.env.USER ?? "postgres";
const children = [];
const ownedPgids = new Set();
const servers = [];
const checks = [];
const blockers = [];
const flowAudits = [];
const serverTraceIds = [];
const launchInputDigests = {};
const gateResults = { exactEmail: false, domain: false, bearer: false, editConflict: false, folder: false, notification: false, denialMatrix: false, senderLibrary: false, browser: false };
// TC-307. Per-slice bookkeeping, so "never attempted" stays distinguishable
// from "attempted and failed" all the way into the artifact.
const attemptedSlices = new Set();
const sliceFailures = new Map();
const blockedSlices = {};
const requiredSlices = parseRequiredSlices(process.env.SHARING_E2E_REQUIRED_SLICES);
const runId = `sharing-e2e-${process.pid}-${randomUUID()}`;
const localUnpushedMode = process.env.SHARING_E2E_LOCAL_UNPUSHED === "1";
const externalControlDir = process.env.SHARING_E2E_EXTERNAL_CONTROL_DIR;
let releaseInputsVerified = false;
let sessionName = runId;
let externalRequests = [];
let tc465Evidence;
// TC-306. The browser audit below can only see destinations the *page*
// requests, and the page only ever talks to the loopback Share host. The
// Share host's own server-side upstream resolution is a second, invisible
// destination set; it stays `allLoopback: false` until the routing gate in
// startShare() proves otherwise against the production resolver.
let upstreamRoutingAudit = { allLoopback: false, upstreams: null, bundleOrigins: null, routes: [] };
let lockHeld = false;
let cleanupStarted = false;

const AGENT_TIMEOUT_MS = 60_000;
const CHILD_TIMEOUT_MS = 20 * 60_000;

async function waitForExternalProductJourney(fixtures, localShareOrigin) {
  if (externalControlDir === undefined) return false;
  const resolvedControlDir = resolve(externalControlDir);
  const temporaryRoots = [resolve(tmpdir()), resolve("/tmp")];
  if (!temporaryRoots.some((root) => resolvedControlDir.startsWith(`${root}/`))) throw new Error("external product control directory must be private temporary storage");
  const controlStat = await stat(resolvedControlDir);
  if (!controlStat.isDirectory() || (controlStat.mode & 0o077) !== 0) throw new Error("external product control directory must have mode 0700");
  await writeFile(join(resolvedControlDir, "services.json"), JSON.stringify({
    shareOrigin: localShareOrigin,
    registryOrigin: fixtures.registryOrigin,
    nodeOrigin: fixtures.nodeOrigin,
    credentialsOrigin: fixtures.credentialsOrigin,
    policyEngineOrigin: fixtures.policyEngineOrigin,
    mailOrigin: fixtures.mailOrigin,
    openKeyOrigin: fixtures.openKeyOrigin,
    walletOrigin: fixtures.walletOrigin,
  }), { flag: "wx", mode: 0o600 });
  const deadline = Date.now() + 15 * 60_000;
  while (Date.now() < deadline) {
    try {
      await stat(join(resolvedControlDir, "release"));
      if (tc465Joined) {
        const evidence = JSON.parse(await readFile(join(resolvedControlDir, "tc465-result.json"), "utf8"));
        const stages = tc500Joined
          ? ["delivery", "senderLibrary", "acquisition", "sessionCredential", "policyV0", "delegate", "invoke", "localDecrypt", "rendered", "legacyPolicySessionAbsent", "zeroOpenKeyBeforeRender", "zeroExternalDestinations"]
          : ["acquisition", "durableCredential", "policyV3Challenge", "policyV3Mint", "delegate", "invoke", "decrypt", "rendered", "legacyPolicySessionAbsent", "zeroExternalDestinations"];
        const sliceKeys = tc500Joined
          ? ["acquisitionIdSha256", "delegationCid", "deliveredMailIdSha256", "policyCid", "receiverDid", "resource", "shareCid"]
          : ["acquisitionIdSha256", "credentialRecord", "credentialSpaceId", "policyCid", "resource", "shareCid"];
        const evidenceType = tc500Joined ? "tinycloud.policy-access/delivered-email-evidence/v1" : "tinycloud.share/tc-465-joined-evidence/v2";
        if (evidence?.type !== evidenceType || Object.keys(evidence).sort().join(",") !== "chain,renderedSha256,slice,statuses,type" || typeof evidence.renderedSha256 !== "string" || !/^[0-9a-f]{64}$/.test(evidence.renderedSha256) || typeof evidence.statuses !== "object" || evidence.statuses === null || stages.some((stage) => evidence.statuses[stage] !== true) || !Array.isArray(evidence.chain) || evidence.chain.length < 12 || typeof evidence.slice !== "object" || evidence.slice === null || Object.keys(evidence.slice).sort().join(",") !== sliceKeys.join(",") || Object.values(evidence.slice).some((value) => typeof value !== "string" || value.length === 0)) throw new Error(`dedicated ${tc500Joined ? "TC-500" : "TC-465"} evidence is incomplete`);
        tc465Evidence = evidence;
        if (tc500Joined) flowAudits.push({ name: "tc-500-exact-email", capturedMailIdSha256: evidence.slice.deliveredMailIdSha256, delivery: true, senderLibrary: true, zeroOpenKeyBeforeRender: true, zeroExternalDestinations: true });
      }
      checks.push("External packed-CLI and normal-Chrome product journey completed while the production-shaped composition remained live.");
      return true;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  throw new Error("external product journey control timed out");
}

function featureProcess(pid) {
  try {
    const command = execFileSync("ps", ["-p", String(pid), "-o", "command="], { encoding: "utf8" });
    return command.includes("test/e2e-sharing") && command.includes("sharing-production-live");
  } catch { return false; }
}

async function acquireLock() {
  try {
    await mkdir(lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    let owner;
    try { owner = JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8")); } catch { owner = undefined; }
    const ownerAlive = owner?.pid !== undefined && (() => { try { process.kill(owner.pid, 0); return true; } catch { return false; } })();
    if (ownerAlive && featureProcess(owner.pid)) throw new Error(`another sharing harness owns the scoped lock (pid ${owner.pid})`);
    await rm(lockPath, { recursive: true, force: true });
    await mkdir(lockPath, { mode: 0o700 });
  }
  await writeFile(join(lockPath, "owner.json"), JSON.stringify({ pid: process.pid, runId, cwd: shareRoot }), { flag: "wx", mode: 0o600 });
  lockHeld = true;
}

async function releaseLock() {
  if (!lockHeld) return;
  lockHeld = false;
  await rm(lockPath, { recursive: true, force: true });
}

function b64(value) { return Buffer.from(value).toString("base64url"); }
function sha256(value) { return createHash("sha256").update(value).digest("base64url"); }
async function recordArtifactDigest(name, path) {
  const bytes = await readFile(path);
  launchInputDigests[name] = { path, digest: createHash("sha256").update(bytes).digest("hex") };
}
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
// `emailOrigin` is the credentials origin here, not `email.tinycloud.xyz`:
// this harness stands up one hermetic stub per upstream and has no separate
// email service, so pointing delivery at the credentials stub keeps it
// covering exactly what it covered before TC-379 split the two origins apart.
// Production keeps them distinct; see `config/trust-bundle.production.json`.
function trustBundleFromRuntime(nodePublicKey) {
  return JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1", shareOrigin: canonical.share, returnOrigin: canonical.share, registryOrigin: canonical.registry, credentialsOrigin: canonical.credentials, policyEngineOrigin: canonical.policy, policyEngineAudience: canonical.policy, policyEngineGrantIssuerDid: policyGrantIssuerDid, emailOrigin: canonical.credentials, nodeOrigin: canonical.node, nodeAudience: "did:web:node.tinycloud.xyz", nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", nodeInvitationPublicKey: nodePublicKey, nodeKeyVersion: 1, nodeEnabled: true, issuerDid: "did:web:issuer.credentials.org", issuerVct: "opencredentials.email/v1", issuerKid: tc465Joined ? "did:web:issuer.credentials.org#controller" : "did:web:issuer.credentials.org#email-signing-key-1", issuerPublicKey, issuerKeyVersion: 1, issuerEnabled: true });
}
function credentialsTrustBundleFromRuntime(nodePublicKey) {
  const bundle = JSON.parse(trustBundleFromRuntime(nodePublicKey));
  delete bundle.emailOrigin;
  delete bundle.policyEngineOrigin;
  delete bundle.policyEngineAudience;
  delete bundle.policyEngineGrantIssuerDid;
  return JSON.stringify(bundle);
}
async function freePort() {
  const server = httpServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}
async function loopback(label, handler) {
  const server = httpServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  servers.push(server);
  const port = server.address().port;
  checks.push(`${label} test service listening on 127.0.0.1:${port}.`);
  return `http://127.0.0.1:${port}`;
}
function run(command, args, cwd, env = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], detached: true });
  let output = "";
  const collect = (chunk) => { output += String(chunk); if (output.length > 32_000) output = output.slice(-32_000); };
  child.stdout.on("data", collect); child.stderr.on("data", collect);
  children.push({ child, output: () => output });
  if (typeof child.pid === "number") ownedPgids.add(child.pid);
  return child;
}

async function assertReleaseInputs() {
  const repositories = tc500Joined ? [
    { name: "share", path: shareRoot, branch: "skgbafa/tc-500-accountless-email-claim", pr: "98" },
    { name: "node", path: nodeRoot, branch: "main" },
    { name: "opencredentials", path: credentialsRoot, branch: "feat/generic-credential-invitation-delivery" },
    { name: "js-sdk", path: resolveJsSdkWorktree(process.env, workspaceRoot), branch: "skgbafa/tc-500-accountless-browser-interop", pr: "408" },
    { name: "policy-engine", path: policyEngineRoot, branch: "feat/plaintext-exact-email-share", pr: "12" },
  ] : tc465Joined ? [
    { name: "share", path: shareRoot, branch: "skgbafa/tc-465-share-receiver-credentials", pr: "78" },
    { name: "node", path: nodeRoot, branch: "skgbafa/tc-470-holder-credential-admission", pr: "210" },
    { name: "opencredentials", path: credentialsRoot, branch: "skgbafa/tc-462-credential-flow-opencredentials-785732297208", pr: "117" },
    { name: "js-sdk", path: resolveJsSdkWorktree(process.env, workspaceRoot), branch: "skgbafa/tc-470-policy-credential-presentation", pr: "386" },
  ] : [
    { name: "share", path: shareRoot, branch: "feat/sharing-production-live", pr: "27" },
    { name: "node", path: nodeRoot, branch: "feat/sharing-production-live", pr: "168" },
    { name: "opencredentials", path: credentialsRoot, branch: "feat/sharing-production-live", pr: "113" },
    { name: "js-sdk", path: resolveJsSdkWorktree(process.env, workspaceRoot), branch: "feat/sharing-production-live", pr: "361" },
  ];
  for (const repository of repositories) {
    const { head, digest } = await verifyReleaseInputRepository(repository, { localUnpushedMode });
    launchInputDigests[repository.name] = { head, digest };
  }
  const sdkRoot = repositories.find((repository) => repository.name === "js-sdk").path;
  // Build the browser SDK and its workspace dependencies from the selected
  // source tree without accepting a previously cached bundle. A stale
  // web-sdk artifact can otherwise hide share-envelope/share-sdk changes and
  // make the joined browser exercise different code from the direct audit.
  await runOnce("bunx", ["turbo", "build", "--force", "--filter=@tinycloud/web-sdk..."], sdkRoot);
  // TC-345. One statement of the rule, shared with startShare() and with
  // `npm run check:web-sdk-link`; every failure names `npm run link:web-sdk`.
  const expectedWebSdk = assertWebSdkLink(shareRoot, sdkRoot);
  await stat(join(expectedWebSdk, "dist/index.mjs"));
  launchInputDigests.jsSdkArtifacts = { path: join(expectedWebSdk, "dist/index.mjs"), digest: createHash("sha256").update(await readFile(join(expectedWebSdk, "dist/index.mjs"))).digest("hex") };
  if (!localUnpushedMode) releaseInputsVerified = true;
  checks.push(localUnpushedMode
    ? `Local unpushed preflight verified clean worktrees for ${repositories.map((repository) => repository.name).join(", ")}; committed local heads/digests recorded without requiring upstream/remote/PR match.`
    : `Release inputs verified clean with matching upstream, remote, and GitHub PR heads; committed tree digests recorded for ${Object.keys(launchInputDigests).join(", ")}.`);
}
async function waitFor(url, timeoutMs = 60_000, child) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const response = await fetch(url, { redirect: "error" }); if (response.status < 500) return response; } catch {}
    if (child?.exitCode !== null && child?.exitCode !== undefined) {
      const output = children.find((entry) => entry.child === child)?.output() ?? "";
      throw new Error(`service exited before ${url} became ready (${child.exitCode}): ${output.slice(-4000)}`);
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`timed out waiting for ${url}`);
}
async function waitForTcp(port, timeoutMs = 30_000, child) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolveConnect, rejectConnect) => {
        const socket = createConnection({ host: "127.0.0.1", port });
        socket.once("connect", () => { socket.destroy(); resolveConnect(); });
        socket.once("error", (error) => { socket.destroy(); rejectConnect(error); });
      });
      return;
    } catch {}
    if (child?.exitCode !== null && child?.exitCode !== undefined) {
      const output = children.find((entry) => entry.child === child)?.output() ?? "";
      throw new Error(`service exited before loopback TCP port ${port} became ready (${child.exitCode}): ${output.slice(-4000)}`);
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`timed out waiting for loopback TCP port ${port}`);
}
async function runOnce(command, args, cwd, env = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  child.stderr.on("data", (chunk) => { output += String(chunk); });
  const timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch {} }, CHILD_TIMEOUT_MS);
  const [code] = await once(child, "exit");
  clearTimeout(timer);
  if (code !== 0) throw new Error(`${command} ${args.join(" ")} exited ${code}: ${output.slice(-4000)}`);
}
async function descriptor(path, child, label) {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    try { return JSON.parse(await readFile(path, "utf8")); } catch {}
    if (child.exitCode !== null) throw new Error(`${label} exited before its descriptor: ${children.find((entry) => entry.child === child)?.output().slice(-4000)}`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  throw new Error(`${label} descriptor was not published`);
}
async function stopAll() {
  await Promise.all(children.slice().reverse().map(async ({ child }) => {
    if (child.exitCode !== null) return;
    try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill("SIGTERM"); }
    await Promise.race([once(child, "exit"), new Promise((resolveWait) => setTimeout(resolveWait, 3000))]);
    if (child.exitCode === null) { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
  }));
}
async function closeAll() {
  await Promise.all(servers.map((server) => new Promise((resolveClose) => { server.closeAllConnections?.(); server.close(() => resolveClose()); })));
}
let agentQueue = Promise.resolve();
function runAgent(args) {
  return new Promise((resolveAgent, rejectAgent) => {
    const child = spawn(agentBrowser, ["--session", sessionName, ...args], { cwd: shareRoot, env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    let settled = false;
    const finish = (callback, value) => { if (settled) return; settled = true; clearTimeout(timer); callback(value); };
    const timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch {} finish(rejectAgent, new Error(`agent-browser ${args.join(" ")} timed out after ${AGENT_TIMEOUT_MS}ms`)); }, AGENT_TIMEOUT_MS);
    child.once("error", (error) => finish(rejectAgent, error));
    child.once("exit", (code) => code === 0 ? finish(resolveAgent, stdout.trim()) : finish(rejectAgent, new Error(`agent-browser ${args.join(" ")} failed: ${stderr || stdout}`)));
  });
}
function agent(args) {
  const task = agentQueue.then(() => runAgent(args));
  agentQueue = task.catch(() => undefined);
  return task;
}
function walletBootstrap(walletOrigin) {
  return `(function () {\n    var address = ${JSON.stringify(wallet.address)};\n    var provider = {\n      selectedAddress: address, chainId: "0x1",\n      request: async function (input) {\n        var method = input.method;\n        if (method === "eth_accounts" || method === "eth_requestAccounts") return [address];\n        if (method === "eth_chainId") return "0x1";\n        if (method === "wallet_getPermissions" || method === "wallet_requestPermissions") return [{ parentCapability: "eth_accounts" }];\n        if (method === "personal_sign") {\n          var params = input.params || [];\n          var raw = String(params.length > 0 ? params[0] : "");\n          var hex = raw.indexOf("0x") === 0 ? raw.slice(2) : null;\n          var octets = hex === null ? [] : (hex.match(/.{1,2}/g) || []).map(function (value) { return parseInt(value, 16); });\n          var message = hex === null ? raw : new TextDecoder().decode(new Uint8Array(octets));\n          var response = await fetch(${JSON.stringify(walletOrigin + "/sign")}, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: message }) });\n          if (!response.ok) throw new Error("deterministic wallet refused the signing request");\n          return (await response.json()).signature;\n        }\n        return null;\n      }, on: function () { return provider; }, removeListener: function () { return provider; }, isConnected: function () { return true; }\n    };\n    var announce = function () { window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" }, provider: provider } })); };\n    window.ethereum = provider;\n    window.addEventListener("eip6963:requestProvider", announce); announce();\n  })()`;
}
function walletBootstrapScript(walletOrigin) {
  return `(function () {
    var address = ${JSON.stringify(wallet.address)};
    var provider = {
      selectedAddress: address,
      chainId: "0x1",
      request: async function (input) {
        var method = input.method;
        if (method === "eth_accounts" || method === "eth_requestAccounts") return [address];
        if (method === "eth_chainId") return "0x1";
        if (method === "wallet_getPermissions" || method === "wallet_requestPermissions") return [{ parentCapability: "eth_accounts" }];
        if (method === "personal_sign") {
          var raw = String((input.params || [])[0] || "");
          var hex = raw.indexOf("0x") === 0 ? raw.slice(2) : null;
          var bytes = hex === null ? [] : (hex.match(/.{1,2}/g) || []).map(function (value) { return parseInt(value, 16); });
          var message = hex === null ? raw : new TextDecoder().decode(new Uint8Array(bytes));
          var response = await fetch(${JSON.stringify(walletOrigin + "/sign")}, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: message }) });
          if (!response.ok) throw new Error("deterministic wallet refused the signing request");
          return (await response.json()).signature;
        }
        return null;
      },
      on: function () { return provider; },
      removeListener: function () { return provider; },
      isConnected: function () { return true; }
    };
    var announced = false;
    var announce = function () {
      if (announced) return;
      announced = true;
      window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: {
        info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" },
        provider: provider
    } }));
    };
    Object.defineProperty(window, "ethereum", { configurable: true, writable: true, value: provider });
    window.addEventListener("eip6963:requestProvider", announce);
    setTimeout(announce, 10000);
  })()`;
}

/*
 * TC-340. Re-read the generated material with the pinned binary before
 * Postgres ever opens it. A repeated X.509 extension parses fine under the
 * toolchain that wrote it and is fatal under OpenSSL 3, so the only place this
 * can be caught cheaply is here, naming the binary and the certificate.
 */
function assertPostgresLoadableCertificates(openssl, certificates) {
  for (const [label, path] of Object.entries(certificates)) {
    let text;
    try {
      text = execFileSync(openssl.path, ["x509", "-in", path, "-noout", "-text"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (error) {
      throw new Error(tlsMaterialDiagnostic({ label, openssl, detail: `${path} could not be parsed back (${String(error?.stderr ?? (error instanceof Error ? error.message : error)).trim().slice(-400)})` }));
    }
    const duplicates = duplicateCertificateExtensions(text);
    if (duplicates.length > 0) throw new Error(tlsMaterialDiagnostic({ label, openssl, detail: `${path} repeats X.509 extension(s) ${duplicates.join(", ")}` }));
  }
  try {
    execFileSync(openssl.path, ["verify", "-CAfile", certificates["certificate authority"], certificates["server certificate"]], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    throw new Error(tlsMaterialDiagnostic({ label: "certificate chain", openssl, detail: `the server certificate does not verify against the harness CA (${String(error?.stderr ?? (error instanceof Error ? error.message : error)).trim().slice(-400)})` }));
  }
}

function assertPostgresAcceptsTls(openssl, postgresUrl, caCertPath) {
  try {
    execFileSync(join(postgresBin, "psql"), [postgresUrl, "-v", "ON_ERROR_STOP=1", "-tAc", "select 1"], {
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PGSSLROOTCERT: caCertPath, PGCONNECT_TIMEOUT: "10" },
    });
  } catch (error) {
    throw new Error(tlsMaterialDiagnostic({ label: "Postgres server", openssl, detail: `psql refused the sslmode=verify-full handshake (${String(error?.stderr ?? (error instanceof Error ? error.message : error)).trim().slice(-400)})` }));
  }
}

async function startFixtures(tempRoot) {
  const walletOrigin = await loopback("deterministic EIP-1193/EIP-6963 wallet", async (request, response) => {
    if (request.url !== "/sign") { response.writeHead(404).end(); return; }
    const caller = request.headers.origin;
    const cors = caller === canonical.share || /^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(caller ?? "") ? { "access-control-allow-origin": caller, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type, x-forwarded-proto", vary: "Origin" } : {};
    if (request.method === "OPTIONS") { response.writeHead(204, cors).end(); return; }
    if (request.method !== "POST") { response.writeHead(405, cors).end(); return; }
    const chunks = []; request.on("data", (chunk) => chunks.push(chunk)); request.on("end", async () => { try { const body = JSON.parse(Buffer.concat(chunks).toString()); const signature = await wallet.signMessage({ message: body.message }); response.writeHead(200, { ...cors, "content-type": "application/json" }).end(JSON.stringify({ address: wallet.address, signature })); } catch { response.writeHead(400, cors).end(); } });
  });
  const openKeyOrigin = await loopback("OpenKey managed-session/SIWE widget", (request, response) => {
    const cors = openKeyApiCors(request.headers.origin);
    if (request.method === "OPTIONS" && request.url === "/api/delegate/sign") { response.writeHead(204, cors).end(); return; }
    if (request.method === "GET" && request.url?.startsWith("/widget/")) {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(openKeyWidgetHtml(wallet.address));
      return;
    }
    if (request.method !== "POST" || (request.url !== "/sign" && request.url !== "/api/delegate/sign")) { response.writeHead(404).end(); return; }
    if (request.url === "/api/delegate/sign" && request.headers.authorization !== `Bearer ${OPENKEY_TEST_SESSION_TOKEN}`) { response.writeHead(401, cors).end(); return; }
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", async () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        if (typeof body.message !== "string" || body.message.length === 0) throw new Error("message missing");
        const signature = await wallet.signMessage({ message: body.message });
        response.writeHead(200, { ...cors, "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify({ signature }));
      } catch {
        response.writeHead(400, cors).end();
      }
    });
  });
  await writeFile(join(tempRoot, "registry-upload.key"), registryUploadSeed.toString("base64url"), { flag: "wx", mode: 0o600 });
  const registry = run("bun", ["packages/registry/src/production-server-cli.ts", "--port", "0"], shareRoot, {
    REGISTRY_AUTH_PUBLIC_KEY: registryUploadPublicKey,
    REGISTRY_LINK_UPLOAD_PUBLIC_KEY: registryUploadPublicKey,
  });
  let registryOrigin;
  const registryDeadline = Date.now() + 30_000;
  while (registryOrigin === undefined && Date.now() < registryDeadline) {
    const output = children.find((entry) => entry.child === registry)?.output() ?? "";
    registryOrigin = output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    if (registryOrigin === undefined) await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  if (registryOrigin === undefined) throw new Error("real Share registry did not publish a loopback URL");
  checks.push(`production Share registry with durable upload authorization started at ${registryOrigin}.`);

  const mailMessages = [];
  const mailReplays = [];
  let nextMailMessageId = 1;
  const mail = await loopback("Resend-compatible mail capture", (request, response) => {
    const traceId = `server-${runId}-${randomUUID()}`;
    serverTraceIds.push(traceId);
    // Reset is an exact control-plane route. Keep it ahead of the delivery
    // route so a reset can never be parsed as a provider message.
    if (request.method === "POST" && request.url === "/emails/reset") {
      mailMessages.length = 0;
      response.writeHead(204, { "x-tinycloud-trace-id": traceId }).end();
      return;
    }
    if (request.method === "POST" && request.url === "/emails") {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error("mail payload");
          const idempotencyKey = request.headers["idempotency-key"];
          const prior = typeof idempotencyKey === "string" ? mailMessages.find((message) => message.idempotencyKey === idempotencyKey) : undefined;
          if (prior !== undefined) {
            mailReplays.push({ idempotencyKey, originalId: prior.id, replayId: prior.id, traceId });
            const replayBody = JSON.stringify({ id: prior.id, replayed: true });
            response.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(replayBody), "x-tinycloud-trace-id": traceId }).end(replayBody);
            return;
          }
          const id = `hermetic-mail-${nextMailMessageId++}`;
          mailMessages.push({ id, idempotencyKey: typeof idempotencyKey === "string" ? idempotencyKey : undefined, payload: body });
          const acceptedBody = JSON.stringify({ id });
          response.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(acceptedBody), "x-tinycloud-trace-id": traceId }).end(acceptedBody);
        } catch {
          response.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid mail payload" }));
        }
      });
      return;
    }
    if (request.method === "GET" && request.url === "/emails") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store", "x-tinycloud-trace-id": traceId }).end(JSON.stringify({ messages: mailMessages }));
      return;
    }
    response.writeHead(404).end();
  });

  const postgresData = join(tempRoot, "postgres");
  const postgresPort = await freePort();
  await runOnce(join(postgresBin, "initdb"), ["-D", postgresData, "-A", "trust", "-U", postgresUser], shareRoot, { LC_ALL: "C" });
  const postgresTlsDir = join(tempRoot, "postgres-tls");
  await mkdir(postgresTlsDir, { recursive: true });
  const postgresCaKeyPath = join(postgresTlsDir, "ca.key");
  const postgresCaCertPath = join(postgresTlsDir, "ca.pem");
  const postgresServerKeyPath = join(postgresTlsDir, "server.key");
  const postgresServerCsrPath = join(postgresTlsDir, "server.csr");
  const postgresServerCertPath = join(postgresTlsDir, "server.crt");
  const postgresServerExtPath = join(postgresTlsDir, "server.ext");
  // TC-340. Pin the toolchain instead of taking whatever `openssl` PATH hands
  // us: an OpenSSL 1.1.1 build emits basicConstraints twice here and Postgres,
  // which links OpenSSL 3, then dies with an opaque `SSL error: invalid
  // certificate` two subprocesses away.
  const openssl = resolveOpensslBinary({ override: process.env[OPENSSL_OVERRIDE_ENV], probe: (path) => execFileSync(path, ["version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) });
  checks.push(`Harness TLS toolchain pinned to ${openssl.path} (${openssl.version.banner})${process.env[OPENSSL_OVERRIDE_ENV] === undefined ? "" : ` via ${OPENSSL_OVERRIDE_ENV}`}; ambient PATH openssl is never used.`);
  await runOnce(openssl.path, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", postgresCaKeyPath, "-out", postgresCaCertPath, "-days", "1", "-subj", "/CN=sharing-e2e-harness-ca", "-addext", "basicConstraints=critical,CA:true"], postgresTlsDir);
  await runOnce(openssl.path, ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", postgresServerKeyPath, "-out", postgresServerCsrPath, "-subj", `/CN=${POSTGRES_TLS_HOSTNAME}`], postgresTlsDir);
  await writeFile(postgresServerExtPath, postgresServerCertExtensionFile(), { flag: "wx" });
  await runOnce(openssl.path, ["x509", "-req", "-in", postgresServerCsrPath, "-CA", postgresCaCertPath, "-CAkey", postgresCaKeyPath, "-CAcreateserial", "-out", postgresServerCertPath, "-days", "1", "-extfile", postgresServerExtPath], postgresTlsDir);
  await chmod(postgresServerKeyPath, 0o600);
  assertPostgresLoadableCertificates(openssl, { "certificate authority": postgresCaCertPath, "server certificate": postgresServerCertPath });
  const postgres = run(join(postgresBin, "postgres"), ["-D", postgresData, "-h", "127.0.0.1,::1", "-p", String(postgresPort), "-c", "unix_socket_directories=", "-c", "ssl=on", "-c", `ssl_cert_file=${postgresServerCertPath}`, "-c", `ssl_key_file=${postgresServerKeyPath}`, "-c", `ssl_ca_file=${postgresCaCertPath}`], shareRoot, { PGUSER: postgresUser });
  await waitForTcp(postgresPort, 30_000, postgres);
  const postgresUrl = postgresConnectionUrl({ user: postgresUser, host: POSTGRES_TLS_HOSTNAME, port: postgresPort, database: "postgres" });
  // The certificate is only genuinely good if the *database* accepts it, so
  // complete one verify-full handshake here rather than discovering the
  // problem inside migrate.sh with no mention of openssl anywhere.
  assertPostgresAcceptsTls(openssl, postgresUrl, postgresCaCertPath);
  checks.push(`hermetic verify-full TLS Postgres persistence started from ${postgresBin} on ${POSTGRES_TLS_HOSTNAME}:${postgresPort} and completed a verify-full handshake against the pinned harness CA.`);

  let policyEngineOrigin;
  let policyEngine;
  if (tc500Joined) {
    const policyPort = await freePort();
    const policyConfigPath = join(tempRoot, "policy-engine.json");
    await writeFile(policyConfigPath, JSON.stringify({
      audience: canonical.policy,
      challengeTtlSeconds: 300,
      acceptedSuites: ["eddsa-ed25519-sha256-jcs-v1"],
      challengeSignerSeedBase64Url: Buffer.alloc(32, 73).toString("base64url"),
      grantIssuerDid: policyGrantIssuerDid,
      grantIssuerSignerSeedBase64Url: policyGrantSeed.toString("base64url"),
      parentDelegations: [],
      issuerKeys: {
        "did:web:issuer.credentials.org": {
          params: { OKP: { public_key: [...ed25519.getPublicKey(issuerSeed)] } },
        },
      },
      signedObjects: [],
      demoOperationsEnabled: false,
      demoOperationsBearerToken: null,
    }), { flag: "wx", mode: 0o600 });
    await runOnce("cargo", ["build", "--quiet", "-p", "policy-engine-http"], policyEngineRoot);
    const policyBinary = join(policyEngineRoot, "target/debug/policy-engine-http");
    policyEngine = run(policyBinary, [], policyEngineRoot, {
      POLICY_ENGINE_HTTP_CONFIG: policyConfigPath,
      POLICY_ENGINE_HTTP_BIND: `127.0.0.1:${policyPort}`,
    });
    policyEngineOrigin = `http://127.0.0.1:${policyPort}`;
    await waitFor(`${policyEngineOrigin}/policy/v0/challenge`, 60_000, policyEngine);
    const policyCors = await fetch(`${policyEngineOrigin}/policy/v0/challenge`, { method: "OPTIONS", headers: { origin: canonical.share, "access-control-request-method": "POST", "access-control-request-headers": "content-type" } });
    assert.equal(policyCors.status, 200, "Policy Engine browser CORS preflight failed");
    assert(["*", canonical.share].includes(policyCors.headers.get("access-control-allow-origin")), "Policy Engine did not allow the Share browser origin");
    await recordArtifactDigest("policyEngineRuntime", policyBinary);
    checks.push(`real standalone Policy Engine started at ${policyEngineOrigin} with its grant and delivery signer pinned.`);
  }

  const nodePort = await freePort();
  const nodeKeysSecretB64 = nodeKeysSecret.toString("base64url");
  // This composition deliberately injects deterministic issuer and node keys.
  // `mounted-fixture` is Node's explicit guard for accepting that material;
  // `local-tee` only supplies the local key-derived TeeContext and correctly
  // leaves the production trust-bundle placeholder rejection enabled.
  await runOnce("cargo", ["build", "--quiet", "-p", "tinycloud-node", "--features", "local-tee,mounted-fixture"], nodeRoot, { TINYCLOUD_KEYS_SECRET: nodeKeysSecretB64 });
  const nodeBinaryPath = join(nodeRoot, "target/debug/tinycloud");
  // Export the public invitation descriptor before launch (it only needs the
  // key material, not a running server) so the canonical trust bundle can be
  // written to disk and handed to Node's own boot via
  // TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_PATH, instead of trusting the node
  // to describe itself after the fact. The exporter reports its own
  // deployment audience (e.g. did:web:tee.node.tinycloud.xyz), which can
  // differ from the audience actually enrolled in the trust bundle below —
  // only nodeInvitationPublicKey is taken from it; the enforcer DID is
  // always read back from the trust bundle Node was actually launched with.
  const nodePublic = tc500Joined
    ? { nodeInvitationPublicKey: Buffer.from(ed25519.getPublicKey(Buffer.alloc(32, 77))).toString("base64url") }
    : JSON.parse(execFileSync(join(nodeRoot, "target/debug/export-share-invitation-descriptor"), [], { cwd: nodeRoot, env: { ...process.env, TINYCLOUD_KEYS_SECRET: nodeKeysSecretB64 }, encoding: "utf8" }));
  const trustBundlePath = join(resolve(tempRoot), "node-trust-bundle.json");
  const nodeTrustBundleJson = trustBundleFromRuntime(nodePublic.nodeInvitationPublicKey);
  await writeFile(trustBundlePath, nodeTrustBundleJson, { flag: "wx" });
  const node = run(nodeBinaryPath, [], nodeRoot, { TMPDIR: tempRoot, RUST_LOG: "error", TINYCLOUD_KEYS_SECRET: nodeKeysSecretB64, ROCKET_ADDRESS: "127.0.0.1", ROCKET_PORT: String(nodePort), ...(tc500Joined ? { TINYCLOUD_STORAGE__DATADIR: join(tempRoot, "node-data") } : buildNodeLaunchEnv(tempRoot, trustBundlePath)) });
  const nodeOrigin = `http://127.0.0.1:${nodePort}`;
  await waitFor(`${nodeOrigin}/${tc500Joined ? "info" : "share/v2/readiness"}`, 180_000, node);
  const nodeEnforcerAudience = nodeEnforcerAudienceFromTrustBundle(nodeTrustBundleJson);
  await recordArtifactDigest("nodeRuntime", nodeBinaryPath);
  checks.push(`real Node production router/persistence started at ${nodeOrigin}.`);
  const nodeInfo = await (await fetch(`${nodeOrigin}/info`)).json();
  let nodeEnforcerDid = nodeEnforcerAudience;
  if (tc500Joined) {
    checks.push("real unmodified current-main Node started for generic /delegate and /invoke; the browser trace is the authority proving zero /share/* requests.");
  } else {
    const readiness = await (await fetch(`${nodeOrigin}/share/v2/readiness`)).json();
    const readinessChecks = Object.fromEntries(Object.entries(readiness.checks ?? {}).map(([key, value]) => [key, value === true]));
    if (readiness.ready !== true || Object.values(readinessChecks).some((value) => value !== true)) throw new Error(`real Node v2 readiness incomplete: ${JSON.stringify({ ready: readiness.ready, checks: readinessChecks })}`);
    const shareV2Capability = assertNodeShareV2Capability(nodeInfo);
    nodeEnforcerDid = shareV2Capability.enforcerDid;
    checks.push(`real Node v2 readiness ${JSON.stringify({ ready: true, checks: readinessChecks })}.`);
  }
  const nodeDescriptor = { url: nodeOrigin, nodeId: nodeEnforcerAudience, enforcerDid: nodeEnforcerDid, trustedNode: { invitationPublicKey: nodePublic.nodeInvitationPublicKey } };

  await runOnce("cargo", ["build", "--quiet", "--manifest-path", credentialsManifest, "--bin", "opencredentials-witness", "--features", "dstack"], credentialsRoot);
  const readinessFile = join(tempRoot, "share-email-readiness.json");
  const migrationsDir = join(credentialsRoot, "deploy/share-email/migrations");
  const migrationEnv = buildMigrationEnv({ postgresUrl, postgresCaCert: postgresCaCertPath, migrationsDir, readinessFile });
  await runOnce(join(credentialsRoot, "scripts/oi-share-email/migrate.sh"), [], credentialsRoot, migrationEnv);
  await runOnce(join(credentialsRoot, "scripts/oi-share-email/readiness-check.sh"), [], credentialsRoot, migrationEnv);
  checks.push(`share-email durable-postgres migrations applied and readiness-check.sh passed against ${migrationsDir}.`);

  const dstackSocketPath = join(tempRoot, "dstack.sock");
  const dstackServer = netServer((socket) => {
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const parsed = parseDstackRequest(buffered);
      if (parsed === undefined) return;
      socket.end(formatHttpResponse(buildDstackResponsePayload(parsed.path, parsed.body, issuerSeed) ?? {}));
    });
  });
  dstackServer.listen(dstackSocketPath);
  await once(dstackServer, "listening");
  servers.push(dstackServer);
  checks.push(`harness-owned dstack Unix-socket simulator listening at ${dstackSocketPath}.`);

  const credentialsBinaryPath = join(credentialsRoot, "rust/opencredentials_witness/target/debug/opencredentials-witness");
  const credentialsPort = await freePort();
  const credentialsTrustBundleJson = credentialsTrustBundleFromRuntime(nodeDescriptor.trustedNode?.invitationPublicKey);
  assert.equal(
    JSON.parse(credentialsTrustBundleJson).issuerPublicKey,
    JSON.parse(nodeTrustBundleJson).issuerPublicKey,
    "OpenCredentials trust bundle issuer key must equal the canonical Node trust bundle key",
  );
  assert.equal(
    JSON.parse(credentialsTrustBundleJson).nodeAudience,
    nodeDescriptor.nodeId,
    "OpenCredentials trust bundle nodeAudience must equal the canonical enrolled Node enforcer audience",
  );
  const credentialsLaunchEnv = buildCredentialsLaunchEnv({
    tempRoot, credentialsPort, corsOrigin: canonical.share, dstackSocket: dstackSocketPath, didWeb: "did:web:issuer.credentials.org",
    trustBundleJson: credentialsTrustBundleJson, shareUrl: canonical.share, resendApiKey: `re_${"a".repeat(32)}`, resendWebhookSecret: "whsec_AAAAAAAAAAAAAAAAAAAAAAAA",
    resendEndpoint: `${mail}/emails`, postgresUrl, postgresCaCert: postgresCaCertPath, migrationsDir, readinessFile,
  });
  if (tc500Joined) Object.assign(credentialsLaunchEnv, {
    CREDENTIAL_ACQUISITION_EMAIL_CAPABILITY: "true",
    CREDENTIAL_INVITATION_CAPABILITY: "true",
    CREDENTIAL_INVITATION_POLICY_ENGINE_DIDS: JSON.stringify([policyGrantIssuerDid]),
    CREDENTIAL_INVITATION_RETURN_ORIGINS: canonical.share,
    CREDENTIAL_INVITATION_AUDIENCE: canonical.credentials,
  });
  const credentials = run(credentialsBinaryPath, [], credentialsRoot, credentialsLaunchEnv);
  const credentialsOrigin = `http://127.0.0.1:${credentialsPort}`;
  await recordArtifactDigest("openCredentialsRuntime", credentialsBinaryPath);
  const credentialsCapabilityId = "tinycloud.share-email-claim";
  const credentialsDeadline = Date.now() + 60_000;
  let credentialsReady = false;
  while (Date.now() < credentialsDeadline) {
    try {
      const response = await fetch(`${credentialsOrigin}/share-email/readiness`);
      const body = await response.json().catch(() => null);
      assertCredentialsReadinessBody(response.status, body, credentialsCapabilityId);
      credentialsReady = true;
      break;
    } catch {}
    if (credentials.exitCode !== null) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  if (!credentialsReady) {
    const rawOutput = children.find((entry) => entry.child === credentials)?.output() ?? "";
    throw new Error(`OpenCredentials readiness did not become ready: ${redactSecrets(rawOutput.slice(-4000), [credentialsLaunchEnv.RESEND_API_KEY, credentialsLaunchEnv.RESEND_WEBHOOK_SECRET])}`);
  }
  if (tc500Joined) {
    const invitationCors = await fetch(`${credentialsOrigin}/v1/credential-invitations`, { method: "OPTIONS", headers: { origin: canonical.share, "access-control-request-method": "POST", "access-control-request-headers": "content-type" } });
    assert.equal(invitationCors.status, 200, "OpenCredentials invitation browser CORS preflight failed");
    assert.equal(invitationCors.headers.get("access-control-allow-origin"), canonical.share, "OpenCredentials did not allow the Share browser origin");
  }
  checks.push(`real OpenCredentials production router/store (dstack-derived issuer key, durable verify-full Postgres) started at ${credentialsOrigin}.`);
  return { walletOrigin, openKeyOrigin, registryOrigin, nodeOrigin: nodeDescriptor.url, nodeDescriptor, credentialsOrigin, policyEngineOrigin, mailOrigin: mail, mailMessages, mailReplays };
}

/*
 * TC-306 hard guard. Runs test/e2e-sharing/assert-loopback-upstreams.ts, which
 * calls the *production* resolveShareUpstreams/upstreamForPath against the
 * exact trust bundle and the exact launch env the Share host is about to
 * receive, and refuses to continue unless every proxied route lands on
 * loopback. Fail loudly here, before a single browser request is made: a
 * harness that silently proxies to production is worse than no harness.
 */
function assertLoopbackShareUpstreams(launchEnv) {
  let stdout;
  try {
    stdout = execFileSync(join(shareRoot, "node_modules/.bin/tsx"), [join(shareRoot, "test/e2e-sharing/assert-loopback-upstreams.ts")], {
      cwd: shareRoot, encoding: "utf8", env: { ...process.env, ...launchEnv }, stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const detail = `${String(error?.stderr ?? "")}${String(error?.stdout ?? "")}`.trim();
    throw new Error(`Share host upstream routing gate failed: ${detail.length > 0 ? detail.slice(-2000) : error instanceof Error ? error.message : String(error)}`);
  }
  const audit = JSON.parse(stdout);
  checks.push(`Share host upstream routing gate resolved every proxied path to loopback through the production resolver: ${JSON.stringify(audit.upstreams)} from production bundle origins ${JSON.stringify(audit.bundleOrigins)}.`);
  return { allLoopback: true, upstreams: audit.upstreams, bundleOrigins: audit.bundleOrigins, routes: audit.routes };
}

async function startShare(tempRoot, fixtures) {
  const sdkRoot = resolveJsSdkWorktree(process.env, workspaceRoot);
  const expectedSdkLink = assertWebSdkLink(shareRoot, sdkRoot);
  await runOnce("npm", ["run", "build"], sdkRoot);
  await stat(join(expectedSdkLink, "dist/index.mjs"));
  await recordArtifactDigest("jsSdkWebRuntime", join(expectedSdkLink, "dist/index.mjs"));
  checks.push(`Share dependency resolved to the built js-sdk worktree at ${expectedSdkLink}.`);
  const port = await freePort();
  const trustPath = join(tempRoot, "trust.json");
  const origin = `http://127.0.0.1:${port}`;
  const shareTrustBundleJson = trustBundleFromRuntime(fixtures.nodeDescriptor.trustedNode?.invitationPublicKey);
  assert.equal(
    JSON.parse(shareTrustBundleJson).nodeAudience,
    fixtures.nodeDescriptor.nodeId,
    "Share trust bundle nodeAudience must equal the canonical enrolled Node enforcer audience used for SHARE_NODE_ENFORCER_DID",
  );
  await writeFile(trustPath, shareTrustBundleJson, { flag: "wx" });
  assert.deepEqual(
    { node: JSON.parse(shareTrustBundleJson).nodeOrigin, credentials: JSON.parse(shareTrustBundleJson).credentialsOrigin, registry: JSON.parse(shareTrustBundleJson).registryOrigin },
    { node: canonical.node, credentials: canonical.credentials, registry: canonical.registry },
    "hermetic upstream routes must name the exact canonical origins the Share trust bundle carries",
  );
  // The shipped viewer consumes the registry client through a same-origin
  // proxy in production; point the production-shaped build at that proxy so
  // browser CSP and the zero-external-destination audit observe the same path.
  const browserBuildEnv = buildShareBrowserBuildEnv(origin, fixtures.openKeyOrigin);
  if (tc465Joined) {
    browserBuildEnv.VITE_SHARE_REGISTRY_URL = `${canonical.share}/registry`;
    browserBuildEnv.VITE_OPENKEY_ORIGIN = "https://openkey.so";
  }
  await runOnce("npm", ["run", "build"], shareRoot, browserBuildEnv);
  const shareAsset = execFileSync("find", [join(shareRoot, "dist/assets"), "-maxdepth", "1", "-name", "main-*.js", "-print"], { encoding: "utf8" }).trim().split("\n")[0];
  if (!shareAsset) throw new Error("Share build did not produce its main browser bundle");
  await recordArtifactDigest("shareBundle", shareAsset);
  const shareLaunchEnv = buildShareHostLaunchEnv({
    host: "127.0.0.1", port, trustBundlePath: trustPath, registryUploadKeyPath: join(tempRoot, "registry-upload.key"), nodeEnforcerDid: fixtures.nodeDescriptor.enforcerDid,
    openKeyOrigin: fixtures.openKeyOrigin, walletOrigin: fixtures.walletOrigin, shareOrigin: origin, registryOrigin: fixtures.registryOrigin,
    canonicalOrigins: { credentials: canonical.credentials, node: canonical.node, registry: canonical.registry },
    nodeTransportOrigin: fixtures.nodeOrigin, credentialsTransportOrigin: fixtures.credentialsOrigin,
    ...(tc500Joined ? { policyEngineCanonicalOrigin: canonical.policy, policyEngineTransportOrigin: fixtures.policyEngineOrigin } : {}),
    ...(tc465Joined ? { senderBindingStore: { root: tempRoot, path: join(tempRoot, "bindings.ndjson") } } : {}),
  });
  // The joined browser keeps the production OpenKey URL and transports it to
  // the loopback widget through interception. Omitting the loopback-only CSP
  // seam selects securityHeadersForPath's production https://openkey.so
  // frame-src instead of authorizing a mixed-content HTTP frame.
  if (tc465Joined) delete shareLaunchEnv.SHARE_HERMETIC_OPENKEY_ORIGIN;
  if (tc500Joined) shareLaunchEnv.SHARE_ACCOUNTLESS_RECEIVER_ENABLED = "true";
  upstreamRoutingAudit = assertLoopbackShareUpstreams(shareLaunchEnv);
  const share = run("npm", ["run", "start:deploy"], shareRoot, shareLaunchEnv);
  await waitFor(`${origin}/health/readiness`, 60_000, share);
  const registryKeyResponse = await fetch(`${origin}/api/share/link-only/registry/public-key`, { headers: { "x-forwarded-proto": "https" } });
  assert.equal(registryKeyResponse.status, 200, "Share host did not publish its registry upload public key");
  assert.equal((await registryKeyResponse.json()).publicKey, registryUploadPublicKey, "Share host and production registry upload keys differ");
  checks.push(`committed production Share host started on loopback at ${origin} with a production trust bundle.`);
  return { origin, share };
}

function networkEntries(value) {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  return Array.isArray(parsed) ? parsed : Array.isArray(parsed?.data) ? parsed.data : parsed?.data?.requests ?? [];
}

async function installBrowserTelemetry() {
  // The routing/Request-semantics logic below is not reimplemented here: it
  // is injected verbatim (via Function.prototype.toString()) from
  // routeTelemetryFetchArgs, which is unit tested directly in Node against
  // the same fetch/Request/Headers/URL globals the browser provides.
  const routeTelemetryFetchArgsSource = routeTelemetryFetchArgs.toString();
  const normalizeTelemetryFetchArgsSource = normalizeTelemetryFetchArgs.toString();
  await agent(["eval", `(function(){if(window.__tinycloudTelemetryInstalled)return;var original=window.fetch;var nodeOrigin=${JSON.stringify(canonical.node)};var credentialsOrigin=${JSON.stringify(canonical.credentials)};var routeTelemetryFetchArgs=${routeTelemetryFetchArgsSource};var normalizeTelemetryFetchArgs=${normalizeTelemetryFetchArgsSource};window.__tinycloudTelemetry=[];window.__tinycloudTelemetryInstalled=true;window.fetch=async function(input,init){var fetchStartTime=performance.now();var isRequestInput=typeof Request!=='undefined'&&input instanceof Request;var method=isRequestInput?(init&&init.method)||input.method:(init&&init.method)||'GET';var browserTraceId=crypto.randomUUID();var requestBodyPromise=method==='POST'&&input&&typeof input.clone==='function'?input.clone().text().catch(function(){return ''; }):Promise.resolve(typeof init?.body==='string'?init.body:'');var routedResult=routeTelemetryFetchArgs(input,init,{nodeOrigin:nodeOrigin,credentialsOrigin:credentialsOrigin,currentOrigin:window.location.origin});var routed=routedResult.url;var normalized=normalizeTelemetryFetchArgs(routedResult.fetchArgs);var delegateByteLength=0;var delegateDigest=null;var delegateDigestAvailable=false;if(method==='POST'&&routed.endsWith('/delegate')){try{var delegateArrayBuf=await normalized.request.clone().arrayBuffer();var delegateBytes=new Uint8Array(delegateArrayBuf);delegateByteLength=delegateBytes.byteLength;if(delegateByteLength>0){var delegateHashBuf=await crypto.subtle.digest('SHA-256',delegateBytes);delegateDigest=Array.from(new Uint8Array(delegateHashBuf)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');delegateDigestAvailable=true;}}catch(e){}}var authorizationPresent=false;var authorizationDigest=null;var authorizationDigestAvailable=false;if(routed.endsWith('/delegate')){var authHeader=normalized.request.headers.get('authorization');authorizationPresent=typeof authHeader==='string'&&authHeader.length>0;if(authorizationPresent){try{var authBytes=new TextEncoder().encode(authHeader);var authHashBuf=await crypto.subtle.digest('SHA-256',authBytes);authorizationDigest=Array.from(new Uint8Array(authHashBuf)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');authorizationDigestAvailable=true;}catch(e){}}}try{var response=await original.apply(window,normalized.fetchArgs);var item={url:routed,method:routedResult.method,status:response.status,requestId:browserTraceId,serverTraceId:response.headers.get('x-tinycloud-trace-id')};if(method==='POST'&&routed.endsWith('/invoke')){var bodyText=await requestBodyPromise;item.requestSpaces=[...new Set(bodyText.match(/tinycloud:[^\"' ]+/g)||[])];}if(method==='POST'&&routed.endsWith('/delegate')){item.requestBodyLength=delegateByteLength;item.requestDigestAvailable=delegateDigestAvailable;if(delegateDigestAvailable&&delegateDigest!==null){item.requestBodyDigest=delegateDigest;}item.authorizationPresent=authorizationPresent;item.authorizationDigestAvailable=authorizationDigestAvailable;if(authorizationDigestAvailable&&authorizationDigest!==null){item.authorizationDigest=authorizationDigest;}}if((!response.ok&&method==='POST')||(method==='POST'&&routed.endsWith('/delegate'))||(method==='POST'&&routed.endsWith('/invoke'))||(method==='POST'&&routed.endsWith('/policies'))){try{var clone=response.clone();var text=await clone.text();var parsedBody=null;try{parsedBody=JSON.parse(text);}catch{}if(routed.endsWith('/policies')){item.responseKeys=parsedBody&&typeof parsedBody==='object'?Object.keys(parsedBody).sort():[];item.responseErrorCode=parsedBody&&parsedBody.error&&typeof parsedBody.error==='object'?parsedBody.error.code||null:null;}if(routed.endsWith('/delegate'))item.responseBody=text.slice(0,1200);if(routed.endsWith('/invoke')){item.responseContentType=response.headers.get('content-type');item.responseBodyLength=text.length;item.responseBodyPreview=text.slice(0,240);}try{item.errorCode=parsedBody&&parsedBody.error?.code||null;}catch{item.errorCode=null;if(!response.ok)item.errorBody=text.slice(0,500);}}catch{item.errorCode=null;}}var pushTime=performance.now();item.fetchStartTime=fetchStartTime;item.pushTime=pushTime;window.__tinycloudTelemetry.push(item);return response;}catch(error){var pushTime=performance.now();window.__tinycloudTelemetry.push({url:routed,method:method,status:0,requestId:browserTraceId,fetchStartTime:fetchStartTime,pushTime:pushTime});throw error;}};})()`]);
}

/*
 * TC-339, enforcement half. See test/e2e-sharing/loopback-transport.mjs for
 * why the authority host must stay canonical while the transport must not.
 *
 * These routes live on the Playwright page, not in the page's JavaScript
 * realm, so they survive every navigation, cover subframes and non-fetch
 * transports, and hold whether or not the application cooperates. Their only
 * job is to make an escape impossible rather than merely improbable: after
 * this call, no request naming a canonical production origin can leave the
 * machine, and one that tries fails at the exact call site instead of quietly
 * succeeding against production.
 */
async function installLoopbackTransportGuard() {
  for (const pattern of loopbackTransportAbortPatterns(canonical)) await agent(["network", "route", pattern, "--abort"]);
  checks.push(`Loopback transport guard aborts every browser request to ${loopbackTransportAbortPatterns(canonical).join(", ")} at the browser network layer, so hermeticity no longer depends on a page-realm shim surviving navigation.`);
}

/*
 * TC-339, routing half. Navigation discards the page realm and with it the
 * fetch shim that rewrites the canonical node/credentials origins onto the
 * loopback Share host. Every navigation in this harness goes through here so
 * that reinstalling the shim is part of navigating rather than something six
 * of seven call sites forgot to do.
 */
async function navigate(url, settleMs) {
  await agent(["open", url]);
  if (settleMs !== undefined) await agent(["wait", String(settleMs)]);
  await installBrowserTelemetry();
  assertRoutingShimInstalled(await agent(["eval", "window.__tinycloudTelemetryInstalled === true"]), url);
}

/** Same contract for the in-page navigations the recipient flow performs. */
async function navigateInPage(href, settleMs = 1500) {
  await agent(["eval", `location.href=${JSON.stringify(href)}`]);
  await agent(["wait", String(settleMs)]);
  await installBrowserTelemetry();
  assertRoutingShimInstalled(await agent(["eval", "window.__tinycloudTelemetryInstalled === true"]), href);
}

async function browserTelemetryEntries() {
  try {
    const entries = networkEntries(await agent(["eval", "JSON.stringify((window.__tinycloudTelemetry&&window.__tinycloudTelemetry.length>0)?window.__tinycloudTelemetry:performance.getEntriesByType('resource').map(function(entry,index){return {url:entry.name,method:'GET',status:200,requestId:'performance-'+index}}))"]));
    if (entries.length > 0) return entries;
    return [{ url: await agent(["get", "url"]), method: "GET", status: 200, requestId: `browser-navigation-${randomUUID()}` }];
  } catch { return []; }
}

function scrubNetwork(entries) {
  return entries.map((entry, index) => {
    let parsed;
    try { parsed = new URL(entry.url); } catch { parsed = undefined; }
    return {
      method: typeof entry.method === "string" ? entry.method : entry.request?.method,
      path: parsed === undefined ? "[invalid-url]" : parsed.pathname,
      origin: parsed === undefined ? "[invalid-origin]" : parsed.origin,
      status: Number.isInteger(entry.status) ? entry.status : entry.response?.status,
      browserTraceId: entry.requestId ?? entry.traceId ?? entry.request?.requestId ?? entry.response?.requestId ?? (Number.isFinite(entry.timestamp) ? `browser-${entry.timestamp}-${index}` : null),
    };
  });
}

async function beginFlow(name) {
  const traceId = `${name}-${randomUUID()}`;
  await agent(["network", "requests", "--clear"]);
  await agent(["eval", `window.__tinycloudTelemetry=[];performance.clearResourceTimings?.();window.__tinycloudSharingFlowTraceId=${JSON.stringify(traceId)}`]);
  return traceId;
}

async function auditFlow(name, traceId, options = {}) {
  const trackedNetwork = options.networkEntries ?? networkEntries(await agent(["network", "requests", "--json"]));
  const network = trackedNetwork.length > 0 ? trackedNetwork : await browserTelemetryEntries();
  if (network.length === 0) throw new Error(`${name} network capture is missing`);
  // The harness-generated flow ID is carried into the page before each flow;
  // browser request IDs below provide the observed per-flow browser trace.
  let mailTraceId = null;
  let messages = [];
  const mailDeadline = Date.now() + (options.expectMail === true ? 5_000 : 0);
  do {
    const mailResponse = await fetch(`${options.mailOrigin}/emails`, { cache: "no-store" });
    mailTraceId = mailResponse.headers.get("x-tinycloud-trace-id");
    const mailState = await mailResponse.json();
    messages = Array.isArray(mailState.messages) ? mailState.messages : [];
    const expectedRecipientObserved = options.expectMailRecipient === undefined || messages.some((message) => stringsIn(message?.payload).includes(options.expectMailRecipient));
    if (options.expectMail !== true || (messages.length > 0 && expectedRecipientObserved)) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  } while (Date.now() < mailDeadline);
  if (mailTraceId === null || mailTraceId.length === 0) throw new Error(`${name} server trace id was not captured`);
  const capturedMail = options.expectMailRecipient === undefined ? messages.at(-1) : messages.find((message) => stringsIn(message?.payload).includes(options.expectMailRecipient));
  const capturedMailId = capturedMail?.id ?? null;
  if (options.expectMail === true && capturedMailId === null) throw new Error(`${name} captured-mail ID is missing`);
  const sanitized = scrubNetwork(network);
  const telemetry = JSON.stringify(sanitized);
  const dynamicSecretTelemetry = {
    claimSecret: !telemetry.includes("claimSecret"),
    authorityHandle: !["amh_sql_001", "amh_kv_001", "SHARE_SENDER_PRIVATE_KEY"].some((secret) => telemetry.includes(secret)),
    piiInUrls: !(options.pii ?? []).some((pii) => telemetry.includes(pii)),
  };
  assert.equal(Object.values(dynamicSecretTelemetry).every(Boolean), true, `${name} telemetry leaked a secret, authority handle, or dynamic PII`);
  const browserTraceIds = sanitized.map((entry) => entry.browserTraceId).filter((value) => typeof value === "string" && value.length > 0);
  if (browserTraceIds.length === 0) throw new Error(`${name} browser request trace IDs are missing`);
  const replayEvidence = options.replayEvidence ?? { attempted: false, accepted: false };
  if (options.requireReplay === true && (!replayEvidence.attempted || !replayEvidence.accepted)) throw new Error(`${name} idempotency replay evidence is missing`);
  flowAudits.push({ name, browserTraceIds, serverTraceIds: [mailTraceId], capturedMailId, idempotencyReplay: replayEvidence, dynamicSecretTelemetry });
  checks.push(`${name} complete network audit captured sanitized browser/server trace IDs, captured-mail ${capturedMailId ?? "none"}, idempotency replay evidence, and dynamic secret/PII telemetry.`);
  return { messages, capturedMail, sanitized };
}

function stringsIn(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (value !== null && typeof value === "object") return Object.values(value).flatMap(stringsIn);
  return [];
}

function mailShareUrl(message) {
  const values = stringsIn(message).flatMap((candidate) => [...candidate.matchAll(/https:\/\/share\.tinycloud\.xyz\/s\/[^\s"'<>]+/g)].map((match) => match[0]));
  const value = values.sort((left, right) => Number(right.includes("?i=") && right.includes("#k=")) - Number(left.includes("?i=") && left.includes("#k=")) || right.length - left.length)[0];
  if (value === undefined) throw new Error("captured mail did not contain the exact generated Share URL");
  return value.replaceAll("&amp;", "&");
}

function localShareUrl(value, origin) {
  const url = new URL(value);
  url.protocol = "http:";
  url.host = new URL(origin).host;
  return url.href;
}

function agentString(value) {
  let current = value;
  for (let unwrap = 0; unwrap < 4 && typeof current === "string"; unwrap += 1) {
    try {
      const parsed = JSON.parse(current);
      if (typeof parsed !== "string") return parsed;
      current = parsed;
    } catch {
      break;
    }
  }
  return current;
}

/*
 * TC-344. Selecting a library option used to be
 * `agent([... kv-source ...]).catch(() => undefined)`. When the select had no
 * options the in-page `s.selectedIndex = 0` threw a TypeError on null, the
 * agent call rejected, and the rejection was discarded — so the run continued
 * with nothing selected and failed sixty seconds later waiting for unrelated
 * text ("Your private link is ready"). The cause was two flows away from the
 * symptom.
 *
 * Every library selection now goes through here. The select must exist, it
 * must have options, and the chooser must match one; each is a distinct,
 * immediate, located failure that names what the library actually offered.
 *
 * `chooser` is the source of a JS function `(options) => option | undefined`
 * evaluated in the page.
 */
async function waitForLibraryOptions(label, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const count = agentString(await agent(["eval", "JSON.stringify((function(){var select=document.querySelector('select[name=kv-source]');return select===null?-1:select.options.length})())"]));
    if (count === -1) throw new Error(`library select is not present while selecting ${label}; the library panel was never shown`);
    if (typeof count === "number" && count > 0) return count;
    if (Date.now() >= deadline) throw new Error(`library select never offered an option for ${label} within ${timeoutMs}ms: the sender's own space listing produced nothing to share`);
    await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  }
}

async function selectLibraryOption(chooser, label) {
  await waitForLibraryOptions(label);
  const script = `JSON.stringify((function(){var select=document.querySelector('select[name=kv-source]');if(select===null)throw new Error('library select is not present');var options=[].slice.call(select.options);var chosen=(${chooser})(options);if(!chosen)throw new Error('the library offers no ' + ${JSON.stringify(label)} + '; options=' + JSON.stringify(options.map(function(option){return {value:option.value,kind:option.dataset.resourceKind||null}})));select.value=chosen.value;select.dispatchEvent(new Event('change',{bubbles:true}));return chosen.value})())`;
  const value = agentString(await agent(["eval", script]));
  if (typeof value !== "string" || value.length === 0) throw new Error(`library selection for ${label} returned no path`);
  return value;
}

function safeBrowserDiagnostic(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    const normalized = value.toLowerCase();
    const category = normalized.includes("signature") ? "signature"
      : normalized.includes("cid") ? "cid"
      : normalized.includes("canonical") || normalized.includes("timestamp") || normalized.includes("expired") ? "canonical-registration"
      : normalized.includes("chain") || normalized.includes("bound") ? "registration-binding"
      : normalized.includes("policy_registration_invalid") || normalized.includes("policy") ? "policy"
      : normalized.includes("capability") ? "capability"
      : normalized.includes("config") ? "config"
      : normalized.includes("auth") || normalized.includes("session") ? "auth"
      : normalized.includes("enforcer") || normalized.includes("did:") ? "identity"
      : normalized.includes("invoke") || normalized.includes("delegate") ? "authorization"
      : normalized.includes("permission") ? "permission"
      : normalized.includes("sign") ? "sign-in"
      : normalized.includes("space") ? "space"
      : normalized.includes("library") ? "library"
      : normalized.includes("network") ? "network"
      : normalized.includes("invalid") ? "invalid"
      : normalized.includes("failed") || normalized.includes("failure") ? "failure"
      : "other";
    return { length: value.length, category };
  }
  if (typeof value !== "object") return { type: typeof value };
  const object = value;
  const message = typeof object.message === "string" ? object.message : typeof object.error === "string" ? object.error : undefined;
  return { type: Array.isArray(value) ? "array" : "object", message: message === undefined ? undefined : safeBrowserDiagnostic(message) };
}

async function browserGate(origin, walletOrigin, mailOrigin, nodeOrigin) {
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  assert.deepEqual((await (await fetch(`${mailOrigin}/emails`)).json()).messages, []);
  await navigate(`${origin}/share.html`);
  await installLoopbackTransportGuard();
  await agent(["set", "headers", JSON.stringify({ "X-Forwarded-Proto": "https" })]);
  await agent(["eval", "document.querySelector('.auth-button')?.disabled === false"]);
  await agent(["eval", "window.__tinycloudOpenKeyDiagnostics=[];window.addEventListener('message',function(event){window.__tinycloudOpenKeyDiagnostics.push({origin:event.origin,source:!!event.source,type:event.data&&event.data.type,name:event.data&&event.data.info&&event.data.info.name});});"]);
  await agent(["eval", "(function(){var original=window.fetch;window.__tinycloudAuthDiagnostics=[];window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');var result=original.apply(this,arguments);if(u.includes('/api/share/auth/openkey'))result.then(function(response){window.__tinycloudAuthDiagnostics.push({path:(new URL(u,location.href)).pathname,status:response.status});});return result;};})()"]);
  await agent(["eval", walletBootstrapScript(walletOrigin)]);
  await agent(["eval", "(function(){var original=Element.prototype.attachShadow;Element.prototype.attachShadow=function(init){var options=init||{};options.mode='open';return original.call(this,options);};})()"]);
  await agent(["click", "button.auth-button"]);
  await agent(["wait", "1000"]);
  await agent(["find", "text", "TinyCloud E2E Wallet", "click"]);
  await agent(["find", "text", "Create TinyCloud Space", "click"]).catch(() => undefined);
  // The mounted fixture already provisions a space. A first-run prompt is
  // optional, so do not probe for it on every flow.
  await agent(["wait", "text=Shared by me."]);
  await agent(["wait", "text=No shares yet"]);
  checks.push("Fresh authenticated sender observed the Shared by me empty state and New share entry point.");
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='New share');if(!button)throw new Error('New share action is not present');button.click();return true;})()"]);
  await agent(["wait", "text=Share a file"]);
  await agent(["eval", "(function(){window.__senderCopiedLink=null;var clipboard={writeText:function(value){window.__senderCopiedLink=value;return Promise.resolve();},readText:function(){return Promise.resolve(window.__senderCopiedLink||'');}};try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:clipboard});}catch{}})()"]);
  checks.push("agent-browser completed the real OpenKey external-wallet/SIWE authentication path with a deterministic provider.");

  const runBearerSlice = async () => {
  const createBearer = async (format, contentMode, traceName) => {
    const traceId = await beginFlow(traceName);
    if (contentMode === "author") await agent(pasteIntoDropzone("# Hermetic sharing\n\nMarkdown created in the browser."));
    else await agent(["upload", "input[name=document]", join(shareRoot, "test/e2e-sharing/fixture.md")]);
    await agent(openAdvancedSettings);
    await agent(["select", "select[name=format]", format]);
    await agent(["click", "input[value=bearer]"]);
    await agent(["click", "button.create-link-button"]);
    await agent(["wait", "text=Your private link is ready"]);
    await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='Copy link' && !candidate.disabled);if(!button)throw new Error('Copy link action is not present');button.click();return true;})()"]);
    await agent(["wait", "text=Link copied to clipboard."]);
    const url = agentString(await agent(["eval", "window.__senderCopiedLink"]));
    assert.equal(typeof url, "string", "sender clipboard did not contain a URL");
    return { traceId, url };
  };

  const compact = await createBearer("compact", "author", "bearer-compact");
  assert.match(compact.url, /^https:\/\/share\.tinycloud\.xyz\/s\/[^#]+#k=/);
  const compactNetwork = await browserTelemetryEntries();
  const localCompact = new URL(compact.url); localCompact.protocol = "http:"; localCompact.host = new URL(origin).host;
  await navigateInPage(localCompact.href);
  assert.match(await agent(["snapshot"]), /shared via link/);
  assert.equal(await agent(["eval", "document.querySelector('iframe')?.srcdoc.includes('Hermetic sharing') === true"]), "true");
  await agent(["eval", `window.__tinycloudSharingFlowTraceId=${JSON.stringify(compact.traceId)}`]);
  await auditFlow("bearer-compact", compact.traceId, { mailOrigin, networkEntries: compactNetwork, skipBrowserTraceCheck: true });
  gateResults.bearer = true;

  await navigate(`${origin}/share.html`); await authenticateBrowserPage(walletOrigin);
  const inline = await createBearer("inline", "upload", "bearer-inline");
  assert.match(inline.url, /^https:\/\/share\.tinycloud\.xyz\/s\/inline#v=2&p=/);
  await auditFlow("bearer-inline", inline.traceId, { mailOrigin });
  await navigate(`${origin}/share.html`); await authenticateBrowserPage(walletOrigin, false);
  await agent(["wait", "text=2 shares loaded."]);
  assert.equal(await agent(["get", "count", ".sender-history-row"]), "2", "fresh same-sender sign-in did not reload the populated encrypted library");
  const libraryCopy = agentString(await agent(["eval", "(()=>{const buttons=[...document.querySelectorAll('button[aria-label^=\"Copy link for\"]')];if(buttons.length<2)throw new Error('sender library copy actions missing; buttons='+buttons.length+'; rows='+document.querySelectorAll('.sender-history-row').length+'; live='+JSON.stringify(document.querySelector('.sender-live')?.textContent||'')+'; error='+JSON.stringify(document.querySelector('.sender-status')?.textContent||'')+'; loadError='+JSON.stringify(window.__tinycloudSenderHistoryError||''));buttons[1].click();return true;})()"]));
  void libraryCopy; await agent(["wait", "text=Link copied."]);
  assert.equal(await agent(["eval", `window.__senderCopiedLink===${JSON.stringify(compact.url)}`]), "true", "sender library reconstructed a non-byte-exact compact link");
  assert.equal(await agent(["eval", `!document.documentElement.textContent.includes(${JSON.stringify(compact.url)}) && !document.documentElement.textContent.includes(${JSON.stringify(inline.url)})`]), "true", "sender library rendered a complete secret URL in page text");
  await agent(["eval", "fetch('/api/share/auth/logout',{method:'POST',credentials:'include'}).then(function(r){return r.status})"]);
  assert.equal(await agent(["eval", "fetch('/api/share/capabilities',{credentials:'include'}).then(function(r){return r.status})"]), "401", "signed-out sender library remained authorized");
  await navigate(`${origin}/share.html`); await authenticateBrowserPage(walletOrigin, false); await agent(["wait", "text=2 shares loaded."]);
  assert.equal(await agent(["get", "count", ".sender-history-row"]), "2", "same sender did not recover its library after session reset");
  gateResults.senderLibrary = true;
  checks.push("Sender library created and persisted shares, reset the session, reloaded the populated same-sender library, copied a byte-exact complete link, rendered no secret URL, and denied signed-out access.");
  checks.push("Encrypted compact and inline bearer links were both observed; bearer creation remained link-only.");
  };

  const runAddressedSlice = async () => {
  await navigate(`${origin}/share.html`); await authenticateBrowserPage(walletOrigin);
  const exactTrace = await beginFlow("exact-email");
  await agent(["click", "input[value=exactEmail]"]); await agent(["fill", "input[name=recipient-value]", "sam@tinycloud.xyz"]);
  // TC-344. The sender's library is whatever is already in the sender's own
  // space, and at this point in the run nothing is: both bearer shares are
  // link-only and never touch KV. So the first addressed share uploads its
  // content — the real "share something new" entry point — which also puts
  // `shares/<shareId>/fixture.md` in the space for the folder and domain
  // slices below to pick from.
  await agent(["upload", "input[name=document]", join(shareRoot, "test/e2e-sharing/fixture.md")]);
  await agent(["check", "input[name=permission][value=edit]"]); await agent(openAdvancedSettings); await agent(["fill", "input[name=delivery-email]", "sam@tinycloud.xyz"]);
  await agent(["click", "button.create-link-button"]); await agent(["wait", "text=Your private link is ready"]);
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='Copy link' && !candidate.disabled);if(!button)throw new Error('Copy link action is not present');button.click();return true;})()"]); await agent(["wait", "text=Link copied to clipboard."]);
  const exactUrl = agentString(await agent(["eval", "window.__senderCopiedLink"])); assert.match(exactUrl, /^https:\/\/share\.tinycloud\.xyz\/s\//);
  assert.deepEqual((await (await fetch(`${mailOrigin}/emails`)).json()).messages, []);
  await agent(["eval", `(function(){var old=window.fetch;window.__tinycloudDeliveryReplay=null;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/share/v2')&&init){window.__tinycloudDeliveryReplay={url:u,method:init.method||'POST',headers:Object.fromEntries(new Headers(init.headers)),body:typeof init.body==='string'?init.body:null};}return old.apply(this,arguments);};})()`]);
  await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Invitation requested"]);
  const replayRaw = await agent(["eval", "JSON.stringify(window.__tinycloudDeliveryReplay)"]);
  if (replayRaw === "null" || replayRaw === "undefined") throw new Error("exact-email delivery request capture is missing");
  let replay = JSON.parse(replayRaw);
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof replay === "string") { try { replay = JSON.parse(replay); continue; } catch { break; } }
    if (replay !== null && typeof replay === "object" && replay.data !== undefined) { replay = replay.data; continue; }
    if (replay !== null && typeof replay === "object" && replay.value !== undefined) { replay = replay.value; continue; }
    break;
  }
  checks.push(`Exact-email delivery replay request captured metadata ${JSON.stringify({ url: replay.url ?? null, method: replay.method ?? null, bodyLength: typeof replay.body === "string" ? replay.body.length : 0, headers: Object.keys(replay.headers ?? {}).sort() }).slice(0, 1200)}.`);
  const replayValue = JSON.parse(await agent(["eval", `fetch(${JSON.stringify(replay.url)},{method:${JSON.stringify(replay.method)},headers:${JSON.stringify(replay.headers)},body:${JSON.stringify(replay.body)}}).then(function(r){return JSON.stringify({status:r.status,ok:r.ok})})`]));
  let replayResult = replayValue;
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof replayResult === "string") { try { replayResult = JSON.parse(replayResult); continue; } catch { break; } }
    if (replayResult !== null && typeof replayResult === "object" && replayResult.data !== undefined) { replayResult = replayResult.data; continue; }
    if (replayResult !== null && typeof replayResult === "object" && replayResult.value !== undefined) { replayResult = replayResult.value; continue; }
    break;
  }
  checks.push(`Exact-email delivery replay observed status ${replayResult.status ?? "unknown"}; response body was omitted from telemetry; normalized result shape ${JSON.stringify(replayValue).slice(0, 500)}.`);
  const exactAudit = await auditFlow("exact-email", exactTrace, { mailOrigin, expectMail: true, requireReplay: true, replayEvidence: { attempted: true, accepted: replayResult.ok === true && replayResult.status === 200 }, pii: ["sam@tinycloud.xyz"] });
  assert.equal(exactAudit.messages.length, 1); assert.match(JSON.stringify(exactAudit.capturedMail.payload), /https:\/\/share\.tinycloud\.xyz\/s\//);
  const exactInviteUrl = localShareUrl(mailShareUrl(exactAudit.capturedMail.payload), origin);
  const canonicalExactInviteUrl = new URL(exactInviteUrl); canonicalExactInviteUrl.protocol = "https:"; canonicalExactInviteUrl.hostname = "share.tinycloud.xyz"; canonicalExactInviteUrl.port = "";
  await navigate(exactInviteUrl, 2000);
  await agent(["eval", "(function(){window.__recipientCopiedLink=null;var clipboard={writeText:function(value){window.__recipientCopiedLink=value;return Promise.resolve();},readText:function(){return Promise.resolve(window.__recipientCopiedLink||'');}};try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:clipboard});}catch{}})()"]);
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='Copy link');if(!button)throw new Error('recipient Copy link button is missing');button.click();return true;})()"]); await agent(["wait", "text=Link copied."]);
  const recipientCopyEvidence = agentString(await agent(["eval", `JSON.stringify({exact:window.__recipientCopiedLink===${JSON.stringify(canonicalExactInviteUrl.href)},scrubbed:location.hash===''&&location.search==='',dom:!document.documentElement.textContent.includes(${JSON.stringify(canonicalExactInviteUrl.href)}),storage:![localStorage,sessionStorage].some(function(store){return Object.values(store).some(function(value){return String(value).includes(${JSON.stringify(canonicalExactInviteUrl.href)});});}),referrer:!document.referrer.includes(${JSON.stringify(canonicalExactInviteUrl.href)})})`]));
  if (recipientCopyEvidence?.exact !== true || recipientCopyEvidence?.scrubbed !== true || recipientCopyEvidence?.dom !== true || recipientCopyEvidence?.storage !== true || recipientCopyEvidence?.referrer !== true) throw new Error(`recipient copy/privacy boundary failed: ${JSON.stringify({ exact: recipientCopyEvidence?.exact === true, scrubbed: recipientCopyEvidence?.scrubbed === true, dom: recipientCopyEvidence?.dom === true, storage: recipientCopyEvidence?.storage === true, referrer: recipientCopyEvidence?.referrer === true })}`);
  checks.push("Production recipient Copy link copied the byte-exact complete in-memory URL, exposed accessible success feedback, and retained a scrubbed URL/privacy boundary.");
  await agent(["eval", `(function(){var old=window.fetch;window.__tinycloudInvokeReplay=null;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/invoke')&&init&&typeof init.body==='string'){try{var parsed=JSON.parse(init.body);var action=parsed&&parsed.request&&parsed.request.action;if(action==='tinycloud.kv/put'||action==='put'){window.__tinycloudInvokeReplay={url:u,method:init.method||'POST',headers:Object.fromEntries(new Headers(init.headers)),body:init.body};}}catch{}}return old.apply(this,arguments);};})()`]);
  const verifyButton = await agent(["get", "count", "button.viewer-primary-action:not([disabled])"]);
  if (verifyButton !== "0") await agent(["click", "button.viewer-primary-action:not([disabled])"]);
  await agent(["wait", "text=Edit shared text"]); await agent(["fill", "textarea[aria-label='Shared text draft']", "# Exact email\n\nA byte-identical stale draft."]);
  await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  const staleRequestRaw = await agent(["eval", "JSON.stringify(window.__tinycloudInvokeReplay)"]);
  if (staleRequestRaw === "null") throw new Error("edit conflict flow did not capture the conditional put request");
  let staleRequest = agentString(staleRequestRaw);
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof staleRequest === "string") { try { staleRequest = JSON.parse(staleRequest); continue; } catch { break; } }
    if (staleRequest !== null && typeof staleRequest === "object" && staleRequest.data !== undefined) { staleRequest = staleRequest.data; continue; }
    if (staleRequest !== null && typeof staleRequest === "object" && staleRequest.value !== undefined) { staleRequest = staleRequest.value; continue; }
    break;
  }
  if (staleRequest === null || typeof staleRequest !== "object") throw new Error("edit conflict flow captured an invalid conditional put request");
  try {
    const shape = JSON.parse(staleRequest.body);
    checks.push(`Conditional KV-put capture shape ${JSON.stringify({ action: shape.action ?? null, bodyKeys: Object.keys(shape).sort(), headerKeys: Object.keys(staleRequest.headers ?? {}).sort(), bodyLength: staleRequest.body.length, ifMatchLength: typeof shape.ifMatch === "string" ? shape.ifMatch.length : 0, jtiLength: typeof shape.jti === "string" ? shape.jti.length : 0 })}.`);
  } catch { checks.push("Conditional KV-put capture shape was not JSON-decodable."); }
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Exact email\n\nA competing current version."]);
  await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Exact email\n\nA byte-identical stale draft."]);
  let staleReplay = agentString(await agent(["eval", `fetch(${JSON.stringify(staleRequest.url)},{method:${JSON.stringify(staleRequest.method)},headers:${JSON.stringify(staleRequest.headers)},body:${JSON.stringify(staleRequest.body)}}).then(function(r){return r.text().then(function(body){return JSON.stringify({status:r.status,body:body})})})`]));
  for (let unwrap = 0; unwrap < 4; unwrap += 1) {
    if (typeof staleReplay === "string") { try { staleReplay = JSON.parse(staleReplay); continue; } catch { break; } }
    if (staleReplay !== null && typeof staleReplay === "object" && staleReplay.data !== undefined) { staleReplay = staleReplay.data; continue; }
    if (staleReplay !== null && typeof staleReplay === "object" && staleReplay.value !== undefined) { staleReplay = staleReplay.value; continue; }
    break;
  }
  checks.push(`Stale replay response shape ${JSON.stringify({ status: staleReplay?.status ?? null, bodyLength: typeof staleReplay?.body === "string" ? staleReplay.body.length : 0, bodyCode: typeof staleReplay?.body === "string" ? staleReplay.body.match(/\"code\"\s*:\s*\"([^\"]+)/)?.[1] ?? null : null })}.`);
  assert.equal(staleReplay.status, 412, `stale If-Match did not return 412 (${staleReplay.status})`);
  const preservedDraft = await agent(["get", "value", "textarea[aria-label='Shared text draft']"]); assert.equal(preservedDraft.includes("byte-identical stale draft"), true);
  await agent(["find", "text", "Reload current version", "click"]); await agent(["wait", "text=Reloaded current version"]);
  gateResults.editConflict = true;
  checks.push("Exact-email Markdown read/edit observed a stale If-Match 412 with a byte-identical draft preserved, then recovered by reloading the current version.");
  gateResults.exactEmail = true; gateResults.notification = true;
  checks.push("Exact-email Markdown link creation, explicit delivery, and byte-identical idempotency replay were observed.");
  };

  const runDomainFlow = async () => {
  await navigate(`${origin}/share.html`); await authenticateBrowserPage(walletOrigin);
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  const domainTrace = await beginFlow("domain");
  // The mounted credential fixture proves the full mailbox identity
  // sam@mailinator.com. Delivery is intentionally the same metadata value,
  // while the signed domain matcher remains the independent authorization.
  const domainDeliveryEmail = "sam@mailinator.com";
  await agent(openAdvancedSettings); await agent(["click", "input[value=emailDomain]"]); await agent(["fill", "input[name=recipient-value]", "mailinator.com"]);
  await agent(pickFromLibrary); await agent(["fill", "input[name=delivery-email]", domainDeliveryEmail]);
  const domainLibraryPath = await selectLibraryOption("(function(options){return options.filter(function(option){return option.dataset.resourceKind==='exact'})[0]})", "library object");
  checks.push(`Domain slice shared the library object ${domainLibraryPath} out of the sender's own space.`);
  await agent(["eval", `(function(){window.__tinycloudDomainDeliveryObserved=false;window.__tinycloudDomainDeliveryShape=null;var old=window.fetch;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/share/v2')&&init&&typeof init.body==='string'){try{var value=JSON.parse(init.body);var auth=value.authorization&&typeof value.authorization==='object'?value.authorization:value;window.__tinycloudDomainDeliveryShape={topKeys:Object.keys(value).sort(),authKeys:auth&&typeof auth==='object'?Object.keys(auth).sort():[],deliveryType:typeof auth.deliveryEmail,matcherKind:auth.recipientMatcher&&auth.recipientMatcher.kind};window.__tinycloudDomainDeliveryObserved=auth.deliveryEmail===${JSON.stringify(domainDeliveryEmail)}&&auth.recipientMatcher&&auth.recipientMatcher.kind==='emailDomain'&&auth.recipientMatcher.value==='mailinator.com';}catch{}}return old.apply(this,arguments);};})()`]);
  await agent(["wait", "500"]);
  const domainFormState = agentString(await agent(["eval", `JSON.stringify((function(){var option=document.querySelector('select[name=kv-source] option:checked');return {recipient:document.querySelector('input[value=emailDomain]')?.checked===true,domain:document.querySelector('input[name=recipient-value]')?.value==='mailinator.com',delivery:document.querySelector('input[name=delivery-email]')?.value===${JSON.stringify(domainDeliveryEmail)},selected:option?option.value:null,selectedKind:option?(option.dataset.resourceKind||null):null};})())`]));
  // TC-344. The signed recipient matcher used to arrive pre-issued on the
  // capability behind the option, so this read the option dataset. Under the
  // owner-policy path the sender authors the matcher in the composer and the
  // option carries none, so the binding to check is the composed form: the
  // domain typed, the delivery address, and the library object selected.
  if (domainFormState?.recipient !== true || domainFormState?.domain !== true || domainFormState?.delivery !== true || domainFormState?.selected !== domainLibraryPath || domainFormState?.selectedKind !== "exact") throw new Error(`domain form/library binding failed: ${JSON.stringify({ recipient: domainFormState?.recipient === true, domain: domainFormState?.domain === true, delivery: domainFormState?.delivery === true, selected: domainFormState?.selected ?? null, expected: domainLibraryPath, selectedKind: domainFormState?.selectedKind ?? null })}`);
  await agent(["fill", "input[name=delivery-email]", "sam@evil.example"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Check the sharing details"]);
  const mismatchedDomainDetail = await agent(["get", "text", ".sender-status-detail"]);
  assert.match(mismatchedDomainDetail, /must belong to the shared domain/i, "mismatched delivery domain was not denied by the shipped composer");
  checks.push("agent-browser denied a mailinator.com policy paired with an evil.example delivery address before link creation, with the user-visible shared-domain validation error.");
  await agent(["fill", "input[name=delivery-email]", domainDeliveryEmail]);
  await agent(["click", "button.create-link-button"]); await agent(["wait", "text=Your private link is ready"]);
  await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Invitation requested"]);
  const domainAudit = await auditFlow("domain", domainTrace, { mailOrigin, expectMail: true, expectMailRecipient: domainDeliveryEmail, pii: [domainDeliveryEmail] });
  const domainDeliveryShape = agentString(await agent(["eval", "JSON.stringify(window.__tinycloudDomainDeliveryShape)"]));
  assert.equal(await agent(["eval", "window.__tinycloudDomainDeliveryObserved === true"]), "true", "domain delivery did not carry the generated full email and signed domain matcher at the enforcing delivery boundary");
  assert.equal(domainDeliveryShape?.deliveryType, "string", "domain delivery boundary did not receive a full delivery email");
  assert.equal(domainDeliveryShape?.matcherKind, "emailDomain", "domain delivery boundary did not receive an independent domain matcher");
  checks.push(`Domain delivery request shape sanitized: ${JSON.stringify(domainDeliveryShape)}.`);
  const domainMailPayload = domainAudit.capturedMail?.payload;
  const domainMailStrings = stringsIn(domainMailPayload);
  checks.push(`Domain provider recipient shape sanitized: ${JSON.stringify({ payloadKeys: domainMailPayload && typeof domainMailPayload === "object" ? Object.keys(domainMailPayload).sort() : [], recipientMatches: domainMailStrings.includes(domainDeliveryEmail), recipientStringLengths: domainMailStrings.filter((value) => value.includes("@mailinator.com")).map((value) => value.length).sort() })}.`);
  assert.equal(domainMailStrings.includes(domainDeliveryEmail), true, "domain provider email did not target the generated full delivery email");
  const domainInviteUrl = localShareUrl(mailShareUrl(domainAudit.capturedMail.payload), origin);
  await navigate(domainInviteUrl); await agent(["wait", "2000"]); await agent(["click", "button.viewer-primary-action"]); await agent(["wait", "2000"]);
  const domainOpenState = agentString(await agent(["eval", "JSON.stringify({contentPresent:(document.querySelector('.viewer-preview-frame')?.srcdoc||'').length>0,isolatedPreview:document.querySelector('.viewer-preview-frame')?.getAttribute('sandbox')==='',status:(document.querySelector('.viewer-policy-status')?.textContent||'').slice(0,240),responses:(window.__tinycloudTelemetry||[]).filter(function(entry){return String(entry.url||'').includes('/share/v1/')||String(entry.url||'').includes('/claims/')}).map(function(entry){return {status:entry.status,errorCode:entry.errorCode||null}})})"]));
  assert.equal(domainOpenState?.contentPresent, true, `full-email domain claim/open did not render authorized content: ${JSON.stringify(domainOpenState)}`);
  assert.equal(domainOpenState?.isolatedPreview, true, `full-email domain content did not use the isolated preview boundary: ${JSON.stringify(domainOpenState)}`);
  gateResults.domain = true;
  checks.push("Full-email domain claim/open rendered authorized content while the signed domain matcher remained independent of delivery email.");
  };

  const runFolderFlow = async () => {
  await navigate(`${origin}/share.html`); await authenticateBrowserPage(walletOrigin);
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  const folderTrace = await beginFlow("folder");
  const folderDeliveryEmail = "sam@mailinator.com";
  await agent(openAdvancedSettings); await agent(["click", "input[value=emailDomain]"]); await agent(["fill", "input[name=recipient-value]", "mailinator.com"]); await agent(["fill", "input[name=delivery-email]", folderDeliveryEmail]); await agent(pickFromLibrary);
  // TC-344. A folder share copies the *direct children* of the chosen prefix,
  // so the prefix has to be one that has direct file children. The sender's
  // space contains `shares/<id>/fixture.md`, which offers both `shares/` (no
  // direct children) and `shares/<id>/` (one). Pick the latter, and say so if
  // the library never offered such a folder.
  const folderPath = await selectLibraryOption("(function(options){var files=options.filter(function(option){return option.dataset.resourceKind==='exact'}).map(function(option){return option.value});return options.filter(function(option){return option.dataset.resourceKind==='prefix'&&option.value.charAt(option.value.length-1)==='/'}).find(function(option){return files.some(function(file){return file.indexOf(option.value)===0&&file.slice(option.value.length).indexOf('/')===-1})})})", "library folder with direct file children");
  checks.push(`Folder slice shared the library folder ${folderPath} out of the sender own space.`);
  await agent(["check", "input[name=permission][value=list]"]); await agent(["check", "input[name=permission][value=edit]"]);
  await agent(["eval", "(function(){window.__tinycloudFolderDeliveryShape=null;var old=window.fetch;window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');if(u.includes('/share/v2')&&init&&typeof init.body==='string'){try{var value=JSON.parse(init.body);var auth=value.authorization&&typeof value.authorization==='object'?value.authorization:value;window.__tinycloudFolderDeliveryShape={actions:Array.isArray(auth.actions)?auth.actions.slice().sort():[],resource:typeof auth.resource==='string'?auth.resource:null,matcherKind:auth.recipientMatcher&&auth.recipientMatcher.kind};}catch{}}return old.apply(this,arguments);};})()"]);
  await agent(["click", "button.create-link-button"]); await agent(["wait", "text=Your private link is ready"]); await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Invitation requested"]);
  const folderAudit = await auditFlow("folder", folderTrace, { mailOrigin, expectMail: true, expectMailRecipient: folderDeliveryEmail, pii: [folderDeliveryEmail] });
  const folderTelemetry = JSON.stringify(folderAudit.capturedMail.payload); const folderDeliveryShape = agentString(await agent(["eval", "JSON.stringify(window.__tinycloudFolderDeliveryShape)"])); checks.push(`Folder delivery action evidence sanitized: ${JSON.stringify(folderDeliveryShape)}.`); assert.equal(folderTelemetry.includes(folderDeliveryEmail), true); assert.equal(folderTelemetry.includes("mailinator.com"), true); assert.deepEqual(folderDeliveryShape?.actions, ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"]); assert.equal(typeof folderDeliveryShape?.resource === "string" && folderDeliveryShape.resource.length > 0 && !folderDeliveryShape.resource.endsWith("/"), true, `folder delivery did not carry a folder resource: ${JSON.stringify(folderDeliveryShape)}`); assert.equal(folderDeliveryShape?.matcherKind, "emailDomain");
  const folderInviteUrl = localShareUrl(mailShareUrl(folderAudit.capturedMail.payload), origin);
  await navigate(folderInviteUrl, 2000); await agent(["set", "headers", JSON.stringify({ Origin: canonical.share })]); await agent(["eval", "(function(){var previous=window.fetch;window.__folderPutCapture=null;window.__policyTrace=[];window.__claimTrace=[];window.fetch=function(input,init){var u=typeof input==='string'?input:String((input&&input.url)||input||'');var result=previous.apply(this,arguments);if(u.includes('/policy/challenges')||u.includes('/policy/session')||u.includes('/v1/share-email/claims/')){result.then(function(response){response.clone().text().then(function(body){var parsed=null;try{parsed=JSON.parse(body);}catch{}var path=(new URL(u,location.href)).pathname;var target=path.includes('/claims/')?window.__claimTrace:window.__policyTrace;target.push({path:path,status:response.status,code:parsed&&parsed.error&&parsed.error.code||null,keys:parsed&&typeof parsed==='object'?Object.keys(parsed).sort():[],body:body.slice(0,400)});});});}if(u.includes('/invoke')&&init&&typeof init.body==='string'){try{var parsed=JSON.parse(init.body);var request=parsed&&parsed.request||{};var action=request.action||request.invocation&&request.invocation.action;if(action==='tinycloud.kv/put'||action==='put'){window.__folderPutCapture={url:u,method:init.method||'POST',headers:Object.fromEntries(new Headers(init.headers)),body:init.body};}}catch{}}return result;};})()"]); await agent(["click", "button.viewer-primary-action"]); await agent(["wait", "3000"]);
  const folderOpenState = agentString(await agent(["eval", "JSON.stringify({title:document.title,policy:(document.querySelector('.viewer-policy-status')?.textContent||'').slice(0,240),claim:(document.querySelector('.viewer-status')?.textContent||'').slice(0,240),trace:window.__policyTrace||[],claimTrace:window.__claimTrace||[],body:(document.body?.innerText||'').replace(/https?:\\/\\/[^\\s]+/g,'[URL]').slice(0,600)})"]));
  if (!String(folderOpenState?.body ?? "").includes("Shared folder")) throw new Error("folder authorization did not complete: " + JSON.stringify(folderOpenState));
  assert.notEqual(await agent(["get", "count", "button.viewer-folder-entry"]), "0", "folder child listing was not observed");
  const folderEntries = agentString(await agent(["eval", "JSON.stringify([...document.querySelectorAll('button.viewer-folder-entry')].map(function(button){return {path:button.dataset.path||'',label:button.textContent||''}}))"]));
  // TC-344. The delivered prefix resource is minted per share by
  // createOwnerPolicyShare, so the invariant is direct-child scope under the
  // resource that was actually delivered, not a fixture folder name.
  const folderResource = folderDeliveryShape.resource;
  assert.equal(Array.isArray(folderEntries) && folderEntries.length > 0 && folderEntries.every((entry) => entry.path.startsWith(`${folderResource}/`) && entry.path.slice(folderResource.length + 1).includes("/") === false), true, `folder list escaped direct-child scope for ${folderResource}: ${JSON.stringify(folderEntries)}`);
  await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button.viewer-folder-entry')].find((candidate)=>candidate.dataset.path?.endsWith('.md'));if(!button)throw new Error('direct child file missing');button.click();return true;})()"]); await agent(["wait", "2000"]);
  assert.equal(await agent(["get", "count", ".viewer-editor-panel"]), "1", "direct child get did not expose the authorized editor");
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Folder draft\n\nA byte-identical stale folder draft."]); await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  const folderStaleRequest = agentString(await agent(["eval", "JSON.stringify(window.__folderPutCapture)"])); assert.equal(folderStaleRequest !== null && typeof folderStaleRequest === "object", true, "folder put request was not captured");
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Folder draft\n\nA competing current folder version."]); await agent(["click", "button.viewer-editor-save"]); await agent(["wait", "text=Saved."]);
  await agent(["fill", "textarea[aria-label='Shared text draft']", "# Folder draft\n\nA byte-identical stale folder draft."]);
  const folderStaleReplay = agentString(await agent(["eval", `fetch(${JSON.stringify(folderStaleRequest.url)},{method:${JSON.stringify(folderStaleRequest.method)},headers:${JSON.stringify(folderStaleRequest.headers)},body:${JSON.stringify(folderStaleRequest.body)}}).then(function(r){return r.text().then(function(body){return JSON.stringify({status:r.status,body:body})})})`]));
  assert.equal(folderStaleReplay?.status, 412, "folder stale If-Match did not return 412"); assert.equal((await agent(["get", "value", "textarea[aria-label='Shared text draft']"])).includes("byte-identical stale folder draft"), true, "folder stale draft was not preserved"); await agent(["find", "text", "Reload current version", "click"]); await agent(["wait", "text=Reloaded current version"]);
  gateResults.folder = true;
  checks.push("Reusable mailinator.com folder flow observed direct-child list/get/put, rejected out-of-scope paths, and preserved a stale If-Match draft through 412 recovery.");
  };

  const runPolicySlice = async () => { await runFolderFlow(); await runDomainFlow(); };

  const runDenialSlice = async () => {
  const denialTrace = await beginFlow("denial-matrix");
  const denialCases = [
    ["signed-out-capabilities", `${origin}/api/share/capabilities`, { method: "GET" }, 401],
    ["signed-out-capability", `${origin}/api/share/capability`, { method: "GET" }, 401],
    // The Share host runs sender-disabled, and /api/share/bindings answers
    // 503 sender_not_ready before it consults the session, so 401 is a status
    // this composition cannot produce. Assert what it does enforce, and do not
    // claim to have observed an authorization decision that never happened.
    ["sender-disabled-bindings", `${origin}/api/share/bindings`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, 503],
    ["signed-out-registry-upload", `${origin}/api/share/link-only/registry/blobs`, { method: "POST", headers: { "content-type": "application/vnd.ipld.raw" }, body: "x" }, 401],
    ["malformed-cid", `${origin}/s/not-a-cid/raw`, { method: "GET" }, 404],
    ["removed-consume", `${origin}/share/v1/invitations/consume`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, 404],
    ["traversal-sibling", `${origin}/share/v1/read/../sibling`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, undefined],
    ["traversal-nested", `${origin}/share/v1/read/%2e%2e/nested`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, undefined],
    ["forged-cursor", `${origin}/api/share/capabilities?cursor=forged-cursor`, { method: "GET" }, 401],
    ["forged-invoke-query", `${origin}/invoke?cursor=forged-cursor`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, undefined],
    ["unauthorized-get", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/get", resource: { kind: "exact", path: "documents/policy-payload.md" } } }) }, undefined],
    ["sibling-escape", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/get", resource: { kind: "exact", path: "documents-archive/secret.md" } } }) }, undefined],
    ["nested-escape", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/get", resource: { kind: "exact", path: "documents/archive/secret.md" } } }) }, undefined],
    ["unauthorized-list", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/list", resource: { kind: "prefix", path: "documents/" } } }) }, undefined],
    ["unauthorized-put", `${origin}/share/v1/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { action: "tinycloud.kv/put", resource: { kind: "exact", path: "documents/policy-payload.md" }, body: [1], ifMatch: null } }) }, undefined],
  ];
  // TC-307. These host-side requests reach the loopback Share host over
  // plaintext http, and the production entrypoint rejects any /api, /share,
  // /v1, /invoke, /delegate or /registry request that is not forwarded as
  // https with 400 https_required -- before it ever consults the session. So
  // every case here was answering the transport guard rather than the
  // authorization boundary it claims to test. The browser sets this header
  // once per session; the host-side matrix has to set it too. The transport
  // guard itself is now asserted as its own case rather than silently
  // standing in for all the others.
  const forwardedHttps = (init) => ({ ...init, headers: { ...(init.headers ?? {}), "x-forwarded-proto": "https" } });
  const plaintextResponse = await fetch(`${origin}/api/share/capabilities`, { method: "GET" });
  assert.equal(plaintextResponse.status, 400, "plaintext API request was not rejected by the transport guard");
  for (const [label, url, init, expected] of denialCases) {
    const response = await fetch(url, forwardedHttps(init));
    if (expected === undefined) assert.equal(response.status >= 400, true, `${label} did not fail closed`); else assert.equal(response.status, expected, `${label} denial status`);
  }
  const evilOriginResponse = await fetch(`${origin}/api/share/capabilities`, forwardedHttps({ headers: { origin: "https://evil.example" } })); assert.equal(evilOriginResponse.status, 401, "wrong-origin capability access was accepted");
  await agent(["eval", "fetch('/api/share/auth/logout',{method:'POST',credentials:'include'}).then(function(r){return r.status})"]);
  assert.equal(await agent(["eval", "fetch('/api/share/capabilities',{credentials:'include'}).then(function(r){return r.status})"]), "401", "signed-out sender history boundary was not enforced");
  gateResults.denialMatrix = true; await auditFlow("denial-matrix", denialTrace, { mailOrigin }); checks.push("Enforcing boundary denial matrix observed signed-out history, wrong origin, malformed and traversal paths, forged cursor/query, removed routes, missing proof, and unauthorized get/list/put fail-closed responses.");
  };

  /*
   * TC-307. Each slice runs behind its own boundary. A slice that throws ends
   * that slice and nothing else, so one broken flow can no longer leave six
   * working ones reporting `false` from never having been attempted. A slice
   * whose declared prerequisite did not pass is skipped and recorded as
   * not-attempted, because running it would report a cause from another slice.
   */
  const sliceRunners = { bearer: runBearerSlice, addressed: runAddressedSlice, policy: runPolicySlice, denial: runDenialSlice };
  for (const slice of GATE_SLICES) {
    const runner = sliceRunners[slice.name];
    if (runner === undefined) throw new Error(`gate slice ${slice.name} has no runner`);
    const blocking = slice.requires.find((name) => !attemptedSlices.has(name) || sliceFailures.has(name) || !GATE_SLICES.find((candidate) => candidate.name === name).flows.every((flow) => gateResults[flow] === true));
    if (blocking !== undefined) { blockedSlices[slice.name] = blocking; continue; }
    attemptedSlices.add(slice.name);
    try {
      await runner();
    } catch (error) {
      sliceFailures.set(slice.name, error instanceof Error ? error.message : String(error));
      // The top-level failure diagnostics only ran when a throw escaped
      // browserGate. Now that a slice contains its own failure it has to
      // capture what the page was showing when it ended, or a contained
      // failure would be a quieter failure than an uncontained one.
      try {
        const state = agentString(await agent(["eval", "JSON.stringify({composerState:document.querySelector('.composer-status')?.dataset.state||null,title:document.querySelector('.sender-status-title')?.textContent||null,detail:document.querySelector('.sender-status-detail')?.textContent||null,libraryOptions:[].slice.call(document.querySelectorAll('select[name=kv-source] option')).map(function(option){return {value:option.value,kind:option.dataset.resourceKind||null}}),authError:(window.__tinycloudAuthError&&window.__tinycloudAuthError.message)||window.__tinycloudAuthError||null,failedTelemetry:(window.__tinycloudTelemetry||[]).filter(function(entry){return entry.status===undefined||entry.status>=400}).map(function(entry){return {path:(function(){try{return new URL(entry.url).pathname}catch(error){return null}})(),status:entry.status||null,errorCode:entry.errorCode||null}})})"]));
        checks.push(`Gate slice ${slice.name} failure page state ${JSON.stringify(state)}.`);
      } catch (diagnosticError) {
        checks.push(`Gate slice ${slice.name} failure page state unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}.`);
      }
      // The Share host answers an unhandled request error with a bare 503
      // capability_unavailable and logs the path and cause to its own stderr.
      // Without this the harness could only ever report the status.
      const hostErrors = [...new Set(children.flatMap((entry) => entry.output().split("\n").filter((line) => line.includes("share-host stage=request-error"))))].slice(-10);
      if (hostErrors.length > 0) checks.push(`Gate slice ${slice.name} Share host request errors ${JSON.stringify(hostErrors)}.`);
      // The Node answers /share/v2/* with 503 capability_unavailable when its
      // share-v2 runtime is absent or no longer live. Readiness is checked once
      // at launch, so a slice that dies on one of those routes has to re-read
      // it here; otherwise "went unready mid-run" and "was never there" are
      // the same 503.
      try {
        // Straight at the Node: the Share host only proxies the five allowed
        // /share/v2 routes, so asking it for readiness answers 404 not_found
        // and says nothing about the runtime that returned the 503.
        const readiness = await (await fetch(`${nodeOrigin}/share/v2/readiness`, { headers: { accept: "application/json" } })).json();
        checks.push(`Gate slice ${slice.name} Node share-v2 readiness at failure ${JSON.stringify(readiness)}.`);
      } catch (readinessError) {
        checks.push(`Gate slice ${slice.name} Node share-v2 readiness at failure unavailable: ${readinessError instanceof Error ? readinessError.message : String(readinessError)}.`);
      }
    }
  }

  const trackedRequests = networkEntries(await agent(["network", "requests", "--json"]));
  const allRequests = trackedRequests.length > 0 ? trackedRequests : await browserTelemetryEntries();
  externalRequests = allRequests.filter((entry) => { try { const url = new URL(entry.url); return url.protocol !== "http:" || (url.hostname !== "127.0.0.1" && url.hostname !== "localhost"); } catch { return true; } });
  if (externalRequests.length !== 0) blockers.push(`Browser attempted non-loopback destinations: ${JSON.stringify(externalRequests.map((entry) => entry.url).slice(0, 20))}`); else gateResults.browser = true;
}

async function writeArtifact(status, summary, extraBlockers = [], sliceEvidence = {}) {
  const scopedRepositories = {
    share: shareRoot,
    node: nodeRoot,
    jsSdk: resolveJsSdkWorktree(process.env, workspaceRoot),
    openCredentials: credentialsRoot,
  };
  const repositoryDigests = {};
  for (const [name, repository] of Object.entries(scopedRepositories)) {
    const commit = execFileSync("git", ["-C", repository, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    const diff = execFileSync("git", ["-C", repository, "diff", "--binary", "--no-ext-diff"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    const untracked = execFileSync("git", ["-C", repository, "ls-files", "--others", "--exclude-standard", "-z"], { encoding: "utf8" });
    const files = untracked.split("\0").filter(Boolean);
    const untrackedBytes = [];
    for (const file of files) untrackedBytes.push(`${file}\0`, await readFile(join(repository, file)));
    const digestInput = Buffer.concat([Buffer.from(commit), Buffer.from("\0"), Buffer.from(diff), Buffer.from("\0"), ...untrackedBytes.map((value) => typeof value === "string" ? Buffer.from(value) : value)]);
    repositoryDigests[name] = { commit, digest: createHash("sha256").update(digestInput).digest("hex"), untracked: files };
  }
  // TC-306: zeroExternalDestinations used to mean "the browser made no
  // non-loopback request", which is trivially true even when the Share host
  // proxies every one of those loopback requests straight out to
  // https://node.tinycloud.xyz — the hop happens server-side, after the
  // browser's request has already terminated on loopback. It now also
  // requires the upstream routing gate to have proven the Share host's own
  // three destinations are loopback, which is the destination set the browser
  // audit structurally cannot see.
  const joinedPassed = tc465Evidence !== undefined && Object.values(tc465Evidence.statuses).every((value) => value === true);
  const joinedSlice = {
    name: tc500Joined ? "tc-500-accountless-exact-email" : "tc-465-exact-email",
    status: joinedPassed ? "passed" : "failed",
    summary: "credential acquisition through exact browser render",
    flows: tc465Evidence?.statuses ?? {},
    unprovenFlows: joinedPassed ? [] : Object.entries(tc465Evidence?.statuses ?? {}).filter(([, value]) => value !== true).map(([name]) => name),
    detail: joinedPassed ? `every required ${tc500Joined ? "TC-500" : "TC-465"} browser journey stage was proven` : `the joined ${tc500Joined ? "TC-500" : "TC-465"} browser journey did not prove every required stage`,
  };
  const genericResult = { requiredSlices, slices: sliceEvidence.sliceReport ?? [], provenSlices: sliceEvidence.verdict?.provenSlices ?? [], unprovenSlices: sliceEvidence.verdict?.unprovenSlices ?? GATE_SLICES.map((slice) => slice.name), requiredSlicesPassed: sliceEvidence.verdict?.requiredSlicesPassed ?? false, allSlicesPassed: sliceEvidence.verdict?.allSlicesPassed ?? false, browserE2ePassed: gateResults.browser && gateResults.bearer && gateResults.exactEmail && gateResults.domain && gateResults.editConflict && gateResults.folder && gateResults.notification && gateResults.denialMatrix, senderLibraryPassed: gateResults.senderLibrary, exactEmailPassed: gateResults.exactEmail, domainPassed: gateResults.domain, bearerPassed: gateResults.bearer, editConflictPassed: gateResults.editConflict, folderPassed: gateResults.folder, notificationPassed: gateResults.notification, denialMatrixPassed: gateResults.denialMatrix, zeroExternalDestinations: gateResults.browser && externalRequests.length === 0 && upstreamRoutingAudit.allLoopback };
  const joinedResult = { requiredSlices: [joinedSlice.name], slices: [joinedSlice], provenSlices: joinedPassed ? [joinedSlice.name] : [], unprovenSlices: joinedPassed ? [] : [joinedSlice.name], requiredSlicesPassed: joinedPassed, allSlicesPassed: joinedPassed, browserE2ePassed: joinedPassed, exactEmailPassed: joinedPassed, zeroExternalDestinations: tc465Evidence?.statuses.zeroExternalDestinations === true, senderLibraryPassed: tc465Evidence?.statuses.senderLibrary === true, domainPassed: false, bearerPassed: false, editConflictPassed: false, folderPassed: false, notificationPassed: tc465Evidence?.statuses.delivery === true, denialMatrixPassed: false };
  const result = { status, summary, localUnpushedMode, releaseInputsVerified, ...(tc465Joined ? joinedResult : genericResult), upstreamRoutingAudit, ...(tc465Evidence === undefined ? {} : { tc465Evidence }), launchInputDigests, repositoryDigests, flowAudits, checks: [...new Set(checks)], blockers: [...new Set([...blockers, ...extraBlockers])] };
  await writeFile(artifactPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
}

let tempRoot;
let share;
async function browserSmokeLoop(origin, walletOrigin) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await navigate(`${origin}/share.html`);
    await authenticateBrowserPage(walletOrigin);
    assert.equal(await agent(["get", "count", "main.composer-shell"]), "1", `sequential browser smoke ${attempt} did not reach the production composer`);
  }
  checks.push("Clean sequential agent-browser smoke loop completed three serialized sessions without retry-as-success semantics.");
}

async function authenticateBrowserPage(walletOrigin, openComposer = true) {
  await agent(["eval", walletBootstrapScript(walletOrigin)]);
  await agent(["eval", "(function(){var original=Element.prototype.attachShadow;Element.prototype.attachShadow=function(init){var options=init||{};options.mode='open';return original.call(this,options);};})()"]);
  await agent(["click", "button.auth-button"]);
  await agent(["wait", "1000"]);
  await agent(["find", "text", "TinyCloud E2E Wallet", "click"]);
  await agent(["wait", "text=Shared by me."]);
  if (openComposer) {
    await agent(["eval", "(()=>{const button=[...document.querySelectorAll('button')].find((candidate)=>candidate.textContent?.trim()==='New share');if(!button)throw new Error('New share action is not present');button.click();return true;})()"]);
    await agent(["wait", "text=Share a file"]);
  }
  await agent(["eval", "(function(){window.__senderCopiedLink=null;var clipboard={writeText:function(value){window.__senderCopiedLink=value;return Promise.resolve();},readText:function(){return Promise.resolve(window.__senderCopiedLink||'');}};try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:clipboard});}catch{}})()"]);
}

async function cleanup() {
  if (cleanupStarted) return;
  cleanupStarted = true;
  try { await agent(["close"]); } catch (error) { blockers.push(`agent-browser cleanup failed: ${error instanceof Error ? error.message : String(error)}`); }
  await stopAll();
  await closeAll();
  if (tempRoot !== undefined) await rm(tempRoot, { recursive: true, force: true });
  await releaseLock();
  const psLines = parsePsLines(execFileSync("ps", ["-axo", "pid=,pgid=,command="], { encoding: "utf8" }));
  const surviving = findSurvivingOwnedProcesses(psLines, ownedPgids, process.pid);
  if (surviving.length > 0) blockers.push(`harness-owned processes remained after cleanup: ${surviving.map((entry) => entry.pid).join(",")}`);
  try {
    const sessions = execFileSync(agentBrowser, ["session", "list"], { cwd: shareRoot, encoding: "utf8", timeout: AGENT_TIMEOUT_MS });
    if (sessions.split("\n").some((line) => line.includes(sessionName))) blockers.push(`harness-owned agent-browser session remained after cleanup: ${sessionName}`);
  } catch (error) { blockers.push(`agent-browser session cleanup audit failed: ${error instanceof Error ? error.message : String(error)}`); }
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.once(signal, () => { void cleanup().finally(() => { process.exitCode = 1; }); });

try {
  await assertReleaseInputs();
  await acquireLock();
  tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-sharing-e2e-"));
  const fixtures = await startFixtures(tempRoot);
  share = await startShare(tempRoot, fixtures);
  const externallyDriven = await waitForExternalProductJourney(fixtures, share.origin);
  if (!externallyDriven) {
    await browserGate(share.origin, fixtures.walletOrigin, fixtures.mailOrigin, fixtures.nodeOrigin);
    await browserSmokeLoop(share.origin, fixtures.walletOrigin);
  }
} catch (error) {
  blockers.push(error instanceof Error ? error.message : String(error));
  try {
    checks.push("Failure diagnostic browser telemetry captured; raw telemetry omitted after privacy audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic browser telemetry unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const snapshot = await agent(["snapshot"]);
    checks.push("Failure diagnostic browser snapshot captured; raw DOM omitted after privacy audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic browser snapshot unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const browserNetwork = networkEntries(await agent(["network", "requests", "--json"]));
    const telemetry = await browserTelemetryEntries();
    const sanitizedNetwork = scrubNetwork(browserNetwork);
    checks.push(`Failure diagnostic browser network ${JSON.stringify(sanitizedNetwork.map((entry) => ({ path: entry.path, method: entry.method, status: entry.status })))}.`);
    const policyResult = sanitizedNetwork.find((entry) => entry.path === "/share/v2/policies");
    if (policyResult !== undefined) checks.push(`Failure diagnostic policy registration HTTP result ${JSON.stringify({ status: policyResult.status ?? null, method: policyResult.method ?? null })}.`);
    checks.push(`Failure diagnostic browser telemetry ${JSON.stringify(telemetry.map((entry) => ({ path: (() => { try { return new URL(entry.url).pathname; } catch { return null; } })(), method: entry.method ?? null, status: entry.status ?? null, errorCode: entry.errorCode ?? null })))}.`);
    checks.push("Failure diagnostic admission network captured; raw network omitted after privacy audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic admission network unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const authDiagnostics = await agent(["eval", "JSON.stringify(window.__tinycloudAuthDiagnostics||null)"]);
    checks.push("Failure diagnostic auth responses captured; raw response bodies omitted after secret audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic auth responses unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const uiDiagnostics = agentString(await agent(["eval", "JSON.stringify([...document.querySelectorAll('[role=status],[role=alert],.composer-live,.composer-status,.notification-status')].map(function(node){var text=node.textContent||'';var match=text.match(/(?:failed: )([0-9]{3})(?: ([A-Za-z0-9_]+))?/);return {className:node.className||null,state:node.dataset.state||null,errorCode:match?match[1]+' '+(match[2]||''):null,text:text,children:[...node.children].map(function(child){return child.textContent||''})}}))"]));
    checks.push(`Failure diagnostic UI state ${JSON.stringify(Array.isArray(uiDiagnostics) ? uiDiagnostics.map((entry) => ({ className: entry?.className ?? null, state: entry?.state ?? null, errorCode: entry?.errorCode ?? null, text: safeBrowserDiagnostic(entry?.text), children: Array.isArray(entry?.children) ? entry.children.map((child) => safeBrowserDiagnostic(child)) : [] })) : [])}.`);
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic UI state unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  try {
    const openKeyDiagnostics = await agent(["eval", "JSON.stringify({status:document.querySelector('.auth-status')?.textContent||null,error:window.__tinycloudAuthError?.message||window.__tinycloudAuthError||null,senderHistoryError:window.__tinycloudSenderHistoryError||null,authResponses:window.__tinycloudAuthDiagnostics||null,messages:window.__tinycloudOpenKeyDiagnostics||null,telemetry:(window.__tinycloudTelemetry||[]).filter(function(entry){return String(entry.url||'').endsWith('/invoke')||String(entry.url||'').endsWith('/delegate')})})"]);
    const parsedDiagnostics = agentString(openKeyDiagnostics);
    checks.push(`Failure diagnostic browser state ${JSON.stringify({ status: safeBrowserDiagnostic(parsedDiagnostics?.status), authError: safeBrowserDiagnostic(parsedDiagnostics?.error), historyError: safeBrowserDiagnostic(parsedDiagnostics?.senderHistoryError), authResponseStatuses: Array.isArray(parsedDiagnostics?.authResponses) ? parsedDiagnostics.authResponses.map((entry) => ({ status: entry?.status ?? null, bodyLength: typeof entry?.body === "string" ? entry.body.length : 0, bodyKeys: (() => { try { const body = JSON.parse(entry.body); return body && typeof body === "object" ? Object.keys(body).sort() : []; } catch { return []; } })() })) : [], messageTypes: Array.isArray(parsedDiagnostics?.messages) ? parsedDiagnostics.messages.map((entry) => entry?.type ?? null).filter(Boolean) : [], telemetry: Array.isArray(parsedDiagnostics?.telemetry) ? parsedDiagnostics.telemetry.map((entry) => ({ path: (() => { try { return new URL(entry.url).pathname; } catch { return null; } })(), status: entry?.status ?? null, errorCode: entry?.errorCode ?? null, responseErrorCode: entry?.responseErrorCode ?? null, responseKeys: Array.isArray(entry?.responseKeys) ? entry.responseKeys : [] })) : [], telemetryCount: Array.isArray(parsedDiagnostics?.telemetry) ? parsedDiagnostics.telemetry.length : 0, failedTelemetry: safeFailedTelemetry(parsedDiagnostics?.telemetry) })}.`);
    checks.push("Failure diagnostic OpenKey/browser auth captured; raw diagnostics omitted after secret audit.");
  } catch (diagnosticError) {
    blockers.push(`Failure diagnostic OpenKey/browser auth unavailable: ${diagnosticError instanceof Error ? diagnosticError.message : String(diagnosticError)}`);
  }
  for (const entry of children) {
    const output = entry.output();
    if (output.length > 0) {
      const outputLines = output.split("\n");
      const policyStages = outputLines.filter((line) => line.includes("policy session bridge rejected") || line.includes("policy session rejected"));
      if (policyStages.length > 0) checks.push(`Failure diagnostic policy stage observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const persistenceFailures = outputLines.filter((line) => line.includes("native share KV put failed"));
      if (persistenceFailures.length > 0) checks.push(`Failure diagnostic native persistence failure observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const delegationFailures = outputLines.filter((line) => line.includes("addressed delegation authorization failed"));
      if (delegationFailures.length > 0) checks.push(`Failure diagnostic addressed delegation failure observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const scopeFailures = outputLines.filter((line) => line.includes("share scope validation failed"));
      if (scopeFailures.length > 0) checks.push(`Failure diagnostic share scope failure observed in child ${entry.child.pid}; raw output omitted after secret audit.`);
      const registrationFailures = outputLines.filter((line) => line.includes("Owner share policy registration failed:"));
      if (registrationFailures.length > 0) {
        const normalized = registrationFailures.map((line) => line.replace(/.*Owner share policy registration failed:\s*/, "").replace(/[^A-Za-z0-9_ :.-]/g, "").slice(0, 120));
        checks.push(`Failure diagnostic owner policy registration result ${JSON.stringify(normalized)}.`);
      }
      const invitationFailures = outputLines.filter((line) => line.includes("credential invitation stage="));
      if (invitationFailures.length > 0) checks.push(`Failure diagnostic ${invitationFailures.map((line) => line.trim()).join(", ")}.`);
      checks.push(`Failure diagnostic child ${entry.child.pid}: output omitted after secret audit; ${output.length} bytes were captured.`);
    }
  }
} finally {
  await cleanup();
}

/*
 * TC-307. The gate is scoped to the slices named by
 * SHARING_E2E_REQUIRED_SLICES (default: the blueprint's first slice,
 * `bearer`), so one broken flow can no longer mask six working ones. The
 * artifact is not scoped: it names every slice, every unproven flow, and
 * whether a slice failed or was never attempted, and `status: "complete"` is
 * reserved for a run that proved all of them. A scoped pass exits 0 while
 * still reading, in the artifact and on stdout, as partial.
 */
const sliceReport = summarizeSlices({ slices: GATE_SLICES, flowResults: gateResults, attempted: [...attemptedSlices], failures: Object.fromEntries(sliceFailures), blockedBy: blockedSlices });
if (tc465Joined) {
  if (tc465Evidence === undefined) blockers.push(`Dedicated ${tc500Joined ? "TC-500" : "TC-465"} joined browser evidence was not received.`);
  const passed = blockers.length === 0 && upstreamRoutingAudit.allLoopback && tc465Evidence !== undefined;
  await writeArtifact(passed ? "complete" : "blocked", passed ? `${tc500Joined ? "TC-500 accountless" : "TC-465"} exact-email receiver joined path completed.` : `${tc500Joined ? "TC-500 accountless" : "TC-465"} exact-email receiver joined path is blocked.`);
  process.exitCode = passed ? 0 : 1;
  process.exit();
}
const verdict = gateVerdict(sliceReport, requiredSlices);
for (const slice of sliceReport) {
  if (slice.status === "passed") continue;
  const message = `Gate slice ${slice.name} (${slice.summary}) is ${slice.status}: ${slice.detail}.`;
  if (verdict.failedRequiredSlices.includes(slice.name)) blockers.push(message); else checks.push(`${message} It is outside the required slice scope (${requiredSlices.join(", ")}) and is reported as unproven, not as a pass.`);
}
const infrastructureClean = blockers.length === 0 && upstreamRoutingAudit.allLoopback && gateResults.browser && externalRequests.length === 0;
const gatePassed = infrastructureClean && verdict.requiredSlicesPassed;
const complete = infrastructureClean && verdict.allSlicesPassed;
await writeArtifact(complete ? "complete" : "blocked", gateSummary(verdict), [], { sliceReport, verdict });
process.exitCode = gatePassed ? 0 : 1;
