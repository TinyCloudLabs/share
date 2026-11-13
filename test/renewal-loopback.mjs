/** Library reload through the published SDK and a real loopback scheduler. Details: TC-2872 */
import { createHash, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { closeSync, chmodSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const worktree = process.cwd();
const nodeBinary = "/var/tmp/tc2904-node-artifact/tinycloud";
const expectedNodeBinarySha256 = "58645b7c9bec9a0d45584c0aca7a8c37bb08ab7b9aad926af05763687d053edd";
const nodeSourceCommit = "3efdddc997eb112803166d6f45a99d8c25344715";
const sdkCommit = process.env.TC2872_SDK_COMMIT;
const preflightOnly = process.env.TC2872_PREFLIGHT_ONLY === "1";
if (!/^[a-f0-9]{40}$/.test(sdkCommit ?? "")) throw new Error("Set TC2872_SDK_COMMIT to the reviewed published SDK commit.");
const [{ blake3 }, { ed25519 }, { bases }] = await Promise.all([
  import(pathToFileURL(join(worktree, "node_modules/@noble/hashes/blake3.js")).href),
  import(pathToFileURL(join(worktree, "node_modules/@noble/curves/ed25519.js")).href),
  import(pathToFileURL(join(worktree, "node_modules/multiformats/dist/src/basics.js")).href),
]);
const { TinyCloudNode } = await import(join(worktree, "node_modules/@tinycloud/node-sdk/dist/index.js"));

const proofId = randomBytes(6).toString("hex");
const root = `/var/tmp/tc2872-share-${proofId}`;
const privateDir = join(root, "private");
const evidencePath = join(root, "evidence.json");
mkdirSync(privateDir, { recursive: true, mode: 0o700 });
chmodSync(root, 0o700);
chmodSync(privateDir, 0o700);
const dataDir = join(privateDir, "data");
const home = join(privateDir, "home");
const tmp = join(privateDir, "tmp");
for (const dir of [dataDir, home, tmp]) mkdirSync(dir, { recursive: true, mode: 0o700 });

async function installRestoreObserver() {
  await import("/src/share/openkey-session.ts");
  const sdkUrl = performance.getEntriesByType("resource").map((entry) => entry.name).find((url) => new URL(url).pathname.includes("tc2872-sdk-config"));
  if (!sdkUrl) throw new Error("The app SDK module URL is unavailable.");
  const { TinyCloudWeb } = await import(sdkUrl);
  const originalRestore = TinyCloudWeb.prototype.restoreSessionWithRenewal;
  if (typeof originalRestore !== "function") throw new Error("SDK restore observer is unavailable.");
  TinyCloudWeb.prototype.restoreSessionWithRenewal = async function (...args) {
    try {
      const result = await originalRestore.apply(this, args);
      await window.recordProofRestore({ status: result.status, code: result.error?.code, message: result.error?.message, causeCode: result.error?.cause?.code, causeMessage: result.error?.cause?.message });
      return result;
    } catch (error) {
      await window.recordProofRestore({ status: "threw", code: error?.code, message: error?.message });
      throw error;
    }
  };
  return { installed: true, sdkPath: new URL(sdkUrl).pathname, sdkUrl };
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
function didFromSecret(secret, context) {
  const seed = blake3(Buffer.concat([secret, Buffer.from(context, "utf8")]));
  const publicKey = ed25519.getPublicKey(seed);
  const multicodec = Uint8Array.from([0xed, 0x01, ...publicKey]);
  return `did:key:${bases.base58btc.encode(multicodec)}`;
}
async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not reserve loopback port");
  const port = address.port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}
async function closeServer(server) {
  if (!server?.listening) return;
  await new Promise((resolve) => server.close(() => resolve()));
}
async function waitForNode(child, origin, expected) {
  const deadline = Date.now() + 20_000;
  let lastStatus = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`owned node exited before readiness (exit=${child.exitCode}, signal=${child.signalCode ?? "none"})`);
    try {
      const response = await fetch(`${origin}/.well-known/tinycloud/node-keys`, { signal: AbortSignal.timeout(1_000) });
      lastStatus = response.status;
      if (response.ok) {
        const keys = await response.json();
        if (keys.nodeDid !== expected.nodeDid || keys.renewerDid !== expected.renewerDid) {
          throw new Error("loopback node identity did not match the synthetic key-derived identity");
        }
        if (!Number.isSafeInteger(keys.renewerEpoch) || keys.renewerEpoch < 0) throw new Error("invalid renewer epoch");
        return keys;
      }
    } catch (error) {
      if (String(error?.message ?? "").includes("identity did not match") || String(error?.message ?? "").includes("invalid renewer epoch")) throw error;
    }
    await delay(250);
  }
  throw new Error(`owned node readiness timeout (last status ${lastStatus ?? "none"})`);
}
function startNode(origin, port, configPath, logPath) {
  const logFd = openSync(logPath, "a", 0o600);
  const child = spawn(nodeBinary, [], {
    cwd: privateDir,
    env: {
      PATH: "/usr/bin:/bin",
      HOME: home,
      TC_HOME: home,
      TMPDIR: tmp,
      TINYCLOUD_CONFIG_FILE: configPath,
      ROCKET_ADDRESS: "127.0.0.1",
      ROCKET_PORT: String(port),
    },
    stdio: ["ignore", logFd, logFd],
  });
  closeSync(logFd);
  return child;
}
async function stopNode(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = once(child, "exit").then(() => true);
  if (await Promise.race([exited, delay(10_000).then(() => false)])) return;
  child.kill("SIGKILL");
  await Promise.race([once(child, "exit"), delay(2_000)]);
}

const evidence = {
  result: "FAIL",
  stage: "setup",
  proofId,
  nodeBinary: { path: nodeBinary, sha256: null, sourceCommit: nodeSourceCommit },
  sdk: { commit: sdkCommit, artifactsSha256: {} },
  contactedOrigins: [],
  httpTrace: [],
  registryHttpTrace: [],
  mode: preflightOnly ? "preflight-only" : "full",
};
let nodeChild;
let registry;
let owner;
let restored;
let browser;
let vite;
let closingBrowser = false;
async function waitUntil(deadline) {
  while (Date.now() < deadline) {
    if (!browser.isConnected()) {
      evidence.browserDisconnectedAt ??= new Date().toISOString();
      throw new Error("Owned proof browser disconnected during the real-clock wait.");
    }
    await delay(Math.min(5000, deadline - Date.now()));
  }
}
let stage = "setup";
const progressPath = join(root, "progress.json");
const progressTimer = setInterval(() => { writeFileSync(progressPath, JSON.stringify({ stage, at: new Date().toISOString(), root }), { mode: 0o600 }); }, 5000);
const originalFetch = globalThis.fetch;
const ownerKey = randomBytes(32).toString("hex");
const staticSecret = randomBytes(32);
const expectedIdentity = {
  nodeDid: didFromSecret(staticSecret, "tinycloud/node/identity"),
  renewerDid: didFromSecret(staticSecret, "tinycloud/node/renewer/v1"),
};
let nodePort;
let registryPort;
let nodeOrigin;
let registryOrigin;
let statusThroughBrowser = false;
try {
  evidence.consumerHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: worktree, encoding: "utf8" }).trim();
  execFileSync("git", ["diff", "--quiet"], { cwd: worktree });
  evidence.consumerSources = Object.fromEntries(["src/share/main.ts", "src/share/library-session.ts", "src/share/openkey-session.ts", "package-lock.json"].map((path) => [path, sha256(join(worktree, path))]));
  evidence.nodeBinary.sha256 = sha256(nodeBinary);
  if (evidence.nodeBinary.sha256 !== expectedNodeBinarySha256) throw new Error("supplied node binary SHA-256 mismatch");
  evidence.sdk.packages = {};
  for (const name of ["sdk-core", "node-sdk", "web-sdk", "node-sdk-wasm", "web-sdk-wasm", "share-sdk", "share-envelope", "sdk-services", "replica"]) {
    const path = join(worktree, `node_modules/@tinycloud/${name}/package.json`);
    evidence.sdk.packages[name] = JSON.parse(readFileSync(path, "utf8")).version;
  }

  stage = "loopback-listeners";
  nodePort = await freePort();
  registryPort = await freePort();
  nodeOrigin = `http://127.0.0.1:${nodePort}`;
  registryOrigin = `http://127.0.0.1:${registryPort}`;
  registry = createServer((request, response) => {
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-headers", "content-type, authorization");
    if (request.method === "OPTIONS") { response.writeHead(204); response.end(); return; }
    evidence.registryHttpTrace.push({ method: request.method, path: request.url, status: 404 });
    response.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
    response.end('{"error":"location record not found"}');
  });
  await new Promise((resolve, reject) => {
    registry.once("error", reject);
    registry.listen(registryPort, "127.0.0.1", resolve);
  });

  const configPath = join(privateDir, "tinycloud.toml");
  const tomlString = (value) => JSON.stringify(value);
  const secretBase64 = staticSecret.toString("base64url");
  const toml = `[default]\naddress = "127.0.0.1"\nport = ${nodePort}\nlog_level = "critical"\n\n[default.storage]\ndatadir = ${tomlString(dataDir)}\ndatabase = ${tomlString(`sqlite:${join(dataDir, "caps.db")}?mode=rwc`)}\n\n[default.keys]\ntype = "Static"\nsecret = ${tomlString(secretBase64)}\n\n[default.telemetry]\nenabled = false\n\n[default.epoch_head_backfill]\nenabled = false\n`;
  writeFileSync(configPath, toml + `\n[default.encryption_network]\nnamed_keys_v1 = true\ndeletion_ledger_path = ${tomlString(join(privateDir, "deletions.jsonl"))}\n`, { mode: 0o600 });
  chmodSync(configPath, 0o600);
  const nodeLog = join(privateDir, "node.log");

  stage = "first-node-start";
  nodeChild = startNode(nodeOrigin, nodePort, configPath, nodeLog);
  const initialIdentity = await waitForNode(nodeChild, nodeOrigin, expectedIdentity);
  evidence.node = { did: initialIdentity.nodeDid, renewerDid: initialIdentity.renewerDid, epoch: initialIdentity.renewerEpoch };

  stage = "sdk-network-guard";
  const allowedOrigins = new Set([nodeOrigin, registryOrigin]);
  globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
    if (url.origin === "https://registry.tinycloud.xyz") { url.host = `127.0.0.1:${registryPort}`; url.protocol = "http:"; input = url.toString(); }
    if (statusThroughBrowser && url.origin === nodeOrigin && url.pathname === "/delegation/status") {
      url.host = `127.0.0.1:${browserPort}`;
      input = url.toString();
    }
    if (!allowedOrigins.has(url.origin)) throw new Error("SDK attempted a non-loopback request; blocked by proof harness");
    const response = await originalFetch(input, init);
    evidence.contactedOrigins.push(url.origin);
    evidence.httpTrace.push({ origin: url.origin === nodeOrigin ? "loopback-node" : url.origin === registryOrigin ? "loopback-registry" : "loopback-browser", method: init?.method ?? (input instanceof Request ? input.method : "GET"), path: url.pathname, status: response.status });
    return response;
  };

  stage = "browser-fixture";
  const { createServer: createViteServer } = await import("vite");
  const { default: puppeteer } = await import("puppeteer");
  const { PUPPETEER_REVISIONS } = await import("puppeteer-core/internal/revisions.js");
  const browserPort = await freePort();
  const browserOrigin = `http://127.0.0.1:${browserPort}`;
  allowedOrigins.add(browserOrigin);
  const sdkFixtureModule = "\0tc2872-sdk-config";
  evidence.fixtureSDKConfig = { scope: "hermetic-library-only", registryUrl: registryOrigin, hostHint: browserOrigin };
  const sdkFixturePlugin = {
    name: "renewal-loopback-sdk-config", enforce: "pre",
    resolveId(id) { if (id === "@tinycloud/web-sdk") return sdkFixtureModule; },
    load(id) {
      if (id !== sdkFixtureModule) return;
      return `export * from "tc2872-published-web-sdk";
import { TinyCloudWeb as PublishedTinyCloudWeb } from "tc2872-published-web-sdk";
export class TinyCloudWeb extends PublishedTinyCloudWeb {
  constructor(config) {
    if (config.tinycloudRegistryUrl !== null || config.sessionStorageKeyPrefix !== "tinycloud-share-library-" || config.tinycloudHosts?.length !== 1 || config.tinycloudHosts[0] !== ${JSON.stringify(browserOrigin)}) throw new Error("Fixture expects the hermetic library SDK config.");
    super({ ...config, tinycloudRegistryUrl: ${JSON.stringify(registryOrigin)} });
  }
}`;
    },
  };
  vite = await createViteServer({ root: worktree, resolve: { alias: { "tc2872-published-web-sdk": join(worktree, "node_modules/@tinycloud/web-sdk/dist/index.mjs") } }, optimizeDeps: { entries: ["src/share/main.ts"], include: ["tc2872-published-web-sdk"] }, define: { "import.meta.env.VITE_SHARE_HERMETIC": JSON.stringify("true") }, server: { host: "127.0.0.1", port: browserPort, strictPort: true, warmup: { clientFiles: ["./src/share/main.ts", "./src/share/sender-home.ts", "./src/share/sender-chrome.ts"] }, proxy: { "^/(delegate|delegation|invoke|peer|info|\\.well-known)": nodeOrigin } }, plugins: [sdkFixturePlugin, { name: "renewal-loopback-fixture", configureServer(server) {
    server.middlewares.use((request, response, next) => {
      if (request.url === "/proof") { response.setHeader("content-type", "text/html"); response.end('<!doctype html><div id="share-app"></div>'); return; }
      if (request.url === "/.well-known/tinycloud-share/config.json") { response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ version: "tinycloud.share/config-v2", environment: "test", shareOrigin: "https://share.fixture.test", senderBootstrapNodeOrigin: "https://node.fixture.test", registryOrigin: "https://registry.fixture.test", credentialsOrigin: "https://witness.fixture.test", accountlessReceiverEnabled: false })); return; }
      next();
    });
  } }] });
  await vite.listen();
  await vite.waitForRequestsIdle();
  browser = await puppeteer.launch({ executablePath: process.env.TC2872_CHROME, headless: true, userDataDir: join(privateDir, "chrome"), args: ["--no-sandbox", "--disable-dev-shm-usage"], env: { PATH: process.env.PATH, HOME: home, TC_HOME: home, TMPDIR: tmp } });
  evidence.browserLaunchedAt = new Date().toISOString();
  browser.on("disconnected", () => { if (!closingBrowser) evidence.browserDisconnectedAt = new Date().toISOString(); });
  const browserVersion = await browser.version();
  evidence.browserVersion = browserVersion;
  if (!browserVersion.endsWith("/" + PUPPETEER_REVISIONS.chrome)) throw new Error("Use the Chrome version pinned by Puppeteer.");
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  const browserBlockedOrigins = new Set();
  evidence.browserBlockedOrigins = [];
  evidence.browserHttpTrace = [];
  await page.exposeFunction("recordProofRestore", (result) => {
    const clean = (value) => typeof value === "string" ? value.replace(/0x[0-9a-fA-F]{64,}|[A-Za-z0-9_-]{100,}/g, "[redacted]").slice(0, 1200) : value;
    evidence.sdkRestore = { stage, status: result.status, code: result.code, message: clean(result.message), causeCode: result.causeCode, causeMessage: clean(result.causeMessage), at: new Date().toISOString() };
  });
  page.on("response", (response) => {
    if (["fetch", "xhr"].includes(response.request().resourceType())) evidence.browserHttpTrace.push({ stage, path: new URL(response.url()).pathname, status: response.status(), contentType: response.headers()["content-type"] });
  });
  page.on("requestfailed", (request) => {
    if (["fetch", "xhr"].includes(request.resourceType())) evidence.browserHttpTrace.push({ stage, path: new URL(request.url()).pathname, failure: request.failure()?.errorText });
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (["data:", "blob:"].includes(url.protocol) || (url.origin === browserOrigin || url.origin === registryOrigin)) void request.continue();
    else { browserBlockedOrigins.add(url.origin); evidence.browserBlockedOrigins = [...browserBlockedOrigins]; void request.abort(); }
  });
  await page.goto(`${browserOrigin}/proof`);
  await page.evaluate(async () => {
    const entry = await import("/src/share/main.ts");
    if (typeof entry.resumeLibraryWithRenewal !== "function") throw new Error("library entry unavailable");
  });
  evidence.restoreObserverPreflight = await page.evaluate(installRestoreObserver);
  const { PrivateKeySigner, MemorySessionStorage } = await import("@tinycloud/node-sdk");
  const { parseSignedSiweCacao } = await import("@tinycloud/sdk-core");
  const signer = new PrivateKeySigner(ownerKey);
  const address = await signer.getAddress();
  const manifest = await page.evaluate(async (address) => (await import("/src/share/openkey-session.ts")).shareManifest(address), address);
  const storage = new MemorySessionStorage();
  owner = new TinyCloudNode({ privateKey: ownerKey, host: nodeOrigin, newUserHost: nodeOrigin, tinycloudRegistryUrl: registryOrigin, autoDiscoverLocalNode: false, autoCreateSpace: true, autoBootstrapAccount: false, persistSession: true, sessionStorage: storage, includeAccountRegistryPermissions: true, domain: "share.fixture.test", spacePrefix: "applications", sessionExpirationMs: 960_000, manifest });
  stage = "synthetic-owner-sign-in";
  await owner.signIn();
  await owner.ensureOwnedSpaceHosted("account");
  const persisted = await storage.load(address);
  if (!persisted) throw new Error("no persisted original");
  const originalSession = owner.restorableSession;
  const original = await parseSignedSiweCacao(originalSession.delegationHeader.Authorization.replace(/^Bearer\s+/i, ""), originalSession.delegationCid);
  const originalExpiryMs = Date.parse(persisted.expiresAt);
  if (originalExpiryMs > Date.now() + 970_000 || originalExpiryMs < Date.now() + 900_000) throw new Error("unexpected original lifetime");
  evidence.original = { cid: original.cid, expiresAt: persisted.expiresAt, manifestApp: manifest.app_id };
  stage = "finite-owner-lease-admission";
  const receipt = await owner.createRenewalLease(new Date(Date.now() + 1_200_000));
  const leaseAuthorization = receipt.leaseAuthorization;
  if (typeof leaseAuthorization !== "string") throw new Error("missing lease authorization");
  evidence.lease = { originalCid: receipt.originalCid, leaseCid: receipt.leaseCid, expiresAt: receipt.leaseExpiresAt };
  const proofPath = "xyz.tinycloud.share/shares/renewal-proof";
  const proofValue = "library-renewal-" + proofId;
  const put = await owner.kv.put(proofPath, proofValue);
  if (!put.ok) throw new Error("original write refused");
  await page.evaluate(async ({ persisted, address, browserOrigin, sdkUrl }) => {
    const { BrowserSessionStorage } = await import(sdkUrl);
    const { LIBRARY_SESSION_PREFIX, saveLibraryAccount } = await import("/src/share/library-session.ts");
    const sessions = new BrowserSessionStorage({ keyPrefix: LIBRARY_SESSION_PREFIX });
    await sessions.save(address, { ...persisted, tinycloudHosts: [browserOrigin] });
    saveLibraryAccount({ address, keyId: "synthetic-owner", keyType: "MANAGED" });
  }, { persisted, address, browserOrigin, sdkUrl: evidence.restoreObserverPreflight.sdkUrl });
  stage = "browser-live-preflight";
  evidence.browserIdentityPreflight = await page.evaluate(async () => {
    const response = await fetch("/.well-known/tinycloud/node-keys");
    if (!response.ok) throw new Error("Browser node identity preflight refused.");
    const identity = await response.json();
    return { nodeDid: identity.nodeDid, renewerDid: identity.renewerDid, renewerEpoch: identity.renewerEpoch };
  });
  if (evidence.browserIdentityPreflight.nodeDid !== initialIdentity.nodeDid || evidence.browserIdentityPreflight.renewerDid !== initialIdentity.renewerDid || evidence.browserIdentityPreflight.renewerEpoch !== initialIdentity.renewerEpoch) throw new Error("Browser identity preflight differs from the owned node.");
  evidence.browserLiveReadPreflight = await page.evaluate(async ({ address, proofPath, proofValue }) => {
    const { createTinyCloudClient, reopenOpenKey } = await import("/src/share/openkey-session.ts");
    const { loadSharePublicConfig } = await import("/src/email-share/config.ts");
    const client = await createTinyCloudClient(reopenOpenKey({ address, keyId: "synthetic-owner", keyType: "MANAGED" }), await loadSharePublicConfig(), () => undefined);
    const unlocked = await client.vault.unlock();
    if (!unlocked.ok) throw new Error("Live library vault preflight refused.");
    const read = await client.kv.get(proofPath);
    if (!read.ok || read.data.data !== proofValue) throw new Error("Live library read preflight refused.");
    return { readOk: true, exactValueMatch: true, unlocked: true };
  }, { address, proofPath, proofValue });
  await page.reload();
  stage = "signed-live-status-preflight";
  statusThroughBrowser = true;
  let liveStatus;
  try { liveStatus = await owner.getDelegationStatus(original.cid); } finally { statusThroughBrowser = false; }
  evidence.liveStatusPreflight = liveStatus.ok
    ? { ok: true, exists: liveStatus.data.exists, active: liveStatus.data.active, status: liveStatus.data.status }
    : { ok: false, code: liveStatus.error.code, message: liveStatus.error.message };
  if (!liveStatus.ok || !liveStatus.data.exists || !liveStatus.data.active) throw new Error("Signed live-status preflight refused.");
  if (preflightOnly) {
    evidence.result = "PREFLIGHT_PASS";
    stage = "preflight-complete";
  } else {
    stage = "wait-real-original-expiry";
    evidence.waitStartedAt = new Date().toISOString();
    writeFileSync(evidencePath, JSON.stringify(evidence, null, 2), { mode: 0o600 });
    await waitUntil(originalExpiryMs - 15_000);
    const near = await owner.kv.get(proofPath);
    if (!near.ok) throw new Error("near-expiry original read refused");
    await waitUntil(originalExpiryMs + 1_500);
    stage = "actual-library-reload";
    if (execFileSync("git", ["rev-parse", "HEAD"], { cwd: worktree, encoding: "utf8" }).trim() !== evidence.consumerHead) throw new Error("Consumer head changed during the proof.");
    execFileSync("git", ["diff", "--quiet"], { cwd: worktree });
    await page.reload();
    await page.evaluate(installRestoreObserver);
    const result = await page.evaluate(async ({ leaseAuthorization, proofPath, proofValue }) => {
      const { savedLibraryAccount, savedLibraryRenewalAccount } = await import("/src/share/library-session.ts");
      const ordinaryExpired = savedLibraryAccount() === undefined;
      const candidate = await savedLibraryRenewalAccount(leaseAuthorization);
      if (!ordinaryExpired || !candidate) throw new Error("candidate discovery did not preserve ordinary expiry");
      const { resumeLibraryWithRenewal } = await import("/src/share/main.ts");
      const status = document.createElement("p");
      const client = await resumeLibraryWithRenewal(leaseAuthorization, status);
      const read = await client.kv.get(proofPath);
      if (!read.ok || read.data.data !== proofValue) throw new Error("library read mismatch");
      return { ordinaryExpired, candidateFound: true, readOk: true, exactValueMatch: true, effectiveExpiry: await client.getRenewalEffectiveExpiry(leaseAuthorization), status: status.textContent };
    }, { leaseAuthorization, proofPath, proofValue });
    evidence.library = result;
    evidence.browserBlockedOrigins = [...browserBlockedOrigins];
    evidence.restoreAfterOriginalExpiry = Date.now() > originalExpiryMs;
    evidence.result = "PASS";
    stage = "complete";
  }
} catch (error) {
  evidence.result = evidence.browserDisconnectedAt ? "INVALIDATED" : "FAIL";
  evidence.errorName = error?.name;
  evidence.error = String(error?.message ?? error).replace(/[A-Za-z0-9_-]{100,}/g, "[redacted]").slice(0, 1200);
} finally {
  clearInterval(progressTimer);
  evidence.stage = stage;
  evidence.finishedAt = new Date().toISOString();
  closingBrowser = true;
  await browser?.close();
  await vite?.close();
  globalThis.fetch = originalFetch;
  await stopNode(nodeChild);
  await closeServer(registry);
  await owner?.signOut();
  writeFileSync(progressPath, JSON.stringify({ stage, result: evidence.result, at: new Date().toISOString(), root }), { mode: 0o600 });
  writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600 });
  console.log(JSON.stringify({ result: evidence.result, stage, evidencePath }));
  process.exitCode = ["PASS", "PREFLIGHT_PASS"].includes(evidence.result) ? 0 : 1;
}
