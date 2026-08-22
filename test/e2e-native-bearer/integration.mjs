/** Native bearer smoke: built viewer, real loopback node, and no legacy harness. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import process from "node:process";
import puppeteer from "puppeteer";
import { composeNativeBearer, nativeBearerHistoryRecord } from "../../src/share/native-bearer.ts";

const sdkWorktree = process.env.TINYCLOUD_JS_SDK_WORKTREE?.trim();
assert(sdkWorktree, "TINYCLOUD_JS_SDK_WORKTREE is required so the native E2E uses an explicit companion SDK checkout");
const fixtureModule = pathToFileURL(resolve(sdkWorktree, "packages/node-sdk/src/test-support/hermetic-encrypted-node.ts")).href;
const { createHermeticEncryptedNode } = await import(fixtureModule);

const root = resolve(import.meta.dirname, "../..");
const bytes = new Uint8Array([0, 255, 1, 13, 10, 128, 65]);
const path = "native/bearer.bin";
const configuredNodeOrigin = "https://node.test";
const mime = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".wasm": "application/wasm", ".json": "application/json" };

function config() {
  return JSON.stringify({ version: "tinycloud.share-email-claim/config-v1", shareOrigin: "https://share.example", registryOrigin: "https://registry.example", nodeOrigin: configuredNodeOrigin, credentialsOrigin: "https://credentials.example", emailOrigin: "https://email.example", nodeAudience: "did:web:node.test", enforcerDid: "did:web:node.test", nodeEnabled: true, issuerDid: "did:web:issuer.example", issuerVct: "opencredentials.email/v1", issuerEnabled: true, nodeInvitationKid: "did:web:node.test#1", nodeInvitationPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nodeKeyVersion: 1, issuerKeyVersion: 1, issuerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", environment: "test" });
}

async function startViewer(ownerOrigin) {
  let server;
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url ?? "/", "http://viewer.invalid").pathname;
    if (pathname === "/.well-known/tinycloud-share/config.json") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); response.end(config()); return;
    }
    const file = pathname === "/viewer" ? "viewer.html" : pathname.replace(/^\//, "") || "index.html";
    try {
      let body = await readFile(resolve(root, "dist", file));
      if (file === "viewer.html") {
        body = Buffer.from(body.toString("utf8").replace("connect-src 'self'", `connect-src 'self' ${configuredNodeOrigin} ${ownerOrigin}`));
      }
      response.writeHead(200, { "content-type": mime[extname(file)] ?? "application/octet-stream" }); response.end(body);
    } catch { response.writeHead(404); response.end("not found"); }
  });
  await new Promise((resolveReady) => server.listen(0, "127.0.0.1", resolveReady));
  const address = server.address(); assert(address && typeof address !== "string");
  return { origin: `http://127.0.0.1:${address.port}`, stop: async () => new Promise((resolveStop) => server.close(() => resolveStop())) };
}

function assertAllowedTraffic(traffic, viewerOrigin, ownerOrigin) {
  const allowed = new Set([viewerOrigin, configuredNodeOrigin, ownerOrigin]);
  assert(traffic.every((value) => allowed.has(new URL(value).origin)), `forbidden browser traffic: ${traffic.join(", ")}`);
}

async function instrumentPage(page, traffic, ownerOrigin) {
  page.setDefaultTimeout(10_000);
  await page.evaluateOnNewDocument(() => {
    const originalFetch = window.fetch.bind(window);
    window.__tinycloudFetchHashes = [];
    window.fetch = (...args) => {
      window.__tinycloudFetchHashes.push(window.location.hash);
      return originalFetch(...args);
    };
  });
  await page.setRequestInterception(true);
  page.on("request", async (request) => {
    traffic.push(request.url());
    if (new URL(request.url()).origin !== configuredNodeOrigin) {
      await request.continue();
      return;
    }
    const url = new URL(request.url());
    const forwarded = await fetch(`${ownerOrigin}${url.pathname}${url.search}`, {
      method: request.method(), headers: request.headers(),
      body: ["GET", "HEAD"].includes(request.method()) ? null : request.postData() ?? null,
    });
    await request.respond({ status: forwarded.status, headers: Object.fromEntries(forwarded.headers), body: Buffer.from(await forwarded.arrayBuffer()) });
  });
}

async function main() {
  const fixture = await createHermeticEncryptedNode({ nativeBearerPath: path });
  const viewer = await startViewer(fixture.host);
  const downloadDir = await mkdtemp(resolve(tmpdir(), "tinycloud-native-bearer-"));
  try {
    const initial = fixture.nativeBearerStats();
    const share = await composeNativeBearer(fixture.owner, { path, bytes, expiresAt: new Date(Date.now() + 60_000), viewerOrigin: "https://share.example", contentType: "application/octet-stream" });
    assert.equal(share.spaceId, fixture.applicationsSpaceId);
    const afterCompose = fixture.nativeBearerStats();
    assert.equal(afterCompose.delegations - initial.delegations, 1, "composer must create exactly one delegation");
    assert.equal(afterCompose.kvWrites - initial.kvWrites, 1, "composer must write content exactly once to the owner node");
    const record = nativeBearerHistoryRecord({ share, path, filename: "bearer.bin", target: { origin: configuredNodeOrigin, nodeAudience: "did:web:node.test" }, registeredAt: new Date("2026-08-22T00:00:00.000Z") });
    assert.equal(record.target.spaceId, fixture.applicationsSpaceId);
    assert.equal(record.enforcementDelegationCid, share.delegationCid);
    assert.deepEqual(record.resource, { kind: "exact", path });
    assert.deepEqual(record.actions, ["tinycloud.kv/get"]);

    const url = `${viewer.origin}/viewer${new URL(share.url).hash}`;
    const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
    try {
      const traffic = [];
      const page = await browser.newPage();
      await instrumentPage(page, traffic, fixture.host);
      await page.goto(url, { waitUntil: "networkidle0" });
      await page.waitForSelector(".viewer-download");
      assert.equal(await page.evaluate(() => location.hash), "");
      const fetchHashes = await page.evaluate(() => window.__tinycloudFetchHashes);
      assert(fetchHashes.length > 0, "viewer issued no instrumented application fetches");
      assert(fetchHashes.every((hash) => hash === ""), `fragment was present at application fetch: ${JSON.stringify(fetchHashes)}`);

      const client = await page.createCDPSession();
      await client.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: downloadDir });
      await page.click(".viewer-download");
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
      const names = await readdir(downloadDir);
      assert.equal(names.length, 1); assert.deepEqual(new Uint8Array(await readFile(resolve(downloadDir, names[0]))), bytes);
      assertAllowedTraffic(traffic, viewer.origin, fixture.host);
      assert(traffic.some((value) => new URL(value).origin === fixture.host || new URL(value).origin === configuredNodeOrigin), "viewer did not invoke owner node");
      assert.equal(fixture.nativeBearerStats().kvReads - afterCompose.kvReads, 1, "viewer must read the exact owner-node object once");

      const revoked = await fixture.owner.revokeDelegation(share.delegationCid); assert.equal(revoked.ok, true);
      assert.equal(fixture.nativeBearerStats().revocations - initial.revocations, 1, "owner node did not record the exact revocation");
      const trafficBeforeReopen = traffic.length;
      const reopening = await browser.newPage();
      await instrumentPage(reopening, traffic, fixture.host);
      await reopening.goto(url, { waitUntil: "networkidle0" });
      await reopening.waitForSelector(".recipient-shell-error");
      assert.equal(fixture.nativeBearerStats().revokedInvocations - initial.revokedInvocations, 1, "reopened link did not receive a node 403 for its revoked proof");
      assert(traffic.slice(trafficBeforeReopen).some((value) => new URL(value).origin === fixture.host || new URL(value).origin === configuredNodeOrigin), "reopened link did not reach the owner node");
      assertAllowedTraffic(traffic, viewer.origin, fixture.host);
    } finally { await browser.close(); }
  } finally { fixture.stop(); await viewer.stop(); await rm(downloadDir, { recursive: true, force: true }); }
}

await main();
