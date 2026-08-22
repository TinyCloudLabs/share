/** Native bearer smoke: built viewer, real loopback node, and no legacy harness. */
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { tmpdir } from "node:os";
import puppeteer from "puppeteer";
import { createHermeticEncryptedNode } from "../../../../../js-sdk/feat/tinycloud-native-sharing/packages/node-sdk/src/test-support/hermetic-encrypted-node.ts";
import { composeNativeBearer } from "../../src/share/native-bearer.ts";

const root = resolve(import.meta.dirname, "../..");
const bytes = new Uint8Array([0, 255, 1, 13, 10, 128, 65]);
const path = "native/bearer.bin";
const mime: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".wasm": "application/wasm", ".json": "application/json" };

function config(nodeOrigin: string): string {
  return JSON.stringify({ version: "tinycloud.share-email-claim/config-v1", shareOrigin: "https://share.example", registryOrigin: "https://registry.example", nodeOrigin, credentialsOrigin: "https://credentials.example", emailOrigin: "https://email.example", nodeAudience: "did:web:node.test", enforcerDid: "did:web:node.test", nodeEnabled: true, issuerDid: "did:web:issuer.example", issuerVct: "opencredentials.email/v1", issuerEnabled: true, nodeInvitationKid: "did:web:node.test#1", nodeInvitationPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nodeKeyVersion: 1, issuerKeyVersion: 1, issuerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", environment: "test" });
}

async function startViewer(nodeOrigin: string): Promise<{ origin: string; stop(): Promise<void> }> {
  let server!: Server;
  server = createServer(async (request, response) => {
    const pathname = new URL(request.url ?? "/", "http://viewer.invalid").pathname;
    if (pathname === "/.well-known/tinycloud-share/config.json") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); response.end(config(nodeOrigin)); return;
    }
    const file = pathname === "/viewer" ? "viewer.html" : pathname.replace(/^\//, "") || "index.html";
    try { const body = await readFile(resolve(root, "dist", file)); response.writeHead(200, { "content-type": mime[extname(file)] ?? "application/octet-stream" }); response.end(body); }
    catch { response.writeHead(404); response.end("not found"); }
  });
  await new Promise<void>((resolveReady) => server.listen(0, "127.0.0.1", resolveReady));
  const address = server.address(); assert(address && typeof address !== "string");
  return { origin: `http://127.0.0.1:${address.port}`, stop: async () => new Promise<void>((resolveStop) => server.close(() => resolveStop())) };
}

async function main(): Promise<void> {
  const fixture = await createHermeticEncryptedNode({ nativeBearerPath: path });
  const viewer = await startViewer("https://node.test");
  const downloadDir = await mkdtemp(resolve(tmpdir(), "tinycloud-native-bearer-"));
  try {
    const share = await composeNativeBearer(fixture.owner, { path, bytes, expiresAt: new Date(Date.now() + 60_000), viewerOrigin: "https://share.example", contentType: "application/octet-stream" });
    assert.equal(share.spaceId, fixture.applicationsSpaceId);
    const url = `${viewer.origin}/viewer${new URL(share.url).hash}`;
    const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
    try {
      const page = await browser.newPage();
      page.setDefaultTimeout(10_000);
      await page.setBypassCSP(true);
      const traffic: string[] = [];
      await page.setRequestInterception(true);
      page.on("request", async (request) => {
        traffic.push(request.url());
        if (new URL(request.url()).origin === "https://node.test") {
          const forwarded = await fetch(`${fixture.host}${new URL(request.url()).pathname}`, { method: request.method(), headers: request.headers(), body: ["GET", "HEAD"].includes(request.method()) ? null : request.postData() ?? null });
          await request.respond({ status: forwarded.status, headers: Object.fromEntries(forwarded.headers), body: Buffer.from(await forwarded.arrayBuffer()) });
        } else await request.continue();
      });
      await page.goto(url, { waitUntil: "networkidle0" });
      await page.waitForSelector(".viewer-download");
      assert.equal(await page.evaluate(() => location.hash), "", "fragment was not scrubbed before viewer work");
      const client = await page.createCDPSession();
      await client.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: downloadDir });
      await page.click(".viewer-download");
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
      const names = await (await import("node:fs/promises")).readdir(downloadDir);
      assert.equal(names.length, 1); assert.deepEqual(new Uint8Array(await readFile(resolve(downloadDir, names[0]!))), bytes);
      assert(traffic.every((value) => { const origin = new URL(value).origin; return origin === viewer.origin || origin === fixture.host; }), `forbidden browser traffic: ${traffic.join(", ")}`);
      assert(traffic.some((value) => new URL(value).origin === fixture.host), "viewer did not invoke owner node");
      const revoked = await fixture.owner.revokeDelegation(share.delegationCid); assert.equal(revoked.ok, true);
      const reopening = await browser.newPage();
      reopening.setDefaultTimeout(10_000);
      await reopening.setBypassCSP(true);
      await reopening.setRequestInterception(true);
      reopening.on("request", async (request) => {
        traffic.push(request.url());
        if (new URL(request.url()).origin === "https://node.test") {
          const forwarded = await fetch(`${fixture.host}${new URL(request.url()).pathname}`, { method: request.method(), headers: request.headers(), body: request.postData() ?? null });
          await request.respond({ status: forwarded.status, headers: Object.fromEntries(forwarded.headers), body: Buffer.from(await forwarded.arrayBuffer()) });
        } else await request.continue();
      });
      await reopening.goto(url, { waitUntil: "networkidle0" });
      await reopening.waitForSelector(".recipient-shell-error");
    } finally { await browser.close(); }
  } finally { fixture.stop(); await viewer.stop(); await rm(downloadDir, { recursive: true, force: true }); }
}

await main();
