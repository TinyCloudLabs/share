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
import { createHash } from "node:crypto";
import { createServer as httpServer } from "node:http";
import { createConnection } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { privateKeyToAccount } from "viem/accounts";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/feat/sharing-experience-e2e");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE ?? join(workspaceRoot, "worktrees/opencredentials/feat/sharing-experience-e2e");
const credentialsManifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
const artifactPath = join(workspaceRoot, ".context/sharing-experience-e2e-result.json");
const canonical = Object.freeze({
  share: "https://share.tinycloud.xyz",
  node: "https://node.tinycloud.xyz",
  credentials: "https://witness.credentials.org",
  registry: "https://registry.tinycloud.xyz",
});
// The mounted Node fixture's policy owner is the secp256k1 key made from 32
// bytes of 0x55. Using that same deterministic account makes the real Share
// OpenKey session own the capability material published by the fixture.
const walletPrivateKey = `0x${"55".repeat(32)}`;
const issuerPublicKey = "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY";
const issuerSecret = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "KN2IoJYLuoxXahdaAVOhhdnOjnRZ1S_deGwfdLsYmHg", d: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M" });
const wallet = privateKeyToAccount(walletPrivateKey);
const agentBrowser = process.env.AGENT_BROWSER_BIN ?? "/Users/samgbafa/.nvm/versions/node/v20.19.4/bin/agent-browser";
const children = [];
const servers = [];
const checks = [];
const blockers = [];
const gateResults = { exactEmail: false, domain: false, bearer: false, editConflict: false, folder: false, notification: false, denialMatrix: false, browser: false };
let sessionName = `sharing-e2e-${process.pid}`;
let externalRequests = [];

function b64(value) { return Buffer.from(value).toString("base64url"); }
function sha256(value) { return createHash("sha256").update(value).digest("base64url"); }
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function fakeTrustBundle(nodePublicKey = "A".repeat(43)) {
  return JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1", shareOrigin: canonical.share, returnOrigin: canonical.share, registryOrigin: canonical.registry, credentialsOrigin: canonical.credentials, nodeOrigin: canonical.node, nodeAudience: "did:web:node.tinycloud.xyz", nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-key-1", nodeInvitationPublicKey: nodePublicKey, nodeKeyVersion: 1, nodeEnabled: true, issuerDid: "did:web:issuer.credentials.org", issuerVct: "opencredentials.email/v1", issuerKid: "did:web:issuer.credentials.org#email-signing-key-1", issuerPublicKey, issuerKeyVersion: 1, issuerEnabled: true });
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
  checks.push(`${label} fixture listening on 127.0.0.1:${port}.`);
  return `http://127.0.0.1:${port}`;
}
function run(command, args, cwd, env = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], detached: true });
  let output = "";
  const collect = (chunk) => { output += String(chunk); if (output.length > 32_000) output = output.slice(-32_000); };
  child.stdout.on("data", collect); child.stderr.on("data", collect);
  children.push({ child, output: () => output });
  return child;
}
async function waitFor(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const response = await fetch(url, { redirect: "error" }); if (response.status < 500) return response; } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`timed out waiting for ${url}`);
}
async function waitForTcp(port, timeoutMs = 30_000) {
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
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`timed out waiting for loopback TCP port ${port}`);
}
async function runOnce(command, args, cwd, env = {}) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += String(chunk); });
  child.stderr.on("data", (chunk) => { output += String(chunk); });
  const [code] = await once(child, "exit");
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
function agent(args) {
  return new Promise((resolveAgent, rejectAgent) => {
    const child = spawn(agentBrowser, ["--session", sessionName, ...args], { cwd: shareRoot, env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.once("error", rejectAgent); child.once("exit", (code) => code === 0 ? resolveAgent(stdout.trim()) : rejectAgent(new Error(`agent-browser ${args.join(" ")} failed: ${stderr || stdout}`)));
  });
}
function walletBootstrap(walletOrigin) {
  return `(function () {\n    var address = ${JSON.stringify(wallet.address)};\n    var provider = {\n      selectedAddress: address, chainId: "0x1",\n      request: async function (input) {\n        var method = input.method;\n        if (method === "eth_accounts" || method === "eth_requestAccounts") return [address];\n        if (method === "eth_chainId") return "0x1";\n        if (method === "wallet_getPermissions" || method === "wallet_requestPermissions") return [{ parentCapability: "eth_accounts" }];\n        if (method === "personal_sign") {\n          var params = input.params || [];\n          var raw = String(params.length > 0 ? params[0] : "");\n          var hex = raw.indexOf("0x") === 0 ? raw.slice(2) : null;\n          var octets = hex === null ? [] : (hex.match(/.{1,2}/g) || []).map(function (value) { return parseInt(value, 16); });\n          var message = hex === null ? raw : new TextDecoder().decode(new Uint8Array(octets));\n          var response = await fetch(${JSON.stringify(walletOrigin + "/sign")}, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: message }) });\n          if (!response.ok) throw new Error("deterministic wallet refused the signing request");\n          return (await response.json()).signature;\n        }\n        return null;\n      }, on: function () { return provider; }, removeListener: function () { return provider; }, isConnected: function () { return true; }\n    };\n    var announce = function () { window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { uuid: "8fd9b04a-e8a0-4c43-9d87-5af504aa1f0d", name: "TinyCloud E2E Wallet", icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E", rdns: "xyz.tinycloud.e2e-wallet" }, provider: provider } })); };\n    window.ethereum = provider;\n    window.addEventListener("eip6963:requestProvider", announce); announce();\n  })()`;
}
const openKeyWidget = `<!doctype html><meta charset="utf-8"><script>parent.postMessage({type:"openkey:ready"},"*");setTimeout(()=>parent.postMessage({type:"openkey:auth:use-external-wallet"},"*"),0);addEventListener("message",e=>{if(e.data&&e.data.type==="openkey:auth:request")parent.postMessage({type:"openkey:auth:use-external-wallet"},"*")});</script>`;

async function startFixtures(tempRoot) {
  const walletOrigin = await loopback("deterministic EIP-1193/EIP-6963 wallet", async (request, response) => {
    if (request.url !== "/sign") { response.writeHead(404).end(); return; }
    const caller = request.headers.origin;
    const cors = /^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(caller ?? "") ? { "access-control-allow-origin": caller, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type", vary: "Origin" } : {};
    if (request.method === "OPTIONS") { response.writeHead(204, cors).end(); return; }
    if (request.method !== "POST") { response.writeHead(405, cors).end(); return; }
    const chunks = []; request.on("data", (chunk) => chunks.push(chunk)); request.on("end", async () => { try { const body = JSON.parse(Buffer.concat(chunks).toString()); const signature = await wallet.signMessage({ message: body.message }); response.writeHead(200, { ...cors, "content-type": "application/json" }).end(JSON.stringify({ address: wallet.address, signature })); } catch { response.writeHead(400, cors).end(); } });
  });
  const openKeyOrigin = await loopback("OpenKey external-wallet/SIWE widget", (request, response) => {
    if (!request.url?.startsWith("/widget/")) { response.writeHead(404).end(); return; }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(`<!doctype html><meta charset="utf-8"><script>parent.postMessage({type:"openkey:ready"},"*");setTimeout(()=>parent.postMessage({type:"openkey:auth:use-external-wallet"},"*"),0);addEventListener("message",e=>{if(e.data&&e.data.type==="openkey:auth:request")parent.postMessage({type:"openkey:auth:use-external-wallet"},"*")});</script>`);
  });
  const registry = run("npm", ["run", "-w", "@tinycloud/share-registry", "dev-server", "--", "--port", "0"], shareRoot);
  let registryOrigin;
  const registryDeadline = Date.now() + 30_000;
  while (registryOrigin === undefined && Date.now() < registryDeadline) {
    const output = children.find((entry) => entry.child === registry)?.output() ?? "";
    registryOrigin = output.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
    if (registryOrigin === undefined) await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  if (registryOrigin === undefined) throw new Error("real Share registry did not publish a loopback URL");
  checks.push(`real Share registry started at ${registryOrigin}.`);

  const mailMessages = [];
  const mail = await loopback("Resend-compatible mail capture", (request, response) => {
    if (request.method === "POST" && request.url === "/emails") {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error("mail payload");
          mailMessages.push(body);
          response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ id: `hermetic-mail-${mailMessages.length}` }));
        } catch {
          response.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid mail payload" }));
        }
      });
      return;
    }
    if (request.method === "GET" && request.url === "/emails") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify({ messages: mailMessages }));
      return;
    }
    if (request.method === "POST" && request.url === "/emails/reset") {
      mailMessages.length = 0;
      response.writeHead(204).end();
      return;
    }
    response.writeHead(404).end();
  });

  const postgresData = join(tempRoot, "postgres");
  const postgresPort = await freePort();
  await runOnce("/opt/homebrew/opt/postgresql@16/bin/initdb", ["-D", postgresData, "-A", "trust", "-U", "samgbafa"], shareRoot, { LC_ALL: "C" });
  run("/opt/homebrew/opt/postgresql@16/bin/postgres", ["-D", postgresData, "-h", "127.0.0.1", "-p", String(postgresPort)], shareRoot, { PGUSER: "samgbafa" });
  await waitForTcp(postgresPort);
  checks.push(`hermetic Postgres persistence started on 127.0.0.1:${postgresPort}.`);

  const nodeDescriptorPath = join(tempRoot, "node.json");
  const node = run("cargo", ["run", "--quiet", "-p", "tinycloud-node-production-e2e", "--features", "mounted-fixture", "--", "--descriptor", nodeDescriptorPath, "--issuer-public-key", issuerPublicKey, "--keys-secret", Buffer.alloc(32, 9).toString("base64url")], nodeRoot, { TINYCLOUD_KEYS_SECRET: Buffer.alloc(32, 9).toString("base64url") });
  const nodeDescriptor = await descriptor(nodeDescriptorPath, node, "production Node");
  checks.push(`real Node production router/persistence started at ${nodeDescriptor.url}.`);

  const credentialsPort = await freePort();
  const credentials = run("cargo", ["run", "--quiet", "--manifest-path", credentialsManifest, "--features", "email-claim-fixture", "--bin", "opencredentials-witness"], credentialsRoot, {
    BIND_ADDR: `127.0.0.1:${credentialsPort}`, CORS_ALLOWED_ORIGINS: canonical.share, DID_WEB: "did:web:issuer.credentials.org", OPENCREDENTIALS_SK: issuerSecret,
    SHARE_EMAIL_CAPABILITY: "true", SHARE_HERMETIC_COMPOSITION: "true", EMAIL_CLAIM_FIXTURE_DATABASE_URL: `postgres://127.0.0.1:${postgresPort}/postgres?sslmode=disable`, SHARE_EMAIL_RESEND_ENDPOINT: `${mail}/emails`,
    SHARE_EMAIL_TRUSTED_NODE_ORIGIN: canonical.node, SHARE_EMAIL_TRUSTED_NODE_AUDIENCE: "did:web:node.tinycloud.xyz", SHARE_EMAIL_TRUSTED_NODE_KID: "did:web:node.tinycloud.xyz#invitation-key-1", SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY: nodeDescriptor.trustedNode?.invitationPublicKey ?? "A".repeat(43),
    SHARE_EMAIL_TRUST_BUNDLE_JSON: fakeTrustBundle(nodeDescriptor.trustedNode?.invitationPublicKey), SHARE_EMAIL_SHARE_URL: canonical.share, RESEND_API_KEY: "hermetic-provider-key", RESEND_WEBHOOK_SECRET: "hermetic-webhook",
  });
  const credentialsOrigin = `http://127.0.0.1:${credentialsPort}`;
  await waitFor(`${credentialsOrigin}/share-email/readiness`, 30_000);
  checks.push(`real OpenCredentials production router/store started at ${credentialsOrigin}.`);
  return { walletOrigin, openKeyOrigin, registryOrigin, nodeOrigin: nodeDescriptor.url, nodeDescriptor, credentialsOrigin, mailOrigin: mail, mailMessages };
}

function senderCapability(nodeDescriptor) {
  const fixture = nodeDescriptor.cases?.find((entry) => entry.kind === "kv");
  if (fixture === undefined) throw new Error("mounted Node fixture did not publish a KV sharing case");
  const policyBytes = canonicalJson(fixture.policy);
  const policy = {
    action: fixture.source.action,
    authorityMaterialDigest: fixture.authorityMaterialDigest,
    contentSourceDigest: fixture.expectedContentSourceDigest,
    delegationCid: fixture.delegationCid,
    expiresAt: fixture.expiresAt,
    policyAuthorityBytes: fixture.authorityMaterial.policyAuthorityBytes,
    policyAuthorityCid: fixture.authorityMaterial.policyAuthorityCid,
    policyBytes: b64(policyBytes),
    policyDigest: sha256(policyBytes),
    policyEnforcementBytes: fixture.authorityMaterial.policyEnforcementBytes,
    policyEnforcementCid: fixture.authorityMaterial.policyEnforcementCid,
    policyCid: fixture.policyCid,
    recipientEmail: fixture.expectedRecipientEmail,
    resource: fixture.source.path,
    source: fixture.source,
    target: { origin: canonical.node, nodeAudience: "did:web:node.tinycloud.xyz", spaceId: fixture.source.space },
  };
  return JSON.stringify({
    scope: {
      policyOwnerDid: fixture.policyOwnerDid,
      senderDid: fixture.senderDid,
      targetOrigin: canonical.node,
      nodeAudience: "did:web:node.tinycloud.xyz",
      spaceId: fixture.source.space,
      delegation: fixture.delegation,
      delegationCid: fixture.delegationCid,
      authorityMaterialHandle: fixture.authorityMaterialHandle,
      authorityMaterialDigest: fixture.authorityMaterialDigest,
      documentName: fixture.documentName,
      senderTrust: "verified",
      trustedNode: fixture.trustedNode,
      expiryMin: fixture.expiresAt,
      expiryMax: fixture.expiresAt,
      expiresAt: fixture.expiresAt,
      actions: ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"],
      prefixes: ["documents"],
      resources: [{ kind: "exact", path: fixture.source.path }, { kind: "prefix", path: "documents/" }],
      authorityMaterial: fixture.authorityMaterial,
    },
    source: fixture.source,
    policy,
  });
}

async function startShare(tempRoot, fixtures) {
  const port = await freePort();
  const trustPath = join(tempRoot, "trust.json");
  const bindingPath = join(tempRoot, "bindings.ndjson");
  const registryKey = Buffer.alloc(32, 7).toString("base64url");
  const origin = `http://127.0.0.1:${port}`;
  await writeFile(trustPath, fakeTrustBundle(fixtures.nodeDescriptor.trustedNode?.invitationPublicKey ?? "A".repeat(43)), { flag: "wx" });
  await runOnce("npm", ["run", "build"], shareRoot, { VITE_OPENKEY_ORIGIN: fixtures.openKeyOrigin, VITE_SHARE_ORIGIN: canonical.share, VITE_SHARE_REGISTRY_URL: `${origin}/registry`, VITE_SHARE_HERMETIC: "true" });
  const share = run("npm", ["run", "preview", "--", "--host", "127.0.0.1", "--port", String(port)], shareRoot, {
    SHARE_TRUST_BUNDLE_FILE: trustPath, SHARE_TRUST_BUNDLE_ALLOW_TEST: "true", SHARE_SENDER_ENABLED: "true", SHARE_SENDER_PRIVATE_KEY: Buffer.alloc(32, 0x44).toString("base64url"), SHARE_SENDER_CAPABILITY_JSON: senderCapability(fixtures.nodeDescriptor), SHARE_BINDING_STORE_PATH: bindingPath, SHARE_REGISTRY_UPLOAD_PRIVATE_KEY: registryKey,
    SHARE_HERMETIC_COMPOSITION: "true", SHARE_HERMETIC_OPENKEY_ORIGIN: fixtures.openKeyOrigin, SHARE_HERMETIC_WALLET_ORIGIN: fixtures.walletOrigin, SHARE_HERMETIC_UPSTREAMS_JSON: JSON.stringify({ node: { origin: canonical.node, transportOrigin: fixtures.nodeOrigin }, credentials: { origin: canonical.credentials, transportOrigin: fixtures.credentialsOrigin ?? "http://127.0.0.1:9" }, registry: { origin: canonical.registry, transportOrigin: fixtures.registryOrigin } }), SHARE_E2E_MAIL_CAPTURE_ORIGIN: fixtures.mailOrigin, VITE_SHARE_REGISTRY_URL: canonical.registry,
  });
  await waitFor(`${origin}/share.html`);
  checks.push(`production-shaped Share preview started at ${origin}.`);
  return { origin, share };
}

async function browserGate(origin, walletOrigin, mailOrigin) {
  await fetch(`${mailOrigin}/emails/reset`, { method: "POST" });
  const initialMail = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.deepEqual(initialMail.messages, []);
  checks.push("Mail capture reset and confirmed zero delivery attempts before browser link creation.");
  await agent(["network", "requests", "--clear"]);
  await agent(["open", `${origin}/share.html`]);
  await agent(["eval", "document.querySelector('.auth-button')?.disabled === false"]);
  await agent(["eval", "--base64", Buffer.from(walletBootstrap(walletOrigin)).toString("base64")]);
  await agent(["eval", "(function(){var original=Element.prototype.attachShadow;Element.prototype.attachShadow=function(init){var options=init||{};options.mode='open';return original.call(this,options);};})()"]);
  await agent(["click", "button.auth-button"]);
  await agent(["wait", "1000"]);
  await agent(["find", "text", "TinyCloud E2E Wallet", "click"]);
  await agent(["wait", "text=Share with intent."]);
  checks.push("agent-browser completed the real OpenKey external-wallet/SIWE authentication path with a deterministic EIP-1193/EIP-6963 provider.");

  await agent(["select", "select[name=content-mode]", "author"]);
  await agent(["fill", "textarea[name=author-content]", "# Hermetic sharing\n\nMarkdown created in the browser."]);
  await agent(["select", "select[name=format]", "compact"]);
  await agent(["click", "input[value=bearer]"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Your private link is ready"]);
  const compact = await agent(["get", "value", "#generated-share-link"]);
  assert.match(compact, /^https:\/\/share\.tinycloud\.xyz\/s\/[^#]+#k=/);
  checks.push("Browser-created Markdown produced an encrypted compact link.");

  await agent(["click", "button.button-secondary"]);
  await agent(["select", "select[name=content-mode]", "upload"]);
  await agent(["upload", "input[name=document]", join(shareRoot, "test/e2e-sharing/fixture.md")]);
  await agent(["select", "select[name=format]", "inline"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Your private link is ready"]);
  const inline = await agent(["get", "value", "#generated-share-link"]);
  assert.match(inline, /^https:\/\/share\.tinycloud\.xyz\/s\/inline#v=2&p=/);
  checks.push("Browser upload produced an encrypted inline link.");

  const localCompact = new URL(compact); localCompact.protocol = "http:"; localCompact.host = new URL(origin).host;
  await agent(["eval", `location.href=${JSON.stringify(localCompact.href)}`]);
  await agent(["wait", "1500"]);
  const viewerSnapshot = await agent(["snapshot"]);
  if (!viewerSnapshot.includes("shared via link")) throw new Error(`viewer did not render the compact share; local compact=${localCompact.href}; snapshot=${viewerSnapshot.slice(0, 2000)}`);
  const renderedMarkdown = await agent(["eval", "document.querySelector('iframe')?.srcdoc.includes('Hermetic sharing') === true"]);
  assert.equal(renderedMarkdown, "true");
  gateResults.bearer = true;
  checks.push("Bearer compact link rendered the encrypted Markdown in the isolated viewer.");
  const bearerMail = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.deepEqual(bearerMail.messages, []);
  checks.push("Bearer link creation remained link-only with zero mail delivery attempts.");

  const requestsPayload = JSON.parse(await agent(["network", "requests", "--json"]));
  const requests = Array.isArray(requestsPayload) ? requestsPayload : Array.isArray(requestsPayload.data) ? requestsPayload.data : requestsPayload.data?.requests ?? [];
  externalRequests = requests.filter((entry) => { try { const url = new URL(entry.url); return url.protocol !== "http:" || (url.hostname !== "127.0.0.1" && url.hostname !== "localhost"); } catch { return true; } });
  if (externalRequests.length !== 0) blockers.push(`Browser attempted non-loopback destinations: ${JSON.stringify(externalRequests.map((entry) => entry.url).slice(0, 20))}`);
  else { gateResults.browser = true; checks.push("agent-browser network audit observed zero unmocked external destinations."); }

  // Addressed flows intentionally continue in the same authenticated browser
  // session. The composer keeps link creation and delivery separate, so the
  // mail capture must remain empty until the explicit confirmation button is
  // pressed.
  await agent(["click", "button.button-secondary"]);
  await agent(["click", "input[value=exactEmail]"]);
  await agent(["fill", "input[name=recipient-value]", "sam@tinycloud.xyz"]);
  await agent(["select", "select[name=content-mode]", "author"]);
  await agent(["fill", "textarea[name=author-content]", "# Exact email\n\nEncrypted exact-recipient Markdown."]);
  await agent(["click", "input[name=notify]"]);
  await agent(["fill", "input[name=delivery-email]", "sam@tinycloud.xyz"]);
  await agent(["click", "button.create-link-button"]);
  await agent(["wait", "text=Your private link is ready"]);
  const exactUrl = await agent(["get", "value", "#generated-share-link"]);
  assert.match(exactUrl, /^https:\/\/share\.tinycloud\.xyz\/s\//);
  const beforeConfirm = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.deepEqual(beforeConfirm.messages, []);
  checks.push("Encrypted exact-email link was created without delivery; mail capture remained empty before confirmation.");
  await agent(["click", "button.confirm-notification"]);
  await agent(["wait", "text=Notification queued"]);
  const exactMail = await (await fetch(`${mailOrigin}/emails`)).json();
  assert.equal(exactMail.messages.length, 1);
  const exactMailText = JSON.stringify(exactMail.messages[0]);
  assert.match(exactMailText, /sam@tinycloud\.xyz/);
  assert.match(exactMailText, /https:\/\/share\.tinycloud\.xyz\/s\//);
  gateResults.exactEmail = true;
  gateResults.notification = true;
  checks.push("Explicit confirmation queued exactly one exact-address notification and the captured message contained the exact Share URL.");
}

async function nativeGate() {
  const sdkRoot = join(workspaceRoot, "worktrees/js-sdk/feat/sharing-experience-e2e");
  const jobs = [
    ["Share Vitest suite", shareRoot, "npm", ["test"]],
    ["Share typecheck", shareRoot, "npm", ["run", "typecheck"]],
    ["js-sdk sdk-core suite", join(sdkRoot, "packages/sdk-core"), "bun", ["test"]],
    ["js-sdk sdk-services suite", join(sdkRoot, "packages/sdk-services"), "bun", ["test"]],
    ["tinycloud-auth email evidence", nodeRoot, "cargo", ["test", "-p", "tinycloud-auth", "share_email_evidence"]],
    ["tinycloud-core share-email suite", nodeRoot, "cargo", ["test", "-p", "tinycloud-core", "share_email", "--lib"]],
    ["tinycloud-node native share suite", nodeRoot, "cargo", ["test", "-p", "tinycloud-node", "share_email", "--lib"]],
    ["OpenCredentials verifier suite", credentialsRoot, "cargo", ["test", "--manifest-path", join(credentialsRoot, "rust/opencredentials_verify/Cargo.toml")]],
    ["OpenCredentials witness suite", credentialsRoot, "cargo", ["test", "--manifest-path", credentialsManifest]],
  ];
  const failures = [];
  for (const [label, cwd, command, args] of jobs) {
    try {
      await runOnce(command, args, cwd);
      checks.push(`Native check passed: ${label}.`);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      checks.push(`Native check failed: ${label}: ${detail}`);
      failures.push(`${label}: ${detail}`);
    }
  }
  if (failures.length > 0) throw new Error(`Native gate failed: ${failures.join(" | ")}`);
}

async function writeArtifact(status, summary, extraBlockers = []) {
  const result = { status, summary, browserE2ePassed: gateResults.browser && gateResults.bearer && gateResults.exactEmail && gateResults.domain && gateResults.editConflict && gateResults.folder && gateResults.notification && gateResults.denialMatrix, exactEmailPassed: gateResults.exactEmail, domainPassed: gateResults.domain, bearerPassed: gateResults.bearer, editConflictPassed: gateResults.editConflict, folderPassed: gateResults.folder, notificationPassed: gateResults.notification, denialMatrixPassed: gateResults.denialMatrix, zeroExternalDestinations: gateResults.browser && externalRequests.length === 0, checks: [...new Set(checks)], blockers: [...new Set([...blockers, ...extraBlockers])] };
  await writeFile(artifactPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
}

let tempRoot;
let share;
try {
  tempRoot = await mkdtemp(join(tmpdir(), "tinycloud-sharing-e2e-"));
  await nativeGate();
  const fixtures = await startFixtures(tempRoot);
  share = await startShare(tempRoot, fixtures);
  await browserGate(share.origin, fixtures.walletOrigin, fixtures.mailOrigin);
} catch (error) {
  blockers.push(error instanceof Error ? error.message : String(error));
} finally {
  try { await agent(["close"]); } catch {}
  await stopAll();
  await closeAll();
  if (tempRoot !== undefined) await rm(tempRoot, { recursive: true, force: true });
}

const missingFlows = Object.entries({ exactEmail: gateResults.exactEmail, domain: gateResults.domain, bearer: gateResults.bearer, editConflict: gateResults.editConflict, folder: gateResults.folder, notification: gateResults.notification, denialMatrix: gateResults.denialMatrix }).filter(([, passed]) => !passed).map(([name]) => name);
if (missingFlows.length > 0) blockers.push(`Browser gate did not pass required flow(s): ${missingFlows.join(", ")}.`);
const complete = blockers.length === 0 && gateResults.browser && gateResults.bearer && gateResults.exactEmail && gateResults.domain && gateResults.editConflict && gateResults.folder && gateResults.notification && gateResults.denialMatrix && externalRequests.length === 0;
await writeArtifact(complete ? "complete" : "blocked", complete ? "Hermetic production-shaped sharing browser gate passed." : "Hermetic gate executed the real local composition and recorded the release blockers without inferring success.");
process.exitCode = complete ? 0 : 1;
