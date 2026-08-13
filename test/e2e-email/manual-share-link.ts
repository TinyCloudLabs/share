import { createHash, randomBytes } from "node:crypto";
import { execFile as execFileCallback, spawn, type ChildProcess } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { mkdtemp, mkdir, open, readFile, rename, rm, stat, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { createServer as createViteServer, type Plugin, type ViteDevServer } from "vite";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize, computeCid, didKeyFromEd25519PublicKey, fromBase64Url, open as openEnvelope, parseShareUrl, shareEnvelopeSchema, toBase64Url } from "@tinycloud/share-envelope";
import { createBearerShare } from "../../packages/cli/src/create.ts";
import { createShareLink } from "../../packages/share-sdk/src/index.ts";
import { createHttpTransport } from "../../src/email-share/transport.ts";
import { issueEmailClaimCredential } from "../../src/email-share/claim.ts";
import { readClaimedShare } from "../../src/email-share/node-client.ts";
import { verifyProductionEmailShare } from "../../src/email-share/runtime.ts";
import { validateSharePublicBinding, type SharePublicConfig } from "../../src/email-share/config.ts";
import { createExportableTestHolder, exportExportableTestHolder } from "./manual-holder.ts";
import { writeEmailPreview } from "./manual-email-preview.ts";
import type { ContentSource } from "../../src/email-share/protocol.ts";

type Json = Record<string, any>;
const execFile = promisify(execFileCallback);
const root = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(root, "../../../..");
const nodeRoot = process.env.TINYCLOUD_NODE_WORKTREE
  ?? resolve(root, "../../../tinycloud-node/feat/email-claim-n4-integration");
const credentialsRoot = process.env.OPENCREDENTIALS_WORKTREE
  ?? resolve(root, "../../../opencredentials/feat/email-claim-o4-integration");
const credentialsTarget = process.env.OPENCREDENTIALS_CARGO_TARGET_DIR
  ?? resolve(workspaceRoot, ".context/build-cache/opencredentials-manual-share");
const defaultArtifactPath = resolve(workspaceRoot, ".context/manual-share-link.json");
const email = "sam@tinycloud.xyz";

function b64(bytes: Uint8Array): string { return toBase64Url(bytes); }
function digest(value: string | Uint8Array): string { return createHash("sha256").update(value).digest("base64url"); }
function sleep(ms: number): Promise<void> { return new Promise((resolveSleep) => setTimeout(resolveSleep, ms)); }
function headers(): Record<string, string> { return { accept: "application/json", "content-type": "application/json" }; }

async function readBody(request: import("node:http").IncomingMessage): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
  const result = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
  return result;
}

async function listen(server: import("node:net").Server, port = 0): Promise<number> {
  await new Promise<void>((resolveListen, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolveListen); });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("local listener did not publish a port");
  return address.port;
}

async function waitJson(path: string, child: ChildProcess, diagnostics: () => string = () => ""): Promise<Json> {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    try { return JSON.parse(await readFile(path, "utf8")) as Json; } catch {}
    if (child.exitCode !== null) throw new Error("fixture exited before publishing readiness" + (diagnostics() ? ": " + diagnostics().slice(-4000) : ""));
    await sleep(250);
  }
  throw new Error("fixture readiness timeout");
}

async function processGroupMembers(pid: number): Promise<number[]> {
  try {
    const result = await execFile("pgrep", ["-g", String(pid)]);
    return result.stdout.split(/\s+/).filter(Boolean).map(Number).filter(Number.isInteger);
  } catch { return []; }
}

async function waitForEmptyProcessGroup(pid: number): Promise<number[]> {
  let members: number[] = [];
  for (let attempt = 0; attempt < 10; attempt += 1) {
    members = await processGroupMembers(pid);
    if (members.length === 0) return members;
    await sleep(100);
  }
  return members;
}

function pidExists(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function processPatternMatches(patterns: readonly string[]): Promise<string[]> {
  const result = await execFile("ps", ["-axo", "pid=,command="]);
  return result.stdout.split("\n").map((line) => line.trim()).filter((line) => patterns.some((pattern) => line.includes(pattern)));
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null) return true;
  return await new Promise<boolean>((resolveExit) => {
    let settled = false;
    const finish = (value: boolean) => { if (!settled) { settled = true; clearTimeout(timer); resolveExit(value); } };
    const timer = setTimeout(() => finish(false), timeoutMs);
    child.once("exit", () => finish(true));
  });
}

async function stopChild(child: ChildProcess | undefined): Promise<void> {
  if (child === undefined || child.pid === undefined) return;
  const pid = child.pid;
  const signalGroup = (signal: NodeJS.Signals) => {
    try { process.kill(-pid, signal); } catch { try { child.kill(signal); } catch {} }
  };
  if (child.exitCode === null) signalGroup("SIGTERM");
  await waitForExit(child, 2_500);
  let survivors = await waitForEmptyProcessGroup(pid);
  if (survivors.length > 0 || pidExists(pid)) signalGroup("SIGKILL");
  await waitForExit(child, 2_500);
  survivors = await waitForEmptyProcessGroup(pid);
  if (survivors.length > 0 || pidExists(pid)) throw new Error(`child process group ${pid} survived bounded cleanup: ${survivors.join(",") || pid}`);
}

async function closeWithDeadline(close: () => Promise<void>, label: string): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      close(),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} close timed out`)), 2_500); }),
    ]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

async function writeArtifact(value: Json, artifactPath: string, allowReplace: boolean, allowUntracked: boolean): Promise<void> {
  await mkdir(dirname(artifactPath), { recursive: true, mode: 0o700 });
  if (!allowUntracked) {
    try { await execFile("git", ["check-ignore", "-q", "--", ".context/manual-share-link.json"], { cwd: workspaceRoot }); }
    catch { throw new Error("manual artifact path is not ignored; refusing to write secrets"); }
  }
  try { await stat(artifactPath); throw new Error("manual artifact already exists; refusing replacement"); }
  catch (error) { if (error instanceof Error && error.message.startsWith("manual artifact") && !allowReplace) throw error; }
  const temporary = artifactPath + "." + process.pid + "." + randomBytes(8).toString("hex") + ".tmp";
  const handle = await open(temporary, "wx", 0o600);
  try { await handle.writeFile(JSON.stringify(value, null, 2) + "\n", "utf8"); await handle.sync(); } finally { await handle.close(); }
  await chmod(temporary, 0o600); await rename(temporary, artifactPath); await chmod(artifactPath, 0o600);
  if (((await stat(artifactPath)).mode & 0o777) !== 0o600) throw new Error("manual artifact permissions are not 0600");
}

async function fileDigest(path: string): Promise<string | undefined> {
  try { return digest(await readFile(path)); }
  catch (error) { if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined; throw error; }
}

async function makeCertificate(temp: string): Promise<{ cert: string; key: string; evidence: Json }> {
  const cert = join(temp, "share.localhost.pem");
  const key = join(temp, "share.localhost-key.pem");
  try { await execFile("mkcert", ["-cert-file", cert, "-key-file", key, "share.localhost", "*.share.localhost"]); }
  catch { throw new Error("mkcert is unavailable or its CA is not trusted; install/trust mkcert and retry"); }
  const { stdout: caRootOutput } = await execFile("mkcert", ["-CAROOT"]);
  const caRoot = caRootOutput.trim();
  const rootCertificate = join(caRoot, "rootCA.pem");
  const { stdout: certificateDetails } = await execFile("openssl", ["x509", "-in", cert, "-noout", "-subject", "-issuer", "-fingerprint", "-sha256", "-text"]);
  const { stdout: rootFingerprint } = await execFile("openssl", ["x509", "-in", rootCertificate, "-noout", "-fingerprint", "-sha256"]);
  await chmod(cert, 0o644); await chmod(key, 0o600);
  return { cert, key, evidence: { client: "curl-default-verification", caRoot, rootCertificate, rootFingerprint: rootFingerprint.trim(), certificate: certificateDetails.trim() } };
}

function optionValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function httpsOriginOption(name: string): string | undefined {
  const raw = optionValue(name);
  if (raw === undefined) return undefined;
  const parsed = new URL(raw);
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") throw new Error(`${name} must be an exact HTTPS origin with no credentials, path, query, or fragment`);
  return parsed.origin;
}

function portOption(name: string): number | undefined {
  const raw = optionValue(name);
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) throw new Error(`${name} must be an integer from 1 through 65535`);
  return parsed;
}

function allowHtmlConnectOrigin(origin: string): Plugin {
  return {
    name: "manual-share-connect-origin",
    enforce: "post",
    transformIndexHtml(html) {
      return html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]+)(">)/g, (_tag, start: string, policy: string, end: string) => {
        const rewritten = policy.replace(/connect-src ([^;]+)/, (directive, sources: string) => sources.split(/\s+/).includes(origin) ? directive : `connect-src ${sources} ${origin}`);
        return start + rewritten + end;
      });
    },
  };
}

const smoke = process.argv.includes("--smoke");
const testManualReplace = process.argv.includes("--test-manual-replace");
const siteOnly = process.argv.includes("--site-only");
const replaceArtifact = process.argv.includes("--replace-artifact") || testManualReplace;
const requestedPublicOrigin = httpsOriginOption("--public-origin");
const requestedNodePublicOrigin = httpsOriginOption("--node-public-origin");
const requestedListenPort = portOption("--listen-port");
const requestedNodeListenPort = portOption("--node-listen-port");

async function main(): Promise<void> {
  if (!siteOnly && (requestedPublicOrigin !== undefined || requestedNodePublicOrigin !== undefined || requestedListenPort !== undefined || requestedNodeListenPort !== undefined)) throw new Error("--public-origin, --node-public-origin, --listen-port, and --node-listen-port require --site-only");
  process.umask(0o077);
  const temp = await mkdtemp(join(tmpdir(), "tinycloud-manual-share-"));
  await chmod(temp, 0o700);
  const smokeOutput = smoke ? await mkdtemp(join(tmpdir(), "tinycloud-manual-share-smoke-")) : undefined;
  if (smokeOutput !== undefined) await chmod(smokeOutput, 0o700);
  const artifactPath = optionValue("--artifact") ?? process.env.MANUAL_SHARE_ARTIFACT_PATH ?? (smokeOutput === undefined ? defaultArtifactPath : join(smokeOutput, "manual-share-link.json"));
  const previewPath = optionValue("--preview") ?? process.env.MANUAL_SHARE_PREVIEW_PATH ?? `${artifactPath}.email.html`;
  let node: ChildProcess | undefined;
  let credentials: ChildProcess | undefined;
  let vite: ViteDevServer | undefined;
  let registry: ReturnType<typeof createHttpServer> | undefined;
  let httpsServer: ReturnType<typeof createHttpsServer> | undefined;
  let persistentArtifactDigest: string | undefined;
  let cleanupPromise: Promise<void> | undefined;
  const cleanupOnce = (): Promise<void> => {
    if (cleanupPromise !== undefined) return cleanupPromise;
    cleanupPromise = (async (): Promise<void> => {
    const failures: string[] = [];
    const attempt = async (label: string, operation: () => Promise<void>) => { try { await operation(); } catch (error) { failures.push(`${label}: ${error instanceof Error ? error.message : "unknown failure"}`); } };
    if (vite !== undefined) await attempt("Vite", () => closeWithDeadline(() => vite!.close(), "Vite"));
    if (httpsServer !== undefined) await attempt("HTTPS listener", () => closeWithDeadline(() => new Promise<void>((resolveClose) => httpsServer!.close(() => resolveClose())), "HTTPS listener"));
    await attempt("OpenCredentials child", () => stopChild(credentials));
    await attempt("Node child", () => stopChild(node));
    if (registry !== undefined) await attempt("registry listener", () => closeWithDeadline(() => new Promise<void>((resolveClose) => registry!.close(() => resolveClose())), "registry listener"));
    await attempt("owned process residue", async () => {
      const residue = await processPatternMatches([temp]);
      if (residue.length > 0) throw new Error(`task-owned process still references ${temp}: ${residue.join(" | ")}`);
    });
    await attempt("temporary files", () => rm(temp, { recursive: true, force: true }));
    if (smokeOutput !== undefined) await attempt("smoke output", () => rm(smokeOutput, { recursive: true, force: true }));
    if (failures.length > 0) throw new Error(`cleanup failed: ${failures.join("; ")}`);
    })();
    return cleanupPromise;
  };
  const handleSignal = (exitCode: number) => {
    void (async () => {
      try { await cleanupOnce(); }
      catch (error) { console.error(`manual-share-link cleanup blocked: ${error instanceof Error ? error.message : "unknown failure"}`); }
      finally { process.exit(exitCode); }
    })();
  };
  process.once("SIGINT", () => handleSignal(130));
  process.once("SIGTERM", () => handleSignal(143));
  try {
    if (smoke && !testManualReplace) throw new Error("--smoke requires --test-manual-replace");
    if (artifactPath !== defaultArtifactPath && !testManualReplace) throw new Error("non-persistent artifact paths require --test-manual-replace");
    persistentArtifactDigest = smoke ? await fileDigest(defaultArtifactPath) : undefined;
    const certificate = await makeCertificate(temp);
    const blobs = new Map<string, Uint8Array>();
    const bindings = new Map<string, Json>();
    registry = createHttpServer((request, response) => void (async () => {
      const pathname = new URL(request.url || "/", "http://registry").pathname;
      const last = pathname.split("/").pop() || "";
      if (request.method === "POST" && pathname === "/blobs") {
        const blob = await readBody(request);
        const cid = await computeCid(blob);
        const deleteAfter = request.headers["x-delete-after"];
        if (typeof deleteAfter !== "string") { response.writeHead(400).end(); return; }
        if (blobs.has(cid)) { response.writeHead(412).end(); return; }
        blobs.set(cid, blob);
        response.writeHead(201, headers()).end(JSON.stringify({ cid, deleteAfter }));
        return;
      }
      if (request.method === "POST" && pathname === "/bindings") {
        const value = JSON.parse(new TextDecoder().decode(await readBody(request))) as Json;
        bindings.set(String(value.shareCid), validateSharePublicBinding(value) as Json);
        response.writeHead(201).end();
        return;
      }
      if (request.method === "GET" && pathname.startsWith("/bindings/")) {
        const value = bindings.get(last);
        if (value === undefined) { response.writeHead(404).end(); return; }
        response.writeHead(200, { ...headers(), "cache-control": "no-store" }).end(JSON.stringify(value));
        return;
      }
      if (request.method === "GET" && pathname.startsWith("/ipfs/")) {
        const blob = blobs.get(last);
        if (blob === undefined) { response.writeHead(404).end(); return; }
        response.writeHead(200, { "content-type": "application/vnd.ipld.raw", "cache-control": "no-store" }).end(blob);
        return;
      }
      response.writeHead(404).end();
    })().catch(() => { if (!response.headersSent) response.writeHead(400); response.end(); }));
    const registryPort = await listen(registry);
    const registryLocal = "http://127.0.0.1:" + registryPort;
    httpsServer = createHttpsServer({ cert: await readFile(certificate.cert), key: await readFile(certificate.key) }, (_request, response) => response.writeHead(503, { "cache-control": "no-store" }).end("starting"));
    const publicPort = await listen(httpsServer, requestedListenPort);
    const localOrigin = "https://share.localhost:" + publicPort;
    const publicOrigin = requestedPublicOrigin ?? localOrigin;
    const publicUrl = new URL(publicOrigin);
    const nodePublicOrigin = requestedNodePublicOrigin ?? publicOrigin;
    const nodeAudience = "did:web:" + new URL(nodePublicOrigin).hostname;
    const invitationKid = nodeAudience + "#invitation-key-1";
    const nodeDescriptorPath = join(temp, "node.json");
    const issuerPublic = b64(ed25519.getPublicKey(new Uint8Array(32).fill(0x43)));
    const keysSecret = Buffer.alloc(32, 9).toString("base64url");
    const nodeArguments = ["run", "--quiet", "-p", "tinycloud-node-production-e2e", "--features", "mounted-fixture", "--", "--descriptor", nodeDescriptorPath, "--issuer-public-key", issuerPublic, "--keys-secret", keysSecret, "--target-origin", nodePublicOrigin, "--return-origin", publicOrigin, "--node-audience", nodeAudience, "--invitation-kid", invitationKid];
    if (requestedNodeListenPort !== undefined) nodeArguments.push("--listen-port", String(requestedNodeListenPort));
    node = spawn("cargo", nodeArguments, { cwd: nodeRoot, detached: true, stdio: ["ignore", "ignore", "pipe"] });
    let nodeOutput = "";
    node.stderr?.on("data", (chunk) => { nodeOutput = (nodeOutput + String(chunk)).slice(-2000); });
    node.on("exit", () => { if (nodeOutput.length > 0) nodeOutput = nodeOutput.slice(-2000); });
    const descriptor = await waitJson(nodeDescriptorPath, node, () => nodeOutput);
    const nodeLocal = descriptor.url as string;
    const fixture = (descriptor.cases as Json[]).find((candidate) => candidate.kind === "kv");
    if (fixture === undefined) throw new Error("mounted Node did not publish a KV fixture");
    const scope = fixture as Json;
    const source = scope.source as ContentSource;
    const senderSeed = new Uint8Array(32).fill(0x44);
    const senderPublicKey = ed25519.getPublicKey(senderSeed);
    const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
    const policyBytes = b64(new TextEncoder().encode(canonicalize(scope.policy)));
    const scopeForShare: any = {
      policyOwnerDid: scope.policyOwnerDid, senderDid,
      signingCapability: { capabilityId: b64(randomBytes(16)), publicKey: senderPublicKey },
      signer: { publicKey: senderPublicKey, sign: async (input: any) => ed25519.sign(new TextEncoder().encode((input.purpose === "envelope" ? "xyz.tinycloud.share/envelope/v1\0" : "xyz.tinycloud.share/invite-authorization/v1\0") + input.message), senderSeed) },
      shareOrigin: publicOrigin, delegation: scope.delegation, delegationCid: scope.delegationCid,
      authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest,
      authorityMaterial: scope.authorityMaterial, targetOrigin: nodePublicOrigin, nodeAudience, spaceId: source.space,
      documentName: "TinyCloud policy payload test", senderTrust: "verified", expiresAt: fixture.expiresAt,
      trustedNode: { targetOrigin: nodePublicOrigin, nodeAudience, invitationKid, invitationPublicKey: fromBase64Url(scope.trustedNode.invitationPublicKey), keyVersion: 1, enabled: true },
    };
    const policy = {
        recipientEmail: email, source, action: source.action, resource: source.path, expiresAt: fixture.expiresAt,
        target: { origin: nodePublicOrigin, nodeAudience, spaceId: source.space }, policyCid: fixture.policyCid,
        policyDigest: digest(canonicalize(scope.policy)), contentSourceDigest: scope.expectedContentSourceDigest,
        delegationCid: scope.delegationCid, authorityMaterialDigest: scope.authorityMaterialDigest,
        policyBytes, policyAuthorityCid: scope.authorityMaterial.mapping.policyAuthorityCid,
        policyAuthorityBytes: scope.authorityMaterial.policyAuthorityBytes, policyEnforcementCid: scope.authorityMaterial.mapping.policyEnforcementCid,
        policyEnforcementBytes: scope.authorityMaterial.policyEnforcementBytes,
    };
    if (siteOnly) {
      const trustBundle = descriptor.trustBundle as Json;
      const localRegistryOrigin = "https://registry.localhost";
      process.env.SHARE_TRUST_BUNDLE = JSON.stringify({ ...trustBundle, shareOrigin: publicOrigin, returnOrigin: publicOrigin, registryOrigin: localRegistryOrigin, credentialsOrigin: publicOrigin, emailOrigin: publicOrigin, nodeOrigin: nodePublicOrigin, nodeAudience, nodeInvitationKid: invitationKid });
      process.env.SHARE_TRUST_BUNDLE_ALLOW_TEST = "true";
      process.env.SHARE_SENDER_ENABLED = "false";
      process.env.SHARE_ACCOUNTLESS_RECEIVER_ENABLED = "false";
      delete process.env.SHARE_SENDER_PRIVATE_KEY;
      delete process.env.SHARE_SENDER_CAPABILITY_JSON;
      process.env.SHARE_TEST_BINDINGS_JSON = "{}";
      process.env.SHARE_HERMETIC_COMPOSITION = "true";
      process.env.SHARE_HERMETIC_UPSTREAMS_JSON = JSON.stringify({ node: { origin: nodePublicOrigin, transportOrigin: nodeLocal }, credentials: { origin: publicOrigin, transportOrigin: nodeLocal }, registry: { origin: localRegistryOrigin, transportOrigin: registryLocal } });
      process.env.VITE_SHARE_REGISTRY_URL = publicOrigin + "/registry";
      vite = await createViteServer({ root, plugins: [allowHtmlConnectOrigin(nodePublicOrigin)], server: { middlewareMode: true, allowedHosts: [publicUrl.hostname], hmr: { server: httpsServer, host: publicUrl.hostname, clientPort: Number(publicUrl.port || "443"), protocol: "wss" } }, appType: "spa" });
      httpsServer.removeAllListeners("request");
      httpsServer.on("request", (request, response) => {
        vite!.middlewares(request, response, () => { if (!response.headersSent) response.writeHead(404).end(); });
      });
      const created = await createBearerShare({
        content: new TextEncoder().encode("# Local TinyCloud share\n\nEdit the Share UI, refresh, and keep iterating locally.\n"),
        filename: "local-share.md",
        registryBaseUrl: registryLocal,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        origin: publicOrigin,
        viewerOrigin: publicOrigin,
        nodeAudience,
        spaceId: source.space,
      });
      console.log("local-share-site ready " + publicOrigin + "/share");
      console.log("local-share-link ready " + created.url);
      console.log("local-share-node ready " + nodePublicOrigin);
      console.log("local-share-edit-root " + root);
      await new Promise<void>((resolveWait) => { process.once("SIGINT", resolveWait); process.once("SIGTERM", resolveWait); });
      return;
    }
    const createAuthorizedLink = (lane: "browser" | "api") => createShareLink({
      email, source, scope: scopeForShare, shareId: `manual-share-${lane}-${Date.now()}-${b64(randomBytes(8))}`,
      expiresAt: fixture.expiresAt, now: new Date(Date.now() - 1000).toISOString(), policy,
      adapters: {
        uploadEnvelope: async (cid, blob) => { blobs.set(cid, blob); },
        publishBinding: async (binding) => {
          const requestBody = { shareCid: binding.shareCid, shareId: binding.shareId, policyCid: binding.policyCid, delegationCid: binding.delegationCid, authorityMaterialHandle: binding.authorityMaterialHandle, authorityMaterialDigest: binding.authorityMaterialDigest, recipientEmail: email, targetOrigin: publicOrigin, nodeAudience, action: source.action, resource: source.path };
          const request = { jti: b64(randomBytes(16)), reportAbuseToken: b64(randomBytes(16)), senderDid, shareCid: binding.shareCid, shareId: binding.shareId, policyCid: binding.policyCid, delegationCid: binding.delegationCid, authorityMaterialHandle: binding.authorityMaterialHandle, authorityMaterialDigest: binding.authorityMaterialDigest, recipientEmail: email, targetOrigin: publicOrigin, nodeAudience, documentName: "TinyCloud policy payload test", senderTrust: "verified", contentSource: source, contentSourceDigest: scope.expectedContentSourceDigest, shareExpiresAt: fixture.expiresAt, requestBodyDigest: digest(canonicalize(requestBody)) };
          const signature = ed25519.sign(new TextEncoder().encode("xyz.tinycloud.share/invite-authorization/v1\0" + canonicalize(request)), senderSeed);
          const result = await fetch(nodeLocal + "/share/v1/invitations/authorize", { method: "POST", headers: { ...headers(), origin: publicOrigin }, body: JSON.stringify({ request, proof: { alg: "EdDSA", kid: senderDid + "#" + senderDid.slice(8), signature: b64(signature) } }) });
          if (!result.ok) { const failure = (await result.json().catch(() => ({}))) as Json; throw new Error(`mounted Node rejected ${lane} invitation authorization status=${result.status} code=${String(failure.error?.code || "unknown")} diagnostics=${nodeOutput.slice(-1200)}`); }
          bindings.set(binding.shareCid as string, {
            shareId: binding.shareId,
            policyCid: binding.policyCid,
            expiry: binding.expiry,
            contentSourceDigest: scope.expectedContentSourceDigest,
            actionDigest: digest(canonicalize(source.action)),
            resourceDigest: digest(canonicalize(source.path)),
          });
        },
      },
    });
    const apiLink = await createAuthorizedLink("api");
    const browserLink = await createAuthorizedLink("browser");
    const resolveLegacyPolicyShare = async (shareUrl: string) => {
      const parsed = parseShareUrl(shareUrl, { expectedOrigin: publicOrigin });
      const blob = blobs.get(parsed.ciphertextCid);
      if (blob === undefined) throw new Error("manual share envelope is missing from the local registry");
      try {
        const envelope = shareEnvelopeSchema.parse(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await openEnvelope(blob, parsed.key32))));
        if (envelope.authorizationTarget.kind !== "policy") throw new Error("manual share is not policy addressed");
        const policy = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(envelope.authorizationTarget.policyBytes))) as Record<string, unknown>;
        return { state: "policy-email-claim-required" as const, envelope, shareCid: parsed.ciphertextCid, policy };
      } finally {
        parsed.key32.fill(0);
      }
    };
    const apiInvitationId = b64(randomBytes(16));
    const apiClaimSecret = b64(randomBytes(32));
    const browserInvitationId = b64(randomBytes(16));
    const browserClaimSecret = b64(randomBytes(32));
    if (apiInvitationId === browserInvitationId || apiClaimSecret === browserClaimSecret) throw new Error("manual invitation material collided");
    const commonProofScope = { policyCid: fixture.policyCid, delegationCid: scope.delegationCid, authorityMaterialHandle: scope.authorityMaterialHandle, authorityMaterialDigest: scope.authorityMaterialDigest, contentSource: source, contentSourceDigest: scope.expectedContentSourceDigest, targetOrigin: publicOrigin, nodeAudience, recipientEmail: email };
    const credentialDescriptorPath = join(temp, "credentials.json");
    credentials = spawn("cargo", ["run", "--quiet", "--manifest-path", resolve(credentialsRoot, "rust/opencredentials_witness/Cargo.toml"), "--features", "email-claim-fixture", "--bin", "email-claim-proof-fixture"], { cwd: resolve(credentialsRoot, "rust/opencredentials_witness"), detached: true, stdio: ["ignore", "pipe", "ignore"], env: { ...process.env, CARGO_TARGET_DIR: credentialsTarget, BIND_ADDR: "127.0.0.1:0", PROOF_SCOPE_JSON: JSON.stringify({ shareCid: apiLink.shareCid, shareId: apiLink.shareId, ...commonProofScope }), PROOF_INVITATIONS_JSON: JSON.stringify({ apiInvitation: { invitationId: apiInvitationId, claimSecret: apiClaimSecret, expiresAt: fixture.expiresAt, scope: { shareCid: apiLink.shareCid, shareId: apiLink.shareId, ...commonProofScope } }, browserInvitation: { invitationId: browserInvitationId, claimSecret: browserClaimSecret, expiresAt: fixture.expiresAt, scope: { shareCid: browserLink.shareCid, shareId: browserLink.shareId, ...commonProofScope } } }), PROOF_INVITATION_ID: apiInvitationId, PROOF_CLAIM_SECRET: apiClaimSecret, PROOF_EXPIRES_AT: fixture.expiresAt } });
    let credentialOutput = "";
    credentials.stdout?.on("data", (chunk) => { credentialOutput += String(chunk); });
    let credentialDescriptor: Json | undefined;
    for (let attempt = 0; attempt < 160 && credentialDescriptor === undefined; attempt += 1) {
      for (const line of credentialOutput.split("\n")) { try { const value = JSON.parse(line) as Json; if (value.testOnly === true && typeof value.url === "string") credentialDescriptor = value; } catch {} }
      if (credentials.exitCode !== null) throw new Error("OpenCredentials fixture exited before readiness");
      await sleep(250);
    }
    if (credentialDescriptor === undefined) throw new Error("OpenCredentials fixture readiness timeout");
    const credentialsLocal = credentialDescriptor.url as string;
    const directFetch = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const parsed = new URL(url instanceof Request ? url.url : String(url));
      const origin = parsed.pathname.startsWith("/share/v1/") ? nodeLocal : credentialsLocal;
      return fetch(origin + parsed.pathname, init);
    };
    const config: SharePublicConfig = { version: "tinycloud.share-email-claim/config-v1", shareOrigin: publicOrigin, registryOrigin: publicOrigin, nodeOrigin: publicOrigin, credentialsOrigin: publicOrigin, emailOrigin: publicOrigin, nodeAudience, enforcerDid: scope.enforcerDid ?? nodeAudience, nodeEnabled: true, issuerDid: "did:web:issuer.credentials.org", issuerVct: "opencredentials.email/v1", issuerEnabled: true, nodeInvitationKid: invitationKid, nodeInvitationPublicKey: b64(fromBase64Url(scope.trustedNode.invitationPublicKey)), nodeKeyVersion: 1, issuerKeyVersion: 1, issuerPublicKey: issuerPublic, environment: "test" };
    const resolved = await resolveLegacyPolicyShare(apiLink.shareUrl);
    if (resolved.state !== "policy-email-claim-required") throw new Error(`manual share did not resolve as a policy claim (state=${resolved.state}, detail=${"detail" in resolved ? resolved.detail : "none"})`);
    const binding = bindings.get(apiLink.shareCid);
    if (binding === undefined) throw new Error("manual authoritative binding is missing");
    const verified = await verifyProductionEmailShare({ envelope: resolved.envelope, shareCid: resolved.shareCid, policy: resolved.policy, config, binding: validateSharePublicBinding(binding) });
    const holder = await createExportableTestHolder();
    const transport = createHttpTransport({ nodeOrigin: publicOrigin, credentialsOrigin: publicOrigin, fetchFn: directFetch });
    const browserResolved = await resolveLegacyPolicyShare(browserLink.shareUrl);
    if (browserResolved.state !== "policy-email-claim-required") throw new Error(`browser invitation did not resolve as an unredeemed policy claim (state=${browserResolved.state}, detail=${"detail" in browserResolved ? browserResolved.detail : "none"})`);
    const browserBinding = bindings.get(browserLink.shareCid);
    if (browserBinding === undefined) throw new Error("browser authoritative binding is missing");
    await verifyProductionEmailShare({ envelope: browserResolved.envelope, shareCid: browserResolved.shareCid, policy: browserResolved.policy, config, binding: validateSharePublicBinding(browserBinding) });
    const claim = await issueEmailClaimCredential({ share: verified, invitationId: apiInvitationId, mailboxProof: apiClaimSecret, method: "magic", holder, transport, credentialTrust: { issuerDid: config.issuerDid, vct: config.issuerVct, issuerPublicKey: fromBase64Url(issuerPublic) } });
    const browserStatusResponse = await fetch(`${credentialsLocal}/test-only/invitations/browserInvitation/status`, { headers: { accept: "application/json" } });
    const browserStatus = await browserStatusResponse.json().catch(() => ({})) as Json;
    if (!browserStatusResponse.ok || browserStatus.testOnly !== true || browserStatus.registered !== true || browserStatus.redeemed !== false || browserStatus.invitationId !== browserInvitationId || browserStatus.shareCid !== browserLink.shareCid || browserStatus.shareId !== browserLink.shareId || Object.prototype.hasOwnProperty.call(browserStatus, "claimSecret")) throw new Error("browser invitation status did not prove registered and unredeemed without its secret");
    const fullUrl = browserLink.shareUrl + "&i=" + browserInvitationId + "&c=" + browserClaimSecret;
    const trustBundle = descriptor.trustBundle as Json;
    const capability = { scope: { ...scope, senderPrivateKey: b64(senderSeed), shareOrigin: publicOrigin, targetOrigin: publicOrigin, nodeAudience, trustedNode: { ...scope.trustedNode, targetOrigin: publicOrigin, nodeAudience, invitationKid } }, source };
    process.env.SHARE_TRUST_BUNDLE = JSON.stringify({ ...trustBundle, shareOrigin: publicOrigin, returnOrigin: publicOrigin, registryOrigin: publicOrigin, credentialsOrigin: publicOrigin, emailOrigin: publicOrigin, nodeOrigin: publicOrigin, nodeAudience, nodeInvitationKid: invitationKid });
    process.env.SHARE_TRUST_BUNDLE_ALLOW_TEST = "true";
    process.env.SHARE_SENDER_ENABLED = "true";
    process.env.SHARE_SENDER_PRIVATE_KEY = b64(senderSeed);
    process.env.SHARE_SENDER_CAPABILITY_JSON = JSON.stringify(capability);
    process.env.SHARE_TEST_BINDINGS_JSON = JSON.stringify(Object.fromEntries(bindings));
    process.env.SHARE_HERMETIC_COMPOSITION = "true";
    process.env.SHARE_HERMETIC_UPSTREAMS_JSON = JSON.stringify({ node: { origin: publicOrigin, transportOrigin: nodeLocal }, credentials: { origin: publicOrigin, transportOrigin: credentialsLocal }, registry: { origin: publicOrigin, transportOrigin: registryLocal } });
    process.env.VITE_SHARE_REGISTRY_URL = publicOrigin + "/registry";
    vite = await createViteServer({ root, server: { middlewareMode: true, allowedHosts: [publicUrl.hostname], hmr: { server: httpsServer, host: publicUrl.hostname, clientPort: Number(publicUrl.port || "443"), protocol: "wss" } }, appType: "spa" });
    const forward = async (request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse, origin: string): Promise<void> => {
      const bytes = await readBody(request);
      const result = await fetch(origin + (request.url || "/"), { method: request.method || "GET", headers: { origin: publicOrigin, "content-type": request.headers["content-type"] || "application/json" }, ...(bytes.length === 0 ? {} : { body: bytes.buffer as ArrayBuffer }) });
      response.writeHead(result.status, Object.fromEntries(result.headers)); response.end(Buffer.from(await result.arrayBuffer()));
    };
    httpsServer.removeAllListeners("request");
    httpsServer.on("request", (request, response) => {
      const path: string = (request.url || "").split("?")[0] || "/";
      if (path === "/__manual/strict-tls") { response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify({ status: "ok" })); return; }
      if (path.startsWith("/share/v1/")) { void forward(request, response, nodeLocal); return; }
      if (path.startsWith("/v1/share-email/")) { void forward(request, response, credentialsLocal); return; }
      vite!.middlewares(request, response, () => { if (!response.headersSent) response.writeHead(404).end(); });
    });
    const strictTlsBody = join(temp, "strict-tls-body.txt");
    let strictTlsStatus = "";
    try {
      const result = await execFile("curl", ["--fail", "--silent", "--show-error", "--location", "--max-time", "5", "-o", strictTlsBody, "-w", "%{http_code}", `${publicOrigin}/__manual/strict-tls`], { env: { ...process.env, NO_PROXY: [process.env.NO_PROXY, "share.localhost"].filter(Boolean).join(",") } });
      strictTlsStatus = result.stdout.trim();
    } catch (error) { throw new Error(`strict default-verification HTTPS fetch failed: ${error instanceof Error ? error.message.slice(0, 1200) : "unknown"}`); }
    if (strictTlsStatus !== "200") throw new Error(`strict default-verification HTTPS fetch returned ${strictTlsStatus || "no status"}`);
    const content = await readClaimedShare({ share: verified, claim: { holder, credential: claim.credential, expiresAt: claim.expiresAt, persisted: false }, transport });
    const contentBytes = new TextEncoder().encode(content);
    let wrongHolderDenied = false;
    try {
      const wrongHolder = await createExportableTestHolder();
      await readClaimedShare({ share: verified, claim: { holder: wrongHolder, credential: claim.credential, expiresAt: claim.expiresAt, persisted: false }, transport });
    } catch { wrongHolderDenied = true; }
    if (!wrongHolderDenied) throw new Error("wrong-holder credential read unexpectedly succeeded");
    const attackerSeed = new Uint8Array(32).fill(0x46);
    const attackerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(attackerSeed));
    const browserSource = browserBinding.contentSource as ContentSource;
    const sessionId = b64(randomBytes(16));
    const issuedAt = new Date(Date.now() - 1000).toISOString();
    const expiresAt = new Date(Date.now() + 30_000).toISOString();
    const invocation: Json = { type: "TinyCloudShareReadInvocation", version: 1, sessionId, shareCid: browserLink.shareCid, shareId: browserLink.shareId, delegationCid: browserBinding.delegationCid, policyCid: browserBinding.policyCid, authorityMaterialHandle: browserBinding.authorityMaterialHandle, authorityMaterialDigest: browserBinding.authorityMaterialDigest, contentSource: browserSource, contentSourceDigest: browserBinding.contentSourceDigest, holderDid: attackerDid, targetOrigin: publicOrigin, nodeAudience, action: browserSource.action, resource: browserSource.path, issuedAt, expiresAt, jti: b64(randomBytes(16)) };
    const readPreimage = { sessionId, delegationCid: browserBinding.delegationCid, authorityMaterialHandle: browserBinding.authorityMaterialHandle, authorityMaterialDigest: browserBinding.authorityMaterialDigest, contentSource: browserSource, contentSourceDigest: browserBinding.contentSourceDigest, action: browserSource.action, resource: browserSource.path, invocation };
    const requestBodyDigest = digest(canonicalize(readPreimage));
    invocation.requestBodyDigest = requestBodyDigest;
    const attackerSignature = ed25519.sign(new TextEncoder().encode("xyz.tinycloud.share/read-invocation/v1\0" + canonicalize(invocation)), attackerSeed);
    const unauthenticatedRead = await fetch(nodeLocal + "/share/v1/read", { method: "POST", headers: { ...headers(), origin: publicOrigin }, body: JSON.stringify({ sessionId, delegationCid: browserBinding.delegationCid, authorityMaterialHandle: browserBinding.authorityMaterialHandle, authorityMaterialDigest: browserBinding.authorityMaterialDigest, contentSource: browserSource, contentSourceDigest: browserBinding.contentSourceDigest, action: browserSource.action, resource: browserSource.path, requestBodyDigest, invocation, proof: { alg: "EdDSA", kid: attackerDid + "#" + attackerDid.slice("did:key:".length), signature: b64(attackerSignature) } }) });
    const unauthenticatedReadBody = await unauthenticatedRead.json().catch(() => ({})) as Json;
    const browserSessionDenied = unauthenticatedRead.status === 403 && unauthenticatedReadBody.error?.code === "read_denied" && !Object.prototype.hasOwnProperty.call(unauthenticatedReadBody, "content");
    const browserSessionEvidence = { status: unauthenticatedRead.status, code: unauthenticatedReadBody.error?.code ?? null, deniedBeforeContent: !Object.prototype.hasOwnProperty.call(unauthenticatedReadBody, "content"), holderDid: attackerDid, nodeIssuedHolderSession: false, binding: { shareCid: browserLink.shareCid, shareId: browserLink.shareId, policyCid: browserBinding.policyCid, delegationCid: browserBinding.delegationCid, source: browserSource, resource: browserSource.path } };
    if (!browserSessionDenied) throw new Error(`browser read without Node-issued holder session was not denied before content: ${JSON.stringify(browserSessionEvidence)}`);
    const holderPrivateJwk = await exportExportableTestHolder(holder);
    const holderPublicJwk = { kty: "OKP", crv: "Ed25519", x: holderPrivateJwk.x, alg: "EdDSA", ext: true, key_ops: ["verify"] };
    const holderKid = holder.did + "#" + holder.did.slice("did:key:".length);
    await writeEmailPreview({ path: previewPath, shareUrl: fullUrl, recipientEmail: email, documentName: "TinyCloud policy payload test" });
    await writeArtifact({ version: "tinycloud.share-email-claim/manual-artifact-v2", createdAt: new Date().toISOString(), shareUrl: fullUrl, browserInvitation: { invitationId: browserInvitationId, claimSecret: browserClaimSecret, shareCid: browserLink.shareCid, shareId: browserLink.shareId, status: "unredeemed", activated: false, redeemed: false, fixtureStatus: { registered: browserStatus.registered, redeemed: browserStatus.redeemed, secretExposed: Object.prototype.hasOwnProperty.call(browserStatus, "claimSecret") } }, apiCredentialFlow: { invitationId: apiInvitationId, claimSecret: apiClaimSecret, shareCid: apiLink.shareCid, shareId: apiLink.shareId, status: "redeemed", activated: true, challenge: true, credentialIssued: true, holderProof: true }, holderDid: holder.did, holderKid, holderPublicJwk, holderPrivateJwk, credential: claim.credential, credentialExpiresAt: claim.expiresAt, contentAccess: { readSuccess: true, contentDigest: digest(content), contentByteLength: contentBytes.length, wrongHolderDenied, browserSessionDenied, browserSessionEvidence }, strictTls: { ...certificate.evidence, fetchExitCode: 0, fetchStatus: Number(strictTlsStatus) }, emailPreview: { path: previewPath, mode: "0600", deliveryStatus: "not-sent", sent: false }, serviceEndpoints: { shareOrigin: publicOrigin, node: nodeLocal, credentials: credentialsLocal, registry: registryLocal }, processMetadata: { nodePid: node.pid, credentialsPid: credentials.pid, harnessPid: process.pid } }, artifactPath, replaceArtifact, testManualReplace);
    console.log("manual-share-link ready " + fullUrl);
    console.log("artifact " + artifactPath);
    if (smoke) {
      const artifactStat = await stat(artifactPath);
      const previewStat = await stat(previewPath);
      const previewHtml = await readFile(previewPath, "utf8");
      const writtenArtifact = JSON.parse(await readFile(artifactPath, "utf8")) as Json;
      const browserRecord = writtenArtifact.browserInvitation as Json;
      const apiRecord = writtenArtifact.apiCredentialFlow as Json;
      if ((artifactStat.mode & 0o777) !== 0o600 || (previewStat.mode & 0o777) !== 0o600 || !previewHtml.includes(fullUrl.replaceAll("&", "&amp;")) || browserRecord.status !== "unredeemed" || browserRecord.redeemed !== false || browserRecord.fixtureStatus?.registered !== true || browserRecord.fixtureStatus?.redeemed !== false || browserRecord.fixtureStatus?.secretExposed !== false || apiRecord.status !== "redeemed" || browserRecord.invitationId === apiRecord.invitationId || browserRecord.claimSecret === apiRecord.claimSecret || writtenArtifact.contentAccess?.browserSessionDenied !== true) throw new Error("lifecycle smoke artifact or email preview evidence is incomplete");
      if (await fileDigest(defaultArtifactPath) !== persistentArtifactDigest) throw new Error("lifecycle smoke modified the persistent manual artifact");
      await cleanupOnce();
      const survivors = [...await processGroupMembers(node.pid ?? -1), ...await processGroupMembers(credentials.pid ?? -1)];
      if (survivors.length > 0) throw new Error(`lifecycle smoke found surviving child PIDs: ${survivors.join(",")}`);
      const patternMatches = await processPatternMatches([join(temp, "node.json"), "email-claim-proof-fixture"]);
      if (patternMatches.length > 0) throw new Error(`lifecycle smoke found surviving process-pattern matches: ${patternMatches.join(" | ")}`);
      console.log(JSON.stringify({ smoke: "passed", strictTls: { exitCode: 0, status: Number(strictTlsStatus) }, artifactMode: "0600", emailPreview: { mode: "0600", containsBrowserLink: true }, persistentArtifactUntouched: true, browserInvitation: { registered: true, unredeemed: true, exactShareCid: browserLink.shareCid, exactShareId: browserLink.shareId, secretExposed: false }, apiCredentialFlow: "redeemed", read: { success: true, contentByteLength: contentBytes.length, contentDigest: digest(content) }, wrongHolderDenied, browserSessionDenied, browserSessionEvidence, childProcesses: "none", processPatternMatches: [] }));
      return;
    }
    await new Promise<void>((resolveWait) => { process.once("SIGINT", resolveWait); process.once("SIGTERM", resolveWait); });
  } finally { await cleanupOnce(); }
}

void main().catch((error) => { console.error("manual-share-link blocked: " + (error instanceof Error ? (error.stack ?? error.message).slice(0, 4000) : "unknown")); process.exitCode = 1; });
