import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, randomUUID } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { createServer as netServer, Socket } from "node:net";
import { join, resolve } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { OPENKEY_TEST_SESSION_TOKEN, openKeyCors, openKeyWidgetHtml } from "./openkey-fixture.mjs";

export const STABLE_INPUTS = Object.freeze({
  node: "7a58693f8bcd0d4e9d4df40dd464abd8c9c763ed",
  openCredentials: "846c018ff4da4dc97a37762a343ad871ea779c54",
  locationRegistry: "74b29179baa0be745a80d28e46124ed53e4c9c15",
});

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ISSUER_SEED = Buffer.alloc(32, 67);
const NODE_SECRET = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
const WALLET = privateKeyToAccount(`0x${"55".repeat(32)}`);
const CANONICAL = Object.freeze({
  share: "https://share.tinycloud.xyz",
  node: "https://tee.node.tinycloud.xyz",
  credentials: "https://witness.credentials.org",
  registry: "https://registry.tinycloud.xyz",
});

function issuerPublicKey() {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, ISSUER_SEED]), format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
}

function run(command, args, cwd, env, children) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], detached: true });
  let output = "";
  const collect = (chunk) => { output = `${output}${String(chunk)}`.slice(-24_000); };
  child.stdout.on("data", collect); child.stderr.on("data", collect);
  children.push({ child, output: () => output });
  return child;
}

function runOnce(command, args, cwd, env = {}) {
  execFileSync(command, args, { cwd, env: { ...process.env, ...env }, stdio: "ignore" });
}

async function freePort() {
  const server = httpServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}

async function waitFor(url, child, timeout = 120_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { cache: "no-store" });
      if (response.status < 500) return response;
    } catch {}
    if (child?.exitCode !== null) throw new Error("native fixture process exited before readiness");
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  throw new Error("native fixture readiness timed out");
}

async function waitForTcp(port, child, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolveConnect, reject) => {
        const socket = new Socket();
        socket.once("error", reject); socket.connect(port, "127.0.0.1", () => { socket.destroy(); resolveConnect(); });
      });
      return;
    } catch {}
    if (child.exitCode !== null) throw new Error("postgres exited before readiness");
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error("postgres readiness timed out");
}

function assertTree(root, commit, label) {
  const actual = execFileSync("git", ["rev-parse", "HEAD^{tree}"], { cwd: root, encoding: "utf8" }).trim();
  const expected = execFileSync("git", ["rev-parse", `${commit}^{tree}`], { cwd: root, encoding: "utf8" }).trim();
  assert.equal(actual, expected, `${label} worktree is not the reviewed stable tree`);
  assert.equal(execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }), "", `${label} worktree is dirty`);
  return createHash("sha256").update(actual).digest("hex");
}

function trustBundle(nodePublicKey) {
  return JSON.stringify({
    version: "tinycloud.share-email-trust-bundle/v1",
    shareOrigin: CANONICAL.share,
    returnOrigin: CANONICAL.share,
    registryOrigin: CANONICAL.registry,
    credentialsOrigin: CANONICAL.credentials,
    emailOrigin: CANONICAL.credentials,
    nodeOrigin: CANONICAL.node,
    nodeAudience: "did:web:tee.node.tinycloud.xyz",
    nodeInvitationKid: "did:web:tee.node.tinycloud.xyz#invitation-key-1",
    nodeInvitationPublicKey: nodePublicKey,
    nodeKeyVersion: 1,
    nodeEnabled: true,
    issuerDid: "did:web:issuer.credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerKid: "did:web:issuer.credentials.org#controller",
    issuerPublicKey: issuerPublicKey(),
    issuerKeyVersion: 1,
    issuerEnabled: true,
  });
}

async function loopback(handler, servers) {
  const server = httpServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening"); servers.push(server);
  return `http://127.0.0.1:${server.address().port}`;
}

export function resendFixtureJsonResponse(value, extraHeaders = {}) {
  const body = JSON.stringify(value);
  return {
    body,
    headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)), ...extraHeaders },
  };
}

export function isCredentialOtpMail(message, recipient) {
  const payload = message?.payload;
  const recipients = Array.isArray(payload?.to) ? payload.to : [payload?.to];
  return payload?.subject === "Your OpenCredentials verification code"
    && recipients.includes(recipient);
}

export function credentialOtpFromMail(message) {
  const match = message?.payload?.text?.match(/^Your 8-digit OpenCredentials code is (\d{8})\.$/m);
  return match?.[1];
}

export async function startNativeStack({ root, nodeRoot, credentialsRoot, registryRoot }) {
  const children = [];
  const servers = [];
  const provenance = {
    // TC500_NODE_COMMIT names a reviewed candidate Node commit; the tree must
    // still be clean and exactly that commit, and its digest is recorded.
    node: assertTree(nodeRoot, process.env.TC500_NODE_COMMIT ?? STABLE_INPUTS.node, "TinyCloud Node"),
    openCredentials: assertTree(credentialsRoot, STABLE_INPUTS.openCredentials, "OpenCredentials"),
    locationRegistry: assertTree(registryRoot, STABLE_INPUTS.locationRegistry, "Location Registry"),
  };

  const openKeyOrigin = await loopback((request, response) => {
    const cors = openKeyCors(request.headers.origin);
    if (request.method === "OPTIONS") { response.writeHead(204, cors).end(); return; }
    if (request.method === "GET" && request.url?.startsWith("/widget/")) {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(openKeyWidgetHtml(WALLET.address)); return;
    }
    if (request.method !== "POST" || (request.url !== "/sign" && request.url !== "/api/delegate/sign")) { response.writeHead(404).end(); return; }
    if (request.url === "/api/delegate/sign" && request.headers.authorization !== `Bearer ${OPENKEY_TEST_SESSION_TOKEN}`) { response.writeHead(401, cors).end(); return; }
    const chunks = []; request.on("data", (chunk) => chunks.push(chunk)); request.on("end", async () => {
      try {
        const { message } = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const signature = await WALLET.signMessage({ message });
        response.writeHead(200, { ...cors, "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify({ address: WALLET.address, signature }));
      } catch { response.writeHead(400, cors).end(); }
    });
  }, servers);

  const mail = [];
  const mailOrigin = await loopback((request, response) => {
    const sendJson = (status, value, extraHeaders = {}) => {
      const { body, headers } = resendFixtureJsonResponse(value, extraHeaders);
      response.writeHead(status, headers).end(body);
    };
    if (request.method === "GET" && request.url === "/messages") { sendJson(200, { messages: mail }, { "cache-control": "no-store" }); return; }
    if (request.method !== "POST" || request.url !== "/emails") { response.writeHead(404).end(); return; }
    const chunks = []; request.on("data", (chunk) => chunks.push(chunk)); request.on("end", () => {
      try {
        const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const prior = mail.find((entry) => entry.idempotencyKey === request.headers["idempotency-key"]);
        if (prior !== undefined) { sendJson(200, { id: prior.id, replayed: true }); return; }
        const entry = { id: `fixture-${mail.length + 1}`, idempotencyKey: request.headers["idempotency-key"], payload }; mail.push(entry);
        sendJson(200, { id: entry.id });
      } catch { response.writeHead(400).end(); }
    });
  }, servers);

  const pgBin = process.env.SHARING_E2E_POSTGRES_BIN ?? execFileSync("pg_config", ["--bindir"], { encoding: "utf8" }).trim();
  const pgUser = process.env.USER ?? "tinycloud";
  const pgData = join(root, "postgres");
  const pgPort = await freePort();
  runOnce(join(pgBin, "initdb"), ["-D", pgData, "-A", "trust", "-U", pgUser], root, { LC_ALL: "C" });
  const tls = join(root, "postgres-tls"); await mkdir(tls);
  const caKey = join(tls, "ca.key"); const ca = join(tls, "ca.pem"); const key = join(tls, "server.key"); const csr = join(tls, "server.csr"); const cert = join(tls, "server.crt"); const ext = join(tls, "server.ext");
  runOnce("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", ca, "-days", "1", "-subj", "/CN=tc500-e2e-ca", "-addext", "basicConstraints=critical,CA:true"], root);
  runOnce("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=db.localhost"], root);
  await writeFile(ext, "subjectAltName=DNS:db.localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n", { flag: "wx" });
  runOnce("openssl", ["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", cert, "-days", "1", "-extfile", ext], root); await chmod(key, 0o600);
  const postgres = run(join(pgBin, "postgres"), ["-D", pgData, "-h", "127.0.0.1", "-p", String(pgPort), "-c", "unix_socket_directories=", "-c", "ssl=on", "-c", `ssl_cert_file=${cert}`, "-c", `ssl_key_file=${key}`, "-c", `ssl_ca_file=${ca}`], root, { PGUSER: pgUser }, children);
  await waitForTcp(pgPort, postgres);
  const postgresLocalUrl = `postgres://${pgUser}@127.0.0.1:${pgPort}/postgres?sslmode=disable`;
  // OpenCredentials requires separated database roles: a schema-owning
  // migrator and a least-privilege runtime role with data access only. It
  // gets its own database so the registry's tables stay out of its schema.
  const psql = (database, user, sql) => runOnce(join(pgBin, "psql"), ["-h", "127.0.0.1", "-p", String(pgPort), "-U", user, "-d", database, "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "-q", "-c", sql], root);
  psql("postgres", pgUser, "CREATE ROLE oc_migrator LOGIN; CREATE ROLE oc_runtime LOGIN;");
  psql("postgres", pgUser, "CREATE DATABASE opencredentials OWNER " + pgUser + ";");
  psql("opencredentials", pgUser, "REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE, CREATE ON SCHEMA public TO oc_migrator; GRANT USAGE ON SCHEMA public TO oc_runtime;");
  const credentialsDatabaseUrl = (user) => `postgres://${user}@db.localhost:${pgPort}/opencredentials?sslmode=verify-full`;

  const nodePort = await freePort();
  runOnce("cargo", ["build", "--quiet", "-p", "tinycloud-node", "--features", "local-tee,mounted-fixture"], nodeRoot, { TINYCLOUD_KEYS_SECRET: NODE_SECRET.toString("base64url") });
  const nodeBinary = join(nodeRoot, "target/debug/tinycloud");
  const descriptor = JSON.parse(execFileSync(join(nodeRoot, "target/debug/export-share-invitation-descriptor"), [], { cwd: nodeRoot, env: { ...process.env, TINYCLOUD_KEYS_SECRET: NODE_SECRET.toString("base64url") }, encoding: "utf8" }));
  const provisionalBundle = trustBundle(descriptor.nodeInvitationPublicKey);
  const trustPath = join(root, "trust.json"); await writeFile(trustPath, provisionalBundle, { flag: "wx", mode: 0o600 });
  const node = run(nodeBinary, [], nodeRoot, {
    TMPDIR: root, RUST_LOG: "error", TINYCLOUD_KEYS_SECRET: NODE_SECRET.toString("base64url"), ROCKET_ADDRESS: "127.0.0.1", ROCKET_PORT: String(nodePort),
    TINYCLOUD_STORAGE__DATADIR: join(root, "node-data"), TINYCLOUD_SHARE_EMAIL__ENABLED: "true", TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_PATH: trustPath,
  }, children);
  const nodeOrigin = `http://127.0.0.1:${nodePort}`;
  await waitFor(`${nodeOrigin}/info`, node, 240_000);
  const nodeInfo = await (await fetch(`${nodeOrigin}/info`)).json();
  assert.match(nodeInfo.nodeId, /^did:key:/);
  const bundle = trustBundle(descriptor.nodeInvitationPublicKey);
  await writeFile(join(root, "credentials-trust.json"), bundle, { flag: "wx", mode: 0o600 });

  runOnce("corepack", ["pnpm", "install", "--frozen-lockfile"], registryRoot);
  runOnce("corepack", ["pnpm", "--filter", "@tinycloud-registry/location-registry", "build"], registryRoot);
  const registryPort = await freePort();
  const registry = run("node", ["packages/location-registry/dist/index.js"], registryRoot, { PORT: String(registryPort), DATABASE_URL: postgresLocalUrl }, children);
  const registryOrigin = `http://127.0.0.1:${registryPort}`;
  assert.equal((await waitFor(`${registryOrigin}/health`, registry)).status, 200);

  const manifest = join(credentialsRoot, "rust/opencredentials_witness/Cargo.toml");
  runOnce("cargo", ["build", "--quiet", "--manifest-path", manifest, "--bin", "opencredentials-witness", "--features", "dstack"], credentialsRoot);
  const migrations = join(credentialsRoot, "deploy/share-email/migrations");
  const readiness = join(root, "oc-readiness.json");
  const databaseEnv = {
    DATABASE_URL: credentialsDatabaseUrl("oc_runtime"), DATABASE_SSL_ROOT_CERT: ca, DATABASE_MIGRATIONS_DIR: migrations, STORAGE_READINESS_FILE: readiness, STORAGE_READINESS_MAX_AGE_SECONDS: "30",
    DATABASE_POOL_MIN: "2", DATABASE_POOL_MAX: "8", DATABASE_CONNECT_TIMEOUT_MS: "5000", DATABASE_RECYCLE_TIMEOUT_MS: "5000", DATABASE_ACQUIRE_TIMEOUT_MS: "500", DATABASE_STATEMENT_TIMEOUT_MS: "2000", DATABASE_IDLE_TRANSACTION_TIMEOUT_MS: "1000",
  };
  runOnce(join(credentialsRoot, "scripts/oi-share-email/migrate.sh"), [], credentialsRoot, { ...databaseEnv, DATABASE_URL: credentialsDatabaseUrl("oc_migrator") });
  psql("opencredentials", "oc_migrator", "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO oc_runtime; GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO oc_runtime;");
  runOnce(join(credentialsRoot, "scripts/oi-share-email/readiness-check.sh"), [], credentialsRoot, databaseEnv);

  const dstackSocket = join(root, "dstack.sock");
  const dstack = netServer((socket) => { let input = Buffer.alloc(0); socket.on("data", (chunk) => {
    input = Buffer.concat([input, chunk]); const split = input.indexOf("\r\n\r\n"); if (split < 0) return;
    const head = input.subarray(0, split).toString("latin1"); const length = Number(head.match(/content-length:\s*(\d+)/i)?.[1] ?? 0); if (input.length < split + 4 + length) return;
    const path = head.split(" ")[1]; const body = input.subarray(split + 4, split + 4 + length).toString("utf8");
    let response;
    if (path === "/Info") response = { app_id: "tc500-native-e2e", compose_hash: "tc500-native-e2e", instance_id: "tc500-native-e2e" };
    else { let requested = ""; try { requested = JSON.parse(body).path ?? ""; } catch {} const bytes = requested === "opencredentials/witness/signing-key" ? ISSUER_SEED : createHash("sha256").update(requested).digest(); response = { key: bytes.toString("hex") }; }
    const payload = Buffer.from(JSON.stringify(response)); socket.end(Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${payload.length}\r\nConnection: close\r\n\r\n`), payload]));
  }); });
  dstack.listen(dstackSocket); await once(dstack, "listening"); servers.push(dstack);

  const credentialsPort = await freePort();
  const credentials = run(join(credentialsRoot, "rust/opencredentials_witness/target/debug/opencredentials-witness"), [], credentialsRoot, {
    ...databaseEnv, TMPDIR: root, KEYS_TYPE: "dstack", DSTACK_SIMULATOR_ENDPOINT: dstackSocket, DID_WEB: "did:web:issuer.credentials.org", BIND_ADDR: `127.0.0.1:${credentialsPort}`,
    CORS_ALLOWED_ORIGINS: CANONICAL.share, SHARE_EMAIL_CAPABILITY: "false", SHARE_EMAIL_DATABASE_MODE: "durable-postgres", SHARE_EMAIL_TRUST_BUNDLE_JSON: bundle, SHARE_EMAIL_SHARE_URL: CANONICAL.share,
    RESEND_API_KEY: `re_${"a".repeat(32)}`, RESEND_WEBHOOK_SECRET: "whsec_AAAAAAAAAAAAAAAAAAAAAAAA", SHARE_EMAIL_RESEND_ENDPOINT: `${mailOrigin}/emails`, SHARE_EMAIL_KEY_DERIVATION_VERSION: "1",
    CREDENTIAL_ACQUISITION_EMAIL_CAPABILITY: "true", CREDENTIAL_INVITATION_CAPABILITY: "true", CREDENTIAL_INVITATION_POLICY_ENGINE_DIDS: JSON.stringify([nodeInfo.nodeId]), CREDENTIAL_INVITATION_RETURN_ORIGINS: CANONICAL.share, CREDENTIAL_INVITATION_AUDIENCE: CANONICAL.credentials,
  }, children);
  const credentialsOrigin = `http://127.0.0.1:${credentialsPort}`;
  assert.equal((await waitFor(`${credentialsOrigin}/health`, credentials)).status, 200);
  assert.equal((await fetch(`${credentialsOrigin}/v1/credential-invitations`, { method: "OPTIONS", headers: { origin: CANONICAL.share, "access-control-request-method": "POST", "access-control-request-headers": "content-type" } })).status, 200);

  return {
    canonical: CANONICAL, walletAddress: WALLET.address, provenance,
    services: { openKeyOrigin, nodeOrigin, credentialsOrigin, registryOrigin, mailOrigin },
    mail,
    async close() {
      for (const { child } of children.reverse()) if (child.exitCode === null) { try { process.kill(-child.pid, "SIGTERM"); } catch {} }
      for (const server of servers.reverse()) await new Promise((resolveClose) => server.close(() => resolveClose()));
    },
  };
}
