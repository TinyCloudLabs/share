#!/usr/bin/env node

/**
 * HTML folder gate on the local native stack (real Node, Location Registry, OpenCredentials, loopback mail),
 * served from the built candidate under the production `_headers`, with the `tc` CLI as the sender:
 *
 *   tc share publish ./site/        (a folder with index.html, bearer: the CLI default)
 *   -> the CLI inlines the folder into ONE self-contained .html and publishes it
 *   -> open the link in a fresh browser context: the page renders in the artifact sandbox with its stylesheet,
 *      script and image, and nothing outside the stack is requested
 *   -> `tc share receive --stdout` returns that one document: no external references, no passive files
 *   -> refused folders (external script, symbolic link, traversal) publish nothing and exit with typed codes.
 *
 * Usage (same prerequisites as artifact-viewer-gate.mjs; TC500_CLI_PACKAGE must be a CLI with folder publishing):
 *   TC500_CLI_PACKAGE=<@tinycloud/cli root> HTML_FOLDER_GATE_SCREENSHOTS=<dir> node test/e2e-prod/html-folder-gate.mjs
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import puppeteer from "puppeteer";

import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { runBoundedStep, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
// The Node tree defaults to <workspace>/worktrees/tinycloud-node/v1.21.0, found by walking up from this
// checkout (it may be repositories/share or worktrees/<name>); TC500_NODE_WORKTREE overrides it.
function findNodeTree() {
  for (let directory = shareRoot; dirname(directory) !== directory; directory = dirname(directory)) {
    const candidate = join(directory, "worktrees/tinycloud-node/v1.21.0");
    if (existsSync(candidate)) return candidate;
  }
  return join(shareRoot, "../worktrees/tinycloud-node/v1.21.0");
}
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? findNodeTree();
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const cliPackage = resolve(process.env.TC500_CLI_PACKAGE ?? join(process.env.HOME ?? "", "scratch/artifacts/TC-1424/cli/node_modules/@tinycloud/cli"));
const screenshotDir = process.env.HTML_FOLDER_GATE_SCREENSHOTS;

const trace = [];
const external = [];
let phase = "setup";
const temporary = await mkdtemp(join(tmpdir(), "html-folder-gate-"));
let stack; let candidate; let browser;


async function waitUntil(check, timeout = 60_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolveWait) => setTimeout(resolveWait, 200));
  }
  return undefined;
}

/** Same remapping as joined-gate.mjs: canonical origins keep their names, transport goes to the stack. */
async function installRouting(page) {
  await page.evaluateOnNewDocument(installBrowserInstrumentation);
  await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    if (url.origin === stack.canonical.share || url.protocol === "data:" || url.protocol === "blob:") { await request.continue(); return; }
    const targets = new Map([
      [stack.canonical.node, stack.services.nodeOrigin],
      [stack.canonical.credentials, stack.services.credentialsOrigin],
      [stack.canonical.registry, stack.services.registryOrigin],
    ]);
    const targetOrigin = targets.get(url.origin);
    if (targetOrigin === undefined) { external.push({ phase, url: `${url.origin}${url.pathname}` }); await request.abort("blockedbyclient"); return; }
    const entry = { phase, method: request.method(), origin: url.origin, path: url.pathname, status: undefined, text: undefined };
    trace.push(entry);
    let body;
    if (!new Set(["GET", "HEAD"]).has(request.method())) {
      const binaryId = request.headers()["x-tc500-binary-id"];
      if (url.pathname === "/invoke" && binaryId !== undefined) {
        const captured = await page.evaluate((id) => { const bytes = window.__tc500BinaryBodies[id]; delete window.__tc500BinaryBodies[id]; return bytes; }, binaryId);
        body = Buffer.from(captured);
      } else body = await request.fetchPostData();
    }
    const headers = new Headers(request.headers());
    for (const key of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-tc500-binary-id"]) headers.delete(key);
    const response = await fetch(new URL(`${url.pathname}${url.search}`, targetOrigin), { method: request.method(), headers, redirect: "manual", ...(body === undefined ? {} : { body }) });
    const bytes = Buffer.from(await response.arrayBuffer());
    entry.status = response.status;
    if (response.status >= 400 && bytes.byteLength < 400) entry.text = bytes.toString("utf8");
    const responseHeaders = Object.fromEntries(response.headers.entries());
    for (const key of ["connection", "content-encoding", "content-length", "keep-alive", "transfer-encoding"]) delete responseHeaders[key];
    responseHeaders["access-control-allow-origin"] = request.headers().origin ?? stack.canonical.share;
    responseHeaders["access-control-allow-credentials"] = "true";
    responseHeaders["access-control-allow-methods"] = "GET, PUT, POST, OPTIONS";
    responseHeaders["access-control-allow-headers"] = request.headers()["access-control-request-headers"] ?? "authorization, content-type";
    responseHeaders.vary = "Origin";
    await request.respond({ status: response.status, headers: responseHeaders, body: bytes });
  })().catch(() => request.abort("failed").catch(() => undefined)); });
}

function cliEnv(tcHome, routeLog) {
  return {
    ...process.env, TC_HOME: tcHome, TC_HOST: stack.canonical.node, NO_COLOR: "1",
    TC500_CLI_ROUTES: JSON.stringify({ [stack.canonical.node]: stack.services.nodeOrigin, [stack.canonical.credentials]: stack.services.credentialsOrigin, [stack.canonical.registry]: stack.services.registryOrigin }),
    TC500_CLI_SHARE_CONFIG: join(shareRoot, "dist/.well-known/tinycloud-share/config.json"), TC500_CLI_ROUTE_LOG: routeLog,
  };
}

function runCli(env, args, input) {
  return new Promise((resolveCli) => {
    const child = spawn(process.execPath, ["--import", resolve(import.meta.dirname, "cli-transport.mjs"), join(cliPackage, "bin/tc"), "--profile", "owner", ...args], { env, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    if (input !== undefined) child.stdin.end(input);
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 5 * 60_000);
    child.on("close", (status) => { clearTimeout(timer); resolveCli({ status, stdout, stderr }); });
  });
}

function shareIds(value, found = []) {
  if (Array.isArray(value)) for (const item of value) shareIds(item, found);
  else if (value !== null && typeof value === "object") {
    if (typeof value.shareId === "string" && !found.includes(value.shareId)) found.push(value.shareId);
    for (const item of Object.values(value)) shareIds(item, found);
  }
  return found;
}

async function open(link, { width = 1440, height = 900, scheme = "light" } = {}) {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  await page.setViewport({ width, height, deviceScaleFactor: 1 });
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
  await installRouting(page);
  await page.goto(link, { waitUntil: "domcontentloaded", timeout: 120_000 });
  return { context, page };
}

async function shoot(page, name) {
  if (screenshotDir === undefined) return;
  await mkdir(screenshotDir, { recursive: true });
  await page.screenshot({ path: join(screenshotDir, `${name}.png`) });
}

try {
  await runBoundedStep("npm", ["run", "build"], shareRoot, {}, 10 * 60_000);
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore", timeout: 60_000 });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8", timeout: 30_000 }).trim();
  candidate = await startCandidateServer({ root: resolve(shareRoot, "dist"), key: await readFile(key), cert: await readFile(cert) });
  stack = await startNativeStack({ root: temporary, nodeRoot, credentialsRoot, registryRoot });
  browser = await puppeteer.launch({ headless: process.env.HEADED !== "1", args: [`--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${candidate.port}`, `--ignore-certificate-errors-spki-list=${spki}`, "--disable-quic", "--no-proxy-server"] });

  phase = "setup";
  const tcHome = join(temporary, "cli-home");
  const profileDir = join(tcHome, ".tinycloud/profiles/owner");
  await mkdir(profileDir, { recursive: true, mode: 0o700 });
  await writeFile(join(tcHome, ".tinycloud/config.json"), JSON.stringify({ defaultProfile: "owner", version: 1 }), { mode: 0o600 });
  await writeFile(join(profileDir, "profile.json"), JSON.stringify({ name: "owner", host: stack.canonical.node, chainId: 1, spaceName: "default", authMethod: "local", posture: "local-owner-key", privateKey: randomBytes(32).toString("hex"), createdAt: new Date().toISOString() }), { mode: 0o600 });
  const env = cliEnv(tcHome, join(temporary, "cli-routes.jsonl"));
  const sharesBefore = async () => {
    const listed = await runCli(env, ["share", "list", "--json"]);
    assert.equal(listed.status, 0, "tc share list failed");
    return shareIds(JSON.parse(listed.stdout));
  };

  // ---- the folder fixture: html + css + js + png, plus passive manifest.json and knowledge/ ----
  const site = join(temporary, "site");
  await cp(join(shareRoot, "test/fixtures/html-folder-site"), site, { recursive: true });

  // ---- refused folders publish nothing, with typed errors -------------------------------------
  phase = "refusals";
  const refused = join(temporary, "refused");
  const attempts = [
    ["external script", "UNSUPPORTED_HTML", 2, async (dir) => writeFile(join(dir, "index.html"), '<!doctype html><script src="https://cdn.example/x.js"></script>')],
    ["traversal", "UNSAFE_PATH", 8, async (dir) => writeFile(join(dir, "index.html"), '<!doctype html><img src="../secret.png">')],
    ["symbolic link", "UNSUPPORTED_FOLDER_ENTRY", 2, async (dir) => { await writeFile(join(dir, "index.html"), "<p>x</p>"); await symlink(join(temporary, "cli-home"), join(dir, "up")); }],
    ["missing file", "HTML_RESOURCE_MISSING", 2, async (dir) => writeFile(join(dir, "index.html"), '<!doctype html><link rel="stylesheet" href="nope.css">')],
  ];
  const known = await sharesBefore();
  for (const [name, code, exit, prepare] of attempts) {
    const dir = join(refused, name.replaceAll(" ", "-"));
    await mkdir(dir, { recursive: true });
    await prepare(dir);
    const result = await runCli(env, ["share", "publish", dir, "--json"]);
    assert.equal(result.status, exit, `${name}: exit code (stderr: ${result.stderr.slice(0, 300)})`);
    assert.equal(JSON.parse(result.stderr.slice(result.stderr.indexOf("{"))).error.code, code, `${name}: error code`);
    assert.equal(/tc1=/.test(result.stdout + result.stderr), false, `${name}: no link was printed`);
  }
  assert.deepEqual(await sharesBefore(), known, "a refused folder creates no share");

  // ---- publish the real folder ----------------------------------------------------------------
  phase = "publish";
  const published = await runCli(env, ["share", "publish", site]);
  assert.equal(published.status, 0, `tc share publish ${site} failed (exit ${published.status}): ${published.stderr.slice(0, 400)}`);
  const link = /https:\/\/share\.tinycloud\.xyz\/viewer#tc1=[^\s"'<>]+/.exec(published.stdout)?.[0];
  assert.ok(link, "tc share publish printed no bearer link");
  assert.match(published.stderr, /Left out of the page and not published/, "the passive files are named");
  const ids = (await sharesBefore()).filter((id) => !known.includes(id));
  assert.equal(ids.length, 1, "exactly one new share");

  // What the CLI reads back is the one self-contained document.
  const received = await runCli(env, ["share", "receive", "--stdin", "--stdout"], link);
  assert.equal(received.status, 0, `tc share receive failed: ${received.stderr.slice(0, 200)}`);
  assert.match(received.stdout, /^<!DOCTYPE html>/);
  assert.match(received.stdout, /data:image\/png;base64,/, "the image is inlined");
  assert.match(received.stdout, /Folder script ran inside the frame\./, "the script is inlined");
  assert.match(received.stdout, /rgb\(12, 99, 77\)/, "the stylesheet is inlined");
  assert.equal(/<script[^>]*\ssrc=|<link[^>]*stylesheet|PASSIVE-KNOWLEDGE-MARKER|xyz\.example\.folder-site|https?:\/\//.test(received.stdout), false, "no external reference and no passive file in the document");

  // ---- recipient: the page renders in the artifact sandbox ------------------------------------
  phase = "open";
  const { context, page } = await open(link);
  await page.waitForSelector(".artifact-chrome", { timeout: 120_000 });
  assert.equal(await page.$eval(".artifact-chrome-title", (node) => node.textContent), "site.html");
  const outer = await (await page.waitForSelector("iframe.viewer-html-frame")).contentFrame();
  assert.equal(await (await page.$("iframe.viewer-html-frame")).evaluate((node) => node.getAttribute("sandbox")), "allow-scripts");
  const inner = await (await outer.waitForSelector("iframe.artifact-document")).contentFrame();
  await inner.waitForFunction(() => document.getElementById("status")?.textContent === "Folder script ran inside the frame.", { timeout: 30_000 });
  assert.equal(await inner.$eval("#title", (node) => getComputedStyle(node).color), "rgb(12, 99, 77)", "the stylesheet applies");
  assert.equal(await inner.$eval("#swatch", (node) => node.complete && node.naturalWidth), 48, "the image loaded");
  await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
  assert.deepEqual(external, [], "no request to any origin outside the stack");
  await shoot(page, "folder-page-1440-light");
  await context.close();

  // ---- revoke: the link stops working ---------------------------------------------------------
  phase = "revoke";
  const revoked = await runCli(env, ["share", "revoke", ids[0], "--json"]);
  assert.equal(revoked.status, 0, `tc share revoke failed: ${revoked.stderr.slice(0, 200)}`);
  const again = await open(link);
  await again.page.waitForSelector(".viewer-state", { timeout: 60_000 });
  assert.equal(await again.page.$eval("h1", (node) => node.textContent), "This share was revoked by its sender");
  assert.equal(await again.page.$("iframe"), null, "no frame after revoke");
  await again.context.close();
  assert.deepEqual(external, [], "nothing outside the stack was contacted at any point");
  console.log(`HTML folder native-stack gate passed (CLI ${JSON.parse(await readFile(join(cliPackage, "package.json"), "utf8")).version}): folder refusals typed, folder published as one page, rendered with css/js/image, revoked`);
} catch (error) {
  console.error(`[html-folder-gate] failed in phase "${phase}": ${String(error?.message ?? error).slice(0, 600)}${error?.cause ? ` (cause: ${String(error.cause.message ?? error.cause).slice(0, 400)})` : ""}`);
  if (external.length > 0) console.error(`[html-folder-gate] external requests attempted: ${JSON.stringify(external.slice(0, 5))}`);
  process.exitCode = 1;
} finally {
  await browser?.close().catch(() => undefined);
  await stack?.close().catch(() => undefined);
  await candidate?.close().catch(() => undefined);
  process.exit();
}
