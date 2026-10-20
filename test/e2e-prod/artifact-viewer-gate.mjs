#!/usr/bin/env node

/**
 * Artifact viewer gate on the local native stack (real Node, Location
 * Registry, OpenCredentials, loopback mail), served from the built candidate
 * under the production `_headers`, with the published `tc` CLI as the sender:
 *
 *   tc share publish report.md / page.html   (bearer, the CLI default)
 *   -> open the link in a fresh browser context
 *   -> fragment scrubbed, bar visible, content rendered, no request to the
 *      author's (probe) origin, hide / recall (pill, Alt+Shift+C), axe AA
 *   -> screenshots at 390 / 1440 px, light and dark
 *   -> tc share revoke <id>
 *   -> reload: "This share was revoked by its sender", no content, no frame
 *      and no bar in the DOM, and the Node answered 401 delegation-revoked.
 *
 * Usage (same prerequisites as joined-gate.mjs):
 *   TC500_CLI_PACKAGE=<@tinycloud/cli root> ARTIFACT_GATE_SCREENSHOTS=<dir> \
 *     node test/e2e-prod/artifact-viewer-gate.mjs
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";

import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { runBoundedStep, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../../");
const nodeRoot = process.env.TC500_NODE_WORKTREE ?? join(workspaceRoot, "worktrees/tinycloud-node/v1.21.0");
const credentialsRoot = process.env.TC500_OPENCREDENTIALS_WORKTREE ?? "/tmp/tc500-oc-846c018";
const registryRoot = process.env.TC500_REGISTRY_WORKTREE ?? "/tmp/tc500-registry-74b2917";
const cliPackage = resolve(process.env.TC500_CLI_PACKAGE ?? join(process.env.HOME ?? "", "scratch/artifacts/TC-1424/cli/node_modules/@tinycloud/cli"));
const screenshotDir = process.env.ARTIFACT_GATE_SCREENSHOTS;
const axeSource = await readFile(join(shareRoot, "node_modules/axe-core/axe.min.js"), "utf8");
// An origin that must never be contacted: the viewer's routing layer records any attempt.
const PROBE = "http://probe.invalid";

const trace = [];
const external = [];
let phase = "setup";
const temporary = await mkdtemp(join(tmpdir(), "artifact-viewer-gate-"));
let stack; let candidate; let browser;

const fixtureMd = (await readFile(join(shareRoot, "test/fixtures/viewer-page/report.md"), "utf8")).replaceAll("__PROBE__", PROBE);
const fixtureHtml = (await readFile(join(shareRoot, "test/fixtures/viewer-page/page.html"), "utf8")).replaceAll("__PROBE__", PROBE);

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

function runCli(env, args) {
  return new Promise((resolveCli) => {
    const child = spawn(process.execPath, ["--import", resolve(import.meta.dirname, "cli-transport.mjs"), join(cliPackage, "bin/tc"), "--profile", "owner", ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
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

async function axeViolations(frame) {
  await frame.evaluate(axeSource);
  const result = await frame.evaluate(() => globalThis.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } }));
  return result.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(" | ")}`);
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

  // ---- sender: the published CLI, a local owner key profile on the stack ----
  phase = "publish";
  const tcHome = join(temporary, "cli-home");
  const profileDir = join(tcHome, ".tinycloud/profiles/owner");
  await mkdir(profileDir, { recursive: true, mode: 0o700 });
  await writeFile(join(tcHome, ".tinycloud/config.json"), JSON.stringify({ defaultProfile: "owner", version: 1 }), { mode: 0o600 });
  await writeFile(join(profileDir, "profile.json"), JSON.stringify({ name: "owner", host: stack.canonical.node, chainId: 1, spaceName: "default", authMethod: "local", posture: "local-owner-key", privateKey: randomBytes(32).toString("hex"), createdAt: new Date().toISOString() }), { mode: 0o600 });
  const env = cliEnv(tcHome, join(temporary, "cli-routes.jsonl"));
  const published = {};
  const known = [];
  for (const [kind, filename, content] of [["md", "q3-agent-report.md", fixtureMd], ["html", "q3-agent-report.html", fixtureHtml]]) {
    const input = join(temporary, filename);
    await writeFile(input, content, { mode: 0o600 });
    const result = await runCli(env, ["share", "publish", input]);
    assert.equal(result.status, 0, `tc share publish ${filename} failed (exit ${result.status})`);
    const link = /https:\/\/share\.tinycloud\.xyz\/viewer#tc1=[^\s"'<>]+/.exec(result.stdout)?.[0];
    assert.ok(link, `tc share publish ${filename} printed no bearer link`);
    const listed = await runCli(env, ["share", "list", "--json"]);
    assert.equal(listed.status, 0, "tc share list failed");
    const ids = shareIds(JSON.parse(listed.stdout)).filter((id) => !known.includes(id));
    assert.equal(ids.length, 1, "the new share is listed exactly once");
    known.push(ids[0]);
    published[kind] = { link, id: ids[0], filename };
  }

  // ---- recipient: open, inspect, hide / recall ------------------------------
  for (const kind of ["md", "html"]) {
    phase = `open-${kind}`;
    const { link, filename } = published[kind];
    const { context, page } = await open(link);
    await page.waitForSelector(".artifact-chrome", { timeout: 120_000 });
    assert.equal(await page.evaluate(() => location.hash), "", `${kind}: the fragment is scrubbed`);
    assert.equal(await page.$eval(".artifact-chrome-title", (node) => node.textContent), filename);
    assert.equal(await page.evaluate(() => document.body.classList.contains("viewer-fullpage")), true);
    if (kind === "md") {
      const frame = await (await page.waitForSelector("iframe.viewer-preview-frame")).contentFrame();
      assert.equal(await frame.$eval("h1", (node) => node.textContent), "Q3 agent report");
      assert.ok(await frame.$(".viewer-mermaid svg"), "mermaid diagram rendered");
      assert.ok((await frame.$$(".viewer-blocked-image")).length === 3, "remote images are blocked, shown as text");
    } else {
      const outer = await (await page.waitForSelector("iframe.viewer-html-frame")).contentFrame();
      assert.equal(await (await page.$("iframe.viewer-html-frame")).evaluate((node) => node.getAttribute("sandbox")), "allow-scripts");
      const inner = await (await outer.waitForSelector("iframe.artifact-document")).contentFrame();
      await inner.waitForFunction(() => document.getElementById("status")?.textContent === "Script ran inside the frame.", { timeout: 30_000 });
    }
    // Nothing from the author's host was even attempted (the routing layer records it).
    await new Promise((resolveWait) => setTimeout(resolveWait, 1_500));
    assert.deepEqual(external, [], `${kind}: no request to any origin outside the stack`);
    assert.deepEqual(await axeViolations(page.mainFrame()), [], `${kind}: axe WCAG AA on the viewer`);
    if (kind === "md") {
      const srcdoc = await page.$eval("iframe.viewer-preview-frame", (node) => node.getAttribute("srcdoc"));
      const standalone = await browser.newPage();
      await standalone.setContent(srcdoc, { waitUntil: "load" });
      assert.deepEqual(await axeViolations(standalone.mainFrame()), [], "md: axe WCAG AA on the markdown frame");
      await standalone.close();
    }
    await page.click(".artifact-chrome-hide");
    assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), true, `${kind}: Hide hides the bar`);
    assert.equal(await page.$eval(".artifact-chrome-pill", (node) => node.hidden), false, `${kind}: the pill appears`);
    await page.click(".artifact-chrome-pill");
    assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), false, `${kind}: the pill recalls the bar`);
    await page.click(".artifact-chrome-hide");
    await page.keyboard.down("Alt"); await page.keyboard.down("Shift"); await page.keyboard.press("KeyC"); await page.keyboard.up("Shift"); await page.keyboard.up("Alt");
    assert.equal(await page.$eval(".artifact-chrome", (node) => node.hidden), false, `${kind}: Alt+Shift+C recalls the bar`);
    await context.close();
  }

  // ---- screenshots of the live views ------------------------------------------
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    for (const scheme of ["light", "dark"]) {
      for (const kind of ["md", "html"]) {
        phase = `shot-${kind}`;
        const { context, page } = await open(published[kind].link, { width, height, scheme });
        await page.waitForSelector(kind === "md" ? "iframe.viewer-preview-frame" : "iframe.viewer-html-frame", { timeout: 120_000 });
        await new Promise((resolveWait) => setTimeout(resolveWait, 1_200));
        await shoot(page, `native-${kind === "md" ? "markdown" : "html"}-${width}-${scheme}`);
        await context.close();
      }
    }
  }

  // ---- revoke, then reload: honest screen, no content -----------------------------
  for (const kind of ["md", "html"]) {
    phase = `revoke-${kind}`;
    const { link, id, filename } = published[kind];
    const { context, page } = await open(link);
    await page.waitForSelector(".artifact-chrome", { timeout: 120_000 });
    const revoked = await runCli(env, ["share", "revoke", id, "--json"]);
    assert.equal(revoked.status, 0, `tc share revoke ${filename} failed (exit ${revoked.status}): ${revoked.stderr.slice(0, 200)}`);
    assert.match(revoked.stdout, /"revoked":\s*true/, "tc share revoke reported revoked:true");
    const before = trace.length;
    await page.reload({ waitUntil: "domcontentloaded" });
    await page.waitForSelector(".viewer-state", { timeout: 120_000 });
    assert.equal(await page.$eval("h1", (node) => node.textContent), "This share was revoked by its sender", `${kind}: the revoked screen`);
    assert.equal(await page.$eval(".viewer-state-chip", (node) => node.textContent), "Revoked");
    const html = await page.content();
    for (const text of ["Q3 agent report", "Revocation is a property", "shares opened", "Script ran inside the frame"]) assert.equal(html.includes(text), false, `${kind}: no shared content ("${text}") in the DOM after revoke`);
    assert.equal(await page.$("iframe, .viewer-content, .artifact-chrome, .artifact-chrome-pill"), null, `${kind}: no frame, content sink or bar after revoke`);
    assert.equal(await page.evaluate(() => document.body.classList.contains("viewer-fullpage")), false);
    const denied = trace.slice(before).filter((entry) => entry.status === 401 && /delegation-(?:ancestor-)?revoked/.test(entry.text ?? ""));
    assert.ok(denied.length > 0, `${kind}: the Node answered 401 delegation-revoked`);
    assert.deepEqual(await axeViolations(page.mainFrame()), [], `${kind}: axe WCAG AA on the revoked screen`);
    await context.close();
  }
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    for (const scheme of ["light", "dark"]) {
      phase = "shot-revoked";
      const { context, page } = await open(published.md.link, { width, height, scheme });
      await page.waitForSelector(".viewer-state", { timeout: 120_000 });
      await shoot(page, `native-revoked-${width}-${scheme}`);
      await context.close();
    }
  }
  assert.deepEqual(external, [], "nothing outside the stack was contacted at any point");
  console.log(`Artifact viewer native-stack gate passed (CLI ${JSON.parse(await readFile(join(cliPackage, "package.json"), "utf8")).version}): md + html published, opened, hidden/recalled, revoked, reloaded`);
} catch (error) {
  console.error(`[artifact-gate] failed in phase "${phase}": ${String(error?.message ?? error).slice(0, 600)}`);
  if (external.length > 0) console.error(`[artifact-gate] external requests attempted: ${JSON.stringify(external.slice(0, 5))}`);
  process.exitCode = 1;
} finally {
  await browser?.close().catch(() => undefined);
  await stack?.close().catch(() => undefined);
  await candidate?.close().catch(() => undefined);
  process.exit();
}
