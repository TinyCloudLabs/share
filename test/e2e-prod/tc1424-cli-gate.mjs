#!/usr/bin/env node
/**
 * TC-1424 throwaway proof: sender = published `tc share publish --to <email> --notify`
 * (js-sdk CLI) instead of the Share web composer; recipient = fresh browser
 * context on the candidate Share build. Same hermetic native stack and
 * transport-only remapping as joined-gate.mjs. Never contacts production.
 *
 * Env: G (gate worktrees root), TC1424_CLI (path to installed @tinycloud/cli),
 * TC1424_OUT (output dir), optional TC500_*_COMMIT/_WORKTREE overrides.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";
import { startCandidateServer } from "./candidate-server.mjs";
import { credentialOtpFromMail, isCredentialOtpMail, startNativeStack } from "./native-stack.mjs";

const shareRoot = resolve(import.meta.dirname, "../..");
const G = process.env.G;
const out = resolve(process.env.TC1424_OUT ?? ".");
const cliBin = join(process.env.TC1424_CLI, "bin/tc");
const shim = resolve(import.meta.dirname, "tc1424-cli-shim.mjs");
const fixtureText = `# TC-1424 CLI email share\n\nnonce ${randomBytes(8).toString("hex")}\n`;
const fixture = Buffer.from(fixtureText, "utf8");
const steps = [];
const trace = [];
let phase = "setup";
const step = (name, status, evidence) => { steps.push({ name, status, evidence }); console.log(`[tc1424] ${status.padEnd(7)} ${name}${evidence ? ` :: ${evidence}` : ""}`); };

const strings = (value, acc = []) => {
  if (typeof value === "string") acc.push(value);
  else if (Array.isArray(value)) value.forEach((item) => strings(item, acc));
  else if (value && typeof value === "object") Object.values(value).forEach((item) => strings(item, acc));
  return acc;
};
const waitUntil = async (check, timeout = 120_000) => {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await new Promise((r) => setTimeout(r, 250)); }
  return undefined;
};

async function installRouting(page, stack) {
  await page.evaluateOnNewDocument(installBrowserInstrumentation);
  page.on("pageerror", (error) => trace.push({ phase, pageerror: String(error?.message).slice(0, 200) }));
  await page.setRequestInterception(true);
  page.on("request", (request) => { void (async () => {
    const url = new URL(request.url());
    if (url.origin === stack.canonical.share || url.protocol === "data:" || url.protocol === "blob:") { await request.continue(); return; }
    const targets = new Map([[stack.canonical.node, stack.services.nodeOrigin], [stack.canonical.credentials, stack.services.credentialsOrigin], [stack.canonical.registry, stack.services.registryOrigin]]);
    const entry = { phase, method: request.method(), origin: url.origin, path: url.pathname, status: undefined };
    trace.push(entry);
    const target = targets.get(url.origin);
    if (target === undefined) { entry.status = "blocked"; await request.abort("blockedbyclient"); return; }
    let body;
    if (!["GET", "HEAD"].includes(request.method())) {
      const binaryId = request.headers()["x-tc500-binary-id"];
      if (url.pathname === "/invoke" && binaryId !== undefined) {
        body = Buffer.from(await page.evaluate((id) => { const b = window.__tc500BinaryBodies[id]; delete window.__tc500BinaryBodies[id]; return b; }, binaryId));
      } else body = await request.fetchPostData();
    }
    const headers = new Headers(request.headers());
    for (const key of ["accept-encoding", "connection", "content-length", "host", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "x-tc500-binary-id"]) headers.delete(key);
    const response = await fetch(new URL(`${url.pathname}${url.search}`, target), { method: request.method(), headers, redirect: "manual", ...(body === undefined ? {} : { body }) });
    const bytes = Buffer.from(await response.arrayBuffer());
    entry.status = response.status;
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

async function credentialInput(page) {
  return waitUntil(async () => {
    const handle = await page.evaluateHandle(() => {
      const c = document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input");
      return c instanceof HTMLInputElement && (c.type === "text" || c.inputMode === "numeric" || c.name === "otp") ? c : null;
    }).catch(() => undefined);
    return handle?.asElement() ?? undefined;
  }, 90_000);
}

const temporary = await mkdtemp(join(tmpdir(), "tc1424-cli-"));
await mkdir(out, { recursive: true });
let stack; let candidate; let browser;
try {
  phase = "build";
  const distConfig = join(shareRoot, "dist/.well-known/tinycloud-share/config.json");
  await readFile(distConfig).catch(() => execFileSync("npm", ["run", "build"], { cwd: shareRoot, stdio: "ignore" }));
  const cert = join(temporary, "candidate.pem"); const key = join(temporary, "candidate.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore" });
  const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8" }).trim();
  candidate = await startCandidateServer({ root: resolve(shareRoot, "dist"), key: await readFile(key), cert: await readFile(cert) });

  phase = "stack";
  stack = await startNativeStack({
    root: temporary,
    nodeRoot: process.env.TC500_NODE_WORKTREE ?? `${G}/node`,
    credentialsRoot: process.env.TC500_OPENCREDENTIALS_WORKTREE ?? `${G}/oc`,
    registryRoot: process.env.TC500_REGISTRY_WORKTREE ?? `${G}/registry`,
  });
  const nodeInfo = await (await fetch(`${stack.services.nodeOrigin}/info`)).json();
  step("local stack up (node, OpenCredentials witness, location registry, Postgres, Resend-compatible mail sink)", "WORKS", `node ${nodeInfo.version ?? "?"} at loopback; provenance ${JSON.stringify(stack.provenance)}`);

  phase = "cli-sender";
  const tcHome = join(temporary, "tc-home");
  const profileDir = join(tcHome, ".tinycloud/profiles/owner");
  await mkdir(profileDir, { recursive: true });
  await writeFile(join(tcHome, ".tinycloud/config.json"), JSON.stringify({ defaultProfile: "owner", version: 1 }));
  await writeFile(join(profileDir, "profile.json"), JSON.stringify({ name: "owner", host: stack.canonical.node, chainId: 1, spaceName: "default", authMethod: "local", posture: "local-owner-key", privateKey: randomBytes(32).toString("hex"), createdAt: new Date().toISOString() }), { mode: 0o600 });
  const fixturePath = join(temporary, "cli-share.md"); await writeFile(fixturePath, fixture);
  const recipient = `tc1424-cli-${Date.now()}@mailinator.com`;
  const shimLog = join(out, "cli-shim-routes.jsonl");
  const env = {
    ...process.env, TC_HOME: tcHome, TC_HOST: stack.canonical.node, NO_COLOR: "1",
    TC1424_MAP: JSON.stringify({ [stack.canonical.node]: stack.services.nodeOrigin, [stack.canonical.credentials]: stack.services.credentialsOrigin, [stack.canonical.registry]: stack.services.registryOrigin }),
    TC1424_SHARE_CONFIG: distConfig, TC1424_SHIM_LOG: shimLog,
  };
  // Async on purpose: the mail sink lives in this process, so a blocking spawn would starve it.
  const cli = await new Promise((resolveCli) => {
    const child = spawn("node", ["--import", shim, cliBin, "--profile", "owner", "share", "publish", fixturePath, "--to", `email:${recipient}`, "--notify", "--json"], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 300_000);
    child.on("close", (status, signal) => { clearTimeout(timer); resolveCli({ status, signal, stdout, stderr }); });
  });
  const redact = (text) => String(text ?? "").replaceAll(/#[^\s"]+/g, "#<fragment>").replaceAll(recipient, "<recipient>").slice(-4000);
  await writeFile(join(out, "cli-publish.json"), JSON.stringify({ exit: cli.status, signal: cli.signal, stdout: redact(cli.stdout), stderr: redact(cli.stderr) }, null, 2));
  let cliJson; try { cliJson = JSON.parse(cli.stdout); } catch {}
  step("`tc share publish <file> --to email:<addr> --notify --json` (published @tinycloud/cli)", cli.status === 0 ? "WORKS" : "BREAKS", `exit ${cli.status}; notification=${JSON.stringify(cliJson?.notification ?? cliJson?.data?.notification ?? null)}; stderr tail: ${redact(cli.stderr).slice(-300)}`);
  const witnessStages = stack.credentialsLog().split("\n").filter((line) => /credential invitation stage=/.test(line));
  await writeFile(join(out, "witness-stages.txt"), `${witnessStages.join("\n")}\nmail sink messages: ${stack.mail.length}\n`);
  if (cli.status !== 0) { step("witness invitation stages (stderr labels)", "INFO", `${JSON.stringify(witnessStages)}; mail sink messages=${stack.mail.length}`); throw new Error("cli publish failed"); }

  phase = "mail";
  const invitationMail = await waitUntil(() => stack.mail.find((m) => strings(m.payload).some((v) => v.includes("/s/inline#"))), 60_000);
  const link = invitationMail && strings(invitationMail.payload).flatMap((v) => [...v.matchAll(/https:\/\/share\.tinycloud\.xyz\/s\/inline#[^\s"'<>]+/g)].map((m) => m[0].replaceAll("&amp;", "&")))[0];
  const to = invitationMail?.payload?.to;
  step("OpenCredentials invitation email captured by local mail sink", link ? "WORKS" : "BREAKS", link ? `from=${JSON.stringify(invitationMail.payload.from)} subject=${JSON.stringify(invitationMail.payload.subject)} to-matches=${JSON.stringify(Array.isArray(to) ? to.includes(recipient) : to === recipient)} link=https://share.tinycloud.xyz/s/inline#<fragment>` : `mail count ${stack.mail.length}`);
  if (!link) throw new Error("no invitation mail");

  phase = "recipient";
  browser = await puppeteer.launch({ headless: true, args: [`--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${candidate.port}`, `--ignore-certificate-errors-spki-list=${spki}`, "--disable-quic", "--no-proxy-server"] });
  const context = await browser.createBrowserContext(); const page = await context.newPage(); await installRouting(page, stack);
  await page.goto(link, { waitUntil: "domcontentloaded", timeout: 180_000 });
  const scrubbed = await page.evaluate(() => location.hash === "");
  step("recipient opens /s/inline link in fresh context; fragment scrubbed", scrubbed ? "WORKS" : "BREAKS", `location.hash empty after load = ${scrubbed}`);
  const otpMail = await waitUntil(() => stack.mail.find((m) => isCredentialOtpMail(m, recipient)), 90_000);
  const code = credentialOtpFromMail(otpMail);
  step("OpenCredentials mailbox-proof code email sent to recipient", code ? "WORKS" : "BREAKS", `subject=${JSON.stringify(otpMail?.payload?.subject)} code length=${code?.length}`);
  const input = await credentialInput(page); assert(input, "otp input missing");
  await input.type(code);
  const autoSubmitted = await page.evaluate(() => document.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input")?.readOnly === true);
  if (!autoSubmitted) await page.evaluate(() => document.querySelector("tinycloud-credential-acquisition").shadowRoot.querySelector("button[type=submit]").click());
  const needle = fixtureText.split("\n")[2];
  const viewerReady = Boolean(await page.waitForSelector(".viewer-download", { timeout: 180_000 }).catch(() => null));
  const textRendered = Boolean(await waitUntil(async () => {
    for (const frame of page.frames()) if (await frame.evaluate((n) => (document.body?.textContent ?? "").includes(n), needle).catch(() => false)) return true;
    return false;
  }, 30_000));
  const rendered = viewerReady && textRendered;
  const holder = await page.evaluate(() => { try { const r = JSON.parse(sessionStorage.getItem("tinycloud.share.receiver-session.v1")); return { holderDidPrefix: r?.holderDid?.slice(0, 12), privateJwkInSessionStorage: typeof r?.jwk?.d === "string" }; } catch { return null; } });
  const r = (path) => trace.filter((e) => e.phase === "recipient" && e.path === path).map((e) => e.status);
  step("recipient OTP -> credential acquisition -> Policy/v3 challenge/delegation -> /delegate -> /invoke -> render", rendered ? "WORKS" : "BREAKS",
    `viewerReady=${viewerReady} fixtureTextRendered=${textRendered} acquisitions=${JSON.stringify(trace.filter((e) => e.phase === "recipient" && e.path.startsWith("/v1/acquisitions") && e.method !== "OPTIONS").map((e) => `${e.method} ${e.path.replace(/acquisitions\/[^/]+/, "acquisitions/<id>")} ${e.status}`))} challenges=${JSON.stringify(r("/policy/v3/challenges"))} delegations=${JSON.stringify(r("/policy/v3/delegations"))} delegate=${JSON.stringify(r("/delegate"))} invoke=${JSON.stringify(r("/invoke"))} holder=${JSON.stringify(holder)}`);
  await writeFile(join(out, "cli-gate-result.json"), JSON.stringify({ result: rendered ? "passed" : "failed", steps }, null, 2));
} catch (error) {
  step(`aborted in phase ${phase}`, "BREAKS", String(error?.message ?? error).slice(0, 400));
  await writeFile(join(out, "cli-gate-result.json"), JSON.stringify({ result: "failed", phase, steps }, null, 2)).catch(() => undefined);
  process.exitCode = 1;
} finally {
  await writeFile(join(out, "cli-browser-trace.json"), JSON.stringify(trace, null, 2)).catch(() => undefined);
  await browser?.close().catch(() => undefined); await stack?.close().catch(() => undefined); await candidate?.close().catch(() => undefined);
  process.exit();
}
