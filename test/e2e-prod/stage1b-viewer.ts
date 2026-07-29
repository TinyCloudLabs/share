/**
 * STAGE 1b — the production VIEWER half of a bearer share, proven in a real
 * browser when the production COMPOSER cannot be reached.
 *
 * Why this exists: `stage1-bearer.mjs` establishes that the sender app hangs
 * forever inside the Web SDK bootstrap ("Connecting to your encrypted
 * TinyCloud…"), so the composer UI is unreachable in production. That blocks
 * the sender half but says nothing about the rest of the path, and the rest of
 * the path has also never run in a real browser against production.
 *
 * So: sign in far enough for the host to issue the share session cookie
 * (POST /api/share/auth/openkey → 200 — this succeeds; the hang is later),
 * then mint the bearer share with `createBearerShare` — the exact function
 * `src/share/link-only.ts` calls, with the exact registry base URL and viewer
 * origin it passes — and upload it to the real registry with that cookie.
 * Then open the resulting link in a clean browser context and check the
 * rendered document and the exact bytes.
 *
 * This is NOT a substitute for driving the composer. It is labelled everywhere
 * as the viewer-half proof. Run:
 *
 *   ../../node_modules/.bin/tsx stage1b-viewer.ts
 */
import { chromium, type BrowserContext, type Page } from "playwright";
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createBearerShare } from "../../packages/cli/src/index.js";
import { attachVirtualAuthenticator, restoreCredential, registerFreshAccount, loadAccount, saveAccount, signInToShare } from "./lib/openkey.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ACCOUNT_PATH = resolve(HERE, ".account.json");
const RUN_DIR = resolve(HERE, "runs", `stage1b-${new Date().toISOString().replace(/[:.]/g, "-")}`);
const SHARE_ORIGIN = process.env.SHARE_ORIGIN ?? "https://share.tinycloud.xyz";

mkdirSync(RUN_DIR, { recursive: true });
const lines: string[] = [];
const log = (line: string): void => {
  console.log(line);
  lines.push(`${new Date().toISOString()} ${line}`);
  writeFileSync(resolve(RUN_DIR, "run.log"), lines.join("\n"));
};

const results: { name: string; ok: boolean; detail?: string }[] = [];
function record(name: string, ok: boolean, detail?: string): void {
  results.push({ name, ok, detail });
  log(`${ok ? "PASS" : "FAIL"}  ${name}${detail === undefined ? "" : ` — ${detail}`}`);
}

const SHARE_URL_RE = /^https:\/\/[^/]+\/s\/(bafkrei[a-z2-7]{52})#k=([A-Za-z0-9_-]{43})$/;

const browser = await chromium.launch({ headless: process.env.HEADED !== "1" });
log(`[browser] ${browser.version()}`);

try {
  const senderContext: BrowserContext = await browser.newContext();
  const senderPage: Page = await senderContext.newPage();
  senderPage.on("pageerror", (error) => log(`[sender pageerror] ${error.message}`));
  senderPage.on("response", (response) => {
    if (/\/api\/share\//.test(response.url())) log(`[sender res ${response.status()}] ${response.request().method()} ${response.url()}`);
  });

  const { cdp, authenticatorId } = await attachVirtualAuthenticator(senderContext, senderPage);
  let account = process.env.FRESH_ACCOUNT === "1" ? undefined : loadAccount(ACCOUNT_PATH);
  if (account === undefined) {
    account = await registerFreshAccount(senderPage, cdp, authenticatorId, log);
    saveAccount(ACCOUNT_PATH, account);
  } else {
    log(`[openkey] reusing account ${account.address}`);
    await restoreCredential(cdp, authenticatorId, account.credential);
  }

  await signInToShare(senderPage, { appUrl: `${SHARE_ORIGIN}/share#/new`, log, until: "session" });
  const cookies = await senderContext.cookies(SHARE_ORIGIN);
  record("production issues a share session cookie for a real OpenKey passkey sign-in", cookies.length > 0, cookies.map((cookie) => cookie.name).join(","));
  const cookieHeader = cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
  await senderContext.close();

  // The registry write is credentialed exactly as src/share/link-only.ts does
  // it (`credentials: "include"` against the same path on the share origin).
  const authenticatedFetch: typeof fetch = (input, init) =>
    fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string> | undefined), cookie: cookieHeader } });

  async function mintAndOpen(filename: string, bytes: Uint8Array, expectNonce?: string): Promise<void> {
    const created = await createBearerShare({
      content: bytes,
      filename,
      registryBaseUrl: `${SHARE_ORIGIN}/api/share/link-only/registry`,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      viewerOrigin: SHARE_ORIGIN,
      fetchFn: authenticatedFetch,
    });
    const parsed = SHARE_URL_RE.exec(created.url);
    record(`the production registry accepts the sealed bearer envelope (${filename})`, parsed !== null, created.url.replace(/#k=.*/, "#k=<redacted>"));
    if (parsed === null) throw new Error(`unexpected url ${created.url}`);

    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    page.on("pageerror", (error) => log(`[viewer pageerror] ${error.message}`));
    record(`recipient context for ${filename} starts with no cookies`, (await context.cookies()).length === 0);

    await page.goto(created.url, { waitUntil: "domcontentloaded" });
    await page.locator("button.viewer-download").waitFor({ timeout: 120_000 });

    const observed = await page.evaluate(() => ({
      href: location.href,
      hash: location.hash,
      referrer: document.referrer,
      historyLength: history.length,
    }));
    log(`[viewer] ${JSON.stringify(observed)}`);
    record(`the #k= fragment is scrubbed from the address bar (${filename})`, !observed.href.includes("#k=") && observed.hash === "", observed.href);
    record(`no referrer reaches the viewer (${filename})`, observed.referrer === "", JSON.stringify(observed.referrer));

    if (expectNonce !== undefined) {
      // Markdown is rendered into a scriptless `sandbox=""` preview iframe
      // (src/viewer/preview-frame.ts), so the top document's innerText does not
      // contain the document. Read every frame.
      const texts: string[] = [];
      for (const frame of page.frames()) {
        texts.push(`--- ${frame.url().slice(0, 60)} ---\n${await frame.evaluate(() => document.body?.innerText ?? "").catch((error) => `<unreadable: ${error.message}>`)}`);
      }
      const rendered = texts.join("\n\n");
      record("the rendered document shows the plaintext nonce", rendered.includes(expectNonce), `${page.frames().length} frame(s); nonce ${expectNonce}`);
      writeFileSync(resolve(RUN_DIR, `${filename}.rendered.txt`), rendered);
    }

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 30_000 }),
      page.locator("button.viewer-download").click(),
    ]);
    const path = resolve(RUN_DIR, `downloaded-${filename}`);
    await download.saveAs(path);
    const got = new Uint8Array(readFileSync(path));
    const same = got.length === bytes.length && got.every((byte, index) => byte === bytes[index]);
    record(`"Download original" returns the exact uploaded bytes (${filename}, ${bytes.length} B)`, same, same ? `${got.length} bytes identical` : `uploaded ${bytes.length} B, downloaded ${got.length} B`);

    await page.screenshot({ path: resolve(RUN_DIR, `${filename}.png`), fullPage: true });
    await context.close();
  }

  const nonce = `tc-prod-nonce-${crypto.randomUUID()}`;
  const markdown = `# Live production proof\n\nnonce: ${nonce}\n\n- created ${new Date().toISOString()}\n- stage 1b, bearer link-only, viewer half\n`;
  await mintAndOpen("stage1b-proof.md", new TextEncoder().encode(markdown), nonce);

  const binary = new Uint8Array(4096);
  crypto.getRandomValues(binary);
  await mintAndOpen("stage1b-proof.bin", binary);
} finally {
  await browser.close();
}

writeFileSync(resolve(RUN_DIR, "results.json"), JSON.stringify(results, null, 2));
const failed = results.filter((entry) => !entry.ok);
log(`\n${results.length - failed.length}/${results.length} checks passed. Artifacts in ${RUN_DIR}`);
if (failed.length > 0) process.exit(1);
