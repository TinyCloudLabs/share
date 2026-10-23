/**
 * Real-browser run (Chrome through puppeteer) of the viewer, the composer's link step and the library's
 * "Send the link again" button, against a local mock of the links API that passes the contract's service
 * vectors. Run with: `npx tsx test/e2e-links-v4.mjs`.
 *
 * Requests the pages send to https://api.tinycloud.xyz are answered by the mock (real CORS applies);
 * any other external request is refused and recorded. At 390 and 1440 px it checks:
 *  - nothing is requested before the viewer's click, the key is in no request, and every refusal
 *    shows the same screen;
 *  - the composer creates a short link with a signed header, and the full link with the notice when
 *    the API refuses;
 *  - "Send the link again" is shown for an expired share and hidden for a live one.
 * LINKS_E2E_SCREENSHOT_DIR sets where screenshots go.
 */
import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { createServer as httpServer } from "node:http";
import { join } from "node:path";

import puppeteer from "puppeteer";
import { createServer } from "vite";

import { generateKey, seal, toBase64Url } from "@tinycloud/share-envelope";
import { createLink } from "../src/short-links/client.ts";
import { buildShortLink } from "../src/short-links/codec.ts";
import { publishLink } from "../src/short-links/publish.ts";
import { buildHeader, HEADER_DOMAIN, signObject } from "../src/short-links/record.ts";
import { createMockLinksApi } from "./fixtures/links-mock-api.ts";
import { ISSUER_DID, sealedMaterial, signWithIssuer } from "./fixtures/link-material.ts";

const API = "https://api.tinycloud.xyz";
const SHARE = "https://share.tinycloud.xyz";
const screenshotDir = process.env.LINKS_E2E_SCREENSHOT_DIR ?? ".context/links-e2e";
await mkdir(screenshotDir, { recursive: true });

const freePort = async () => {
  const listener = httpServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  return port;
};
const port = await freePort();
const origin = `http://127.0.0.1:${port}`;
process.env.VITE_SHARE_VIEWER_HERMETIC = "true";
const server = await createServer({ configFile: "vite.config.ts", logLevel: "error", server: { host: "127.0.0.1", port, strictPort: true, hmr: false } });
await server.listen();

const links = createMockLinksApi({ now: Date.now, audience: API, corsOrigins: [origin] });
const fetchForNode = links.fetchFor(API);
const external = [];
const apiLog = [];

/** Sends the page's requests to the mock API; refuses every other external request. */
async function wire(page) {
  await page.setRequestInterception(true);
  page.on("request", async (request) => {
    const url = request.url();
    if (url.startsWith(origin) || url.startsWith("data:") || url.startsWith("blob:")) return request.continue();
    if (url.startsWith(API)) {
      const headers = request.headers();
      apiLog.push({ method: request.method(), url, headers, body: request.postData() ?? "" });
      const response = await links.handle({ method: request.method(), path: new URL(url).pathname, headers, ...(request.postData() ? { body: request.postData() } : {}) });
      const body = Buffer.from(await response.arrayBuffer());
      return request.respond({ status: response.status, headers: Object.fromEntries(response.headers), body });
    }
    external.push(url);
    return request.abort();
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const text = (page, selector) => page.$eval(selector, (node) => node.textContent);

async function shareLink() {
  const material = await sealedMaterial();
  const published = await publishLink({ material, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), signer: { issuerDid: ISSUER_DID, sign: signWithIssuer }, shareOrigin: SHARE, apiOrigin: API, fetchFn: fetchForNode });
  assert.equal(published.form, "short");
  return { link: published.url, key: material.envelopeKey };
}

async function courierLink(plaintext) {
  const key = generateKey();
  const sealed = await seal(new TextEncoder().encode(JSON.stringify(plaintext)), key);
  const header = await buildHeader({ type: "courier", issuer: ISSUER_DID, audience: API, issuedAt: new Date(), expiresAt: new Date(Date.now() + 3_600_000), body: sealed.blob });
  const signature = await signObject(HEADER_DOMAIN, header, signWithIssuer);
  const created = await createLink({ header, signature, body: sealed.blob }, { apiOrigin: API, fetchFn: fetchForNode });
  return buildShortLink({ origin: SHARE, type: "courier", id: created.id, key: toBase64Url(key), cid: header.bodyCid });
}

const local = (link) => { const url = new URL(link); return `${origin}${url.pathname}${url.hash}`; };
const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
const results = [];
const note = (name, detail = "") => { results.push(`PASS ${name}${detail === "" ? "" : `: ${detail}`}`); };

try {
  for (const [label, width, height] of [["phone-390", 390, 844], ["desktop-1440", 1440, 900]]) {
    const open = async (url) => {
      const page = await browser.newPage();
      await page.setViewport({ width, height, deviceScaleFactor: 1 });
      await wire(page);
      apiLog.length = 0;
      await page.goto(url, { waitUntil: "load" });
      return page;
    };
    const shot = (page, name) => page.screenshot({ path: join(screenshotDir, `${label}-${name}.png`), fullPage: true });

    // ---- Viewer: confirm gate, key privacy, refusals --------------------------------------------------
    const { link, key } = await shareLink();
    let page = await open(local(link));
    await page.waitForSelector(".link-confirm-action");
    assert.equal(await text(page, ".link-confirm-action"), "Open");
    assert.equal(apiLog.length, 0, "no API request before the click");
    assert.equal(await page.evaluate(() => location.hash), "", "fragment scrubbed from the address bar");
    await shot(page, "viewer-confirm");
    await page.click(".link-confirm-action");
    await page.waitForFunction(() => !document.querySelector(".link-confirm-action"), { timeout: 10_000 });
    await sleep(500);
    const reads = apiLog.filter((entry) => entry.method === "GET");
    assert.equal(reads.length, 1, "one read after the click");
    assert.ok(!JSON.stringify(apiLog).includes(key), "the key is in no API request");
    assert.ok(!JSON.stringify(apiLog).includes("#v=4"), "no link fragment is sent");
    assert.equal(reads[0].url.includes("?"), false, "no query string");
    note(`${label} viewer confirm gate`, `0 requests before the click, 1 read after, key absent`);
    await page.close();

    // The same screen for every refusal.
    const screens = new Map();
    const tampered = {
      "deleted": async () => { const fresh = await shareLink(); links.state.records.clear(); return fresh.link; },
      "wrong key": async () => { const fresh = await shareLink(); return fresh.link.replace(/k=[A-Za-z0-9_-]{43}/, `k=${"A".repeat(43)}`); },
      "cid mismatch": async () => { const fresh = await shareLink(); return fresh.link.replace(/c=bafkrei[a-z2-7]{52}/, "c=bafkreie3nxr36mwl2jprkro4mr42bdkcvvvrwbvbxur2qe6iq4mxhvdrfq"); },
      "truncated": async () => { const fresh = await shareLink(); return fresh.link.slice(0, -14); },
      "removed version": async () => { const fresh = await shareLink(); return fresh.link.replace("#v=4", "#v=3"); },
      "issuer mismatch": async () => {
        const material = await sealedMaterial({ version: 3, signature: { signerDid: "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK", algorithm: "Ed25519", value: "x" } });
        return (await publishLink({ material, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), signer: { issuerDid: ISSUER_DID, sign: signWithIssuer }, shareOrigin: SHARE, apiOrigin: API, fetchFn: fetchForNode })).url;
      },
    };
    for (const [name, make] of Object.entries(tampered)) {
      const bad = await make();
      page = await open(local(bad));
      await page.waitForSelector(".link-confirm-action");
      await page.click(".link-confirm-action");
      await page.waitForFunction(() => document.querySelector("#viewer")?.textContent?.includes("This share isn't available"), { timeout: 10_000 });
      screens.set(name, await page.$eval("#viewer", (node) => node.innerHTML));
      if (name === "deleted") await shot(page, "viewer-not-found");
      await page.close();
    }
    assert.equal(new Set(screens.values()).size, 1, "every refusal renders the same screen");
    note(`${label} viewer refusals`, `${screens.size} cases (${[...screens.keys()].join(", ")}) render one screen`);

    // Invitation at /c/.
    page = await open(local(await courierLink({ issuer: ISSUER_DID, note: "hello" })));
    await page.waitForSelector(".link-confirm-action");
    await page.click(".link-confirm-action");
    await page.waitForSelector(".courier-record", { timeout: 10_000 });
    assert.equal(await text(page, ".courier-record-value"), "hello");
    await shot(page, "viewer-courier-placeholder");
    note(`${label} viewer /c/ route`, "verified invitation shown through the placeholder view");
    await page.close();

    // ---- Composer: short link, then full link with the notice ------------------------------------------
    for (const mode of ["short", "full"]) {
      links.state.capacityFull = mode === "full";
      page = await open(`${origin}/test/fixtures/links-e2e/harness.html?screen=composer`);
      await page.waitForFunction(() => document.documentElement.dataset.ready === "yes");
      await page.click("input[name=recipient][value=exactEmail]");
      await page.type("input[name=recipient-value]", "reader@example.com");
      const input = await page.$("input[type=file]");
      await input.uploadFile(new URL("../README.md", import.meta.url).pathname);
      await page.click("button[type=submit]");
      await page.waitForSelector(".result-title", { timeout: 20_000 });
      const created = await page.evaluate(() => window.__qa.links[0]);
      const posts = apiLog.filter((entry) => entry.method === "POST" && entry.url.endsWith("/v1/links"));
      if (mode === "short") {
        assert.match(created, /^https:\/\/share\.tinycloud\.xyz\/s\/[a-z2-7]{26}#v=4&k=[A-Za-z0-9_-]{43}&c=bafkrei/);
        assert.equal(posts.length, 1);
        const sent = JSON.parse(posts[0].body);
        assert.deepEqual(Object.keys(sent).sort(), ["body", "header", "signature"]);
        assert.ok(!posts[0].body.includes(new URL(created).hash.match(/k=([^&]+)/)[1]), "the key is not in the create request");
        assert.equal(await page.$(".result-notice"), null);
        note(`${label} composer short link`, "signed create accepted through browser CORS; key absent from the request");
      } else {
        assert.ok(created.startsWith(`${SHARE}/s/full#v=4&k=`));
        assert.equal(await text(page, ".result-notice"), "Short link unavailable: using the full link");
        note(`${label} composer full link`, "API refused (503): full link and notice shown");
      }
      await shot(page, `composer-${mode}`);
      await page.close();
    }
    links.state.capacityFull = false;

    // ---- Library: Send the link again ------------------------------------------------------------------
    page = await open(`${origin}/test/fixtures/sender-layout/harness.html?screen=library&reader=ok`);
    await page.waitForFunction(() => document.querySelector(".sender-freshness")?.textContent?.includes("Statuses confirmed"), { timeout: 10_000 });
    const rows = await page.$$eval(".sender-history-row", (nodes) => nodes.map((row) => ({ name: row.querySelector(".sender-item-cell strong")?.textContent, kind: row.querySelector(".sender-status-text")?.dataset.kind, again: row.querySelector(".sender-send-again")?.hidden, shown: getComputedStyle(row.querySelector(".sender-send-again")).display !== "none" })));
    const old = rows.find((row) => row.name === "old-share.md");
    const live = rows.find((row) => row.name?.startsWith("quarterly"));
    assert.deepEqual([old.kind, old.again, old.shown], ["expired", false, true], "shown for an expired share");
    assert.deepEqual([live.kind, live.again, live.shown], ["ready", true, false], "hidden, and not rendered, for a live share");
    assert.ok(rows.filter((row) => row.kind === "ready").every((row) => !row.shown), "no live row shows the button");
    assert.equal(await page.$eval('button[aria-label^="Send the link again: old-share"]', (node) => node.textContent), "Send the link again");
    await shot(page, "library-send-again-states");
    await page.click('button[aria-label^="Send the link again: old-share"]');
    await page.waitForSelector(".send-again-hint", { timeout: 10_000 });
    assert.equal(await text(page, ".send-again-hint"), "Attach old-share.md again to send the link again.");
    await shot(page, "composer-send-again");
    note(`${label} library Send the link again`, "button shown on the expired row, hidden on the live row; opens the prefilled composer");
    await page.close();
  }
  assert.deepEqual(external, [], "no external request other than the API");
  results.push("PASS no external requests outside the API mock");
} finally {
  await browser.close();
  await server.close();
}
console.log(results.join("\n"));
console.log(`screenshots: ${screenshotDir}`);
process.exit(0);
