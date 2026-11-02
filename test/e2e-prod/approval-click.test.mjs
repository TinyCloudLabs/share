import { test } from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import puppeteer from "puppeteer";
import { approvePick, boxMoved, clickApprove, clickState, signatureMismatch, signaturesFor, signaturesIn, signedSince, watchSignatures } from "./approval-click.mjs";
import { APPROVE_NAME } from "./smoke-redact.mjs";

// jsdom has no layout: an element counts as visible unless it (or an ancestor) is `hidden`.
const doc = (html) => {
  const { window } = new JSDOM(`<body>${html}</body>`);
  window.Element.prototype.getClientRects = function () { return this.closest("[hidden]") ? [] : [{}]; };
  return window.document;
};
const pick = (html) => approvePick(APPROVE_NAME.source, doc(html));
const label = (result) => result.button?.textContent ?? null;

test("the pick is the last button of the last visible dialog, only under an approval label", () => {
  assert.equal(label(pick(`<div role=dialog><button>Cancel</button><button>Approve</button></div>`)), "Approve");
  assert.equal(label(pick(`<div role=dialog><button>Cancel</button><button>Approve exact bytes</button></div>`)), "Approve exact bytes");
  assert.equal(label(pick(`<div role=dialog hidden><button>Approve</button></div><div role=dialog><button>Cancel</button><button>Approve</button></div>`)), "Approve");
  assert.equal(pick(`<div role=dialog><button>Cancel</button><button disabled>Signing…</button></div>`).button, null);
});

test("a renamed or unexpected last button is never clicked, and its label is reported", () => {
  assert.deepEqual(pick(`<div role=dialog><button>Cancel</button><button>Approve &amp; sign</button></div>`), { button: null, rejected: "Approve & sign" });
  assert.deepEqual(pick(`<div role=dialog><button>Approve</button><button>Cancel</button></div>`), { button: null, rejected: "Cancel" });
});

test("without a dialog only a button named exactly Approve (or Approve exact bytes) is picked", () => {
  assert.equal(label(pick(`<button>Approve all later</button><button>Approve</button>`)), "Approve");
  assert.deepEqual(pick(`<button>Approve all later</button>`), { button: null, rejected: "" });
});

test("only Signing… marks the clicked button as signing; disabled alone is not", () => {
  const page = doc(`<button id=a>Approve</button><button id=b disabled>Approve</button><button id=c disabled>Signing…</button>`);
  assert.deepEqual(clickState(page.getElementById("a")), { connected: true, disabled: false, signing: false });
  assert.deepEqual(clickState(page.getElementById("b")), { connected: true, disabled: true, signing: false });
  assert.deepEqual(clickState(page.getElementById("c")), { connected: true, disabled: true, signing: true });
});

test("signatures are the completed OpenKey sign calls of one stage", () => {
  const trail = [
    { stage: "share-create", method: "POST", origin: "https://api.openkey.so", path: "/api/keys/<id>/sign", status: 200 },
    { stage: "share-create", method: "POST", origin: "https://api.openkey.so", path: "/api/delegate/authorize-sign", status: 200 },
    { stage: "share-create", method: "POST", origin: "https://api.openkey.so", path: "/api/delegate/authorize-sign-prepare", status: 200 },
    { stage: "share-create", method: "POST", origin: "https://api.openkey.so", path: "/api/keys/<id>/sign", status: 500 },
    { stage: "share-sign-in", method: "POST", origin: "https://api.openkey.so", path: "/api/keys/<id>/sign", status: 200 },
    { stage: "share-create", method: "GET", origin: "https://api.openkey.so", path: "/api/keys/<id>", status: 200 },
    { stage: "share-create", method: "POST", origin: "https://openkey.so", path: "/api/keys/<id>/sign", status: 200 },
    { stage: "share-create", method: "POST", origin: "https://evil-openkey.so", path: "/api/keys/<id>/sign", status: 200 },
  ];
  assert.equal(signaturesIn(trail, "share-create"), 3);
  assert.equal(signaturesIn(trail, "share-sign-in"), 1);
});

test("a step's counted approvals must equal its OpenKey signatures", () => {
  assert.equal(signatureMismatch(1, 1), null);
  assert.equal(signatureMismatch(0, 0), null);
  assert.match(signatureMismatch(1, 2), /2 OpenKey signatures for 1 counted approvals/);
  assert.match(signatureMismatch(1, 0), /0 OpenKey signatures for 1 counted approvals/);
  assert.match(signatureMismatch(2, 1), /1 OpenKey signatures for 2 counted approvals/);
});

test("boxMoved reports the larger shift, and null without both boxes", () => {
  assert.equal(boxMoved({ x: 10, y: 10, height: 40 }, { x: 10, y: 74, height: 40 }), 64);
  assert.equal(boxMoved(null, { x: 0, y: 0, height: 1 }), null);
});

test("clickApprove on a real page: taken only by Signing… or a sign call; a swallowed or layout-blocked click is a drop", async () => {
  const browser = await puppeteer.launch({ args: process.env.GITHUB_ACTIONS === "true" ? ["--no-sandbox"] : [] });
  try {
    const page = await browser.newPage();
    const button = (label, onclick) => `<div role="dialog"><button>Cancel</button><button onclick="document.body.dataset.clicks=Number(document.body.dataset.clicks||0)+1;${onclick}">${label}</button></div>`;
    const signing = "this.disabled=true;this.textContent='Signing…'";
    // OpenKey's layout block (TC-2320): disabled for a moment after a resize (≈300 ms; 600 ms here so a
    // poll on a loaded runner can't miss it), then enabled again, no signing.
    const layoutBlock = "this.disabled=true;setTimeout(()=>{this.disabled=false},600)";
    let signed = false;
    page.on("console", (message) => { if (message.text() === "signed") signed = true; });
    const report = {};
    let clock = 0;
    const options = { sign: page.mainFrame(), during: "share", report, closed: () => false, signedSince: () => signed, at: () => ++clock, stage: () => "share-create", reviewSeenAt: 0, takenMs: 1_000 };

    await page.setContent(button("Approve", signing));
    assert.equal(await clickApprove(options), true, "Signing… is taken");
    assert.equal(report.approveClicksNotTaken, undefined);

    await page.setContent(button("Approve", "console.log('signed')"));
    assert.equal(await clickApprove(options), true, "a sign call after the click is taken, even with no Signing…");
    signed = false;

    await page.setContent(button("Approve", layoutBlock));
    const started = Date.now();
    assert.equal(await clickApprove({ ...options, takenMs: 2_000 }), false, "disabled then enabled again without signing is NOT taken");
    assert.ok(Date.now() - started < 2_000, "the re-enable ends the wait without running out the clock");
    assert.equal(report.approveClicksNotTaken, 1);
    assert.equal(report.approveClicksDropped[0].disabledWithoutSigning, true);

    await page.setContent(button("Approve", signing) + `<div class="overlay-x" style="position:fixed;inset:0;z-index:9"></div>`);
    assert.equal(await clickApprove(options), false);
    assert.equal(report.approveClicksNotTaken, 2);
    assert.deepEqual(report.approveClicksDropped[1], {
      during: "share", stage: "share-create", atMs: 4, msSinceReview: 4, disabledWithoutSigning: false, buttonMovedPx: 0,
      clickPointOnButton: false, clickPointTag: "div", clickPointClasses: "overlay-x",
    });
    await page.evaluate(() => document.querySelector(".overlay-x").remove());
    assert.equal(await clickApprove(options), true, "the retry is taken once nothing covers the button");

    await page.setContent(button("Approve &amp; sign for qa-x@mail.example", signing));
    assert.equal(await clickApprove(options), false);
    assert.equal(await page.evaluate(() => Number(document.body.dataset.clicks ?? 0)), 0, "a renamed label was clicked");
    assert.deepEqual(report.approveLabelsRejected, ["Approve & sign for <email>"], "the rejected label is scrubbed");
    assert.equal(report.approveClicksNotTaken, 2, "a refused pick is not a dropped click");
  } finally {
    await browser.close();
  }
});

test("watchSignatures counts completed OpenKey sign calls by the step they started in", async () => {
  const browser = await puppeteer.launch({ args: process.env.GITHUB_ACTIONS === "true" ? ["--no-sandbox"] : [] });
  try {
    const page = await browser.newPage();
    // A stand-in OpenKey API: answered in the browser, never on the network. One sign call is slow.
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin === "https://example.test") return request.respond({ status: 200, contentType: "text/html", body: "<p>page</p>" });
      const headers = { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*" };
      if (request.method() === "OPTIONS") return request.respond({ status: 204, headers });
      const status = url.pathname.endsWith("/fail/sign") ? 500 : 200;
      const reply = () => request.respond({ status, headers, contentType: "application/json", body: "{}" });
      return url.pathname.includes("/slow/") ? setTimeout(reply, 400) : reply();
    });
    let step = "first"; let clock = 0;
    const calls = watchSignatures(page, { calls: {}, step: () => step, at: () => ++clock });
    await page.goto("https://example.test/");
    const call = (url, method = "POST") => page.evaluate((u, m) => fetch(u, { method: m, headers: { "content-type": "text/plain" }, body: m === "POST" ? "{}" : undefined }).then(() => true, () => false), url, method);

    await call("https://api.openkey.so/api/keys/k1/sign");
    await call("https://openkey.so/api/delegate/authorize-sign");
    await call("https://api.openkey.so/api/delegate/authorize-sign-prepare");
    await call("https://api.openkey.so/api/keys/k1", "GET");
    await call("https://api.openkey.so/api/keys/fail/sign");
    const slow = call("https://api.openkey.so/api/keys/slow/sign");
    await new Promise((done) => setTimeout(done, 100));
    step = "second"; // the slow call started in "first" and finishes after the step changed
    await slow;
    await call("https://api.openkey.so/api/keys/k2/sign");
    await new Promise((done) => setTimeout(done, 200));

    assert.equal(signaturesFor(calls, "first"), 3, "two sign calls plus the slow one, attributed to the step it started in");
    assert.equal(signaturesFor(calls, "second"), 1);
    assert.equal(calls.open.size, 0);
    assert.equal(signedSince(calls, 1_000), false);
    assert.equal(signedSince(calls, 1), true);
  } finally {
    await browser.close();
  }
});
