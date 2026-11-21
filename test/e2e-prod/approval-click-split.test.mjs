import { test } from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import puppeteer from "puppeteer";
import { SPLIT_REFUSAL, clickApprove, elevatedRefusal, elevatedScreen, splitContinueRefusal, splitState } from "./approval-click.mjs";
import { ELEVATED_ALLOW_NAME } from "./smoke-redact.mjs";

// OpenKey's per-permission review for a request it can split (TC-2927), as elevated-warning.svelte renders it:
// one card per permission with Reject and Allow buttons, neither chosen to start with, and Continue disabled
// until every card is decided.
const SITE = "share.tinycloud.xyz";
const NETWORK = "Unlock all your encrypted data";
const SHARE_PREFIX = "Unlock encrypted items in a folder named share";
const EXPECTED = { site: SITE, cards: [NETWORK, SHARE_PREFIX], required: [NETWORK] };

const doc = (html) => {
  const { window } = new JSDOM(`<body>${html}</body>`);
  window.Element.prototype.getClientRects = function () { return this.closest("[hidden]") ? [] : [{}]; };
  return window.document;
};
const card = (heading, status) => `<section role="group"><h2><span>${heading}</span><span>Sensitive</span></h2><p>${SITE} could unlock it.</p>`
  + (status === undefined
    ? `<div><button class="reject">Reject this permission</button><button class="allow">Allow this permission</button></div>`
    : `<p><span>${status}</span><button>Change</button></p>`) + `</section>`;
const warning = (cards, { continueDisabled = true } = {}) => `<div role="dialog" aria-modal="true" aria-labelledby="elevated-title"><h1 id="elevated-title">${SITE} is asking for more access</h1>`
  + cards.join("") + `<div><button class="continue"${continueDisabled ? " disabled" : ""}>Continue</button></div></div>`;
const ALLOWED = "You allowed this permission.";
const REJECTED = "You rejected this permission.";

test("a split warning is read card by card: allowed or not, and whether Continue is enabled", () => {
  const fresh = splitState(doc(warning([card(NETWORK), card(SHARE_PREFIX)])));
  assert.deepEqual(fresh, { shown: true, cards: [{ heading: NETWORK, allowed: false, offered: true }, { heading: SHARE_PREFIX, allowed: false, offered: true }], canContinue: false });
  const decided = splitState(doc(warning([card(NETWORK, ALLOWED), card(SHARE_PREFIX, REJECTED)], { continueDisabled: false })));
  assert.deepEqual(decided.cards.map((entry) => entry.allowed), [true, false]);
  assert.equal(decided.canContinue, true);
  assert.deepEqual(splitState(doc(`<div hidden>${warning([card(NETWORK)])}</div>`)), { shown: false, cards: [], canContinue: false });
});

test("Continue is refused unless every card reads as allowed", () => {
  const state = (cards, canContinue = true) => splitState(doc(warning(cards, { continueDisabled: !canContinue })));
  assert.equal(splitContinueRefusal(state([card(NETWORK, ALLOWED), card(SHARE_PREFIX, ALLOWED)])), null);
  assert.equal(splitContinueRefusal(state([card(NETWORK, ALLOWED), card(SHARE_PREFIX, REJECTED)])), `not allowed at Continue: ${SHARE_PREFIX}`);
  assert.equal(splitContinueRefusal(state([card(NETWORK, ALLOWED), card(SHARE_PREFIX)])), `not allowed at Continue: ${SHARE_PREFIX}`);
  assert.equal(splitContinueRefusal(state([card(NETWORK, ALLOWED)], false)), "Continue is not enabled");
  assert.equal(splitContinueRefusal(splitState(doc(""))), "the warning is not showing its cards");
});

test("a split warning is refused for the split reason only when everything else matches the step", () => {
  const shown = (cards, site = SITE) => {
    const found = elevatedScreen(ELEVATED_ALLOW_NAME.source, doc(warning(cards.map((heading) => card(heading))).replaceAll(SITE, site)));
    return { title: found.title, cards: found.cards, whole: found.allow !== null };
  };
  assert.equal(elevatedRefusal(shown([NETWORK, SHARE_PREFIX]), EXPECTED), SPLIT_REFUSAL);
  assert.match(elevatedRefusal(shown([SHARE_PREFIX]), EXPECTED), /^missing permission/);
  assert.match(elevatedRefusal(shown([NETWORK, "Create encryption keys anywhere in your account"]), EXPECTED), /^unexpected permission/);
  assert.match(elevatedRefusal(shown([NETWORK], "evil.example"), EXPECTED), /^unexpected title/);
  assert.equal(elevatedRefusal(shown([NETWORK]), null), "not expected at this step");
});

test("clickApprove through a split warning: Allow on every card, all allowed at Continue, then Continue; anything else is not continued", async () => {
  const browser = await puppeteer.launch({ args: process.env.GITHUB_ACTIONS === "true" ? ["--no-sandbox"] : [] });
  try {
    const page = await browser.newPage();
    // A stand-in for OpenKey's review: Approve opens the split warning; Continue (enabled once every card is decided)
    // brings the review back reading "Signing…", unless `stall` is set. `rejectFirst` makes the first card's Allow
    // read as rejected, as if the owner had chosen otherwise.
    const flow = (cards, { stall = false, rejectFirst = false } = {}) => `<div id=root></div><script>(() => {
      const root = document.getElementById("root");
      const cards = ${JSON.stringify(cards)};
      const decisions = {};
      const count = (name) => { document.body.dataset[name] = Number(document.body.dataset[name] ?? 0) + 1; };
      const review = (label) => { root.innerHTML = '<div role="dialog"><button>Cancel</button><button id="approve"' + (label === "Signing…" ? " disabled" : "") + '>' + label + '</button></div>'; };
      const draw = () => {
        const all = cards.every((heading) => decisions[heading] !== undefined);
        root.innerHTML = '<div role="dialog" aria-modal="true" aria-labelledby="elevated-title"><h1 id="elevated-title">${SITE} is asking for more access</h1>'
          + cards.map((heading, index) => '<section role="group"><h2><span>' + heading + '</span><span>Sensitive</span></h2>'
            + (decisions[heading] === undefined
              ? '<div><button class="reject" data-card="' + index + '">Reject this permission</button><button class="allow" data-card="' + index + '">Allow this permission</button></div>'
              : '<p><span>' + (decisions[heading] === "allow" ? "You allowed this permission." : "You rejected this permission.") + '</span><button>Change</button></p>')
            + '</section>').join("")
          + '<div><button class="continue"' + (all ? "" : " disabled") + '>Continue</button></div></div>';
      };
      review("Approve");
      root.addEventListener("click", (event) => {
        const target = event.target;
        if (target.id === "approve") { count("approveClicks"); draw(); }
        else if (target.classList.contains("allow")) { count("allowClicks"); const heading = cards[Number(target.dataset.card)]; decisions[heading] = ${rejectFirst} && Number(target.dataset.card) === 0 ? "reject" : "allow"; draw(); }
        else if (target.classList.contains("continue")) { count("continueClicks"); if (!${stall}) setTimeout(() => review("Signing…"), 100); }
      });
    })();</script>`;
    const clicks = () => page.evaluate(() => ({ approve: Number(document.body.dataset.approveClicks ?? 0), allow: Number(document.body.dataset.allowClicks ?? 0), cont: Number(document.body.dataset.continueClicks ?? 0) }));
    let clock = 0;
    const run = (report, elevated) => clickApprove({ sign: page.mainFrame(), during: "signIn", report, closed: () => false, at: () => ++clock, stage: () => "share-sign-in", reviewSeenAt: 0, takenMs: 1_000, elevated });

    await page.setContent(flow([NETWORK, SHARE_PREFIX]));
    const taken = {};
    assert.equal(await run(taken, EXPECTED), true, "Approve, Allow on each card, Continue, Signing…: taken");
    assert.deepEqual(await clicks(), { approve: 1, allow: 2, cont: 1 });
    assert.deepEqual({ ...taken.elevatedScreens[0], atMs: 0 }, {
      during: "signIn", stage: "share-sign-in", atMs: 0, title: `${SITE} is asking for more access`, cards: [NETWORK, SHARE_PREFIX],
      wholeRequest: false, allowed: true, allowedAtContinue: [NETWORK, SHARE_PREFIX],
    });
    assert.equal(taken.elevatedRefused, undefined);
    assert.equal(taken.approveClicksDropped, undefined);

    // A card OpenKey shows as rejected after the press is never continued past.
    await page.setContent(flow([NETWORK, SHARE_PREFIX], { rejectFirst: true }));
    const rejected = {};
    assert.equal(await run(rejected, EXPECTED), false);
    assert.deepEqual(await clicks(), { approve: 1, allow: 1, cont: 0 }, "Continue was pressed with a rejected card");
    assert.equal(rejected.elevatedRefused.reason, `card did not read as allowed: ${NETWORK}`);
    assert.equal(rejected.elevatedScreens[0].allowed, false);

    // A split warning at a step that expects none, or with an unexplained card, is touched by nothing.
    await page.setContent(flow([NETWORK]));
    const unexpected = {};
    assert.equal(await run(unexpected, null), false);
    assert.deepEqual(await clicks(), { approve: 1, allow: 0, cont: 0 });
    assert.equal(unexpected.elevatedRefused.reason, "not expected at this step");
    await page.setContent(flow([NETWORK, "Create encryption keys anywhere in your account"]));
    const extra = {};
    assert.equal(await run(extra, EXPECTED), false);
    assert.deepEqual(await clicks(), { approve: 1, allow: 0, cont: 0 });
    assert.match(extra.elevatedRefused.reason, /^unexpected permission/);

    await page.setContent(flow([NETWORK], { stall: true }));
    const stalled = {};
    assert.equal(await run(stalled, EXPECTED), false, "a Continue that never signs is not taken");
    assert.deepEqual(await clicks(), { approve: 1, allow: 1, cont: 1 });
    assert.equal(stalled.approveClicksNotTaken, 1);
    assert.equal(stalled.approveClicksDropped[0].screen, "elevated-split");
  } finally {
    await browser.close();
  }
});
