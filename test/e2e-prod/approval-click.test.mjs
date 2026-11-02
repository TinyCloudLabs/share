import { test } from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { approvalTaken, boxMoved } from "./approval-click.mjs";

const doc = (html) => new JSDOM(`<body>${html}</body>`).window.document;

test("an Approve that is still enabled means the click was not taken", () => {
  assert.equal(approvalTaken(doc(`<button>Cancel</button><button>Approve</button>`)), false);
  assert.equal(approvalTaken(doc(`<button>Cancel</button><button>Approve exact bytes</button>`)), false);
});

test("a disabled Approve, Signing…, or no Approve at all means the review took the click", () => {
  assert.equal(approvalTaken(doc(`<button>Cancel</button><button disabled>Approve</button>`)), true);
  assert.equal(approvalTaken(doc(`<button disabled>Cancel</button><button disabled>Signing…</button>`)), true);
  assert.equal(approvalTaken(doc(`<p>Done</p>`)), true);
});

test("a button whose name only starts with Approve is not taken for the approval's button", () => {
  assert.equal(approvalTaken(doc(`<button>Approve all later</button><button disabled>Signing…</button>`)), true);
  assert.equal(approvalTaken(doc(`<button disabled>Approve all later</button><button>Approve</button>`)), false);
});

test("boxMoved reports the larger shift, and null without both boxes", () => {
  assert.equal(boxMoved({ x: 10, y: 10, height: 40 }, { x: 10, y: 74, height: 40 }), 64);
  assert.equal(boxMoved({ x: 10, y: 10, height: 40 }, { x: 10, y: 10, height: 40 }), 0);
  assert.equal(boxMoved(null, { x: 0, y: 0, height: 1 }), null);
});
