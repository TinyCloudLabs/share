import { test } from "node:test";
import assert from "node:assert/strict";
import { bodySandboxOk } from "./body-frame.mjs";

test("a body frame's sandbox may be empty or grant only popups", () => {
  for (const value of ["", "  ", "allow-popups", "allow-popups-to-escape-sandbox", "allow-popups allow-popups-to-escape-sandbox", " allow-popups\tallow-popups-to-escape-sandbox "]) {
    assert.equal(bodySandboxOk(value), true, JSON.stringify(value));
  }
});

test("script, same-origin, any other token, or no sandbox at all fails", () => {
  for (const value of [
    "allow-scripts",
    "allow-same-origin",
    "allow-popups allow-scripts",
    "allow-popups-to-escape-sandbox allow-same-origin",
    "allow-forms",
    "allow-top-navigation",
    "allow-popupsx",
    null,
    undefined,
  ]) {
    assert.equal(bodySandboxOk(value), false, JSON.stringify(value));
  }
});
