import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { appFrameAt, consoleEntry, consoleType, isHostileRefusal, postMessageWarning, redactUrls } from "./console-filter.mjs";

const APP_ID = "xyz.tinycloud.e2e.hostile";
const raw = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/console-filter.raw.json", import.meta.url)), "utf8"));

const entries = raw.map((e) => ({
  raw: e,
  entry: consoleEntry(e.phase, consoleType(e.level), e.text, { url: e.url ?? undefined, lineNumber: e.lineNumber ?? undefined }),
}));

const cspRefusals = entries.filter(({ raw: e }) => e.phase === `open-${APP_ID}` && e.level === "error" && /violates the following Content Security Policy|Refused to connect because/.test(e.text));

test("redactUrls keeps the closing quote and paren", () => {
  assert.equal(
    redactUrls("Connecting to 'http://127.0.0.1:43949/fetch' violates"),
    "Connecting to '<url>' violates",
  );
  assert.equal(
    redactUrls("target origin provided ('https://share.tinycloud.xyz') does not match"),
    "target origin provided ('<url>') does not match",
  );
  assert.equal(
    redactUrls("Fetch API cannot load http://127.0.0.1:43949/fetch. Refused"),
    "Fetch API cannot load <url> Refused",
  );
});

test("hostile frame refusals from the open phase are accepted", () => {
  assert.ok(cspRefusals.length >= 2, "fixture must contain CSP refusals from the open phase");
  for (const { raw: e, entry } of cspRefusals) {
    assert.equal(isHostileRefusal(entry, APP_ID), true, `${e.text} at ${entry.at}`);
  }
});

test("a refusal from a non-app document is not accepted by the hostile filter", () => {
  const top = consoleEntry(`open-${APP_ID}`, "error", "Connecting to 'http://127.0.0.1:1/x' violates the following Content Security Policy directive: \"connect-src 'none'\". The action has been blocked.", { url: "https://share.tinycloud.xyz/apps/", lineNumber: 4 });
  assert.equal(isHostileRefusal(top, APP_ID), false);
  const otherPhase = { ...cspRefusals[0].entry, phase: "open-com.example.other" };
  assert.equal(isHostileRefusal(otherPhase, APP_ID), false);
});

test("appFrameAt accepts frame documents and empty urls, rejects app-page documents", () => {
  assert.equal(appFrameAt("about:srcdoc:1010"), true);
  assert.equal(appFrameAt("https://share.tinycloud.xyz/jsx-sandbox.html:12"), true);
  assert.equal(appFrameAt(":22"), true);
  assert.equal(appFrameAt("https://share.tinycloud.xyz/apps/:4"), false);
});

test("postMessage warning from the install-gate axe probe matches after redaction", () => {
  const e = raw.find((r) => /postMessage/.test(r.text));
  assert.ok(e, "fixture must contain the postMessage warning");
  assert.equal(postMessageWarning.test(redactUrls(e.text)), true, redactUrls(e.text));
});

test("the old redaction would have lost the postMessage closing paren", () => {
  const oldRedact = (text) => text.replaceAll(/https:\/\/[^\s#]+(?:#[^\s]*)?/g, "<url>");
  const e = raw.find((r) => /postMessage/.test(r.text));
  assert.equal(postMessageWarning.test(oldRedact(e.text)), false);
});
