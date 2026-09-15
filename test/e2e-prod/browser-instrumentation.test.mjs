import assert from "node:assert/strict";
import test from "node:test";
import { installBrowserInstrumentation } from "./browser-instrumentation.mjs";

test("captures a binary invoke body supplied through a Request", async () => {
  const originalWindow = globalThis.window;
  const originalNavigator = globalThis.navigator;
  const originalLocation = globalThis.location;
  let forwarded;
  try {
    globalThis.window = { fetch: async (input, init) => { forwarded = { input, init }; return new Response(); } };
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: {} });
    globalThis.location = new URL("https://share.tinycloud.xyz/");
    installBrowserInstrumentation();
    const bytes = Uint8Array.from([0, 1, 128, 255]);
    const request = new Request("https://tee.node.tinycloud.xyz/invoke", { method: "POST", headers: { "content-type": "application/vnd.tinycloud.encrypted-envelope+json" }, body: new Blob([bytes]) });

    await window.fetch(request);

    assert.deepEqual(window.__tc500BinaryBodies, [[0, 1, 128, 255]]);
    assert.equal(forwarded.input, request);
    assert.equal(forwarded.init, undefined);
  } finally {
    globalThis.window = originalWindow;
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: originalNavigator });
    globalThis.location = originalLocation;
  }
});
