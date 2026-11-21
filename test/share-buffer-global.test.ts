/**
 * TC-2933. The TinyCloud SDKs read a SIWE recap with Node's `Buffer`, and a browser has none: without the global the
 * versioned sign-in fails after OpenKey approves ("Buffer is not defined"). The sign-in module loads the file that installs it.
 */
import { describe, expect, it } from "vitest";
import { installBuffer } from "../src/share/install-buffer.js";

describe("Buffer for the SDKs' recap decoding", () => {
  it("gives a scope without Buffer one that decodes a base64 recap", () => {
    const browser: { Buffer?: typeof Buffer } = {};
    installBuffer(browser);
    expect(browser.Buffer?.from("eyJhIjoxfQ==", "base64").toString("utf8")).toBe('{"a":1}');
  });

  it("leaves a scope that has Buffer alone", () => {
    const own = Buffer;
    const scope: { Buffer?: typeof Buffer } = { Buffer: own };
    installBuffer(scope);
    expect(scope.Buffer).toBe(own);
  });
});
