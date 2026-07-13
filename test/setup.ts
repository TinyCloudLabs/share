/**
 * Test-environment shims: vitest's jsdom environment lacks Web Crypto's
 * `subtle` (needed by the envelope AEAD) and sometimes TextEncoder/Decoder.
 * Backfill them from node — environment plumbing only, no app behavior.
 */
import { webcrypto } from "node:crypto";
import { TextDecoder, TextEncoder } from "node:util";

if (typeof globalThis.TextEncoder === "undefined") {
  Object.assign(globalThis, { TextEncoder, TextDecoder });
}
if (globalThis.crypto?.subtle === undefined) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
  });
}
