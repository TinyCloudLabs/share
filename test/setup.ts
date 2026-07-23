/**
 * Test-environment shims: vitest's jsdom environment lacks Web Crypto's
 * `subtle` (needed by the envelope AEAD) and sometimes TextEncoder/Decoder.
 * Backfill them from node — environment plumbing only, no app behavior.
 */
import { webcrypto } from "node:crypto";
import { TextDecoder, TextEncoder } from "node:util";

// jsdom's encoder can return a Uint8Array from its own realm. Multiformats
// intentionally rejects that value, so use Node's realm consistently even
// when jsdom already installed an encoder.
Object.assign(globalThis, { TextEncoder, TextDecoder });
if (globalThis.crypto?.subtle === undefined) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
  });
}
