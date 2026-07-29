/**
 * Test-environment shims: vitest's jsdom environment lacks Web Crypto's
 * `subtle` (needed by the envelope AEAD), sometimes TextEncoder/Decoder, and
 * `Blob.prototype.arrayBuffer`/`text` (needed by every composer path that reads
 * the selected file). Backfill them from node — environment plumbing only, no
 * app behavior.
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

// jsdom implements Blob/File but not their async readers, so `file.arrayBuffer()`
// throws "is not a function" and any test driving a real upload path dies at the
// first read. FileReader IS implemented, so read through it.
function readBlob(blob: Blob): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => { resolve(reader.result as ArrayBuffer); };
    reader.onerror = () => { reject(reader.error ?? new Error("blob read failed")); };
    reader.readAsArrayBuffer(blob);
  });
}

if (typeof globalThis.Blob === "function" && typeof Blob.prototype.arrayBuffer !== "function") {
  Object.defineProperty(Blob.prototype, "arrayBuffer", {
    configurable: true, writable: true,
    value: function arrayBuffer(this: Blob): Promise<ArrayBuffer> { return readBlob(this); },
  });
}

if (typeof globalThis.Blob === "function" && typeof Blob.prototype.text !== "function") {
  Object.defineProperty(Blob.prototype, "text", {
    configurable: true, writable: true,
    value: async function text(this: Blob): Promise<string> { return new TextDecoder().decode(new Uint8Array(await readBlob(this))); },
  });
}
