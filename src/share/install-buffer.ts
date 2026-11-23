import { Buffer } from "buffer";

/**
 * The TinyCloud SDKs read a SIWE message's recap with Node's `Buffer` (`extractRecapAttenuations`), which a browser lacks:
 * without it the versioned sign-in fails after OpenKey approves ("Buffer is not defined").
 */
export function installBuffer(scope: { Buffer?: typeof Buffer }): void {
  scope.Buffer ??= Buffer;
}

// Loaded before any sign-in runs.
installBuffer(globalThis);
