import assert from "node:assert/strict";
import test from "node:test";
import { buildShareBrowserBuildEnv } from "./share-browser-build-env.mjs";

test("share browser build env sets viewer-only hermetic mode, canonical share origin, same-origin registry proxy, and the loopback OpenKey origin", () => {
  const env = buildShareBrowserBuildEnv("http://127.0.0.1:4123", "http://127.0.0.1:4200");

  assert.deepEqual(env, {
    VITE_SHARE_VIEWER_HERMETIC: "true",
    VITE_SHARE_ORIGIN: "https://share.tinycloud.xyz",
    VITE_SHARE_REGISTRY_URL: "http://127.0.0.1:4123/registry",
    VITE_OPENKEY_ORIGIN: "http://127.0.0.1:4200",
  });
});

test("share browser build env never sets the broad VITE_SHARE_HERMETIC flag that also redirects SDK authority host construction", () => {
  const env = buildShareBrowserBuildEnv("http://127.0.0.1:4123", "http://127.0.0.1:4200");

  assert.equal(Object.prototype.hasOwnProperty.call(env, "VITE_SHARE_HERMETIC"), false);
});

test("share browser build env never points VITE_SHARE_REGISTRY_URL at the canonical public registry host", () => {
  const env = buildShareBrowserBuildEnv("http://127.0.0.1:4123", "http://127.0.0.1:4200");

  assert.equal(env.VITE_SHARE_REGISTRY_URL.startsWith("http://127.0.0.1:4123"), true);
});

test("share browser build env rejects a non-loopback origin", () => {
  assert.throws(() => buildShareBrowserBuildEnv("https://share.tinycloud.xyz", "http://127.0.0.1:4200"), /origin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share browser build env rejects an origin carrying a path", () => {
  assert.throws(() => buildShareBrowserBuildEnv("http://127.0.0.1:4123/share.html", "http://127.0.0.1:4200"), /origin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share browser build env rejects a non-loopback openKeyOrigin", () => {
  assert.throws(() => buildShareBrowserBuildEnv("http://127.0.0.1:4123", "https://openkey.so"), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share browser build env rejects a zero port on the openKeyOrigin", () => {
  assert.throws(() => buildShareBrowserBuildEnv("http://127.0.0.1:4123", "http://127.0.0.1:0"), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share browser build env rejects a non-string origin", () => {
  assert.throws(() => buildShareBrowserBuildEnv(undefined, "http://127.0.0.1:4200"), /origin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});
