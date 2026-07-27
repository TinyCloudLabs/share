import assert from "node:assert/strict";
import test from "node:test";
import { buildShareHostLaunchEnv } from "./share-launch-env.mjs";

function baseArgs() {
  return {
    host: "127.0.0.1",
    port: 4123,
    trustBundlePath: "/tmp/harness-root/trust.json",
    registryUploadKeyPath: "/tmp/harness-root/registry-upload.key",
    nodeEnforcerDid: "did:web:node.tinycloud.xyz",
    openKeyOrigin: "http://127.0.0.1:4200",
    walletOrigin: "http://127.0.0.1:4300",
  };
}

test("share host launch env carries the exact host/port/trust/registry/node/hermetic-CSP values with sender disabled", () => {
  const env = buildShareHostLaunchEnv(baseArgs());

  assert.deepEqual(env, {
    HOST: "127.0.0.1",
    PORT: "4123",
    SHARE_TRUST_BUNDLE_FILE: "/tmp/harness-root/trust.json",
    SHARE_SENDER_ENABLED: "false",
    SHARE_REGISTRY_UPLOAD_KEY_PATH: "/tmp/harness-root/registry-upload.key",
    SHARE_NODE_ENFORCER_DID: "did:web:node.tinycloud.xyz",
    SHARE_HERMETIC_OPENKEY_ORIGIN: "http://127.0.0.1:4200",
    SHARE_HERMETIC_WALLET_ORIGIN: "http://127.0.0.1:4300",
  });
});

test("share host launch env never sets static authority, fixture, composition, allow-test, or binding-store variables", () => {
  const env = buildShareHostLaunchEnv(baseArgs());

  const forbiddenKeys = [
    "SHARE_SENDER_PRIVATE_KEY",
    "SHARE_SENDER_CAPABILITY_JSON",
    "SHARE_SENDER_CAPABILITIES_JSON",
    "SHARE_TEST_BINDINGS_JSON",
    "SHARE_HERMETIC_COMPOSITION",
    "SHARE_TRUST_BUNDLE_ALLOW_TEST",
    "SHARE_BINDING_STORE_ROOT",
    "SHARE_BINDING_STORE_PATH",
  ];

  for (const key of forbiddenKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(env, key), false, `launch env must not set ${key}`);
  }
});

test("share host launch env rejects a non-loopback openKeyOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: "https://openkey.so" }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a localhost alias for walletOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), walletOrigin: "http://localhost:4300" }), /walletOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects an openKeyOrigin carrying a path", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: "http://127.0.0.1:4200/widget" }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a walletOrigin carrying a query string", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), walletOrigin: "http://127.0.0.1:4300?x=1" }), /walletOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects an openKeyOrigin carrying a fragment", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: "http://127.0.0.1:4200#top" }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a walletOrigin carrying embedded credentials", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), walletOrigin: "http://user:pass@127.0.0.1:4300" }), /walletOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects an IPv6 loopback openKeyOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: "http://[::1]:4200" }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a malformed walletOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), walletOrigin: "not-a-url" }), /walletOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a non-string openKeyOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: undefined }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});
