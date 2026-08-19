import assert from "node:assert/strict";
import test from "node:test";
import { buildShareHostLaunchEnv } from "./share-launch-env.mjs";

const canonicalOrigins = {
  credentials: "https://witness.credentials.org",
  node: "https://node.tinycloud.xyz",
  registry: "https://registry.tinycloud.xyz",
};

function baseArgs() {
  return {
    host: "127.0.0.1",
    port: 4123,
    trustBundlePath: "/tmp/harness-root/trust.json",
    registryUploadKeyPath: "/tmp/harness-root/registry-upload.key",
    nodeEnforcerDid: "did:web:node.tinycloud.xyz",
    openKeyOrigin: "http://127.0.0.1:4200",
    walletOrigin: "http://127.0.0.1:4300",
    shareOrigin: "http://127.0.0.1:4123",
    registryOrigin: "http://127.0.0.1:4400",
    canonicalOrigins,
    nodeTransportOrigin: "http://127.0.0.1:4500",
    credentialsTransportOrigin: "http://127.0.0.1:4600",
  };
}

test("share host launch env carries the exact host/port/trust/registry/node/hermetic-CSP/hermetic-browser-origin/hermetic-registry-origin values with sender disabled", () => {
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
    SHARE_HERMETIC_BROWSER_ORIGIN: "http://127.0.0.1:4123",
    SHARE_HERMETIC_REGISTRY_ORIGIN: "http://127.0.0.1:4400",
    SHARE_HERMETIC_COMPOSITION: "true",
    SHARE_HERMETIC_UPSTREAMS_JSON: JSON.stringify({
      node: { origin: "https://node.tinycloud.xyz", transportOrigin: "http://127.0.0.1:4500" },
      credentials: { origin: "https://witness.credentials.org", transportOrigin: "http://127.0.0.1:4600" },
      registry: { origin: "https://registry.tinycloud.xyz", transportOrigin: "http://127.0.0.1:4400" },
    }),
  });
});

// TC-306. This is the assertion whose absence let the harness proxy
// /delegate, /invoke, /share/v1/*, /share/v2/*, /info and /v1/share-email/* to
// the public production node for thirteen rounds of fixes while the locally
// built node under test received zero browser requests. Every route
// src/host/upstream.ts can return is one of these three origins, so requiring
// all three to be loopback is exhaustive.
test("share host launch env routes every proxied upstream to loopback, never to a production origin", () => {
  const env = buildShareHostLaunchEnv(baseArgs());

  assert.equal(env.SHARE_HERMETIC_COMPOSITION, "true", "SHARE_HERMETIC_UPSTREAMS_JSON is ignored without SHARE_HERMETIC_COMPOSITION=true");
  const routes = JSON.parse(env.SHARE_HERMETIC_UPSTREAMS_JSON);
  assert.deepEqual(Object.keys(routes).sort(), ["credentials", "node", "registry"], "resolveShareUpstreams requires exactly these three keys");
  for (const [service, route] of Object.entries(routes)) {
    assert.deepEqual(Object.keys(route).sort(), ["origin", "transportOrigin"]);
    assert.equal(route.origin, canonicalOrigins[service], `${service} route must name the exact trust-bundle origin it replaces`);
    assert.match(route.transportOrigin, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/, `${service} must resolve to a loopback origin`);
  }
});

test("share host launch env can bind the standalone policy engine to loopback", () => {
  const env = buildShareHostLaunchEnv({
    ...baseArgs(),
    policyEngineCanonicalOrigin: "https://policy.tinycloud.xyz",
    policyEngineTransportOrigin: "http://127.0.0.1:4700",
  });
  const routes = JSON.parse(env.SHARE_HERMETIC_UPSTREAMS_JSON);
  assert.deepEqual(routes.policyEngine, {
    origin: "https://policy.tinycloud.xyz",
    transportOrigin: "http://127.0.0.1:4700",
  });
});

test("share host launch env never sets static authority, fixture, allow-test, or binding-store variables", () => {
  const env = buildShareHostLaunchEnv(baseArgs());

  const forbiddenKeys = [
    "SHARE_SENDER_PRIVATE_KEY",
    "SHARE_SENDER_CAPABILITY_JSON",
    "SHARE_SENDER_CAPABILITIES_JSON",
    "SHARE_TEST_BINDINGS_JSON",
    "SHARE_TRUST_BUNDLE_ALLOW_TEST",
    "SHARE_BINDING_STORE_ROOT",
    "SHARE_BINDING_STORE_PATH",
    "SHARE_SENDER_ROOT_KEY_PATH",
  ];

  for (const key of forbiddenKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(env, key), false, `launch env must not set ${key}`);
  }
});

test("the dedicated TC-465 composition alone enables the sender with a durable binding store", () => {
  const env = buildShareHostLaunchEnv({ ...baseArgs(), senderBindingStore: { root: "/tmp/harness-root", path: "/tmp/harness-root/bindings.ndjson" } });
  assert.equal(env.SHARE_SENDER_ENABLED, "true");
  assert.equal(env.SHARE_BINDING_STORE_ROOT, "/tmp/harness-root");
  assert.equal(env.SHARE_BINDING_STORE_PATH, "/tmp/harness-root/bindings.ndjson");
  assert.equal(env.SHARE_SENDER_ROOT_KEY_PATH, "/tmp/harness-root/sender-root.key");
  for (const key of ["SHARE_SENDER_PRIVATE_KEY", "SHARE_SENDER_CAPABILITY_JSON", "SHARE_SENDER_CAPABILITIES_JSON", "SHARE_TRUST_BUNDLE_ALLOW_TEST"]) assert.equal(Object.prototype.hasOwnProperty.call(env, key), false);
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

test("share host launch env rejects a non-loopback shareOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), shareOrigin: "https://share.tinycloud.xyz" }), /shareOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a shareOrigin carrying a path", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), shareOrigin: "http://127.0.0.1:4123/share.html" }), /shareOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects an IPv6 loopback shareOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), shareOrigin: "http://[::1]:4123" }), /shareOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a non-string shareOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), shareOrigin: undefined }), /shareOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a missing port on openKeyOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: "http://127.0.0.1" }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a zero port on walletOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), walletOrigin: "http://127.0.0.1:0" }), /walletOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a leading-zero port on shareOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), shareOrigin: "http://127.0.0.1:04123" }), /shareOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects an out-of-range port on openKeyOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), openKeyOrigin: "http://127.0.0.1:65536" }), /openKeyOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a non-loopback registryOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), registryOrigin: "https://registry.tinycloud.xyz" }), /registryOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a registryOrigin carrying a path", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), registryOrigin: "http://127.0.0.1:4400/blobs" }), /registryOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a non-string registryOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), registryOrigin: undefined }), /registryOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a production nodeTransportOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), nodeTransportOrigin: "https://node.tinycloud.xyz" }), /nodeTransportOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a missing nodeTransportOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), nodeTransportOrigin: undefined }), /nodeTransportOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects a missing credentialsTransportOrigin", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), credentialsTransportOrigin: undefined }), /credentialsTransportOrigin must be an exact http:\/\/127\.0\.0\.1:<port> origin/);
});

test("share host launch env rejects canonical origins that do not name exactly the three upstreams", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), canonicalOrigins: { ...canonicalOrigins, share: "https://share.tinycloud.xyz" } }), /canonicalOrigins must be an object naming exactly credentials, node, and registry/);
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), canonicalOrigins: undefined }), /canonicalOrigins must be an object naming exactly credentials, node, and registry/);
});

test("share host launch env rejects a loopback canonical origin, which would mean the trust bundle itself was rewritten", () => {
  assert.throws(() => buildShareHostLaunchEnv({ ...baseArgs(), canonicalOrigins: { ...canonicalOrigins, node: "http://127.0.0.1:4500" } }), /canonicalOrigins\.node must be the exact https trust-bundle origin/);
});
