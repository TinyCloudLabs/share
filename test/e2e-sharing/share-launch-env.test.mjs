import assert from "node:assert/strict";
import test from "node:test";
import { buildShareHostLaunchEnv } from "./share-launch-env.mjs";

test("share host launch env carries the exact host/port/trust/registry/node values with sender disabled", () => {
  const env = buildShareHostLaunchEnv({
    host: "127.0.0.1",
    port: 4123,
    trustBundlePath: "/tmp/harness-root/trust.json",
    registryUploadKeyPath: "/tmp/harness-root/registry-upload.key",
    nodeEnforcerDid: "did:web:node.tinycloud.xyz",
  });

  assert.deepEqual(env, {
    HOST: "127.0.0.1",
    PORT: "4123",
    SHARE_TRUST_BUNDLE_FILE: "/tmp/harness-root/trust.json",
    SHARE_SENDER_ENABLED: "false",
    SHARE_REGISTRY_UPLOAD_KEY_PATH: "/tmp/harness-root/registry-upload.key",
    SHARE_NODE_ENFORCER_DID: "did:web:node.tinycloud.xyz",
  });
});

test("share host launch env never sets static authority, fixture, hermetic, or binding-store variables", () => {
  const env = buildShareHostLaunchEnv({
    host: "127.0.0.1",
    port: 4123,
    trustBundlePath: "/tmp/harness-root/trust.json",
    registryUploadKeyPath: "/tmp/harness-root/registry-upload.key",
    nodeEnforcerDid: "did:web:node.tinycloud.xyz",
  });

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
