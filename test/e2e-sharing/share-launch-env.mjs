// Sender-disabled Share hosts never touch the durable binding store, so the
// launch env must omit SHARE_BINDING_STORE_ROOT/PATH entirely: the production
// share-adapter's binding-store-root guard (src/host/share-adapter.ts) fires
// on any non-canonical root whenever the trust bundle is production-shaped,
// even with the sender disabled. Passing a harness tempRoot there rejects the
// launch before /health/readiness.
export function buildShareHostLaunchEnv({ host, port, trustBundlePath, registryUploadKeyPath, nodeEnforcerDid }) {
  return {
    HOST: host,
    PORT: String(port),
    SHARE_TRUST_BUNDLE_FILE: trustBundlePath,
    SHARE_SENDER_ENABLED: "false",
    SHARE_REGISTRY_UPLOAD_KEY_PATH: registryUploadKeyPath,
    SHARE_NODE_ENFORCER_DID: nodeEnforcerDid,
  };
}
