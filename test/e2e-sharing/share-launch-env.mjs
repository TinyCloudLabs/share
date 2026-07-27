// Sender-disabled Share hosts never touch the durable binding store, so the
// launch env must omit SHARE_BINDING_STORE_ROOT/PATH entirely: the production
// share-adapter's binding-store-root guard (src/host/share-adapter.ts) fires
// on any non-canonical root whenever the trust bundle is production-shaped,
// even with the sender disabled. Passing a harness tempRoot there rejects the
// launch before /health/readiness.
//
// SHARE_HERMETIC_OPENKEY_ORIGIN/SHARE_HERMETIC_WALLET_ORIGIN are the existing
// CSP hooks read by src/host/trust-bundle.ts's securityHeadersForPath(): they
// widen frame-src/connect-src to admit the harness's loopback OpenKey widget
// and deterministic wallet signer. SHARE_HERMETIC_BROWSER_ORIGIN is the
// dedicated local-browser-origin seam read by src/host/share-adapter.ts's
// createShareHostFromEnv(): it authorizes exactly the loopback page the
// harness drives the browser to as an Origin for the OpenKey nonce/proof
// endpoints, and lets the session cookie omit Secure only for that exact
// origin. All three must be exact loopback origins with no credentials,
// path, query, or fragment, or the launch is rejected before the Share host
// can start.
const LOOPBACK_ORIGIN_PATTERN = /^http:\/\/127\.0\.0\.1:\d+$/;

function loopbackOrigin(value, label) {
  if (typeof value !== "string" || !LOOPBACK_ORIGIN_PATTERN.test(value)) {
    throw new Error(`${label} must be an exact http://127.0.0.1:<port> origin`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be an exact http://127.0.0.1:<port> origin`);
  }
  if (parsed.origin !== value || parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    throw new Error(`${label} must be an exact http://127.0.0.1:<port> origin`);
  }
  return value;
}

export function buildShareHostLaunchEnv({ host, port, trustBundlePath, registryUploadKeyPath, nodeEnforcerDid, openKeyOrigin, walletOrigin, shareOrigin }) {
  return {
    HOST: host,
    PORT: String(port),
    SHARE_TRUST_BUNDLE_FILE: trustBundlePath,
    SHARE_SENDER_ENABLED: "false",
    SHARE_REGISTRY_UPLOAD_KEY_PATH: registryUploadKeyPath,
    SHARE_NODE_ENFORCER_DID: nodeEnforcerDid,
    SHARE_HERMETIC_OPENKEY_ORIGIN: loopbackOrigin(openKeyOrigin, "openKeyOrigin"),
    SHARE_HERMETIC_WALLET_ORIGIN: loopbackOrigin(walletOrigin, "walletOrigin"),
    SHARE_HERMETIC_BROWSER_ORIGIN: loopbackOrigin(shareOrigin, "shareOrigin"),
  };
}
