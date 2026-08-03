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
// origin. SHARE_HERMETIC_REGISTRY_ORIGIN is the dedicated registry-transport
// seam also read by createShareHostFromEnv(): it points the same-origin
// authenticated registry proxy (used by the "Shared by me" composer's
// encrypted-blob upload) at the harness's own real local
// @tinycloud/share-registry process instead of the canonical public
// registry. All four must be exact loopback origins with no credentials,
// path, query, or fragment, or the launch is rejected before the Share host
// can start. The dedicated TC-465 joined runner is the sole exception: it
// passes senderBindingStore and proves the Policy/v3 binding journal.
const LOOPBACK_ORIGIN_PATTERN = /^http:\/\/127\.0\.0\.1:([0-9]+)$/;

// Port digits must match src/host/share-adapter.ts's parseHermeticBrowserOrigin
// exactly: no leading zero, no zero port, no out-of-range port. A regex-only
// \d+ check would let "http://127.0.0.1:0" or ":07200" pass here while the
// server's parser rejects them, so a harness-generated env could pass this
// helper and then fail Share host startup.
export function loopbackOrigin(value, label) {
  const invalid = () => { throw new Error(`${label} must be an exact http://127.0.0.1:<port> origin`); };
  if (typeof value !== "string") return invalid();
  const match = LOOPBACK_ORIGIN_PATTERN.exec(value);
  if (match === null) return invalid();
  const portText = match[1];
  if (!/^[1-9][0-9]*$/.test(portText)) return invalid();
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return invalid();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return invalid();
  }
  if (parsed.origin !== value || parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    return invalid();
  }
  return value;
}

export const HERMETIC_UPSTREAM_SERVICES = Object.freeze(["credentials", "node", "registry"]);

// TC-306. SHARE_HERMETIC_REGISTRY_ORIGIN above only redirects the Share
// host's *own* authenticated registry client. Everything the browser proxies
// through the Share host — /delegate, /invoke, /info, /peer/generate/*,
// /encryption/*, /share/v1/*, /share/v2/*, /v1/share-email/*, /registry* — is
// resolved server-side by src/host/upstream.ts's resolveShareUpstreams, which
// reads only SHARE_HERMETIC_UPSTREAMS_JSON. When that variable is absent it
// returns the trust bundle's canonical *production* origins with no warning,
// so a harness that omits it proxies the browser's traffic to
// https://node.tinycloud.xyz while its own locally built node receives
// nothing. Build the routes here, in the same place the rest of the launch
// env is built, so the two can never drift apart again.
//
// resolveShareUpstreams accepts a route only when SHARE_HERMETIC_COMPOSITION
// is exactly "true", the object names exactly node/credentials/registry, each
// `origin` is byte-equal to the corresponding bundle origin, and each
// `transportOrigin` is loopback. Anything else throws at Share host startup.
export function hermeticUpstreamRoutes({ canonicalOrigins, nodeTransportOrigin, credentialsTransportOrigin, registryTransportOrigin }) {
  if (typeof canonicalOrigins !== "object" || canonicalOrigins === null || Array.isArray(canonicalOrigins)) throw new Error("canonicalOrigins must be an object naming exactly credentials, node, and registry");
  const named = Object.keys(canonicalOrigins).sort();
  if (named.length !== HERMETIC_UPSTREAM_SERVICES.length || named.some((key, index) => key !== HERMETIC_UPSTREAM_SERVICES[index])) throw new Error("canonicalOrigins must be an object naming exactly credentials, node, and registry");
  const transportOrigins = { credentials: credentialsTransportOrigin, node: nodeTransportOrigin, registry: registryTransportOrigin };
  const routes = {};
  for (const service of HERMETIC_UPSTREAM_SERVICES) {
    const origin = canonicalOrigins[service];
    // The bundle origins are canonical https production origins; a loopback
    // value here would mean the trust bundle itself was rewritten, which is
    // exactly the non-production shape this harness must never test.
    if (typeof origin !== "string" || !/^https:\/\/[a-z0-9.-]+$/.test(origin)) throw new Error(`canonicalOrigins.${service} must be the exact https trust-bundle origin`);
    routes[service] = { origin, transportOrigin: loopbackOrigin(transportOrigins[service], `${service}TransportOrigin`) };
  }
  return routes;
}

export function buildShareHostLaunchEnv({ host, port, trustBundlePath, registryUploadKeyPath, nodeEnforcerDid, openKeyOrigin, walletOrigin, shareOrigin, registryOrigin, canonicalOrigins, nodeTransportOrigin, credentialsTransportOrigin, senderBindingStore }) {
  // Validated under its own label first so the SHARE_HERMETIC_REGISTRY_ORIGIN
  // contract keeps reporting `registryOrigin` rather than the transport alias.
  const registry = loopbackOrigin(registryOrigin, "registryOrigin");
  const routes = hermeticUpstreamRoutes({
    canonicalOrigins,
    nodeTransportOrigin,
    credentialsTransportOrigin,
    // The registry transport is the same real local registry process the
    // Share host's own registry client already points at.
    registryTransportOrigin: registry,
  });
  if (senderBindingStore !== undefined && (typeof senderBindingStore !== "object" || senderBindingStore === null || Array.isArray(senderBindingStore) || Object.keys(senderBindingStore).sort().join(",") !== "path,root" || typeof senderBindingStore.root !== "string" || typeof senderBindingStore.path !== "string" || !senderBindingStore.path.startsWith(`${senderBindingStore.root}/`))) throw new Error("senderBindingStore must name an exact root and descendant path");
  return {
    HOST: host,
    PORT: String(port),
    SHARE_TRUST_BUNDLE_FILE: trustBundlePath,
    SHARE_SENDER_ENABLED: senderBindingStore === undefined ? "false" : "true",
    ...(senderBindingStore === undefined ? {} : { SHARE_BINDING_STORE_ROOT: senderBindingStore.root, SHARE_BINDING_STORE_PATH: senderBindingStore.path }),
    SHARE_REGISTRY_UPLOAD_KEY_PATH: registryUploadKeyPath,
    SHARE_NODE_ENFORCER_DID: nodeEnforcerDid,
    SHARE_HERMETIC_OPENKEY_ORIGIN: loopbackOrigin(openKeyOrigin, "openKeyOrigin"),
    SHARE_HERMETIC_WALLET_ORIGIN: loopbackOrigin(walletOrigin, "walletOrigin"),
    SHARE_HERMETIC_BROWSER_ORIGIN: loopbackOrigin(shareOrigin, "shareOrigin"),
    SHARE_HERMETIC_REGISTRY_ORIGIN: registry,
    SHARE_HERMETIC_COMPOSITION: "true",
    SHARE_HERMETIC_UPSTREAMS_JSON: JSON.stringify({ node: routes.node, credentials: routes.credentials, registry: routes.registry }),
  };
}
