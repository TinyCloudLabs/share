// TC-339. Where the harness's hermeticity actually lives.
//
// The signed authority host and the transport destination are two different
// things, and only one of them may move.
//
//   * Authority. `src/share/openkey-session.ts` builds the Web SDK against
//     `config.nodeOrigin` — https://node.tinycloud.xyz — whose hostname is the
//     enrolled `did:web:node.tinycloud.xyz` audience the local node was
//     launched with (trustBundleFromRuntime). Moving it to
//     window.location.origin is what VITE_SHARE_HERMETIC used to do, and it
//     produced repeatable /delegate 500s (cdb0da9). It must not move.
//
//   * Transport. The bytes must land on the loopback Share host, which proxies
//     every node/credentials/registry route to the local processes
//     (src/host/upstream.ts, proven route-by-route by
//     assert-loopback-upstreams.ts before any browser request is made).
//
// In production the two coincide because DNS points node.tinycloud.xyz at the
// real node. The harness cannot own that name, so something has to decouple
// them. The question is only where that decoupling lives and whether it is
// enforced or merely hoped for.
//
// It used to be neither: `installBrowserTelemetry()` monkey-patched
// window.fetch, and the URL rewrite rode along inside a *telemetry* shim that
// navigation silently discarded. Six of the seven `authenticateBrowserPage`
// call sites ran against a page with no shim at all, so the SDK really did
// dial https://node.tinycloud.xyz. Hermetic by accident, un-hermetic without a
// sound.
//
// This module supplies the enforcement half: a browser-network-layer route
// that aborts every request to a canonical production origin. It is installed
// once per session on the Playwright page, so unlike a page-realm shim it
// survives navigation by construction, covers subframes and non-fetch
// transports, and needs nothing from the application. Escaping to production
// is no longer a silent success — it is an immediate, located failure.

/**
 * The canonical production origins this harness replaces with local processes.
 * Every one of them has a loopback stand-in wired through the Share host, so a
 * request that still names one is by definition an escape.
 */
export function loopbackTransportAbortPatterns(canonicalOrigins) {
  if (typeof canonicalOrigins !== "object" || canonicalOrigins === null || Array.isArray(canonicalOrigins)) {
    throw new TypeError("loopbackTransportAbortPatterns requires the canonical origin map");
  }
  const entries = Object.entries(canonicalOrigins);
  if (entries.length === 0) throw new Error("loopbackTransportAbortPatterns requires at least one canonical origin");
  const patterns = [];
  for (const [name, origin] of entries) {
    if (typeof origin !== "string" || origin.length === 0) throw new TypeError(`canonical ${name} origin is missing`);
    let parsed;
    try { parsed = new URL(origin); } catch { throw new TypeError(`canonical ${name} origin is not a URL: ${origin}`); }
    if (parsed.protocol !== "https:" || parsed.origin !== origin) throw new TypeError(`canonical ${name} origin must be a canonical HTTPS origin: ${origin}`);
    if (/^(?:127\.0\.0\.1|localhost|\[::1\])$/.test(parsed.hostname)) throw new TypeError(`canonical ${name} origin must not be loopback: ${origin}`);
    patterns.push(`${origin}/**`);
  }
  return Object.freeze([...new Set(patterns)].sort());
}

/**
 * Assertion run after every navigation. The page-realm routing shim is
 * reinstalled by the harness's own navigate() helper; if it is ever missing,
 * say so at the navigation that dropped it rather than several steps later at
 * a sign-in that mysteriously reached the public internet.
 */
export function assertRoutingShimInstalled(evaluated, context) {
  const installed = typeof evaluated === "string" ? evaluated.trim() === "true" : evaluated === true;
  if (installed) return true;
  throw new Error(`loopback routing shim is absent after navigating to ${context}: the page would address ${"https://node.tinycloud.xyz"} over the real network. Navigation must reinstall it (see navigate() in integration.mjs).`);
}
