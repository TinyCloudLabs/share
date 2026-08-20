/*
 * TC-306 routing gate.
 *
 * The sharing harness proxies every native request through the Share host,
 * which resolves its destinations server-side with
 * src/host/upstream.ts's resolveShareUpstreams. That resolution is invisible
 * to the browser: the page only ever sees the loopback Share host, so the
 * harness's "zero external destinations" browser audit cannot observe it. For
 * eleven days a missing SHARE_HERMETIC_UPSTREAMS_JSON therefore sent
 * /delegate to the public production node while the locally built node under
 * test received nothing, and every audit stayed green.
 *
 * This gate runs the *production* resolver — not a harness reimplementation —
 * against the exact trust bundle and the exact launch env the Share host is
 * about to be started with, and fails loudly if anything resolves off
 * loopback. resolveShareUpstreams returns exactly three origins and
 * upstreamForPath can only ever return one of them, so proving those three
 * are loopback proves no proxied route can leave the composition.
 *
 * Run with the Share host launch env in the environment; prints the resolved
 * routing table as JSON on success.
 */

import process from "node:process";
import { loadTrustBundle } from "../../src/host/trust-bundle.js";
import { resolveShareUpstreams, upstreamForPath } from "../../src/host/upstream.js";

const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/;

// Every branch of upstreamForPath, so a future route added without a
// hermetic destination is caught here rather than in production telemetry.
const PROXIED_PATHS = [
  "/info",
  "/peer/generate/did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
  "/encryption/networks",
  "/encryption/networks/hermetic-network",
  "/encryption/networks/hermetic-network/decrypt",
  "/encryption/networks/hermetic-network/revoke",
  "/.well-known/encryption/network/hermetic-network",
  "/policy/v3/challenges",
  "/policy/v3/delegations",
  "/delegate",
  "/invoke",
  "/v1/share-email/invitations",
  "/v1/share-email/claims/redeem",
  "/s/bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/raw",
  "/registry",
  "/registry/blobs",
];

const bundle = loadTrustBundle(process.env);
const upstreams = resolveShareUpstreams(bundle, process.env);

const offLoopback = Object.entries(upstreams).filter(([, origin]) => !LOOPBACK_ORIGIN.test(origin));
if (offLoopback.length > 0) {
  throw new Error(`Share host upstreams resolve off loopback: ${JSON.stringify(Object.fromEntries(offLoopback))}. SHARE_HERMETIC_UPSTREAMS_JSON present=${process.env.SHARE_HERMETIC_UPSTREAMS_JSON !== undefined} SHARE_HERMETIC_COMPOSITION=${JSON.stringify(process.env.SHARE_HERMETIC_COMPOSITION ?? null)}`);
}

// The bundle itself must stay production-shaped: the whole point is that the
// harness drives the shipped production trust tuple and only the *transport*
// is loopback. A loopback bundle origin would mean the harness rewrote the
// trust bundle instead of routing it.
const bundleOrigins = { node: bundle.public.nodeOrigin, credentials: bundle.public.credentialsOrigin, registry: bundle.public.registryOrigin };
const nonProduction = Object.entries(bundleOrigins).filter(([, origin]) => !origin.startsWith("https://"));
if (nonProduction.length > 0) {
  throw new Error(`Share trust bundle is not production-shaped: ${JSON.stringify(Object.fromEntries(nonProduction))}`);
}

const routes = PROXIED_PATHS.map((path) => {
  const upstream = upstreamForPath(bundle, path, process.env);
  if (upstream === undefined) throw new Error(`proxied path ${path} no longer resolves to an upstream; the routing gate is stale`);
  if (!LOOPBACK_ORIGIN.test(upstream.origin)) throw new Error(`${path} resolves to the non-loopback origin ${upstream.origin}`);
  return { path, service: upstream.service, origin: upstream.origin };
});

process.stdout.write(`${JSON.stringify({ bundleOrigins, upstreams, routes })}\n`);
