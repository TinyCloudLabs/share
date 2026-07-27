// The committed Share host serves the recipient bundle at its own loopback
// origin, but src/main.ts's captureAndScrubLaunch only rewrites a captured
// 127.0.0.1 shareHref back to the canonical https://share.tinycloud.xyz
// origin when VITE_SHARE_HERMETIC === "true" (see src/main.ts:20-22) — every
// other flag here is already exercised by the production build. The viewer's
// registry client (src/viewer/config.ts) must also observe the same
// same-origin proxy the CSP and zero-external-destination audit expect
// (src/host/share-adapter.ts serves it at "/registry" on the Share host
// itself), never the canonical public registry host.
import { loopbackOrigin } from "./share-launch-env.mjs";

const CANONICAL_SHARE_ORIGIN = "https://share.tinycloud.xyz";

export function buildShareBrowserBuildEnv(origin, openKeyOrigin) {
  const shareLocalOrigin = loopbackOrigin(origin, "origin");
  const validatedOpenKeyOrigin = loopbackOrigin(openKeyOrigin, "openKeyOrigin");
  return {
    VITE_SHARE_HERMETIC: "true",
    VITE_SHARE_ORIGIN: CANONICAL_SHARE_ORIGIN,
    VITE_SHARE_REGISTRY_URL: `${shareLocalOrigin}/registry`,
    VITE_OPENKEY_ORIGIN: validatedOpenKeyOrigin,
  };
}
