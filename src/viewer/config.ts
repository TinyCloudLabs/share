/**
 * Viewer configuration (stage 3, bearer slice).
 *
 * The registry base is configured at build time via
 * `VITE_SHARE_REGISTRY_URL`.
 *
 * - PRODUCTION builds REQUIRE it: a missing value throws at startup rather
 *   than silently shipping a loopback default that would send every share
 *   fetch to 127.0.0.1 (or to whatever squats on that port).
 * - Dev builds fall back to the local dev registry
 *   (`npm run -w @tinycloud/share-registry dev-server -- --port 8787`).
 *
 * NOTE: the CSP `connect-src` in viewer.html must list this origin. In
 * production the CSP is served as headers with the deployment allowlist
 * (viewer spec §2) — keep the two in sync.
 */

export interface ViewerBuildEnv {
  readonly PROD: boolean;
  readonly VITE_SHARE_REGISTRY_URL?: string | undefined;
}

const DEV_REGISTRY_URL = "http://127.0.0.1:8787";

/** Pure resolver so both build flavors are unit-testable. Fails closed. */
export function resolveRegistryBaseUrl(env: ViewerBuildEnv): string {
  const configured = env.VITE_SHARE_REGISTRY_URL;
  if (configured !== undefined && configured.length > 0) return configured;
  if (env.PROD) {
    throw new Error(
      "VITE_SHARE_REGISTRY_URL is required in production builds — refusing to fall back to a loopback registry",
    );
  }
  return DEV_REGISTRY_URL;
}

export const REGISTRY_BASE_URL: string = resolveRegistryBaseUrl({
  PROD: import.meta.env.PROD,
  VITE_SHARE_REGISTRY_URL: import.meta.env.VITE_SHARE_REGISTRY_URL as
    | string
    | undefined,
});
