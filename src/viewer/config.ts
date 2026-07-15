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
 * Vite consumes the same deployment parsers to generate viewer.html and the
 * production `_headers` CSP, so runtime routing and browser policy cannot
 * silently drift.
 */
import {
  parseAllowedNodeOrigins,
  parseOpenKeyOrigin,
  parseRegistryOrigin,
} from "./deployment-config.js";

export interface ViewerBuildEnv {
  readonly PROD: boolean;
  readonly VITE_SHARE_REGISTRY_URL?: string | undefined;
  readonly VITE_SHARE_ALLOWED_NODE_ORIGINS?: string | undefined;
  readonly VITE_SHARE_OPENKEY_ORIGIN?: string | undefined;
}

/** Pure resolver so both build flavors are unit-testable. Fails closed. */
export function resolveRegistryBaseUrl(env: ViewerBuildEnv): string {
  return parseRegistryOrigin(env.VITE_SHARE_REGISTRY_URL, env.PROD);
}

export const REGISTRY_BASE_URL: string = resolveRegistryBaseUrl({
  PROD: import.meta.env.PROD,
  VITE_SHARE_REGISTRY_URL: import.meta.env.VITE_SHARE_REGISTRY_URL as
    | string
    | undefined,
});

export const ALLOWED_NODE_ORIGINS: readonly string[] = parseAllowedNodeOrigins(
  import.meta.env.VITE_SHARE_ALLOWED_NODE_ORIGINS as string | undefined,
);

export const OPENKEY_ORIGIN: string = parseOpenKeyOrigin(
  import.meta.env.VITE_SHARE_OPENKEY_ORIGIN as string | undefined,
);
