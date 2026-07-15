import { canonicalNodeAudienceForOrigin } from "../../packages/envelope/src/deployment-origin.js";

export const DEFAULT_ALLOWED_NODE_ORIGINS = ["https://node.tinycloud.xyz"] as const;
export const DEFAULT_OPENKEY_ORIGIN = "https://openkey.so";
export const DEFAULT_DEV_REGISTRY_ORIGIN = "http://127.0.0.1:8787";

function isCanonicalDevRegistryOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" &&
      url.origin === value &&
      url.port !== "" &&
      (url.hostname === "127.0.0.1" || url.hostname === "localhost");
  } catch {
    return false;
  }
}

/** Frozen v2 grammar: lowercase multi-label DNS, default-port HTTPS, no path. */
export function isCanonicalDeploymentHttpsOrigin(value: string): boolean {
  return canonicalNodeAudienceForOrigin(value) !== null;
}

/** One parser shared by the viewer runtime and Vite's CSP generation. */
export function parseAllowedNodeOrigins(value: string | undefined): readonly string[] {
  const origins = value === undefined || value.trim() === ""
    ? [...DEFAULT_ALLOWED_NODE_ORIGINS]
    : value.split(",").map((item) => item.trim());
  if (
    origins.length === 0 ||
    origins.some((origin) => !isCanonicalDeploymentHttpsOrigin(origin)) ||
    new Set(origins).size !== origins.length
  ) {
    throw new Error(
      "VITE_SHARE_ALLOWED_NODE_ORIGINS must be a comma-separated list of unique canonical HTTPS origins",
    );
  }
  return Object.freeze(origins);
}

export function nodeOriginsCspSource(origins: readonly string[]): string {
  return origins.join(" ");
}

export function parseOpenKeyOrigin(value: string | undefined): string {
  const origin = value === undefined || value.trim() === ""
    ? DEFAULT_OPENKEY_ORIGIN
    : value.trim();
  if (!isCanonicalDeploymentHttpsOrigin(origin)) {
    throw new Error("VITE_SHARE_OPENKEY_ORIGIN must be one canonical HTTPS origin");
  }
  return origin;
}

export function parseRegistryOrigin(
  value: string | undefined,
  production: boolean,
): string {
  const origin = value === undefined || value.trim() === ""
    ? production ? "" : DEFAULT_DEV_REGISTRY_ORIGIN
    : value.trim();
  if (origin === "") {
    throw new Error(
      "VITE_SHARE_REGISTRY_URL is required in production builds — refusing to fall back to a loopback registry",
    );
  }
  if (
    !isCanonicalDeploymentHttpsOrigin(origin) &&
    !(production === false && isCanonicalDevRegistryOrigin(origin))
  ) {
    throw new Error(
      "VITE_SHARE_REGISTRY_URL must be a canonical deployment HTTPS origin (or an explicit loopback HTTP origin in development)",
    );
  }
  return origin;
}

export interface ViewerDeploymentCspSources {
  readonly registryOrigin: string;
  readonly nodeOrigins: readonly string[];
  readonly openKeyOrigin: string;
}

/** Shared by Vite's HTML transform and emitted `_headers` rewrite. */
export function replaceViewerDeploymentCspSources(
  text: string,
  sources: ViewerDeploymentCspSources,
): string {
  return text
    .replaceAll("__TINYCLOUD_REGISTRY_CONNECT_SRC__", sources.registryOrigin)
    .replaceAll(
      "__TINYCLOUD_NODE_CONNECT_SRC__",
      nodeOriginsCspSource(sources.nodeOrigins),
    )
    .replaceAll("__TINYCLOUD_OPENKEY_FRAME_SRC__", sources.openKeyOrigin);
}
