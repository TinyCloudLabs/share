import type { ShareTrustBundle } from "./trust-bundle.js";

export type ShareUpstream = "node" | "credentials" | "registry";

export interface ShareUpstreamOrigins {
  readonly node: string;
  readonly credentials: string;
  readonly registry: string;
}

interface HermeticRoute {
  readonly origin: string;
  readonly transportOrigin: string;
}

const LOOPBACK = /^http:\/\/127\.0\.0\.1(?::\d+)?$/;
const LEGACY_TRANSPORT_ENV = [
  "SHARE_NODE_TRANSPORT_ORIGIN",
  "SHARE_CREDENTIALS_TRANSPORT_ORIGIN",
  "SHARE_REGISTRY_TRANSPORT_ORIGIN",
] as const;

function exactRecord(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) throw new Error(`${label} has an invalid shape`);
  return record;
}

function route(value: unknown, expectedOrigin: string, label: string): HermeticRoute {
  const record = exactRecord(value, ["origin", "transportOrigin"], label);
  if (record.origin !== expectedOrigin || typeof record.transportOrigin !== "string" || !LOOPBACK.test(record.transportOrigin)) throw new Error(`${label} is not bound to its trust-bundle origin`);
  return { origin: expectedOrigin, transportOrigin: record.transportOrigin };
}

/**
 * Resolve service destinations from the validated public trust tuple. The
 * only alternate route is an explicit hermetic test resolver whose entries
 * name the exact bundle origin they replace and may target loopback only.
 */
export function resolveShareUpstreams(bundle: ShareTrustBundle, env: NodeJS.ProcessEnv = process.env): ShareUpstreamOrigins {
  if (LEGACY_TRANSPORT_ENV.some((name) => env[name] !== undefined)) throw new Error("legacy Share transport overrides are forbidden; use the explicit hermetic resolver");
  const defaults = { node: bundle.public.nodeOrigin, credentials: bundle.public.credentialsOrigin, registry: bundle.public.registryOrigin } as const;
  const raw = env.SHARE_HERMETIC_UPSTREAMS_JSON;
  if (raw === undefined) return defaults;
  if (env.SHARE_HERMETIC_COMPOSITION !== "true") throw new Error("SHARE_HERMETIC_UPSTREAMS_JSON requires SHARE_HERMETIC_COMPOSITION=true");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error("SHARE_HERMETIC_UPSTREAMS_JSON must be valid JSON"); }
  const routes = exactRecord(value, ["node", "credentials", "registry"], "SHARE_HERMETIC_UPSTREAMS_JSON");
  const node = route(routes.node, defaults.node, "hermetic node route");
  const credentials = route(routes.credentials, defaults.credentials, "hermetic credentials route");
  const registry = route(routes.registry, defaults.registry, "hermetic registry route");
  return { node: node.transportOrigin, credentials: credentials.transportOrigin, registry: registry.transportOrigin };
}

export function upstreamForPath(bundle: ShareTrustBundle, path: string, env: NodeJS.ProcessEnv = process.env): { readonly service: ShareUpstream; readonly origin: string } | undefined {
  const origins = resolveShareUpstreams(bundle, env);
  if (path.startsWith("/share/v1/")) return { service: "node", origin: origins.node };
  if (path.startsWith("/v1/share-email/")) return { service: "credentials", origin: origins.credentials };
  if (path === "/registry" || path.startsWith("/registry/")) return { service: "registry", origin: origins.registry };
  return undefined;
}
