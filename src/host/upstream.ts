import type { ShareTrustBundle } from "./trust-bundle.js";

export type ShareUpstream = "node" | "credentials" | "registry";

export interface ShareUpstreamOrigins {
  readonly node: string;
  readonly credentials: string;
  readonly registry: string;
}

export const UPSTREAM_BODY_LIMIT = 128 * 1024;
const REQUEST_HEADERS = new Set(["accept", "content-type", "idempotency-key", "if-none-match", "x-delete-after"]);
// Share owns caching, framing, referrer, and content-sniffing policy.  An
// upstream may provide only its protocol media type plus validators; it may
// not rewrite the browser security boundary.
const RESPONSE_HEADERS = new Set(["content-type", "etag", "vary"]);

function mediaType(value: string | null): string | undefined {
  return value?.split(";", 1)[0]?.trim().toLowerCase();
}

function routePolicy(path: string, method: string): { readonly service: ShareUpstream; readonly requestType: string | undefined; readonly responseTypes: readonly string[]; readonly maxBody: number } {
  const upper = method.toUpperCase();
  if (path.startsWith("/share/v1/")) {
    if (upper !== "POST" || !["/share/v1/policy/challenges", "/share/v1/policy/sessions", "/share/v1/read"].includes(path)) throw new Error("upstream method is not allowed");
    return { service: "node", requestType: "application/json", responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  if (path.startsWith("/v1/share-email/")) {
    const jsonPost = ["/v1/share-email/invitations", "/v1/share-email/invitations/resend", "/v1/share-email/claims/challenge", "/v1/share-email/claims/redeem", "/v1/share-email/claims/activate", "/v1/share-email/webhooks/resend"];
    if (path === "/v1/share-email/claims/activate" && upper === "GET") return { service: "credentials", requestType: undefined, responseTypes: ["application/json"], maxBody: 0 };
    if (upper !== "POST" || !jsonPost.includes(path)) throw new Error("upstream method is not allowed");
    return { service: "credentials", requestType: "application/json", responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  if (path === "/registry" || path.startsWith("/registry/")) {
    if (upper === "GET") return { service: "registry", requestType: undefined, responseTypes: ["application/vnd.ipld.raw", "application/json"], maxBody: 0 };
    if (upper === "POST") return { service: "registry", requestType: "application/vnd.ipld.raw", responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  throw new Error("upstream route is not allowed");
}

export function sanitizeUpstreamRequest(path: string, method: string, incoming: Headers, bodyLength: number, shareOrigin: string): Headers {
  const policy = routePolicy(path, method);
  if (bodyLength > policy.maxBody) throw new Error("upstream body is too large");
  const contentType = mediaType(incoming.get("content-type"));
  if (policy.requestType !== undefined && contentType !== policy.requestType) throw new Error("upstream content type is not allowed");
  if (policy.requestType === undefined && contentType !== undefined) throw new Error("unexpected upstream content type");
  const headers = new Headers();
  for (const name of REQUEST_HEADERS) {
    const value = incoming.get(name);
    if (value !== null) headers.set(name, value);
  }
  headers.delete("host");
  headers.delete("content-length");
  headers.set("origin", shareOrigin);
  return headers;
}

export function sanitizeUpstreamResponse(path: string, method: string, response: Response): Response {
  const policy = routePolicy(path, method);
  if (response.status >= 300 && response.status < 400) throw new Error("upstream redirects are not allowed");
  const contentType = mediaType(response.headers.get("content-type"));
  if (response.status >= 200 && response.status < 300 && contentType !== undefined && !policy.responseTypes.includes(contentType)) throw new Error("upstream response content type is not allowed");
  const headers = new Headers();
  for (const name of RESPONSE_HEADERS) {
    const value = response.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  headers.delete("set-cookie");
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  return new Response(response.body, { status: response.status, headers });
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
