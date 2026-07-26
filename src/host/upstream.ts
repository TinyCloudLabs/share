import type { ShareTrustBundle } from "./trust-bundle.js";

export type ShareUpstream = "node" | "credentials" | "registry";

export interface ShareUpstreamOrigins {
  readonly node: string;
  readonly credentials: string;
  readonly registry: string;
}

export const UPSTREAM_BODY_LIMIT = 128 * 1024;
// Native Share KV bodies carry base64url content inside a signed JSON
// envelope. Keep the proxy ceiling aligned with Node's encoded request
// ceiling so an exact 100 MiB content write can cross the production-shaped
// boundary without silently falling back to the small JSON API limit.
export const NATIVE_SHARE_BODY_LIMIT = Math.floor((100 * 1024 * 1024 / 3) * 4) + 2_000_000;
export const REGISTRY_UPLOAD_BODY_LIMIT = 100 * 1024 * 1024 + (1 + 12 + 16);
const REQUEST_HEADERS = new Set([
  "accept",
  "authorization",
  "content-type",
  "etag",
  "idempotency-key",
  "if-match",
  "if-none-match",
  "x-delete-after",
  "x-tinycloud-cursor",
  "x-tinycloud-limit",
  "x-tinycloud-next-cursor",
  "x-tinycloud-source",
]);
// Share owns caching, framing, referrer, and content-sniffing policy.  An
// upstream may provide only its protocol media type plus validators; it may
// not rewrite the browser security boundary.
const RESPONSE_HEADERS = new Set(["content-type", "etag", "vary", "x-tinycloud-next-cursor", "retry-after"]);

function mediaType(value: string | null): string | undefined {
  return value?.split(";", 1)[0]?.trim().toLowerCase();
}

function peerPath(path: string): string | undefined {
  let decoded: string;
  try { decoded = decodeURIComponent(path); } catch { return undefined; }
  return /^\/peer\/generate\/(?:tinycloud|did):[A-Za-z0-9._:-]+$/i.test(decoded) ? decoded : undefined;
}

function routePolicy(path: string, method: string): { readonly service: ShareUpstream; readonly requestTypes: readonly string[]; readonly responseTypes: readonly string[]; readonly maxBody: number } {
  const upper = method.toUpperCase();
  if (path === "/info") {
    if (upper !== "GET") throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: [], responseTypes: ["application/json"], maxBody: 0 };
  }
  // The Web SDK stages the sender's host key before opening its first space.
  // Keep this route limited to a single encoded TinyCloud/did space segment;
  // arbitrary peer-management paths must never become a same-origin proxy.
  if (peerPath(path) !== undefined) {
    if (upper !== "GET") throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: [], responseTypes: ["text/plain"], maxBody: 0 };
  }
  if (path === "/encryption/networks") {
    if (upper !== "POST") throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: ["application/json"], responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  if (/^\/encryption\/networks\/[^/]+$/.test(path)) {
    if (upper !== "GET") throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: [], responseTypes: ["application/json"], maxBody: 0 };
  }
  if (/^\/encryption\/networks\/[^/]+\/(?:decrypt|revoke)$/.test(path)) {
    if (upper !== "POST") throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: path.endsWith("/decrypt") ? ["application/json"] : [], responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  if (/^\/.well-known\/encryption\/network\/[^/]+$/.test(path)) {
    if (upper !== "GET") throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: [], responseTypes: ["application/json"], maxBody: 0 };
  }
  if (path.startsWith("/share/v1/")) {
    if (upper !== "POST" || !["/share/v1/invitations/authorize", "/share/v1/policy/challenges", "/share/v1/policy/session", "/share/v1/read"].includes(path)) throw new Error("upstream method is not allowed");
    return { service: "node", requestTypes: ["application/json"], responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  if (path === "/delegate" || path === "/invoke") {
    if (upper !== "POST") throw new Error("upstream method is not allowed");
    // `/delegate` normally carries the signed delegation entirely in
    // Authorization; retain the JSON form for legacy callers and vectors.
    if (path === "/delegate") return { service: "node", requestTypes: ["application/json", "application/vnd.tinycloud.delegation+json", "application/vnd.tinycloud.share+json"], responseTypes: ["application/json", "application/octet-stream", "application/vnd.tinycloud.delegation+json", "application/vnd.tinycloud.share+json"], maxBody: UPSTREAM_BODY_LIMIT };
    // The legacy Web SDK sends ordinary space invocations with a JSON string
    // body but no explicit media type. Fetch labels that request text/plain;
    // this is still authenticated by the native Authorization header and is
    // normalized to Rocket's application/json route below. V2 share invokes
    // continue to require their dedicated vendor media type.
    return { service: "node", requestTypes: ["application/json", "text/plain", "application/vnd.tinycloud.delegation+json", "application/vnd.tinycloud.share+json"], responseTypes: ["application/json", "application/octet-stream", "application/vnd.tinycloud.delegation+json", "application/vnd.tinycloud.share+json"], maxBody: NATIVE_SHARE_BODY_LIMIT };
  }
  if (path.startsWith("/v1/share-email/")) {
    const jsonPost = ["/v1/share-email/invitations", "/v1/share-email/invitations/resend", "/v1/share-email/claims/challenge", "/v1/share-email/claims/redeem", "/v1/share-email/claims/activate", "/v1/share-email/webhooks/resend"];
    if (path === "/v1/share-email/claims/activate" && upper === "GET") return { service: "credentials", requestTypes: [], responseTypes: ["application/json"], maxBody: 0 };
    if (upper !== "POST" || !jsonPost.includes(path)) throw new Error("upstream method is not allowed");
    return { service: "credentials", requestTypes: ["application/json"], responseTypes: ["application/json"], maxBody: UPSTREAM_BODY_LIMIT };
  }
  // Keep the same-origin route narrow to a CID-shaped token. The registry
  // remains authoritative for canonical CID parsing and byte verification;
  // accepting the full lowercase base32 alphabet here also preserves the
  // raw gateway contract for legacy fixtures that contain 0/1 characters.
  if (/^\/s\/bafkrei[a-z0-9]+\/raw$/.test(path)) {
    if (upper !== "GET") throw new Error("upstream method is not allowed");
    return { service: "registry", requestTypes: [], responseTypes: ["application/vnd.ipld.raw"], maxBody: 0 };
  }
  if (path === "/registry" || path.startsWith("/registry/")) {
    if (upper === "GET") return { service: "registry", requestTypes: [], responseTypes: ["application/vnd.ipld.raw", "application/json"], maxBody: 0 };
    if (upper === "POST") return { service: "registry", requestTypes: ["application/vnd.ipld.raw"], responseTypes: ["application/json"], maxBody: REGISTRY_UPLOAD_BODY_LIMIT };
  }
  throw new Error("upstream route is not allowed");
}

export function sanitizeUpstreamRequest(path: string, method: string, incoming: Headers, bodyLength: number, shareOrigin: string): Headers {
  const policy = routePolicy(path, method);
  if (bodyLength > policy.maxBody) throw new Error("upstream body is too large");
  const contentType = mediaType(incoming.get("content-type"));
  const emptyNativeDelegation = path === "/delegate" && bodyLength === 0 && contentType === undefined;
  const emptyNativeInvoke = path === "/invoke" && bodyLength === 0 && contentType === undefined;
  if (policy.requestTypes.length > 0 && !emptyNativeDelegation && !emptyNativeInvoke && (contentType === undefined || !policy.requestTypes.includes(contentType))) throw new Error(`upstream content type is not allowed (${contentType ?? "missing"})`);
  if (policy.requestTypes.length === 0 && contentType !== undefined) throw new Error("unexpected upstream content type");
  const headers = new Headers();
  for (const name of REQUEST_HEADERS) {
    const carriesNativeAuth = path === "/delegate" || path === "/invoke" || path === "/encryption/networks" || /^\/encryption\/networks\/[^/]+\/(?:decrypt|revoke)$/.test(path);
    if (name === "authorization" && !carriesNativeAuth) continue;
    const value = incoming.get(name);
    if (value !== null) headers.set(name, value);
  }
  headers.delete("host");
  headers.delete("content-length");
  // Rocket's native JSON route requires a media type even for the signed
  // bodyless space-list invocation; SDK capability headers intentionally do
  // not supply one. Normalize only the legacy untyped/text form here. The
  // share-v2 vendor media type selects the dedicated native share route on
  // the real Node router and must reach that route unchanged.
  if (path === "/invoke" && (emptyNativeInvoke || contentType === "text/plain" || contentType === "application/vnd.tinycloud.delegation+json")) headers.set("content-type", "application/json");
  headers.set("origin", shareOrigin);
  return headers;
}

/** Native delegation/invocation metadata is carried by headers, never by URLs. */
export function assertSafeUpstreamQuery(pathname: string, search: string): void {
  if (search === "") return;
  const query = new URLSearchParams(search);
  for (const key of query.keys()) {
    if (/authorization|bearer|credential|email|fragment|key|secret|token/i.test(key)) throw new Error("credential-bearing query parameters are not allowed");
  }
  if ((pathname === "/delegate" || pathname === "/invoke") && [...query.keys()].some((key) => key !== "cursor" && key !== "limit")) throw new Error("native invocation query parameters are not allowed");
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
  if (path === "/info") return { service: "node", origin: origins.node };
  if (peerPath(path) !== undefined) return { service: "node", origin: origins.node };
  if (path === "/encryption/networks" || /^\/encryption\/networks\/[^/]+(?:\/decrypt|\/revoke)?$/.test(path) || /^\/.well-known\/encryption\/network\/[^/]+$/.test(path)) return { service: "node", origin: origins.node };
  if (path.startsWith("/share/v1/")) return { service: "node", origin: origins.node };
  if (path === "/delegate" || path === "/invoke") return { service: "node", origin: origins.node };
  if (/^\/s\/bafkrei[a-z0-9]+\/raw$/.test(path)) return { service: "registry", origin: origins.registry };
  if (path.startsWith("/v1/share-email/")) return { service: "credentials", origin: origins.credentials };
  if (path === "/registry" || path.startsWith("/registry/")) return { service: "registry", origin: origins.registry };
  return undefined;
}

export function upstreamPathFor(path: string): string {
  const match = /^\/s\/(bafkrei[a-z0-9]+)\/raw$/.exec(path);
  return match?.[1] === undefined ? path : `/ipfs/${match[1]}?format=raw`;
}
