import { computeCid } from "@tinycloud/share-envelope";
import { DEFAULT_MAX_BLOB_BYTES, DELETE_AFTER_HEADER, IF_NONE_MATCH_HEADER, IF_NONE_MATCH_CREATE_ONLY, RAW_BLOCK_CONTENT_TYPE, readBodyBounded } from "./client.js";

interface R2ObjectLike { arrayBuffer(): Promise<ArrayBuffer>; customMetadata?: Record<string, string> }
interface R2Bucket {
  get(key: string): Promise<R2ObjectLike | null>;
  put(key: string, value: ArrayBuffer | Uint8Array, options?: unknown): Promise<void>;
  delete?(keys: string | string[]): Promise<void>;
  list?(options?: { prefix?: string; cursor?: string; include?: string[] }): Promise<{ objects: Array<{ key: string; customMetadata?: Record<string, string> }>; truncated: boolean; cursor?: string }>;
}
export interface DurableObjectStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}
export interface DurableObjectState {
  storage: DurableObjectStorage;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
}
export interface DurableObjectStub { fetch(input: string, init?: RequestInit): Promise<Response> }
export interface DurableObjectNamespace { getByName(name: string): DurableObjectStub }
export interface RegistryEnv {
  REGISTRY: R2Bucket;
  REGISTRY_AUTH_PUBLIC_KEY?: string;
  REGISTRY_LINK_UPLOAD_PUBLIC_KEY?: string;
  UPLOAD_AUTHORIZATION?: DurableObjectNamespace;
  MAX_BLOB_BYTES?: string;
}
const CORS = { "access-control-allow-origin": "https://share.tinycloud.xyz", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,accept,if-none-match,x-delete-after,x-tinycloud-authorization", "access-control-max-age": "86400", "strict-transport-security": "max-age=31536000; includeSubDomains", vary: "Origin" };
const LINK_PROXY_ORIGIN = "https://registry.tinycloud.xyz";
const LINK_AUTHORIZATION_DOMAIN = "xyz.tinycloud.share/registry-authorization/v1\0";
const LINK_AUTHORIZATION_TTL_MS = 2 * 60 * 1000;
const LINK_RETENTION_LIMIT_MS = 8 * 24 * 60 * 60 * 1000;
const DELETE_AFTER_METADATA = "tinycloud-delete-after";
const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const B64_JTI = /^[A-Za-z0-9_-]{22}$/;
const REGISTRY_STORE_DOMAIN = "xyz.tinycloud.share/registry-store/v1\0";
const CANONICAL_EXPIRY = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const json = (status: number, body: unknown, extra: HeadersInit = {}) => new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json", ...extra } });
const key = (kind: string, id: string) => `${kind}/${id}`;
function canonicalExpiry(value: unknown): number | null {
  if (typeof value !== "string" || !CANONICAL_EXPIRY.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}
function authBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("invalid base64url");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (normalized.length % 4)) % 4;
  const decoded = atob(`${normalized}${"=".repeat(padding)}`);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}
export class UploadAuthorization {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") return new Response(null, { status: 404 });
    const pathname = new URL(request.url).pathname;
    if (pathname === "/consume") {
      let accepted = false;
      await this.state.blockConcurrencyWhile(async () => {
        if (await this.state.storage.get<boolean>("consumed") === true) return;
        await this.state.storage.put("consumed", true);
        accepted = true;
      });
      return new Response(null, { status: accepted ? 204 : 409 });
    }
    if (pathname === "/reserve") {
      let accepted = false;
      try {
        const body = await request.json() as { now?: unknown; windowMs?: unknown; limit?: unknown };
        const nowValue = body.now;
        const windowMsValue = body.windowMs;
        const limitValue = body.limit;
        if (typeof nowValue !== "number" || !Number.isSafeInteger(nowValue) || typeof windowMsValue !== "number" || !Number.isSafeInteger(windowMsValue) || windowMsValue <= 0 || typeof limitValue !== "number" || !Number.isSafeInteger(limitValue) || limitValue <= 0) return new Response(null, { status: 400 });
        const now = nowValue;
        const windowMs = windowMsValue;
        const limit = limitValue;
        await this.state.blockConcurrencyWhile(async () => {
          const prior = await this.state.storage.get<{ count: number; windowStartedAt: number }>("budget");
          const budget = prior === undefined || now - prior.windowStartedAt >= windowMs
            ? { count: 0, windowStartedAt: now }
            : prior;
          if (budget.count >= limit) return;
          await this.state.storage.put("budget", { count: budget.count + 1, windowStartedAt: budget.windowStartedAt });
          accepted = true;
        });
      } catch {
        return new Response(null, { status: 400 });
      }
      return new Response(null, { status: accepted ? 204 : 409 });
    }
    return new Response(null, { status: 404 });
  }
}
async function consumeUploadAuthorization(env: RegistryEnv, jti: string): Promise<boolean> {
  if (!env.UPLOAD_AUTHORIZATION) return false;
  try {
    const response = await env.UPLOAD_AUTHORIZATION.getByName(jti).fetch("https://upload-authorization/consume", { method: "POST" });
    return response.status === 204;
  } catch {
    return false;
  }
}

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

async function authorizeStoreRequest(request: Request, env: RegistryEnv): Promise<{ readonly operation: "consume" | "reserve"; readonly key: string; readonly body: Record<string, unknown> } | null> {
  if (!env.UPLOAD_AUTHORIZATION || !env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY) return null;
  try {
    const body = await request.json() as unknown;
    if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
    const value = body as Record<string, unknown>;
    const operation = value.operation;
    const keyValue = value.key;
    const signature = request.headers.get("x-tinycloud-registry-store-signature");
    if ((operation !== "consume" && operation !== "reserve") || typeof keyValue !== "string" || keyValue.length === 0 || typeof signature !== "string") return null;
    const publicKey = await crypto.subtle.importKey("raw", Uint8Array.from(authBytes(env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY)), { name: "Ed25519" }, false, ["verify"]);
    const verified = await crypto.subtle.verify("Ed25519", publicKey, Uint8Array.from(authBytes(signature)), new TextEncoder().encode(`${REGISTRY_STORE_DOMAIN}${stable(value)}`));
    if (!verified) return null;
    if (operation === "consume") {
      if (Object.keys(value).sort().join(",") !== "expiresAt,key,operation") return null;
    } else if (Object.keys(value).sort().join(",") !== "key,limit,now,operation,windowMs") return null;
    const stub = env.UPLOAD_AUTHORIZATION.getByName(`${operation}:${keyValue}`);
    const response = await stub.fetch(`https://upload-authorization/${operation === "consume" ? "consume" : "reserve"}`, { method: "POST", body: JSON.stringify(value) });
    return response.status === 204 ? { operation, key: keyValue, body: value } : null;
  } catch {
    return null;
  }
}
async function authorized(request: Request, env: RegistryEnv, operation: string, resource: string): Promise<boolean> {
  const encoded = request.headers.get("x-tinycloud-authorization");
  if (!encoded || !env.REGISTRY_AUTH_PUBLIC_KEY) return false;
  try {
    const outer = JSON.parse(encoded) as { authorization?: Record<string, unknown>; proof?: { alg?: string; signature?: string } };
    const body = outer.authorization; const proof = outer.proof;
    const expiresAt = canonicalExpiry(body?.expiresAt);
    if (!body || proof?.alg !== "EdDSA" || typeof proof.signature !== "string" || body.type !== "TinyCloudShareInviteAuthorization" || body.version !== 1 || body.action !== operation || body.resource !== resource || expiresAt === null || expiresAt <= Date.now()) return false;
    const publicKey = await crypto.subtle.importKey("raw", Uint8Array.from(authBytes(env.REGISTRY_AUTH_PUBLIC_KEY)), { name: "Ed25519" }, false, ["verify"]);
    const unsigned = JSON.stringify(Object.keys(body).sort().reduce((o, k) => { o[k] = body[k]; return o; }, {} as Record<string, unknown>));
    return await crypto.subtle.verify("Ed25519", publicKey, Uint8Array.from(authBytes(proof.signature)), new TextEncoder().encode(`xyz.tinycloud.share/registry-authorization/v1\0${unsigned}`));
  } catch { return false; }
}
async function linkUploadAuthorized(request: Request, env: RegistryEnv, bytes: Uint8Array): Promise<boolean> {
  const encoded = request.headers.get("x-tinycloud-authorization");
  if (!encoded || !env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY) return false;
  try {
    const outer = JSON.parse(encoded) as { authorization?: Record<string, unknown>; proof?: Record<string, unknown> };
    const body = outer.authorization;
    const proof = outer.proof;
    const expectedKeys = ["action", "audience", "bodyDigest", "contentLength", "deleteAfter", "expiresAt", "jti", "mode", "resource", "sessionBinding", "type", "version"];
    if (
      !body ||
      !proof ||
      Object.keys(body).sort().join(",") !== expectedKeys.sort().join(",") ||
      Object.keys(proof).sort().join(",") !== "alg,signature" ||
      proof.alg !== "EdDSA" ||
      typeof proof.signature !== "string" ||
      body.type !== "TinyCloudShareRegistryAuthorization" ||
      body.version !== 1 ||
      body.audience !== LINK_PROXY_ORIGIN ||
      body.mode !== "link-only" ||
      body.action !== "tinycloud.share/upload" ||
      body.resource !== "registry/blobs" ||
      body.contentLength !== bytes.byteLength ||
      typeof body.bodyDigest !== "string" ||
      !B64_256.test(body.bodyDigest) ||
      typeof body.sessionBinding !== "string" ||
      !B64_256.test(body.sessionBinding) ||
      typeof body.jti !== "string" ||
      !B64_JTI.test(body.jti) ||
      typeof body.deleteAfter !== "string" ||
      body.deleteAfter !== request.headers.get(DELETE_AFTER_HEADER) ||
      typeof body.expiresAt !== "string"
    ) return false;
    const now = Date.now();
    const expiresAt = canonicalExpiry(body.expiresAt);
    const deleteAfter = canonicalExpiry(body.deleteAfter);
    if (
      expiresAt === null ||
      expiresAt <= now ||
      expiresAt > now + LINK_AUTHORIZATION_TTL_MS ||
      deleteAfter === null ||
      deleteAfter <= now ||
      deleteAfter > now + LINK_RETENTION_LIMIT_MS
    ) return false;
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes)),
    );
    const bodyDigest = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    if (bodyDigest !== body.bodyDigest) return false;
    const publicKey = await crypto.subtle.importKey("raw", Uint8Array.from(authBytes(env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY)), { name: "Ed25519" }, false, ["verify"]);
    const unsigned = JSON.stringify(Object.keys(body).sort().reduce((o, k) => { o[k] = body[k]; return o; }, {} as Record<string, unknown>));
    const verified = await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      Uint8Array.from(authBytes(proof.signature)),
      new TextEncoder().encode(`${LINK_AUTHORIZATION_DOMAIN}${unsigned}`),
    );
    return verified && await consumeUploadAuthorization(env, body.jti);
  } catch { return false; }
}
function retentionExpiry(request: Request): number | null {
  const value = request.headers.get(DELETE_AFTER_HEADER);
  if (!value) return null;
  const timestamp = Date.parse(value);
  const now = Date.now();
  return Number.isFinite(timestamp) && timestamp > now && timestamp <= now + LINK_RETENTION_LIMIT_MS
    ? timestamp
    : null;
}
function linkAuthorizationAdmitsBody(request: Request, env: RegistryEnv, max: number): boolean {
  const encoded = request.headers.get("x-tinycloud-authorization");
  if (!encoded || !env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY) return false;
  try {
    const outer = JSON.parse(encoded) as { authorization?: Record<string, unknown>; proof?: Record<string, unknown> };
    const body = outer.authorization;
    const proof = outer.proof;
    const contentLength = request.headers.get("content-length");
    return !!body && !!proof && body.type === "TinyCloudShareRegistryAuthorization" && body.version === 1 &&
      body.mode === "link-only" && body.action === "tinycloud.share/upload" && body.audience === LINK_PROXY_ORIGIN && body.resource === "registry/blobs" &&
      Number.isSafeInteger(body.contentLength) && Number(body.contentLength) >= 0 && Number(body.contentLength) <= max &&
      (!contentLength || Number(contentLength) === Number(body.contentLength)) &&
      typeof body.bodyDigest === "string" && B64_256.test(body.bodyDigest) &&
      typeof body.sessionBinding === "string" && B64_256.test(body.sessionBinding) &&
      typeof body.jti === "string" && B64_JTI.test(body.jti) &&
      typeof body.deleteAfter === "string" && body.deleteAfter === request.headers.get(DELETE_AFTER_HEADER) &&
      retentionExpiry(request) !== null && typeof body.expiresAt === "string" &&
      canonicalExpiry(body.expiresAt) !== null && canonicalExpiry(body.expiresAt)! > Date.now() && canonicalExpiry(body.expiresAt)! <= Date.now() + LINK_AUTHORIZATION_TTL_MS &&
      proof.alg === "EdDSA" && typeof proof.signature === "string";
  } catch {
    return false;
  }
}
function expiryFromObject(object: R2ObjectLike): number | null {
  const value = object.customMetadata?.[DELETE_AFTER_METADATA];
  const timestamp = value ? Date.parse(value) : NaN;
  return Number.isFinite(timestamp) ? timestamp : null;
}
async function readBlob(object: R2ObjectLike, env: RegistryEnv, objectKey: string): Promise<{ object: R2ObjectLike; expiry: number } | null> {
  const expiry = expiryFromObject(object);
  if (expiry === null || expiry <= Date.now()) {
    await env.REGISTRY.delete?.(objectKey);
    return null;
  }
  return { object, expiry };
}
function cacheHeaders(expiry: number, cid: string): HeadersInit {
  const maxAge = Math.max(0, Math.ceil((expiry - Date.now()) / 1000));
  return { "content-type": RAW_BLOCK_CONTENT_TYPE, "cache-control": `public, max-age=${maxAge}, must-revalidate`, etag: `"${cid}"` };
}
function response(body: ArrayBuffer | Uint8Array, headers: HeadersInit): Response { return new Response(body as BodyInit, { headers: { ...CORS, ...headers } }); }
const worker = { async fetch(request: Request, env: RegistryEnv): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname === "registry.tinycloud.xyz" && url.protocol !== "https:") {
    return new Response(null, { status: 308, headers: { ...CORS, location: `https://${url.host}${url.pathname}${url.search}` } });
  }
  const origin = request.headers.get("origin");
  const linkProxyUpload = (request.method === "POST" || request.method === "PUT") && url.pathname === "/blobs" && origin === LINK_PROXY_ORIGIN;
  if (origin && origin !== "https://share.tinycloud.xyz" && !linkProxyUpload) return json(403, { error: "origin-not-allowed" });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (request.method === "POST" && url.pathname === "/internal/upload-authorizations") {
    const authorizedStore = await authorizeStoreRequest(request, env);
    return authorizedStore === null ? json(503, { error: "upload-authorization-unavailable" }) : new Response(null, { status: 204, headers: CORS });
  }
  const max = Number(env.MAX_BLOB_BYTES ?? DEFAULT_MAX_BLOB_BYTES);
  const bindingMatch = url.pathname.match(/^\/(?:bindings|\.well-known\/tinycloud-share\/bindings)\/([^/]+)(?:\.json)?$/);
  if ((request.method === "GET" || request.method === "HEAD") && bindingMatch) {
    const object = await env.REGISTRY.get(key("binding", bindingMatch[1]!)); if (!object) return json(404, { error: "not-found" });
    const headers = { "content-type": "application/json", "cache-control": "public, max-age=300" };
    return request.method === "HEAD" ? new Response(null, { headers: { ...CORS, ...headers } }) : response(await object.arrayBuffer(), headers);
  }
  const blobMatch = url.pathname.match(/^\/(?:blobs|ipfs)\/([^/]+)$/);
  if ((request.method === "GET" || request.method === "HEAD") && blobMatch) {
    const cid = blobMatch[1]!; if (url.pathname.startsWith("/ipfs/") && url.searchParams.get("format") !== "raw") return json(406, { error: "raw-format-required" });
    const object = await env.REGISTRY.get(key("blob", cid)); if (!object) return json(404, { error: "not-found" });
    const live = await readBlob(object, env, key("blob", cid)); if (!live) return json(410, { error: "expired" });
    const headers = cacheHeaders(live.expiry, cid);
    return request.method === "HEAD" ? new Response(null, { headers: { ...CORS, ...headers } }) : response(await live.object.arrayBuffer(), headers);
  }
  if ((request.method === "POST" || request.method === "PUT") && url.pathname === "/blobs") {
    if (request.headers.get(IF_NONE_MATCH_HEADER) !== IF_NONE_MATCH_CREATE_ONLY) return json(428, { error: "if-none-match-required" });
    const legacyAuthorized = origin !== LINK_PROXY_ORIGIN && await authorized(request, env, "tinycloud.share/upload", "registry/blobs");
    const admitted = origin === LINK_PROXY_ORIGIN ? linkAuthorizationAdmitsBody(request, env, max) : legacyAuthorized;
    if (!admitted) return json(401, { error: "signed-authorization-required" });
    const expiry = retentionExpiry(request); if (expiry === null) return json(400, { error: "invalid-retention" });
    let bytes: Uint8Array;
    try { bytes = await readBodyBounded(request, max); } catch { return json(413, { error: "blob-too-large" }); }
    const linkAuthorized = origin === LINK_PROXY_ORIGIN && await linkUploadAuthorized(request, env, bytes);
    if (!legacyAuthorized && !linkAuthorized) return json(401, { error: "signed-authorization-required" });
    const cid = await computeCid(bytes); const objectKey = key("blob", cid); const existing = await env.REGISTRY.get(objectKey);
    if (existing) {
      const prior = new Uint8Array(await existing.arrayBuffer()); if (prior.length !== bytes.length || prior.some((v, i) => v !== bytes[i])) return json(409, { error: "cid-overwrite-mismatch" });
      const priorExpiry = expiryFromObject(existing); const effectiveExpiry = priorExpiry === null ? expiry : Math.min(priorExpiry, expiry);
      if (priorExpiry === null || effectiveExpiry < priorExpiry) await env.REGISTRY.put(objectKey, prior, { httpMetadata: { contentType: RAW_BLOCK_CONTENT_TYPE }, customMetadata: { [DELETE_AFTER_METADATA]: new Date(effectiveExpiry).toISOString() } });
      return json(200, { cid, deleteAfter: new Date(effectiveExpiry).toISOString() });
    }
    await env.REGISTRY.put(objectKey, bytes, { httpMetadata: { contentType: RAW_BLOCK_CONTENT_TYPE }, customMetadata: { [DELETE_AFTER_METADATA]: new Date(expiry).toISOString() } }); return json(201, { cid, deleteAfter: new Date(expiry).toISOString() });
  }
  if ((request.method === "POST" || request.method === "PUT") && url.pathname === "/bindings") {
    const cid = url.searchParams.get("cid"); if (!cid || !(await authorized(request, env, "tinycloud.share/bind", `registry/bindings/${cid}`))) return json(401, { error: "signed-authorization-required" });
    let bytes: Uint8Array;
    try { bytes = await readBodyBounded(request, max); } catch { return json(413, { error: "binding-too-large" }); }
    const bindingKey = key("binding", cid); const existing = await env.REGISTRY.get(bindingKey); if (existing) { const prior = new Uint8Array(await existing.arrayBuffer()); if (prior.length !== bytes.length || prior.some((v, i) => v !== bytes[i])) return json(409, { error: "binding-overwrite-mismatch" }); return json(200, { cid }); }
    await env.REGISTRY.put(bindingKey, bytes, { httpMetadata: { contentType: "application/json" } }); return json(201, { cid });
  }
  return json(404, { error: "not-found" });
}, async scheduled(_event: unknown, env: RegistryEnv): Promise<void> {
  if (!env.REGISTRY.list || !env.REGISTRY.delete) return;
  let cursor: string | undefined;
  do {
    const page = await env.REGISTRY.list({ prefix: "blob/", ...(cursor ? { cursor } : {}), include: ["customMetadata"] });
    const expired = page.objects.filter((object) => {
      const expiry = object.customMetadata?.[DELETE_AFTER_METADATA];
      return !expiry || !Number.isFinite(Date.parse(expiry)) || Date.parse(expiry) <= Date.now();
    }).map((object) => object.key);
    if (expired.length > 0) await env.REGISTRY.delete(expired);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
} };
export default worker;
