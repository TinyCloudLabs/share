import { computeCid } from "@tinycloud/share-envelope";
import { DEFAULT_MAX_BLOB_BYTES, DELETE_AFTER_HEADER, IF_NONE_MATCH_HEADER, IF_NONE_MATCH_CREATE_ONLY, RAW_BLOCK_CONTENT_TYPE } from "./client.js";

interface R2ObjectLike { arrayBuffer(): Promise<ArrayBuffer> }
interface R2Bucket { get(key: string): Promise<R2ObjectLike | null>; put(key: string, value: ArrayBuffer | Uint8Array, options?: unknown): Promise<void> }
export interface RegistryEnv { REGISTRY: R2Bucket; REGISTRY_AUTH_PUBLIC_KEY?: string; MAX_BLOB_BYTES?: string }
const CORS = { "access-control-allow-origin": "https://share.tinycloud.xyz", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type,accept,if-none-match,x-delete-after,x-tinycloud-authorization", "access-control-max-age": "86400", vary: "Origin" };
const json = (status: number, body: unknown, extra: HeadersInit = {}) => new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json", ...extra } });
const key = (kind: string, id: string) => `${kind}/${id}`;
function authBytes(value: string): Uint8Array { const s = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "==="); return Uint8Array.from(s, c => c.charCodeAt(0)); }
async function authorized(request: Request, env: RegistryEnv, operation: string, resource: string): Promise<boolean> {
  const encoded = request.headers.get("x-tinycloud-authorization");
  if (!encoded || !env.REGISTRY_AUTH_PUBLIC_KEY) return false;
  try {
    const outer = JSON.parse(encoded) as { authorization?: Record<string, unknown>; proof?: { alg?: string; signature?: string } };
    const body = outer.authorization; const proof = outer.proof;
    if (!body || proof?.alg !== "EdDSA" || typeof proof.signature !== "string" || body.type !== "TinyCloudShareInviteAuthorization" || body.version !== 1 || body.action !== operation || body.resource !== resource || typeof body.expiresAt !== "string" || Date.parse(body.expiresAt) <= Date.now()) return false;
    const publicKey = await crypto.subtle.importKey("raw", authBytes(env.REGISTRY_AUTH_PUBLIC_KEY).slice().buffer, { name: "Ed25519" }, false, ["verify"]);
    const unsigned = JSON.stringify(Object.keys(body).sort().reduce((o, k) => { o[k] = body[k]; return o; }, {} as Record<string, unknown>));
    return await crypto.subtle.verify("Ed25519", publicKey, authBytes(proof.signature).slice().buffer, new TextEncoder().encode(`xyz.tinycloud.share/registry-authorization/v1\0${unsigned}`));
  } catch { return false; }
}
function response(body: ArrayBuffer | Uint8Array, headers: HeadersInit): Response { return new Response(body as BodyInit, { headers: { ...CORS, ...headers } }); }
export default { async fetch(request: Request, env: RegistryEnv): Promise<Response> {
  const origin = request.headers.get("origin"); if (origin && origin !== "https://share.tinycloud.xyz") return json(403, { error: "origin-not-allowed" });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const url = new URL(request.url); const max = Number(env.MAX_BLOB_BYTES ?? DEFAULT_MAX_BLOB_BYTES);
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
    const headers = { "content-type": RAW_BLOCK_CONTENT_TYPE, "cache-control": "public, max-age=29030400, immutable", etag: `"${cid}"` };
    return request.method === "HEAD" ? new Response(null, { headers: { ...CORS, ...headers } }) : response(await object.arrayBuffer(), headers);
  }
  if ((request.method === "POST" || request.method === "PUT") && url.pathname === "/blobs") {
    if (!(await authorized(request, env, "tinycloud.share/upload", "registry/blobs"))) return json(401, { error: "signed-authorization-required" });
    if (request.headers.get(IF_NONE_MATCH_HEADER) !== IF_NONE_MATCH_CREATE_ONLY) return json(428, { error: "if-none-match-required" });
    const bytes = new Uint8Array(await request.arrayBuffer()); if (bytes.byteLength > max) return json(413, { error: "blob-too-large" });
    const cid = await computeCid(bytes); const existing = await env.REGISTRY.get(key("blob", cid)); if (existing) { const prior = new Uint8Array(await existing.arrayBuffer()); if (prior.length !== bytes.length || prior.some((v, i) => v !== bytes[i])) return json(409, { error: "cid-overwrite-mismatch" }); return json(200, { cid, deleteAfter: request.headers.get(DELETE_AFTER_HEADER) }); }
    await env.REGISTRY.put(key("blob", cid), bytes, { httpMetadata: { contentType: RAW_BLOCK_CONTENT_TYPE } }); return json(201, { cid, deleteAfter: request.headers.get(DELETE_AFTER_HEADER) });
  }
  if ((request.method === "POST" || request.method === "PUT") && url.pathname === "/bindings") {
    const cid = url.searchParams.get("cid"); if (!cid || !(await authorized(request, env, "tinycloud.share/bind", `registry/bindings/${cid}`))) return json(401, { error: "signed-authorization-required" });
    const bytes = new Uint8Array(await request.arrayBuffer()); const bindingKey = key("binding", cid); const existing = await env.REGISTRY.get(bindingKey); if (existing) { const prior = new Uint8Array(await existing.arrayBuffer()); if (prior.length !== bytes.length || prior.some((v, i) => v !== bytes[i])) return json(409, { error: "binding-overwrite-mismatch" }); return json(200, { cid }); }
    await env.REGISTRY.put(bindingKey, bytes, { httpMetadata: { contentType: "application/json" } }); return json(201, { cid });
  }
  return json(404, { error: "not-found" });
} };
