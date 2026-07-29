import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createShareHostFromEnv } from "./share-adapter.js";
import { loadTrustBundle, securityHeadersForPath, type ShareTrustBundle } from "./trust-bundle.js";
import { assertSafeUpstreamQuery, NATIVE_SHARE_BODY_LIMIT, REGISTRY_UPLOAD_BODY_LIMIT, sanitizeUpstreamRequest, sanitizeUpstreamResponse, upstreamForPath, upstreamPathFor } from "./upstream.js";

const DEFAULT_STATIC_ROOT = resolve(process.cwd(), "dist");
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const DEFAULT_REQUEST_BODY_LIMIT = 128 * 1024;
class RequestTooLargeError extends Error {}
const contentTypes: Record<string, string> = { ".html": "text/html; charset=UTF-8", ".js": "text/javascript; charset=UTF-8", ".css": "text/css; charset=UTF-8", ".json": "application/json; charset=UTF-8", ".svg": "image/svg+xml" };

type ShareHost = ReturnType<typeof createShareHostFromEnv>;

function dynamic(path: string): boolean {
  return path === "/health/readiness" || path === "/api/health/readiness" || path === "/.well-known/tinycloud-share/config.json" ||
    path === "/api/share/auth/openkey/nonce" || path === "/api/share/auth/openkey" || path === "/api/share/auth/login" ||
    path === "/api/share/auth/logout" || path === "/api/share/capability" || path === "/api/share/capabilities" ||
    path === "/api/share/sender-identity" ||
    path === "/api/share/sign" || path === "/api/share/bindings" || path.startsWith("/.well-known/tinycloud-share/bindings/") || /^\/s\/bafkrei[a-z0-9]+\/raw$/.test(path) ||
    path.startsWith("/api/share/link-only/registry/") ||
    path === "/registry" || path.startsWith("/registry/") || path.startsWith("/share/v1/") || path.startsWith("/share/v2/") || path === "/delegate" || path === "/invoke" || path.startsWith("/v1/share-email/");
}

function rewrite(path: string): string {
  if (/^\/s\/[a-z2-7]+$/.test(path) || path === "/s/inline") return "/viewer.html";
  if (path === "/share") return "/share.html";
  if (path === "/viewer") return "/viewer.html";
  if (path === "/how-it-works" || path === "/how-it-works/") return "/how-it-works.html";
  return path;
}

export function senderOnlyRoute(path: string): boolean {
  return path === "/share/v1/invitations/authorize";
}

function json(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: { code } }), { status, headers: JSON_HEADERS });
}

function requestBodyLimit(path: string): number {
  // Link-only uploads are authenticated and bounded again by the registry
  // proxy. The production listener must allow the framed 100 MiB product
  // limit to reach that gate instead of rejecting it at the generic JSON
  // request limit.
  if (path === "/invoke") return NATIVE_SHARE_BODY_LIMIT;
  if (path.startsWith("/share/v2/")) return 100 * 1024 * 1024;
  if (path === "/api/share/link-only/registry/blobs" || path === "/registry" || path.startsWith("/registry/")) return REGISTRY_UPLOAD_BODY_LIMIT;
  return DEFAULT_REQUEST_BODY_LIMIT;
}

async function bytes(request: Request, maxBytes = DEFAULT_REQUEST_BODY_LIMIT): Promise<Uint8Array> {
  const value = new Uint8Array(await request.arrayBuffer());
  if (value.length > maxBytes) throw new RequestTooLargeError("request too large");
  return value;
}

function withSecurityHeaders(bundle: ShareTrustBundle, path: string, result: Response): Response {
  const headers = new Headers(result.headers);
  for (const [name, value] of Object.entries(securityHeadersForPath(bundle, path))) headers.set(name, value);
  return new Response(result.body, { status: result.status, statusText: result.statusText, headers });
}

function requiresHttps(path: string): boolean {
  return path.startsWith("/api/") || path === "/delegate" || path === "/invoke" || path.startsWith("/registry") || path.startsWith("/share/") || path.startsWith("/v1/");
}

function rejectPlaintext(request: Request, path: string): Response | undefined {
  if (!requiresHttps(path)) return undefined;
  const forwarded = request.headers.get("x-forwarded-proto");
  const protocol = forwarded === null ? new URL(request.url).protocol.replace(":", "") : forwarded.split(",", 1)[0]!.trim().toLowerCase();
  if (protocol === "https") return undefined;
  return json(400, "https_required");
}

export function createProductionHandler(options: { readonly bundle: ShareTrustBundle; readonly host: ShareHost; readonly staticRoot?: string; readonly enforceHttps?: boolean }): (request: Request) => Promise<Response> {
  const staticRoot = options.staticRoot ?? DEFAULT_STATIC_ROOT;
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (options.enforceHttps === true) {
      const plaintext = rejectPlaintext(request, path);
      if (plaintext !== undefined) return withSecurityHeaders(options.bundle, path, plaintext);
    }
    const upstream = upstreamForPath(options.bundle, path);
    if (upstream !== undefined) {
      assertSafeUpstreamQuery(path, url.search);
      if (!options.host.readiness.senderReady && senderOnlyRoute(path)) return withSecurityHeaders(options.bundle, path, json(503, "sender_not_ready"));
      let body: Uint8Array;
      try {
        body = await bytes(request, requestBodyLimit(path));
      } catch (error) {
        if (error instanceof RequestTooLargeError) return withSecurityHeaders(options.bundle, path, json(413, "request_too_large"));
        throw error;
      }
      let result: Response;
      try {
        const headers = sanitizeUpstreamRequest(path, method, request.headers, body.length, options.bundle.public.shareOrigin);
        const upstreamPath = upstream.service === "registry" ? (path.startsWith("/registry") ? path.slice("/registry".length) || "/" : upstreamPathFor(path)) : path.startsWith("/peer/generate/") ? decodeURIComponent(path) : path;
        const target = new URL(`${upstreamPath}${path.startsWith("/s/") ? "" : url.search}`, upstream.origin);
        const init: RequestInit & { duplex?: "half" } = { method, headers, redirect: "error", ...(body.length === 0 ? {} : { body: body.buffer as ArrayBuffer, duplex: "half" }) };
        result = sanitizeUpstreamResponse(path, method, await fetch(target, init));
      } catch (error) {
        result = error instanceof Error && (error.message === "upstream route is not allowed" || error.message === "upstream method is not allowed")
          ? json(404, "not_found")
          : json(502, "upstream_unavailable");
      }
      return withSecurityHeaders(options.bundle, path, result);
    }
    if (dynamic(path)) return withSecurityHeaders(options.bundle, path, await options.host.handler(request));
    if (method !== "GET" && method !== "HEAD") {
      const result = json(405, "method_not_allowed");
      result.headers.set("allow", "GET, HEAD");
      return withSecurityHeaders(options.bundle, path, result);
    }
    const relative = rewrite(path);
    const safe = normalize(relative).replace(/^\.\.(?:\/|$)/g, "");
    const file = join(staticRoot, safe === "/" ? "index.html" : safe.replace(/^\//, ""));
    try {
      const body = await readFile(file);
      const headers = new Headers();
      const contentType = contentTypes[extname(file)];
      if (contentType !== undefined) headers.set("content-type", contentType);
      return withSecurityHeaders(options.bundle, path, new Response(method === "HEAD" ? null : body, { status: 200, headers }));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return withSecurityHeaders(options.bundle, path, json(404, "not_found"));
      throw error;
    }
  };
}

function incomingHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (typeof value === "string") headers.set(name, value);
    else if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
  }
  return headers;
}

async function incomingRequest(request: IncomingMessage): Promise<Request> {
  const chunks: Buffer[] = [];
  let size = 0;
  const path = new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`).pathname;
  const maxBytes = requestBodyLimit(path);
  for await (const chunk of request) {
    const value = Buffer.from(chunk as Uint8Array);
    size += value.length;
    if (size > maxBytes) throw new RequestTooLargeError("request too large");
    chunks.push(value);
  }
  const body = Buffer.concat(chunks);
  const init: RequestInit & { duplex?: "half" } = {
    method: request.method ?? "GET",
    headers: incomingHeaders(request),
    ...(body.length === 0 ? {} : { body: body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer, duplex: "half" }),
  };
  return new Request(new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`), init);
}

async function send(response: ServerResponse, result: Response): Promise<void> {
  for (const [name, value] of result.headers) response.setHeader(name, value);
  const getSetCookie = (result.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") {
    const cookies = getSetCookie.call(result.headers);
    if (cookies.length > 0) response.setHeader("set-cookie", cookies);
  }
  response.writeHead(result.status);
  response.end(Buffer.from(await result.arrayBuffer()));
}

export function startProductionServer(env: NodeJS.ProcessEnv = process.env): ReturnType<typeof createServer> {
  if (env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true") throw new Error("SHARE_TRUST_BUNDLE_ALLOW_TEST is forbidden by the production Share host");
  if (env.SHARE_SENDER_PRIVATE_KEY !== undefined || env.SHARE_SENDER_CAPABILITY_JSON !== undefined || env.SHARE_SENDER_CAPABILITIES_JSON !== undefined) throw new Error("static sender authority variables are forbidden; authenticate through OpenKey");
  const bundle = loadTrustBundle(env);
  const host = createShareHostFromEnv(env);
  const handler = createProductionHandler({ bundle, host, enforceHttps: true });
  const server = createServer((request, response) => {
    void incomingRequest(request).then(handler).then((result) => send(response, result)).catch((error) => {
      console.error(`share-host stage=request-error path=${(request.url ?? "/").split("?")[0] ?? "/"}`);
      if (error instanceof RequestTooLargeError) {
        if (!response.headersSent) response.writeHead(413, JSON_HEADERS);
        response.end(JSON.stringify({ error: { code: "request_too_large" } }));
        return;
      }
      if (!response.headersSent) response.writeHead(503, JSON_HEADERS);
      response.end(JSON.stringify({ error: { code: "capability_unavailable" } }));
    });
  });
  server.listen(Number(env.PORT ?? 8787), env.HOST ?? "0.0.0.0", () => console.log("share production host ready"));
  return server;
}

const entry = process.argv[1] === undefined ? undefined : pathToFileURL(resolve(process.argv[1])).href;
if (entry === import.meta.url) startProductionServer();
