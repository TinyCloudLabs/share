import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { createShareHostFromEnv } from "./share-adapter.js";
import { loadTrustBundle, securityHeadersForPath } from "./trust-bundle.js";

const root = fileURLToPath(new URL("../../dist/", import.meta.url));
if (process.env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true") throw new Error("SHARE_TRUST_BUNDLE_ALLOW_TEST is forbidden by the production Share host");
const bundle = loadTrustBundle();
const host = createShareHostFromEnv();
const dynamic = (path: string): boolean => path === "/.well-known/tinycloud-share/config.json" || path === "/api/share/auth/login" || path === "/api/share/auth/logout" || path === "/api/share/capability" || path === "/api/share/capabilities" || path === "/api/share/sign" || path === "/api/share/bindings" || path.startsWith("/.well-known/tinycloud-share/bindings/") || path === "/registry" || path.startsWith("/registry/");
const rewrites = (path: string): string => /^\/s\/[a-z2-7]+$/.test(path) ? "/viewer.html" : path === "/share" ? "/share.html" : path === "/viewer" ? "/viewer.html" : path;
const contentTypes: Record<string, string> = { ".html": "text/html; charset=UTF-8", ".js": "text/javascript; charset=UTF-8", ".css": "text/css; charset=UTF-8", ".json": "application/json; charset=UTF-8", ".svg": "image/svg+xml" };

async function body(request: import("node:http").IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of request) { const bytes = Buffer.from(chunk as Uint8Array); size += bytes.length; if (size > 128 * 1024) throw new Error("request too large"); chunks.push(bytes); }
  return new Uint8Array(Buffer.concat(chunks));
}

createServer((request, response) => {
  void (async () => {
    const path = (request.url ?? "/").split("?")[0] ?? "/";
    for (const [name, value] of Object.entries(securityHeadersForPath(bundle, path))) response.setHeader(name, value);
    if (dynamic(path)) {
      const bytes = await body(request);
      const init: RequestInit & { duplex?: "half" } = { method: request.method ?? "GET", headers: Object.fromEntries(Object.entries(request.headers).filter((entry): entry is [string, string] => typeof entry[1] === "string")), ...(bytes.length === 0 ? {} : { body: bytes.buffer as ArrayBuffer, duplex: "half" }) };
      const result = await host.handler(new Request(`https://${request.headers.host ?? new URL(bundle.public.shareOrigin).host}${request.url ?? path}`, init));
      response.writeHead(result.status, Object.fromEntries(result.headers)); response.end(Buffer.from(await result.arrayBuffer())); return;
    }
    const relative = rewrites(path);
    const safe = normalize(relative).replace(/^\.\.(?:\/|$)/g, "");
    const file = join(root, safe === "/" ? "index.html" : safe.replace(/^\//, ""));
    const bytes = await readFile(file);
    const contentType = contentTypes[extname(file)]; if (contentType !== undefined) response.setHeader("content-type", contentType);
    response.writeHead(200); response.end(bytes);
  })().catch(() => { if (!response.headersSent) response.writeHead(503, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }); response.end(JSON.stringify({ error: { code: "capability_unavailable" } })); });
}).listen(Number(process.env.PORT ?? 8787), process.env.HOST ?? "0.0.0.0", () => console.log("share production host ready"));
