/**
 * TLS static server for the TC-500 production-origin browser gate.
 *
 * This deliberately serves only the built Share candidate.  The current
 * SDK-only application has no same-origin API or auth paths: sender auth is
 * OpenKey and every authority/data request goes to its independently named
 * service.  Consequently this is not a proxy for an old Share API (and must
 * never grow a catch-all upstream proxy).
 */
import { createReadStream, readFileSync, statSync } from "node:fs";
import { createServer } from "node:https";
import { extname, join, normalize, resolve } from "node:path";
import { parseProductionHeaders, productionHeadersForPath } from "./production-headers.mjs";

const CONTENT_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".wasm": "application/wasm",
};

const routeFile = (pathname) => {
  if (pathname === "/share") return "/share.html";
  if (pathname === "/viewer" || pathname.startsWith("/s/")) return "/viewer.html";
  if (pathname === "/how-it-works" || pathname === "/how-it-works/") return "/how-it-works.html";
  return pathname === "/" ? "/index.html" : pathname;
};

function candidatePath(root, pathname) {
  const filename = routeFile(pathname);
  const candidate = resolve(root, `.${normalize(filename)}`);
  if (candidate !== root && !candidate.startsWith(`${root}/`)) return undefined;
  return candidate;
}

/** Start an isolated HTTPS server; callers select it only with Chrome's CDP resolver rule. */
export async function startCandidateServer({ root, key, cert, port = 0 }) {
  const staticRoot = resolve(root);
  // Vite copies public/_headers into dist. Serving the candidate with this
  // parsed contract keeps CSP, Trusted Types, sandbox, cache, and referrer
  // behavior identical to the Cloudflare Pages deployment under test.
  const headerRules = parseProductionHeaders(readFileSync(join(staticRoot, "_headers"), "utf8"));
  const server = createServer({ key, cert }, (request, response) => {
    // A browser resolver rule can accidentally send other local requests here.
    // Refuse them rather than becoming a generic TLS endpoint.
    const host = String(request.headers.host ?? "").replace(/:\d+$/, "");
    if (host !== "share.tinycloud.xyz") {
      response.writeHead(421, { "cache-control": "no-store" });
      response.end("misdirected request");
      return;
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { allow: "GET, HEAD", "cache-control": "no-store" });
      response.end();
      return;
    }
    const pathname = new URL(request.url ?? "/", "https://share.tinycloud.xyz").pathname;
    const filename = candidatePath(staticRoot, pathname);
    if (filename === undefined) {
      response.writeHead(400, { "cache-control": "no-store" });
      response.end("invalid path");
      return;
    }
    let stats;
    try { stats = statSync(filename); } catch { stats = undefined; }
    if (stats?.isFile() !== true) {
      response.writeHead(404, { "cache-control": "no-store" });
      response.end("not found");
      return;
    }
    response.writeHead(200, {
      ...productionHeadersForPath(headerRules, pathname),
      "content-type": CONTENT_TYPES[extname(filename)] ?? "application/octet-stream",
    });
    if (request.method === "HEAD") { response.end(); return; }
    createReadStream(filename).pipe(response);
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("candidate server has no TCP address");
  return {
    port: address.port,
    async close() { await new Promise((resolvePromise, reject) => server.close((error) => error === undefined ? resolvePromise() : reject(error))); },
  };
}
