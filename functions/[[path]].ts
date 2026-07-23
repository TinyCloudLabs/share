const EXACT = new Set([
  "/.well-known/tinycloud-share/config.json", "/health/readiness", "/api/health/readiness",
  "/api/share/auth/openkey/nonce", "/api/share/auth/openkey", "/api/share/auth/login", "/api/share/auth/logout",
  "/api/share/capability", "/api/share/capabilities", "/api/share/sign", "/api/share/bindings",
]);
const PREFIXES = ["/.well-known/tinycloud-share/bindings/", "/registry/", "/share/v1/", "/v1/share-email/"];
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

function routed(path: string): boolean { return EXACT.has(path) || PREFIXES.some((prefix) => path.startsWith(prefix)); }
function origin(value: string | undefined): URL | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  try { const url = new URL(value); if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) return undefined; return url; }
  catch { return undefined; }
}

export const onRequest: PagesFunction<{ SHARE_API_ORIGIN?: string }> = async (context) => {
  const incoming = new URL(context.request.url);
  if (!routed(incoming.pathname)) return context.next();
  if (!METHODS.has(context.request.method)) return new Response(JSON.stringify({ error: { code: "method_not_allowed" } }), { status: 405, headers: { "content-type": "application/json; charset=utf-8", allow: "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", "cache-control": "no-store" } });
  const upstream = origin(context.env.SHARE_API_ORIGIN);
  if (upstream === undefined) return new Response(JSON.stringify({ error: { code: "proxy_misconfigured" } }), { status: 503, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  const target = new URL(incoming.pathname + incoming.search, upstream);
  const headers = new Headers(context.request.headers);
  headers.set("host", upstream.host);
  headers.set("origin", incoming.origin);
  headers.delete("cf-connecting-ip"); headers.delete("x-forwarded-host"); headers.delete("x-forwarded-proto");
  const response = await fetch(new Request(target, { method: context.request.method, headers, body: ["GET", "HEAD"].includes(context.request.method) ? undefined : context.request.body, redirect: "error" }));
  const out = new Response(response.body, response);
  out.headers.delete("server"); out.headers.delete("via");
  return out;
};
