const EXACT = new Set([
  "/.well-known/tinycloud-share/config.json", "/health/readiness", "/api/health/readiness",
  "/api/share/auth/openkey/nonce", "/api/share/auth/openkey", "/api/share/auth/login", "/api/share/auth/logout",
  "/api/share/capability", "/api/share/capabilities", "/api/share/sign", "/api/share/bindings",
]);
const PREFIXES = ["/.well-known/tinycloud-share/bindings/", "/registry/", "/share/v1/", "/v1/share-email/"];
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
type PagesContext<Env> = { request: Request; env: Env; next: () => Promise<Response> };

function routed(path: string): boolean { return EXACT.has(path) || path === "/registry" || PREFIXES.some((prefix) => path.startsWith(prefix)); }
function origin(value: string | undefined): URL | undefined {
  return value === "https://api.share.tinycloud.xyz" ? new URL(value) : undefined;
}

export const onRequest = async (context: PagesContext<{ SHARE_API_ORIGIN?: string }>): Promise<Response> => {
  const incoming = new URL(context.request.url);
  if (!routed(incoming.pathname)) return context.next();
  if (!METHODS.has(context.request.method)) return new Response(JSON.stringify({ error: { code: "method_not_allowed" } }), { status: 405, headers: { "content-type": "application/json; charset=utf-8", allow: "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", "cache-control": "no-store" } });
  const upstream = origin(context.env.SHARE_API_ORIGIN);
  if (upstream === undefined) return new Response(JSON.stringify({ error: { code: "proxy_misconfigured" } }), { status: 503, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  const target = new URL(incoming.pathname + incoming.search, upstream);
  const headers = new Headers(context.request.headers);
  headers.delete("host");
  headers.set("origin", incoming.origin);
  headers.delete("cf-connecting-ip"); headers.delete("x-forwarded-host"); headers.delete("x-forwarded-proto");
  const init: RequestInit & { duplex?: "half" } = { method: context.request.method, headers, redirect: "manual", ...(["GET", "HEAD"].includes(context.request.method) ? {} : { body: context.request.body ?? null, duplex: "half" }) };
  let response: Response; try { response = await fetch(new Request(target, init)); } catch { return new Response(JSON.stringify({ error: { code: "upstream_unavailable" } }), { status: 502, headers: { "content-type": "application/json", "cache-control": "no-store" } }); }
  if (response.status >= 300 && response.status < 400) return new Response(JSON.stringify({ error: { code: "upstream_unavailable" } }), { status: 502, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  const out = new Response(response.body, response);
  out.headers.delete("server"); out.headers.delete("via");
  return out;
};
