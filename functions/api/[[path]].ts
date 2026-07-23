const ALLOWED = new Set([
  "/.well-known/tinycloud-share/config.json",
  "/api/share/auth/openkey/nonce", "/api/share/auth/openkey", "/api/share/auth/login", "/api/share/auth/logout",
  "/api/share/capability", "/api/share/capabilities", "/api/share/sign", "/api/share/bindings",
  "/health/readiness", "/api/health/readiness",
]);
const PREFIXES = ["/.well-known/tinycloud-share/bindings/"];
export const onRequest: PagesFunction<{ SHARE_API_ORIGIN: string }> = async ({ request, env }) => {
  const url = new URL(request.url);
  if (![...ALLOWED].includes(url.pathname) && !PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) return new Response("Not found", { status: 404 });
  const upstream = new URL(env.SHARE_API_ORIGIN);
  if (upstream.protocol !== "https:" || upstream.username || upstream.password || upstream.pathname !== "/") return new Response("Proxy misconfigured", { status: 503 });
  const target = new URL(url.pathname + url.search, upstream);
  const headers = new Headers(request.headers);
  headers.set("host", upstream.host);
  headers.set("origin", "https://share.tinycloud.xyz");
  return fetch(new Request(target, { method: request.method, headers, body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body, redirect: "error" }));
};
