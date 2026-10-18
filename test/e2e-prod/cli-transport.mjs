// Preloaded into the `tc` CLI by joined-gate.mjs (`node --import`). The CLI
// keeps every canonical origin it signs and validates (Share, owner Node,
// OpenCredentials, Location Registry); only the transport is remapped to the
// hermetic stack, mirroring the browser's request interception. Every other
// non-loopback destination is refused, so the CLI leg can never reach
// production. The route log carries method/origin/path/status labels only.
import dns from "node:dns";
import { appendFileSync, readFileSync } from "node:fs";

const routes = new Map(Object.entries(JSON.parse(process.env.TC500_CLI_ROUTES ?? "{}")));
const shareConfig = process.env.TC500_CLI_SHARE_CONFIG;
const routeLog = process.env.TC500_CLI_ROUTE_LOG;
const loopback = new Set(["127.0.0.1", "localhost", "[::1]"]);

function record(entry) {
  if (routeLog) appendFileSync(routeLog, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
}

const lookup = dns.lookup;
dns.lookup = function hermeticLookup(hostname, ...rest) {
  if (loopback.has(hostname)) return lookup.call(this, hostname, ...rest);
  record({ refused: "dns" });
  const error = Object.assign(new Error("hermetic CLI transport refused DNS"), { code: "ENOTFOUND" });
  const callback = rest.at(-1);
  if (typeof callback === "function") { process.nextTick(callback, error); return {}; }
  throw error;
};

const fetchImpl = globalThis.fetch;
globalThis.fetch = async function hermeticFetch(input, init) {
  const request = input instanceof Request ? input : undefined;
  const url = new URL(request ? request.url : String(input));
  const method = (init?.method ?? request?.method ?? "GET").toUpperCase();
  if (url.origin === "https://share.tinycloud.xyz" && url.pathname === "/.well-known/tinycloud-share/config.json" && shareConfig) {
    // The candidate build's own public config, unchanged.
    record({ method, origin: url.origin, path: url.pathname, status: 200 });
    return new Response(readFileSync(shareConfig), { status: 200, headers: { "content-type": "application/json" } });
  }
  const target = routes.get(url.origin);
  if (target === undefined) {
    if (loopback.has(url.hostname)) return fetchImpl(input, init);
    record({ refused: "fetch", origin: url.origin });
    throw new TypeError("hermetic CLI transport refused a non-stack origin");
  }
  const rewritten = new URL(`${url.pathname}${url.search}`, target);
  const response = request ? await fetchImpl(new Request(rewritten, request), init) : await fetchImpl(rewritten, init);
  record({ method, origin: url.origin, path: url.pathname, status: response.status });
  return response;
};
