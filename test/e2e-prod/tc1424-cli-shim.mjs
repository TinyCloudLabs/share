// TC-1424 throwaway proof aid, preloaded into the published `tc` CLI with
// `node --import`. It keeps every canonical production origin the CLI signs
// and validates (share/node/witness/registry) while sending the bytes to the
// local native stack. Any other non-loopback destination is refused, so a run
// can never write to production. Logs route labels only (no bodies/queries).
import dns from "node:dns";
import { appendFileSync, readFileSync } from "node:fs";

const map = new Map(Object.entries(JSON.parse(process.env.TC1424_MAP ?? "{}")));
const shareConfig = process.env.TC1424_SHARE_CONFIG;
const log = process.env.TC1424_SHIM_LOG;
const loopback = new Set(["127.0.0.1", "localhost", "[::1]"]);

function record(entry) {
  if (log) appendFileSync(log, `${JSON.stringify(entry)}\n`);
}

const originalLookup = dns.lookup;
dns.lookup = function guardedLookup(hostname, ...rest) {
  if (!loopback.has(hostname)) {
    record({ blocked: "dns", hostname });
    const callback = rest.at(-1);
    const error = Object.assign(new Error(`TC-1424 shim refused DNS for ${hostname}`), { code: "ENOTFOUND" });
    if (typeof callback === "function") { process.nextTick(callback, error); return {}; }
    throw error;
  }
  return originalLookup.call(this, hostname, ...rest);
};

const originalFetch = globalThis.fetch;
globalThis.fetch = async function shimFetch(input, init) {
  const request = input instanceof Request ? input : undefined;
  const url = new URL(request ? request.url : String(input));
  const method = (init?.method ?? request?.method ?? "GET").toUpperCase();
  if (url.origin === "https://share.tinycloud.xyz" && url.pathname === "/.well-known/tinycloud-share/config.json" && shareConfig) {
    record({ method, origin: url.origin, path: url.pathname, status: 200, servedBy: "shim-config" });
    return new Response(readFileSync(shareConfig), { status: 200, headers: { "content-type": "application/json" } });
  }
  const target = map.get(url.origin);
  if (target === undefined) {
    if (loopback.has(url.hostname)) return originalFetch(input, init);
    record({ blocked: "fetch", method, origin: url.origin, path: url.pathname });
    throw new TypeError(`TC-1424 shim refused ${url.origin}`);
  }
  const rewritten = new URL(`${url.pathname}${url.search}`, target);
  const response = request
    ? await originalFetch(new Request(rewritten, request), init)
    : await originalFetch(rewritten, init);
  record({ method, origin: url.origin, path: url.pathname, status: response.status });
  // Debug-only (local fixture data): capture the delivery authorization exchange.
  if (process.env.TC1424_CAPTURE && url.pathname === "/policy/v3/deliveries/authorize") {
    const text = await response.clone().text();
    appendFileSync(process.env.TC1424_CAPTURE, `${JSON.stringify({ request: typeof init?.body === "string" ? JSON.parse(init.body) : null, status: response.status, response: JSON.parse(text) })}\n`, { mode: 0o600 });
  }
  return response;
};
