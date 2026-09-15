export const PRODUCTION_CREDENTIALS_ORIGIN = "https://witness.credentials.org";
export const PRODUCTION_LOCATION_REGISTRY_ORIGIN = "https://registry.tinycloud.xyz";

const NODE_ROUTES = new Set(["/policy/v3/challenges", "/policy/v3/delegations", "/delegate", "/invoke"]);

/**
 * Audit only method/origin/path tuples. Query strings, bodies, browser
 * messages, mailbox identity, OTP, and the invitation fragment never enter
 * this boundary and therefore cannot be emitted by its report.
 */
export function auditRecipientTrace(trace, ownerNodeOrigin) {
  const seenAt = (origin, suffix) => trace.some((entry) => entry.origin === origin && entry.path === suffix);
  const nodeRequests = trace.filter((entry) => NODE_ROUTES.has(entry.path));
  const nodeInvokeCount = nodeRequests.filter((entry) => entry.path === "/invoke").length;
  if (trace.some((entry) => /openkey/i.test(entry.origin))) throw new Error("recipient contacted OpenKey before render");
  if (!seenAt(PRODUCTION_CREDENTIALS_ORIGIN, "/v1/acquisitions")) throw new Error("recipient never started acquisition at the pinned OpenCredentials origin");
  if (trace.some((entry) => entry.path === "/v1/acquisitions" && entry.origin !== PRODUCTION_CREDENTIALS_ORIGIN)) throw new Error("recipient sent acquisition to an untrusted origin");
  if (!trace.some((entry) => entry.origin === PRODUCTION_LOCATION_REGISTRY_ORIGIN && entry.path.startsWith("/v1/locations/"))) throw new Error("recipient did not discover the owner Node through the Location Registry");
  if (!seenAt(ownerNodeOrigin, "/policy/v3/challenges") || !seenAt(ownerNodeOrigin, "/policy/v3/delegations")) throw new Error("recipient never completed embedded Policy/v3 admission at the discovered owner Node");
  if (!seenAt(ownerNodeOrigin, "/delegate") || nodeInvokeCount < 2) throw new Error("recipient did not import delegation and invoke KV plus decrypt at the discovered owner Node");
  if (nodeRequests.some((entry) => entry.origin !== ownerNodeOrigin)) throw new Error("recipient crossed owner Node identities during policy or storage enforcement");
  if (trace.some((entry) =>
    /api\.share|email\.tinycloud|policy\./.test(entry.origin)
    || entry.path.startsWith("/share/")
    || (entry.origin === PRODUCTION_LOCATION_REGISTRY_ORIGIN && !entry.path.startsWith("/v1/locations/")))) {
    throw new Error("recipient contacted a prohibited Share registry, API, or standalone policy data plane");
  }
  return Object.freeze({
    verifiedOrigins: Object.freeze({
      credentials: PRODUCTION_CREDENTIALS_ORIGIN,
      locationRegistry: PRODUCTION_LOCATION_REGISTRY_ORIGIN,
      ownerNode: ownerNodeOrigin,
    }),
    verifiedRoutes: Object.freeze(["/v1/locations/:subject", "/v1/acquisitions", "/policy/v3/challenges", "/policy/v3/delegations", "/delegate", "/invoke"]),
    nodeInvokeCount,
  });
}
