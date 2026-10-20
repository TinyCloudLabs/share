/**
 * What the /courier session may do, and the check that holds it to that.
 *
 * The page reads the owner's own courier mailbox (the whole prefix, get and
 * list) and writes exactly two things: the person's approval decisions and
 * their standing orders. Nothing else is requested: no `del`, no `metadata`,
 * no other space, no delegation, no wildcard.
 *
 * `COURIER_MANIFEST_SCOPE` is the generic policy `signInWithManifest` applies.
 * It cannot say "put only under two prefixes", so `assertCourierPermissions`
 * states that on the RESOLVED manifest (what the SDK will actually request,
 * defaults expanded and the prefix applied), as an exact allow-list of
 * (service, space, path, actions) tuples.
 */
import { resolveManifest, type Manifest, type ResolvedCapabilities } from "@tinycloud/sdk-core";
import type { ManifestScope } from "../share/manifest-policy.js";

/** Where the CLI keeps the courier profile's data: the agent mailbox space and its key prefix. */
export const COURIER_SPACE = "agents";
export const COURIER_PREFIX = "xyz.tinycloud.courier/";
export const APPROVALS_PREFIX = `${COURIER_PREFIX}me/approvals/`;
export const ORDERS_PREFIX = `${COURIER_PREFIX}me/orders/`;
/** Its own app id: it never overwrites another app's registry record. */
export const COURIER_VIEW_APP_ID = "xyz.tinycloud.courier.view";
export const COURIER_APP_NAME = "TinyCloud Courier";
/** The session lasts one hour, the helper's maximum. */
export const COURIER_SESSION_MS = 60 * 60 * 1000;

export function courierManifest(): Manifest {
  return {
    manifest_version: 1,
    app_id: COURIER_VIEW_APP_ID,
    name: "TinyCloud Courier",
    description: "Read your agent threads and write your approvals and standing orders.",
    space: COURIER_SPACE,
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    permissions: [
      { service: "tinycloud.kv", space: COURIER_SPACE, path: COURIER_PREFIX, actions: ["get", "list"], skipPrefix: true },
      { service: "tinycloud.kv", space: COURIER_SPACE, path: APPROVALS_PREFIX, actions: ["put"], skipPrefix: true },
      { service: "tinycloud.kv", space: COURIER_SPACE, path: ORDERS_PREFIX, actions: ["put"], skipPrefix: true },
    ],
  };
}

/** Input to `signInWithManifest`. The path entry ends in `/`: it is matched on path segments. */
export const COURIER_MANIFEST_SCOPE: ManifestScope = {
  allowedSpaces: [COURIER_SPACE],
  allowedServices: ["kv"],
  allowedActions: ["get", "list", "put"],
  allowedPathPrefixes: [{ space: COURIER_SPACE, prefix: COURIER_PREFIX }],
};

export class CourierManifestError extends Error {
  constructor(detail: string) {
    super(`courier-manifest-rejected: ${detail}`);
    this.name = "CourierManifestError";
  }
}

const bare = (action: string): string => action.slice(action.lastIndexOf("/") + 1);
const shortService = (service: string): string => (service.startsWith("tinycloud.") ? service.slice("tinycloud.".length) : service);

/** The exact (path, action) pairs the session may hold. Anything else, or anything missing, is refused. */
const ALLOWED: Readonly<Record<string, readonly string[]>> = {
  [COURIER_PREFIX]: ["get", "list"],
  [APPROVALS_PREFIX]: ["put"],
  [ORDERS_PREFIX]: ["put"],
};

/**
 * Throws unless the RESOLVED request is exactly: kv get+list on the courier
 * prefix, kv put on `me/approvals/` and kv put on `me/orders/`, all in the
 * `agents` space. A put anywhere else (`me/`, `me/approvals` without the slash,
 * a `..` path), a `del`, `metadata`, a delegation ability, another space or a
 * missing grant all fail. The SDK's own `capabilities` read is tolerated.
 */
export function assertCourierPermissions(manifest: Manifest): void {
  let resolved: ResolvedCapabilities;
  try {
    resolved = resolveManifest(manifest);
  } catch (error) {
    throw new CourierManifestError(error instanceof Error ? error.message : "the manifest did not resolve");
  }
  if (resolved.includePublicSpace) throw new CourierManifestError("public space requested");
  if (resolved.additionalDelegates.length > 0) throw new CourierManifestError("a delegate DID would receive the grant");
  const seen: Record<string, string[]> = {};
  for (const resource of resolved.resources) {
    const service = shortService(resource.service);
    const actions = resource.actions.map(bare);
    if (service === "capabilities") {
      if (actions.some((action) => action !== "read")) throw new CourierManifestError("capabilities beyond read");
      continue;
    }
    const at = `${resource.service} ${resource.space} ${JSON.stringify(resource.path)}`;
    if (service !== "kv") throw new CourierManifestError(`service not allowed: ${at}`);
    if (resource.space !== COURIER_SPACE) throw new CourierManifestError(`space not allowed: ${at}`);
    const allowed = Object.hasOwn(ALLOWED, resource.path) ? ALLOWED[resource.path] : undefined;
    if (allowed === undefined) throw new CourierManifestError(`path not allowed: ${at}`);
    for (const action of actions) {
      if (!allowed.includes(action)) throw new CourierManifestError(`action ${action} not allowed: ${at}`);
    }
    seen[resource.path] = [...(seen[resource.path] ?? []), ...actions];
  }
  for (const [path, actions] of Object.entries(ALLOWED)) {
    const have = seen[path] ?? [];
    for (const action of actions) {
      if (!have.includes(action)) throw new CourierManifestError(`missing ${action} on ${JSON.stringify(path)}`);
    }
  }
}
