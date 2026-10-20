/**
 * What an installed app may be signed for, and what its bridge may touch. Pure:
 * no DOM, no network; the SDK's manifest functions are passed in so the page can
 * load the SDK after a click and tests can use the real one.
 *
 * THE GRANT-CAP RULE. The copy of `manifest.json` in the person's own TinyCloud
 * is theirs to edit (their agent may rewrite it), and it decides what the app is
 * signed for. It can never widen beyond what the CATALOG's manifest for the
 * installed bundle declared. `capGrants` composes both manifests with the SDK's
 * own `composeManifestRequest` (the exact set of ReCap resources the sign-in
 * would ask OpenKey to sign) and requires every (service, space, action, path)
 * of the stored one to be covered by one of the catalog's:
 *
 *   - same service and space, and the action is in the covering grant's actions;
 *   - the path is equal, or the covering grant's path ends in "/" and the path
 *     starts with it, or the covering path is "" (the whole service in that space).
 *
 * Narrowing (fewer actions, a longer path, fewer grants) always passes. A path
 * with a ".." or empty segment, a delegation target, secrets, a space other than
 * `applications`, a service other than kv/sql, a custom folder prefix and a public
 * space are refused or removed before anything is signed, so the sign-in the runner
 * asks for contains nothing the bridge cannot use.
 */
import type { ComposedManifestRequest, Manifest, ResolvedCapabilities, ResourceCapability } from "@tinycloud/sdk-core";

import { REGISTRY_RESOURCES } from "./install-plan.ts";

/** The SDK functions the rule needs. `import("@tinycloud/sdk-core")` satisfies it. */
export interface ManifestSdk {
  validateManifest(input: unknown): Manifest;
  resolveManifest(input: Manifest): ResolvedCapabilities;
  composeManifestRequest(inputs: readonly Manifest[], options?: { includeAccountRegistryPermissions?: boolean }): ComposedManifestRequest;
}

export const APP_SPACE = "applications";
/** A runtime session is never longer than this. */
export const RUNTIME_SESSION_EXPIRY = "1h";
export const RUNTIME_SESSION_MS = 60 * 60 * 1000;

export type GrantRefusal =
  | { reason: "widened"; detail: string }
  | { reason: "unsupported"; detail: string }
  | { reason: "invalid"; detail: string };

/** Equal, a "/"-ending prefix of, or the empty path (the whole service in that space). */
export function pathCovers(grantPath: string, target: string): boolean {
  if (grantPath === "") return true;
  if (grantPath.endsWith("/")) return target.startsWith(grantPath);
  return target === grantPath;
}

function plainPath(path: string): boolean {
  if (path.includes("\0") || path.includes("\\")) return false;
  const segments = path.split("/");
  // A trailing "/" gives a last empty segment; any other empty, "." or ".." segment is refused.
  return segments.every((segment, index) => (segment === "" ? index === segments.length - 1 || path === "" : segment !== "." && segment !== ".."));
}

function coveredBy(resource: ResourceCapability, grants: readonly ResourceCapability[], action: string): boolean {
  return grants.some((grant) => grant.service === resource.service && grant.space === resource.space && grant.actions.includes(action) && pathCovers(grant.path, resource.path));
}

const registryKey = (resource: { service: string; space: string; path: string; actions: readonly string[] }): string => `${resource.service}|${resource.space}|${resource.path}|${[...resource.actions].sort().join(",")}`;
const REGISTRY_KEYS: ReadonlySet<string> = new Set(REGISTRY_RESOURCES.map(registryKey));

/** Resources the SDK adds to every sign-in (the account registry, capabilities/read), which are not the app's own. */
function isImplicit(resource: ResourceCapability): boolean {
  if (REGISTRY_KEYS.has(registryKey(resource))) return true;
  return resource.service === "tinycloud.capabilities" && resource.space === APP_SPACE && resource.path === "" && resource.actions.length === 1 && resource.actions[0] === "tinycloud.capabilities/read";
}

export interface CappedGrants {
  /** What the runner signs in with: the person's copy, with a 1 h expiry and no public space. */
  readonly signing: Manifest;
  /** The SDK's resolution of `signing` (own folder, skipPrefix grants and defaults, in the app's space). */
  readonly resolved: ResolvedCapabilities;
}

/** The runner's sign-in manifest and what it resolves to, or why the stored manifest cannot be used. */
export function capGrants(stored: Manifest, catalog: Manifest, sdk: ManifestSdk): { ok: true; value: CappedGrants } | { ok: false; refusal: GrantRefusal } {
  const refuse = (reason: GrantRefusal["reason"], detail: string): { ok: false; refusal: GrantRefusal } => ({ ok: false, refusal: { reason, detail } });
  try {
    if (stored.app_id !== catalog.app_id) return refuse("invalid", "the manifest names a different app");
    if (stored.did !== undefined) return refuse("unsupported", "the manifest delegates to another party");
    if (stored.secrets !== undefined && Object.keys(stored.secrets).length > 0) return refuse("unsupported", "the manifest asks for secrets");
    if (stored.prefix !== undefined && stored.prefix !== stored.app_id) return refuse("unsupported", "the manifest changes the app's folder");
    if ((stored.space ?? APP_SPACE) !== APP_SPACE) return refuse("unsupported", "the manifest changes the app's space");

    const signing: Manifest = { ...stored, expiry: RUNTIME_SESSION_EXPIRY, includePublicSpace: false };
    const own = sdk.composeManifestRequest([signing], { includeAccountRegistryPermissions: true });
    if (own.delegationTargets.length > 0) return refuse("unsupported", "the manifest delegates to another party");
    const cap = sdk.composeManifestRequest([catalog], { includeAccountRegistryPermissions: true });

    for (const resource of own.resources) {
      if (isImplicit(resource)) continue;
      if (resource.space !== APP_SPACE || (resource.service !== "tinycloud.kv" && resource.service !== "tinycloud.sql")) {
        return refuse("unsupported", `${resource.service} in ${resource.space}`);
      }
      if (!plainPath(resource.path)) return refuse("invalid", `a path this page cannot use: ${resource.path}`);
      for (const action of resource.actions) {
        if (!coveredBy(resource, cap.resources, action)) return refuse("widened", `${action} on ${resource.path === "" ? "everything" : resource.path}`);
      }
    }
    // The implicit entries must be exactly the SDK's own (never something the manifest smuggled under their names).
    const implicitOwn = own.resources.filter(isImplicit).map(registryKey).sort().join("\n");
    const implicitCap = cap.resources.filter(isImplicit).map(registryKey).sort().join("\n");
    if (implicitOwn !== implicitCap) return refuse("widened", "account list permissions differ");
    return { ok: true, value: { signing, resolved: sdk.resolveManifest(signing) } };
  } catch (error) {
    return refuse("invalid", error instanceof Error ? error.message.slice(0, 200) : "the manifest could not be read");
  }
}

export type BridgeService = "tinycloud.kv" | "tinycloud.sql";
export type BridgeAction = "get" | "put" | "list" | "del" | "read" | "write" | "schema";

/** `(service, path, action)` against the runner's resolved manifest. `absolute` calls need a `skipPrefix` grant. */
export type Authorizer = (service: BridgeService, path: string, action: BridgeAction, absolute: boolean) => boolean;

export function makeAuthorizer(signing: Manifest, sdk: Pick<ManifestSdk, "resolveManifest">): Authorizer {
  const all = sdk.resolveManifest(signing).resources.filter((grant) => grant.space === APP_SPACE && (grant.service === "tinycloud.kv" || grant.service === "tinycloud.sql"));
  // A path outside the app's own folder is only reachable through an entry that said `skipPrefix: true`.
  const skipEntries = (signing.permissions ?? []).filter((entry) => entry.skipPrefix === true);
  const skipGrants = skipEntries.length === 0 ? [] : sdk.resolveManifest({ ...signing, defaults: false, permissions: skipEntries }).resources.filter((grant) => grant.space === APP_SPACE && (grant.service === "tinycloud.kv" || grant.service === "tinycloud.sql"));
  return (service, path, action, absolute) => {
    const pool = absolute ? skipGrants : all;
    return pool.some((grant) => grant.service === service && grant.actions.includes(`${service}/${action}`) && pathCovers(grant.path, path));
  };
}
