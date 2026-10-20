/**
 * What a manifest may ask for before `signInWithManifest` lets it near OpenKey.
 *
 * The sign-in helper is reusable: Share's library, the viewer's "Save a copy"
 * and (next) an app-install flow all pass it a manifest. A manifest is the
 * list of things the person is asked to approve in one signature, so a
 * manifest that is too broad is a broad grant on the person's account. The SDK
 * accepts a manifest that asks for `*` on every service, or for delegation
 * rights over the account's `default` space, and with `defaults` left unset it
 * adds a standard grant over the whole space by itself. So the helper checks
 * the RESOLVED request (what the SDK would actually sign: defaults expanded,
 * prefix applied) against a scope the caller states, and refuses anything
 * outside it before any OpenKey window opens.
 *
 * This checks the manifest only. The SDK adds its own account-registry
 * permissions to every sign-in on top of it (see `signInWithManifest`).
 */
import { resolveManifest, type Manifest, type ResourceCapability } from "@tinycloud/sdk-core";

/** The delegation namespace, however it is cased. */
const DELEGATION = /^(?:tinycloud\.)?delegation$/i;

export type ManifestRejection =
  | "invalid-manifest"
  | "public-space"
  | "delegate-target"
  | "wildcard"
  | "delegation-ability"
  | "service-not-allowed"
  | "action-not-allowed"
  | "space-not-allowed"
  | "path-not-allowed";

/** Thrown, with nothing signed and no OpenKey window opened, for a manifest outside its scope. */
export class ManifestRejectedError extends Error {
  readonly code: ManifestRejection;
  constructor(code: ManifestRejection, detail: string) {
    super(`manifest-rejected:${code}: ${detail}`);
    this.name = "ManifestRejectedError";
    this.code = code;
  }
}

/**
 * A path a permission may sit under, in any space or only in `space`. `{address}`
 * stands for the signed-in account, lower-cased. A prefix is matched on path
 * SEGMENTS: `v1` and `v1/` both accept `v1`, `v1/` and `v1/x`, never `v10/`. To
 * name exactly one key (an encryption network), give its whole path: it then
 * matches only that path.
 */
export type ScopedPrefix = string | { readonly space: string; readonly prefix: string };

/** What one caller says its manifest may ask for. Everything not listed is refused. */
export interface ManifestScope {
  /** Spaces the manifest may name. Omitted: only the manifest's own `space`. A space-wide `tinycloud.capabilities` read is allowed only in these too. */
  readonly allowedSpaces?: readonly string[];
  /** Services (`tinycloud.kv`, or `kv`). Omitted: kv, sql and vault. `capabilities` (read) is allowed in `allowedSpaces` without being named; `delegation` only if named here AND by a qualified entry in `allowedActions`. */
  readonly allowedServices?: readonly string[];
  /**
   * Action names. A bare name (`get`) applies to every service except `delegation` and `capabilities`; a qualified
   * name (`tinycloud.kv/put`, `tinycloud.delegation/list`) applies to that service only. Omitted: get, put, list,
   * metadata, head, read, write. `del`, `schema`, `admin`, `export` and the like must be named here.
   */
  readonly allowedActions?: readonly string[];
  /** Paths the permissions must sit under. Omitted: the manifest's own non-empty `prefix` (default `app_id`). A manifest with an empty prefix must say. */
  readonly allowedPathPrefixes?: readonly ScopedPrefix[];
}

const DEFAULT_SERVICES: readonly string[] = ["kv", "sql", "vault"];
const DEFAULT_ACTIONS: readonly string[] = ["get", "put", "list", "metadata", "head", "read", "write"];
/** The address to check a manifest against before OpenKey has said who is signing in. */
export const MANIFEST_CHECK_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * The permissions the Web SDK adds to EVERY sign-in on top of the manifest, so it can keep a new account's own
 * space registry in sync (`includeAccountRegistryPermissions`). They are not part of the manifest, so the check
 * above never sees them; they are listed here as the one documented exception, and a test compares this list
 * with what the SDK composes, so an SDK that adds more fails the build instead of widening a session unseen.
 */
export const SDK_ACCOUNT_REGISTRY_RESOURCES: readonly { readonly service: string; readonly space: string; readonly path: string; readonly actions: readonly string[] }[] = [
  { service: "tinycloud.kv", space: "account", path: "applications/", actions: ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/list"] },
  { service: "tinycloud.kv", space: "account", path: "spaces/", actions: ["tinycloud.kv/get", "tinycloud.kv/put", "tinycloud.kv/list"] },
  { service: "tinycloud.kv", space: "account", path: "system/bootstrap/complete", actions: ["tinycloud.kv/get", "tinycloud.kv/put"] },
  { service: "tinycloud.delegation", space: "account", path: "", actions: ["tinycloud.delegation/list"] },
  { service: "tinycloud.sql", space: "account", path: "account", actions: ["tinycloud.sql/read", "tinycloud.sql/write", "tinycloud.sql/schema"] },
  { service: "tinycloud.capabilities", space: "account", path: "", actions: ["tinycloud.capabilities/read"] },
];

function shortName(value: string): string {
  return value.startsWith("tinycloud.") ? value.slice("tinycloud.".length) : value;
}

/** `tinycloud.kv/get` is namespace `kv`, name `get`; a bare `get` has no namespace. */
function splitAction(action: string): { readonly namespace: string | undefined; readonly name: string } {
  const slash = action.lastIndexOf("/");
  return slash === -1 ? { namespace: undefined, name: action } : { namespace: shortName(action.slice(0, slash)), name: action.slice(slash + 1) };
}

/** Collapses repeated slashes and drops trailing ones: `v1/`, `v1//` and `v1` are the same segment path. */
function segments(path: string): string {
  return path.replace(/\/{2,}/g, "/").replace(/\/+$/, "");
}

/** True when `path` is `prefix` or lies under it, on segment boundaries. */
function underPrefix(path: string, prefix: string): boolean {
  const p = segments(prefix);
  const candidate = segments(path);
  return candidate !== "" && p !== "" && (candidate === p || candidate.startsWith(`${p}/`));
}

function prefixesFor(scope: ManifestScope, manifest: Manifest, address: string): readonly { readonly space: string | undefined; readonly prefix: string }[] {
  if (scope.allowedPathPrefixes !== undefined) {
    return scope.allowedPathPrefixes.map((entry) => {
      const { space, prefix } = typeof entry === "string" ? { space: undefined, prefix: entry } : entry;
      return { space, prefix: prefix.replaceAll("{address}", address.toLowerCase()) };
    });
  }
  const own = manifest.prefix ?? manifest.app_id;
  return segments(own) === "" ? [] : [{ space: undefined, prefix: own }];
}

function describe(resource: ResourceCapability): string {
  return `${resource.service} ${resource.space} ${JSON.stringify(resource.path)}`;
}

/**
 * Refuses, with a `ManifestRejectedError`, a manifest whose resolved request is
 * outside `scope`. `address` is the signed-in account (for `{address}` in a
 * prefix); a caller that has not connected yet passes `MANIFEST_CHECK_ADDRESS`
 * to check the shape first.
 */
export function assertManifestInScope(manifest: Manifest, scope: ManifestScope, address: string): void {
  let resolved: ReturnType<typeof resolveManifest>;
  try {
    resolved = resolveManifest(manifest);
  } catch (error) {
    throw new ManifestRejectedError("invalid-manifest", error instanceof Error ? error.message : "the manifest did not resolve");
  }
  if (resolved.includePublicSpace) throw new ManifestRejectedError("public-space", "includePublicSpace must be false");
  if (resolved.additionalDelegates.length > 0) throw new ManifestRejectedError("delegate-target", "a manifest with a delegate DID hands its grant to another key");

  const spaces = scope.allowedSpaces ?? [resolved.space];
  const services = (scope.allowedServices ?? DEFAULT_SERVICES).map(shortName);
  const actions = (scope.allowedActions ?? DEFAULT_ACTIONS).map(splitAction);
  const prefixes = prefixesFor(scope, manifest, address);

  for (const resource of resolved.resources) {
    const service = shortName(resource.service);
    const at = describe(resource);
    // Whatever the resource, an ability in the delegation namespace is how a grant is passed on or listed.
    const delegating = DELEGATION.test(service) || resource.actions.some((action) => DELEGATION.test(splitAction(action).namespace ?? ""));
    const delegationNamed = services.includes("delegation") && actions.some((entry) => entry.namespace === "delegation");
    if (delegating && !(service === "delegation" && delegationNamed)) throw new ManifestRejectedError("delegation-ability", `delegation in ${at}`);
    if (resource.service.includes("*") || resource.actions.some((action) => action.includes("*"))) {
      // `*` is a wildcard over services or actions; a `*` only inside a path is a literal key name and is the path rule's business.
      throw new ManifestRejectedError("wildcard", `wildcard in ${at}`);
    }
    // An ability belongs to its own service: `tinycloud.delegation/list` or `tinycloud.vault/put` on a kv resource is not a kv ability.
    for (const action of resource.actions) {
      const { namespace } = splitAction(action);
      if (namespace !== undefined && namespace !== service) throw new ManifestRejectedError("action-not-allowed", `ability ${action} does not belong to ${at}`);
    }
    if (service === "capabilities") {
      // The SDK adds a read of the capability list to every space the manifest names. It is metadata of that space's grants, so it follows the space rule like anything else.
      if (resource.actions.some((action) => splitAction(action).name !== "read")) throw new ManifestRejectedError("action-not-allowed", `capabilities beyond read in ${at}`);
      if (!spaces.includes(resource.space)) throw new ManifestRejectedError("space-not-allowed", `space not allowed: ${at}`);
      if (segments(resource.path) !== "") throw new ManifestRejectedError("path-not-allowed", `a capabilities read names no path: ${at}`);
      continue;
    }
    const qualifiedOnly = service === "delegation";
    if (!services.includes(service)) throw new ManifestRejectedError("service-not-allowed", `service not allowed: ${at}`);
    for (const action of resource.actions) {
      const { name } = splitAction(action);
      if (!actions.some((entry) => entry.name === name && (entry.namespace === service || (entry.namespace === undefined && !qualifiedOnly)))) {
        throw new ManifestRejectedError("action-not-allowed", `action ${action} not allowed in ${at}`);
      }
    }
    // An encryption network is not in a space: the SDK reports the pseudo-space "encryption" for it.
    if (service !== "encryption" && !spaces.includes(resource.space)) throw new ManifestRejectedError("space-not-allowed", `space not allowed: ${at}`);
    // A delegation list names no path (it lists the space's grants); the space rule above is what scopes it.
    const unpathed = service === "delegation" && segments(resource.path) === "";
    if (!unpathed && !prefixes.some((entry) => (entry.space === undefined || entry.space === resource.space) && underPrefix(resource.path, entry.prefix))) {
      throw new ManifestRejectedError("path-not-allowed", `path outside the declared prefixes: ${at}`);
    }
  }
}
