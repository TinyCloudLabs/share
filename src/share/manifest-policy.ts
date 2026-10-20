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

/** A path prefix a permission may sit under: in any space, or only in `space`. `{address}` stands for the signed-in account, lower-cased. */
export type ScopedPrefix = string | { readonly space: string; readonly prefix: string };

/** What one caller says its manifest may ask for. Everything not listed is refused. */
export interface ManifestScope {
  /** Spaces the manifest may name. Omitted: only the manifest's own `space`. */
  readonly allowedSpaces?: readonly string[];
  /** Services (`tinycloud.kv`, or `kv`). Omitted: kv, sql and vault. `tinycloud.capabilities` read is always allowed (the SDK adds it to every space). */
  readonly allowedServices?: readonly string[];
  /** Short action names. Omitted: get, put, list, metadata, head, read, write. `del`, `schema`, `admin`, `export` and the like must be named here. */
  readonly allowedActions?: readonly string[];
  /** Paths the permissions must sit under. Omitted: the manifest's own non-empty `prefix` (default `app_id`). A manifest with an empty prefix must say. */
  readonly allowedPathPrefixes?: readonly ScopedPrefix[];
}

const DEFAULT_SERVICES: readonly string[] = ["kv", "sql", "vault"];
const DEFAULT_ACTIONS: readonly string[] = ["get", "put", "list", "metadata", "head", "read", "write"];
/** Never granted by a default, whatever else is named: delegation rights are how a grant is passed on. */
const DELEGATION_SERVICE = /^(?:tinycloud\.)?delegation$/;
/** The address to check a manifest against before OpenKey has said who is signing in. */
export const MANIFEST_CHECK_ADDRESS = "0x0000000000000000000000000000000000000000";

function shortName(value: string): string {
  return value.startsWith("tinycloud.") ? value.slice("tinycloud.".length) : value;
}

function actionName(action: string): string {
  const slash = action.lastIndexOf("/");
  return slash === -1 ? action : action.slice(slash + 1);
}

function normalizedPath(path: string): string {
  return path.replace(/\/{2,}/g, "/");
}

function prefixesFor(scope: ManifestScope, manifest: Manifest, address: string): readonly { readonly space: string | undefined; readonly prefix: string }[] {
  if (scope.allowedPathPrefixes !== undefined) {
    return scope.allowedPathPrefixes.map((entry) => {
      const { space, prefix } = typeof entry === "string" ? { space: undefined, prefix: entry } : entry;
      return { space, prefix: normalizedPath(prefix.replaceAll("{address}", address.toLowerCase())) };
    });
  }
  const own = manifest.prefix ?? manifest.app_id;
  return own === "" || own === "/" ? [] : [{ space: undefined, prefix: normalizedPath(own.endsWith("/") ? own : `${own}/`) }];
}

function describe(resource: ResourceCapability): string {
  return `${resource.service} ${resource.space} ${JSON.stringify(resource.path)}`;
}

/**
 * Refuses, with a `ManifestRejectedError`, a manifest whose resolved request is
 * outside `scope`. `address` is the signed-in account (for `{address}` in a
 * prefix); a caller that has not connected yet passes the zero address to check
 * the shape first.
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
  const actions = (scope.allowedActions ?? DEFAULT_ACTIONS).map(actionName);
  const prefixes = prefixesFor(scope, manifest, address);

  for (const resource of resolved.resources) {
    const service = shortName(resource.service);
    const at = describe(resource);
    if (DELEGATION_SERVICE.test(resource.service) || resource.actions.some((action) => /(?:^|\/)delegat/i.test(action))) {
      throw new ManifestRejectedError("delegation-ability", `delegation in ${at}`);
    }
    if (resource.service.includes("*") || resource.actions.some((action) => action.includes("*"))) {
      // `*` is a wildcard over services or actions; a `*` only inside a path is a literal key name and is the path rule's business.
      throw new ManifestRejectedError("wildcard", `wildcard in ${at}`);
    }
    // The SDK adds a read of the space's capability list to every space it sees; that is read-only and needs no scope.
    if (service === "capabilities") {
      if (resource.actions.some((action) => actionName(action) !== "read")) throw new ManifestRejectedError("action-not-allowed", `capabilities beyond read in ${at}`);
      continue;
    }
    if (!services.includes(service)) throw new ManifestRejectedError("service-not-allowed", `service not allowed: ${at}`);
    for (const action of resource.actions) {
      if (!actions.includes(actionName(action))) throw new ManifestRejectedError("action-not-allowed", `action ${action} not allowed in ${at}`);
    }
    // An encryption network is not in a space: the SDK reports the pseudo-space "encryption" for it.
    if (service !== "encryption" && !spaces.includes(resource.space)) throw new ManifestRejectedError("space-not-allowed", `space not allowed: ${at}`);
    const path = normalizedPath(resource.path);
    if (path === "" || path === "/" || !prefixes.some((entry) => (entry.space === undefined || entry.space === resource.space) && path.startsWith(entry.prefix))) {
      throw new ManifestRejectedError("path-not-allowed", `path outside the declared prefixes: ${at}`);
    }
  }
}
