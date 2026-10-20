/**
 * What an app's manifest lets it read and change, as plain data for the detail
 * sheet. Pure: no DOM, no network. Descriptions come from the manifest's own
 * `description`s; the sheet renders them with textContent only.
 *
 * This mirrors what the SDK signs for (sdk-core `resolveManifest`), and only
 * that. Grants come from:
 *  - `permissions[]` (path prefix applied unless `skipPrefix`; `space` per entry);
 *  - `secrets{}` (vault entries in the `secrets` space);
 *  - the default tier: a manifest that does not set `defaults: false` also gets
 *    the standard tier (key-value and SQL read/write of the app's own folder);
 *    "admin" adds SQL schema changes, "all" adds DuckDB;
 *  - an automatic addition: `capabilities/read` in every space used.
 * Kit-style `resources.*` blocks are descriptive and grant nothing, so they are
 * not listed.
 */

export interface AccessItem {
  /** The manifest's own description, or null when none was given (or the SDK adds the grant itself). */
  description: string | null;
  /** Service label, e.g. "Key-value". */
  service: string;
  /** The space it applies in, or null for the app's own default space ("applications"). */
  space: string | null;
  /** Where it applies, for display: a path, prefix, secret name or database name; "everything in ..." for a whole space. */
  target: string;
  /**
   * The path as the SDK resolves it (prefix applied unless `skipPrefix`), for the notices:
   * "" is the whole space; `<folder>/` a folder; no slash a root-level key or database.
   */
  path: string;
  /** Short action names, e.g. ["get", "list"]. */
  actions: string[];
}

export interface AccessSummary {
  read: AccessItem[];
  change: AccessItem[];
}

/** Actions that only look at data. Everything else, including unknown names, counts as a change. */
const READ_ACTIONS: Record<string, true> = { get: true, list: true, read: true, head: true, metadata: true, query: true, select: true, decrypt: true };

const SERVICE_LABELS: Record<string, string> = {
  "tinycloud.kv": "Key-value",
  "tinycloud.sql": "SQL database",
  "tinycloud.duckdb": "DuckDB",
  "tinycloud.vault": "Secret",
  "tinycloud.encryption": "Encryption",
  "tinycloud.capabilities": "Capabilities",
  "tinycloud.delegation": "Delegation",
};

const DEFAULT_SPACE = "applications";
const SECRETS_SPACE = "secrets";
/** The synthetic space the SDK gives every encryption grant: networks belong to the account, not to a space. */
const ENCRYPTION_SPACE = "encryption";
const ENCRYPTION_SERVICE = "tinycloud.encryption";
/** Where the SDK keeps vault data in key-value: `vault/<key>`; a named secret is `vault/secrets/<NAME>` (or `.../scoped/<scope>/<NAME>`). */
const VAULT_ROOT = "vault/";

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);
const text = (value: unknown): string | null => (typeof value === "string" && value.trim() !== "" ? value : null);
const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** "tinycloud.kv/put" and "put" both become "put". */
function shortAction(action: string): string {
  const slash = action.lastIndexOf("/");
  return slash === -1 ? action : action.slice(slash + 1);
}

const actionsOf = (value: unknown): string[] =>
  list(value).filter((action): action is string => typeof action === "string" && action !== "").map(shortAction);

function serviceLabel(service: string): string {
  return Object.hasOwn(SERVICE_LABELS, service) ? (SERVICE_LABELS[service] ?? service) : service;
}

/** The folder an app's paths live in: `prefix` if set ("" disables it), else the app id. */
function folderFor(manifest: Json): string {
  const prefix = typeof manifest.prefix === "string" ? manifest.prefix : (text(manifest.app_id) ?? "");
  return prefix === "" ? "" : `${prefix.replace(/\/+$/, "")}/`;
}

function resolvePath(folder: string, path: string, skipPrefix: boolean): string {
  const resolved = skipPrefix || folder === "" ? path : `${folder}${path.replace(/^\/+/, "")}`;
  // "/" alone is "everything" in a key-value or SQL grant, the same as an empty path.
  return /^\/*$/.test(resolved) ? "" : resolved;
}

const wholeSpace = (space: string | null): string => `everything in the ${space ?? DEFAULT_SPACE} space`;

/** The SDK's reading of `defaults`: only `false` turns it off; "admin" and "all" widen; anything else is standard. */
export function defaultsTier(value: unknown): "none" | "standard" | "admin" | "all" {
  if (value === false) return "none";
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "admin" || normalized === "all") return normalized;
  }
  return "standard";
}

function defaultItems(manifest: Json): { read: AccessItem[]; change: AccessItem[] } {
  const tier = defaultsTier(manifest.defaults);
  if (tier === "none") return { read: [], change: [] };
  const folder = folderFor(manifest);
  const target = folder === "" ? "everything in the app's space" : `${folder}*`;
  const item = (service: string, description: string, actions: string[]): AccessItem => ({ description, service: serviceLabel(service), space: null, target, path: folder, actions });
  const read = [
    item("tinycloud.kv", "Everything the app has stored in its own folder (default grant).", ["get", "list", "metadata"]),
    item("tinycloud.sql", "Everything in the app's own SQL databases (default grant).", ["read"]),
  ];
  const change = [
    item("tinycloud.kv", "Save, replace and delete anything in its own folder (default grant).", ["put", "del"]),
    item("tinycloud.sql", tier === "standard" ? "Write to its own SQL databases (default grant)." : "Write to, and change the tables of, its own SQL databases (default grant).", tier === "standard" ? ["write"] : ["write", "schema"]),
  ];
  if (tier === "all") {
    read.push(item("tinycloud.duckdb", "Everything in the app's own DuckDB databases (default grant).", ["read"]));
    change.push(item("tinycloud.duckdb", "Write to its own DuckDB databases (default grant).", ["write"]));
  }
  return { read, change };
}

/** Vault actions as the SDK normalises them (read/write/delete are aliases). */
function vaultActions(value: unknown): string[] {
  const aliases: Record<string, string> = { read: "get", write: "put", delete: "del" };
  return actionsOf(value).map((action) => (Object.hasOwn(aliases, action) ? (aliases[action] ?? action) : action));
}

/** The SDK reads a secret spec as `true`, an action string, an action array, or {name, scope, actions, description}. */
function secretItem(key: string, spec: unknown): { item: Omit<AccessItem, "actions">; actions: string[] } {
  const fields = isObject(spec) ? spec : {};
  const name = text(fields.name) ?? key;
  const scope = text(fields.scope);
  const rawActions = isObject(spec) ? (spec.actions === undefined ? ["read"] : typeof spec.actions === "string" ? [spec.actions] : spec.actions) : typeof spec === "string" ? [spec] : Array.isArray(spec) ? spec : ["read"];
  return {
    // `path` is where the SDK puts the secret (`vault/secrets/<NAME>`); `target` is the name a person knows it by.
    item: { description: text(fields.description), service: serviceLabel("tinycloud.vault"), space: SECRETS_SPACE, target: scope === null ? name : `${scope}/${name}`, path: scope === null ? `${VAULT_ROOT}secrets/${name.trim()}` : `${VAULT_ROOT}secrets/scoped/${scope}/${name.trim()}` },
    actions: vaultActions(rawActions),
  };
}

function place(summary: AccessSummary, item: Omit<AccessItem, "actions">, actions: string[]): void {
  const reads = actions.filter((action) => Object.hasOwn(READ_ACTIONS, action));
  const changes = actions.filter((action) => !Object.hasOwn(READ_ACTIONS, action));
  if (reads.length > 0) summary.read.push({ ...item, actions: reads });
  if (changes.length > 0) summary.change.push({ ...item, actions: changes });
}

/**
 * Why a manifest cannot be described by this module (and so cannot be installed), or null. These are the shapes the
 * SDK resolves in a way the lists and sentences here do not mirror, and that matter: a `did` hands everything the
 * app is granted to another key; a `prefix` or `space` that is not text is used by the SDK as it is, where this
 * module would read it as "not given"; a blank space (the same, in the manifest or in a permission); an explicit
 * `tinycloud.capabilities` grant (the SDK adds that read per space itself, so a hand-written one is a second row for the
 * same thing). A catalog app has none of them, so they are refused rather than described.
 * scripts/apps-catalog.mjs applies the same three checks to the committed catalog.
 */
export function unsupportedManifest(manifest: unknown): string | null {
  if (!isObject(manifest)) return null;
  if (manifest.did !== undefined) return "it hands its access to another identity (did)";
  if (manifest.prefix !== undefined && typeof manifest.prefix !== "string") return "its prefix is not text";
  if (manifest.space !== undefined && (typeof manifest.space !== "string" || manifest.space.trim() === "")) return "its space is not text";
  for (const entry of list(manifest.permissions)) {
    if (!isObject(entry)) continue;
    // A blank space would be read here as "not given" (the app's own data) where the SDK uses it as written.
    if (entry.space !== undefined && (typeof entry.space !== "string" || entry.space.trim() === "")) return "one of its permissions names a space that is not text";
    // The SDK adds the read of each space's permission list itself; asking for it by hand adds nothing the page could describe.
    if (entry.service === "tinycloud.capabilities" || entry.service === "capabilities") return "it asks for the permission-list read itself (the SDK adds that automatically)";
  }
  return null;
}

/** Reads a manifest of unknown shape. Never throws; fields it cannot read are left out. */
export function summarizeAccess(manifest: unknown): AccessSummary {
  const summary: AccessSummary = { read: [], change: [] };
  if (!isObject(manifest)) return summary;

  const defaults = defaultItems(manifest);
  summary.read.push(...defaults.read);
  summary.change.push(...defaults.change);

  const folder = folderFor(manifest);
  const manifestSpace = text(manifest.space) ?? DEFAULT_SPACE;
  for (const entry of list(manifest.permissions)) {
    if (!isObject(entry)) continue;
    const service = text(entry.service);
    const path = typeof entry.path === "string" ? entry.path : null;
    if (service === null || path === null) continue;
    if (service === ENCRYPTION_SERVICE) {
      // The SDK forces the synthetic `encryption` space and no prefix: the path is a network id, not a folder.
      place(summary, { description: text(entry.description), service: serviceLabel(service), space: ENCRYPTION_SPACE, target: path, path }, actionsOf(entry.actions));
      continue;
    }
    const space = text(entry.space) ?? manifestSpace;
    const shownSpace = space === DEFAULT_SPACE ? null : space;
    // `tinycloud.vault` is the SDK's shorthand for key-value under `vault/` (the prefix, if any, comes first): it is key-value to a reader.
    const vault = service === "tinycloud.vault";
    const resolved = vault ? `${VAULT_ROOT}${resolvePath(folder, path, entry.skipPrefix === true)}` : resolvePath(folder, path, entry.skipPrefix === true);
    place(summary, { description: text(entry.description), service: serviceLabel(vault ? "tinycloud.kv" : service), space: shownSpace, target: resolved === "" ? wholeSpace(shownSpace) : resolved, path: resolved }, actionsOf(entry.actions));
  }

  if (isObject(manifest.secrets)) {
    for (const [key, spec] of Object.entries(manifest.secrets)) {
      const { item, actions } = secretItem(key, spec);
      place(summary, item, actions);
    }
  }

  // The one grant the SDK adds itself: capabilities/read in every space the manifest uses.
  // (A public-space companion exists only when a KV grant is handed to another DID, not at sign-in.)
  const all = [...summary.read, ...summary.change];
  for (const space of new Set(all.map((item) => item.space ?? DEFAULT_SPACE))) {
    summary.read.push({ description: "See which permissions it has been given in this space (added automatically).", service: serviceLabel("tinycloud.capabilities"), space: space === DEFAULT_SPACE ? null : space, target: space, path: "", actions: ["read"] });
  }
  return summary;
}
