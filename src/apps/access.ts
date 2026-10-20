/**
 * What an app's manifest lets it read and change, as plain data for the detail
 * sheet. Pure: no DOM, no network. The text of every item comes from the
 * manifest's own `description`s; the sheet renders it with textContent only.
 *
 * Grants come from two places, mirroring the SDK's manifest resolution:
 *  - the explicit entries: `permissions[]`, and the kit's descriptive
 *    `resources.{kv,sql,duckdb}[]` blocks;
 *  - the default tier. A manifest that does not set `defaults: false` also
 *    gets the standard tier (read/write/delete of the app's whole folder);
 *    "admin" adds SQL schema changes and "all" adds DuckDB.
 */

export interface AccessItem {
  /** The manifest's own description, or null when the app gave none. */
  description: string | null;
  /** Service label, e.g. "Key-value". */
  service: string;
  /** Where it applies: a path, prefix or database name. */
  target: string;
  /** Short action names, e.g. ["get", "list"]. */
  actions: string[];
}

export interface SecretItem {
  name: string;
  description: string | null;
  required: boolean;
}

export interface AccessSummary {
  read: AccessItem[];
  change: AccessItem[];
  secrets: SecretItem[];
}

/** Actions that only look at data. Everything else, including unknown names, counts as a change. */
const READ_ACTIONS: Record<string, true> = { get: true, list: true, read: true, head: true, metadata: true, query: true, select: true };

const SERVICE_LABELS: Record<string, string> = {
  "tinycloud.kv": "Key-value",
  "tinycloud.sql": "SQL database",
  "tinycloud.duckdb": "DuckDB",
};

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
  return skipPrefix || folder === "" ? path : `${folder}${path.replace(/^\/+/, "")}`;
}

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
  const read: AccessItem[] = [
    { description: "Everything the app has stored in its own folder (default grant).", service: serviceLabel("tinycloud.kv"), target, actions: ["get", "list", "metadata"] },
    { description: "Everything in the app's own SQL databases (default grant).", service: serviceLabel("tinycloud.sql"), target, actions: ["read"] },
  ];
  const change: AccessItem[] = [
    { description: "Save, replace and delete anything in its own folder (default grant).", service: serviceLabel("tinycloud.kv"), target, actions: ["put", "del"] },
    { description: tier === "standard" ? "Write to its own SQL databases (default grant)." : "Write to, and change the tables of, its own SQL databases (default grant).", service: serviceLabel("tinycloud.sql"), target, actions: tier === "standard" ? ["write"] : ["write", "schema"] },
  ];
  if (tier === "all") {
    read.push({ description: "Everything in the app's own DuckDB databases (default grant).", service: serviceLabel("tinycloud.duckdb"), target, actions: ["read"] });
    change.push({ description: "Write to its own DuckDB databases (default grant).", service: serviceLabel("tinycloud.duckdb"), target, actions: ["write"] });
  }
  return { read, change };
}

function place(summary: AccessSummary, item: Omit<AccessItem, "actions">, actions: string[]): void {
  const reads = actions.filter((action) => Object.hasOwn(READ_ACTIONS, action));
  const changes = actions.filter((action) => !Object.hasOwn(READ_ACTIONS, action));
  if (reads.length > 0) summary.read.push({ ...item, actions: reads });
  if (changes.length > 0) summary.change.push({ ...item, actions: changes });
}

/** Reads a manifest of unknown shape. Never throws; fields it cannot read are left out. */
export function summarizeAccess(manifest: unknown): AccessSummary {
  const summary: AccessSummary = { read: [], change: [], secrets: [] };
  if (!isObject(manifest)) return summary;

  const defaults = defaultItems(manifest);
  summary.read.push(...defaults.read);
  summary.change.push(...defaults.change);

  const folder = folderFor(manifest);
  for (const entry of list(manifest.permissions)) {
    if (!isObject(entry)) continue;
    const service = text(entry.service);
    const path = typeof entry.path === "string" ? entry.path : null;
    if (service === null || path === null) continue;
    place(summary, { description: text(entry.description), service: serviceLabel(service), target: resolvePath(folder, path, entry.skipPrefix === true) }, actionsOf(entry.actions));
  }

  const resources = isObject(manifest.resources) ? manifest.resources : {};
  for (const [kind, service, targetKey] of [["kv", "tinycloud.kv", "prefix"], ["sql", "tinycloud.sql", "name"], ["duckdb", "tinycloud.duckdb", "name"]] as const) {
    for (const entry of list(resources[kind])) {
      if (!isObject(entry)) continue;
      const target = text(entry[targetKey]) ?? text(entry.name);
      if (target === null) continue;
      place(summary, { description: text(entry.description), service: serviceLabel(service), target: kind === "kv" ? resolvePath(folder, target, false) : target }, actionsOf(entry.capabilities));
    }
  }

  for (const entry of [...list(resources.secrets), ...list(manifest.secrets)]) {
    // The SDK's `secrets` shorthand is a list of names; the kit's resources carry a description.
    if (typeof entry === "string" && entry !== "") summary.secrets.push({ name: entry, description: null, required: false });
    else if (isObject(entry) && text(entry.name) !== null) summary.secrets.push({ name: text(entry.name) ?? "", description: text(entry.description), required: entry.required === true });
  }
  return summary;
}
