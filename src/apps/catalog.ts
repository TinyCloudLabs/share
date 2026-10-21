import catalogJson from "../../apps/catalog.json";

/** One `apps/catalog.json` entry (`tinycloud.share.apps-catalog/v1`). scripts/apps-catalog.mjs defines and checks the contract. */
export interface CatalogEntry {
  app_id: string;
  name: string;
  description: string;
  /** Kill switch: the entry stays listed, but cannot be opened. Lives here, not in the bundle, so the digests do not change. */
  disabled?: true;
  /** Why it is unavailable, in a sentence; shown as text. Present only with `disabled`. */
  disabledReason?: string;
  publisher: { name: string; did?: string };
  /** `tag` is null when the entry pins a bare commit. */
  source: { repo: string; tag: string | null; commit: string };
  /** The kit's own release record, when the bundle ships one (informational; the catalog digest is what is verified). */
  release?: { version: string; digest: string };
  manifest: { path: string; sha256: string };
  bundle: { root: string; files: { path: string; sha256: string; size: number }[]; digest: string };
  knowledge: { root: string; digest: string } | null;
}

export interface Catalog {
  schema: "tinycloud.share.apps-catalog/v1";
  apps: CatalogEntry[];
}

/** Compiled into the page: the browser fetches no catalog. */
export const catalog: Catalog = catalogJson as Catalog;

/** "v1.2.0", or "commit 5059c5b" for an entry pinned to a bare commit. */
export function versionLabel(entry: CatalogEntry): string {
  return entry.source.tag ?? `commit ${entry.source.commit.slice(0, 7)}`;
}

/** The longest reason the page shows (it cuts a longer one); the catalog check refuses a longer one. scripts/apps-catalog.mjs has the same number. */
export const MAX_DISABLED_REASON_CHARS = 280;

export type Availability = { available: true } | { available: false; reason: string };

/** Whether an entry may be installed or opened. The /apps page and the runner both ask this, so one flag stops both. */
export function availabilityOf(entry: CatalogEntry): Availability {
  if (entry.disabled !== true) return { available: true };
  const reason = typeof entry.disabledReason === "string" ? entry.disabledReason.trim() : "";
  if (reason === "") return { available: false, reason: "This app is temporarily unavailable." };
  // The CI catalog check refuses a longer reason; the page cuts one anyway (with a mark), so a bad catalog cannot fill the screen.
  const characters = [...reason];
  return { available: false, reason: characters.length <= MAX_DISABLED_REASON_CHARS ? reason : `${characters.slice(0, MAX_DISABLED_REASON_CHARS - 1).join("")}…` };
}

/** Thrown by `assertAvailable` for a disabled entry. */
export class EntryDisabledError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super("catalog-entry-disabled");
    this.name = "EntryDisabledError";
    this.reason = reason;
  }
}

/** The runner's gate (and the installer's): throws `EntryDisabledError` for a disabled entry, before any fetch or sign-in. */
export function assertAvailable(entry: CatalogEntry): void {
  const availability = availabilityOf(entry);
  if (!availability.available) throw new EntryDisabledError(availability.reason);
}
