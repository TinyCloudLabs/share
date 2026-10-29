import catalogJson from "../../apps/catalog.json";

/** One app version in `apps/catalog.json`; app versions share an id, with current first. */
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

export type Availability = { available: true } | { available: false; reason: string; temporary: boolean };

/** The file the runner runs. An entry without it has no code to open. */
const CODE_FILE = "app.jsx";

/** The reason for an entry the catalog lists without its code. */
const NO_CODE_REASON = "This app isn't available right now.";

/**
 * Whether an entry may be installed, repaired, or opened. The /apps cards and details, the repair panel, and the runner
 * (`assertAvailable`) all ask this, so one rule decides them all.
 */
export function availabilityOf(entry: CatalogEntry): Availability {
  if (entry.disabled === true) return { available: false, reason: disabledReason(entry), temporary: true };
  if (!entry.bundle.files.some((file) => file.path === CODE_FILE)) return { available: false, reason: NO_CODE_REASON, temporary: false };
  return { available: true };
}

function disabledReason(entry: CatalogEntry): string {
  const reason = typeof entry.disabledReason === "string" ? entry.disabledReason.trim() : "";
  if (reason === "") return "This app is temporarily unavailable.";
  // The CI catalog check refuses a longer reason; the page cuts one anyway (with a mark), so a bad catalog cannot fill the screen.
  const characters = [...reason];
  return characters.length <= MAX_DISABLED_REASON_CHARS ? reason : `${characters.slice(0, MAX_DISABLED_REASON_CHARS - 1).join("")}…`;
}

/** Thrown by `assertAvailable` for an entry that cannot be opened. */
export class EntryDisabledError extends Error {
  readonly reason: string;
  readonly temporary: boolean;
  constructor(reason: string, temporary: boolean) {
    super("catalog-entry-disabled");
    this.name = "EntryDisabledError";
    this.reason = reason;
    this.temporary = temporary;
  }
}

/** The runner's gate: throws `EntryDisabledError` for an entry that cannot be opened (switched off, or without code), before any fetch or sign-in. */
export function assertAvailable(entry: CatalogEntry): void {
  const availability = availabilityOf(entry);
  if (!availability.available) throw new EntryDisabledError(availability.reason, availability.temporary);
}
