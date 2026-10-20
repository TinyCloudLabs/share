import catalogJson from "../../apps/catalog.json";

/** One `apps/catalog.json` entry (`tinycloud.share.apps-catalog/v1`). scripts/apps-catalog.mjs defines and checks the contract. */
export interface CatalogEntry {
  app_id: string;
  name: string;
  description: string;
  publisher: { name: string; did?: string };
  /** `tag` is null when the entry pins a bare commit. */
  source: { repo: string; tag: string | null; commit: string };
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
