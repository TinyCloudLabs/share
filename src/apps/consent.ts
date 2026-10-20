/**
 * The plain statements the pre-consent sheet makes about an app, derived from
 * the SAME `summarizeAccess` result the sheet's lists are drawn from (and so
 * from what the SDK would sign for the app when it is opened). Pure.
 */
import { type AccessItem, type AccessSummary, summarizeAccess } from "./access.ts";
import type { CatalogEntry } from "./catalog.ts";

export const SAMPLE_NOTICE = "Sample app: use throwaway data only.";
export const SQL_CHANGE_NOTICE = "This app can change or delete its own tables.";

export interface Consent {
  /** What the app will be able to do once it is opened (not granted by the install). */
  runtime: AccessSummary;
  /** Sentences the sheet states plainly above the lists, most important first. */
  notices: string[];
}

/** The first folder of a resolved target (`<app_id>/<path>`), or null when the target has none. */
function ownerOf(target: string): string | null {
  const slash = target.indexOf("/");
  return slash > 0 ? target.slice(0, slash) : null;
}

/** An app id's display name: the catalog's, else the id itself. */
function nameOf(appId: string, catalog: readonly CatalogEntry[]): string {
  return catalog.find((entry) => entry.app_id === appId)?.name ?? appId;
}

const isSql = (item: AccessItem): boolean => item.service === "SQL database";
const isKv = (item: AccessItem): boolean => item.service === "Key-value";
/** A grant that is in the app's default space and under another app's folder. */
const foreignOwner = (item: AccessItem, own: string): string | null => {
  const owner = item.space === null && (isSql(item) || isKv(item)) ? ownerOf(item.target) : null;
  return owner !== null && owner !== own ? owner : null;
};

/** `<owner>/<db>` is one database; a path ending in "/" or "*" reaches every database of that app. */
const wholeScope = (target: string): string => (/[/*]$/.test(target) ? "all of its databases" : "whole database");

export function consentFor(entry: CatalogEntry, manifest: unknown, catalog: readonly CatalogEntry[]): Consent {
  const runtime = summarizeAccess(manifest);
  const notices: string[] = [];
  if (entry.sample === true) notices.push(SAMPLE_NOTICE);

  const ownSqlChange = runtime.change.some((item) => isSql(item) && item.space === null && foreignOwner(item, entry.app_id) === null);
  if (ownSqlChange) notices.push(SQL_CHANGE_NOTICE);
  // Anything else in SQL that changes data, in another place, is said plainly too.
  for (const item of runtime.change.filter(isSql)) {
    const owner = foreignOwner(item, entry.app_id);
    if (owner !== null) notices.push(`This app can change or delete tables in ${nameOf(owner, catalog)}'s database (${wholeScope(item.target)}).`);
    else if (item.space !== null) notices.push(`This app can change or delete tables in the database ${item.target} in your ${item.space} space.`);
  }

  for (const item of runtime.read) {
    const owner = foreignOwner(item, entry.app_id);
    if (owner === null) continue;
    notices.push(isSql(item)
      ? `This app can read ${nameOf(owner, catalog)}'s database (${wholeScope(item.target)}).`
      : `This app can read ${nameOf(owner, catalog)}'s files under ${item.target}.`);
  }
  for (const item of runtime.change.filter(isKv)) {
    const owner = foreignOwner(item, entry.app_id);
    if (owner !== null) notices.push(`This app can change or delete ${nameOf(owner, catalog)}'s files under ${item.target}.`);
  }
  return { runtime, notices: [...new Set(notices)] };
}
