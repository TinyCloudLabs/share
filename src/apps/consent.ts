/**
 * The plain statements the pre-consent sheet makes about an app, derived from
 * the SAME `summarizeAccess` result the sheet's lists are drawn from (and so
 * from what the SDK would sign for the app when it is opened). Pure.
 *
 * Every grant is classified by WHERE it reaches, from its resolved path:
 *  - `own`: under `<app_id>/` in the applications space (the expected place);
 *  - `whole`: an empty path, the whole space (every app's data in it);
 *  - `other-app`: under another app's folder;
 *  - `root`: a key or database in the applications space that is under no
 *    app's folder (`skipPrefix` with a bare name);
 *  - `other-space`: any space other than applications.
 * `statementFor` is total over (service, reach): a change or a read that is
 * not an ordinary use of the app's own folder always gets a sentence, so an
 * app cannot ask for a reach the sheet does not state. Own-folder key-value
 * access gets none because the lists below already say it and it is what every
 * app has.
 */
import { type AccessItem, type AccessSummary, summarizeAccess } from "./access.ts";
import type { CatalogEntry } from "./catalog.ts";
import { possessive } from "./possessive.ts";

export const SQL_CHANGE_NOTICE = "Can change or delete its own tables.";

export interface Consent {
  /** What the app will be able to do once it is opened (not granted by the install). */
  runtime: AccessSummary;
  /** Sentences the sheet states plainly above the lists, most important first. */
  notices: string[];
}

/** Most characters of manifest text (a path, a database, a secret name) a sentence repeats; longer text ends in "…". */
export const MAX_NOTICE_TEXT_CHARS = 120;

/** `text`, cut to the cap with a truncation mark. */
export function clip(text: string): string {
  const characters = [...text];
  return characters.length <= MAX_NOTICE_TEXT_CHARS ? text : `${characters.slice(0, MAX_NOTICE_TEXT_CHARS - 1).join("")}…`;
}

export type Reach = "own" | "whole" | "other-app" | "root" | "other-space";

/** The first folder of a resolved path (`<owner>/<rest>`), or null when it has none. */
function ownerOf(path: string): string | null {
  const slash = path.indexOf("/");
  return slash > 0 ? path.slice(0, slash) : null;
}

export function reachOf(item: AccessItem, appId: string): Reach {
  if (item.space !== null) return "other-space";
  if (item.path === "") return "whole";
  const owner = ownerOf(item.path);
  if (owner === appId) return "own";
  return owner === null ? "root" : "other-app";
}

/** `<owner>/<db>` is one database; a path ending in "/" or "*" reaches every database of that app. */
const databases = (path: string): string => (/[/*]$/.test(path) ? "all of its databases" : "whole database");

/** One sentence for a grant, or null for an ordinary own-folder key-value grant. */
export function statementFor(source: AccessItem, kind: "read" | "change", appId: string, nameOf: (id: string) => string | undefined): string | null {
  const owner = ownerOf(source.path);
  const listed = owner === null ? undefined : nameOf(owner);
  // Everything a sentence repeats from a manifest or the catalog is cut to the cap, with a mark.
  const item: AccessItem = { ...source, path: clip(source.path), target: clip(source.target) };
  const theirs = listed === undefined ? undefined : possessive(clip(listed));
  // A folder that is no listed app's is described by its path, like a root-level key: the sheet never calls it an app's.
  const found = reachOf(source, appId);
  const reach: Reach = found === "other-app" && listed === undefined ? "root" : found;
  const change = kind === "change";
  const space = item.space ?? "applications";

  switch (item.service) {
    case "Capabilities":
      return null; // the SDK's own read of the space's permission list; the list says so
    case "Encryption":
      // A network id, not a folder. The node checks only the network id (no conditions): decrypt reaches EVERYTHING encrypted to that network, whoever stored it.
      return change ? `This app can create or revoke encryption networks (${item.target}).` : `This app can decrypt anything encrypted to your TinyCloud encryption network (${item.target}), including data it did not store.`;
    case "Delegation":
      return "This app can hand access to your data on to other keys.";
    case "Secret":
      return change ? `This app can change or delete the secret ${item.target}.` : `This app can read the secret ${item.target}.`;
    case "SQL database": {
      if (reach === "own") return change ? SQL_CHANGE_NOTICE : null;
      if (reach === "whole") return change ? "This app can change or delete tables in every SQL database in your applications space, including other apps'." : "This app can read every SQL database in your applications space, including other apps'.";
      if (reach === "other-app") return change ? `This app can change or delete tables in ${theirs} database (${databases(item.path)}).` : `This app can read ${theirs} database (${databases(item.path)}).`;
      if (reach === "root") return change ? `This app can change or delete tables in the database ${item.path}, which is not inside its own folder.` : `This app can read the database ${item.path}, which is not inside its own folder.`;
      if (item.path === "") return change ? `This app can change or delete tables in every SQL database in your ${space} space.` : `This app can read every SQL database in your ${space} space.`;
      return change ? `This app can change or delete tables in the database ${item.path} in your ${space} space.` : `This app can read the database ${item.path} in your ${space} space.`;
    }
    case "Key-value": {
      if (reach === "own") return null;
      if (reach === "whole") return change ? "This app can change or delete any file in your applications space, including other apps' files." : "This app can read everything in your applications space, including other apps' data.";
      if (reach === "other-app") return change ? `This app can change or delete ${theirs} files under ${item.path}.` : `This app can read ${theirs} files under ${item.path}.`;
      if (reach === "root") return change ? `This app can change or delete files outside its own folder: ${item.path} in your applications space.` : `This app can read files outside its own folder: ${item.path} in your applications space.`;
      if (item.path === "") return change ? `This app can change or delete every file in your ${space} space.` : `This app can read every file in your ${space} space.`;
      return change ? `This app can change or delete files under ${item.path} in your ${space} space.` : `This app can read files under ${item.path} in your ${space} space.`;
    }
    default: {
      // DuckDB, encryption, and any service this sheet does not know: say what and where, never nothing.
      if (reach === "own") return change ? `This app can change or delete its own ${item.service} data.` : null;
      const where = reach === "whole" ? `everything in your ${space} space` : reach === "other-space" ? `${item.path === "" ? "everything" : item.path} in your ${space} space` : `${item.path} in your applications space`;
      return change ? `This app can change or delete ${item.service} data: ${where}.` : `This app can read ${item.service} data: ${where}.`;
    }
  }
}

export function consentFor(entry: CatalogEntry, manifest: unknown, catalog: readonly CatalogEntry[]): Consent {
  const runtime = summarizeAccess(manifest);
  const nameOf = (id: string): string | undefined => catalog.find((candidate) => candidate.app_id === id)?.name;
  const notices: string[] = [];
  // Changes first: they are the ones a person most needs to see.
  for (const kind of ["change", "read"] as const) {
    for (const item of runtime[kind]) {
      const statement = statementFor(item, kind, entry.app_id, nameOf);
      if (statement !== null) notices.push(statement);
    }
  }
  return { runtime, notices: [...new Set(notices)] };
}
