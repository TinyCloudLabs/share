/**
 * The apps page's links from the runner: `#repair=<app_id>` opens the repair panel, `#uninstall=<app_id>` opens the
 * app's details sheet. Nothing runs from the hash: the person still clicks Repair or Uninstall. Any other hash, a
 * malformed id or an id not in the catalog does nothing and returns false.
 */
import type { MountedApps } from "./view.ts";

export function applyAppsHash(mounted: MountedApps, hash: string): boolean {
  const match = /^#(repair|uninstall)=(.+)$/.exec(hash);
  if (match === null) return false;
  let appId: string;
  try { appId = decodeURIComponent(match[2] ?? ""); } catch { return false; }
  return match[1] === "repair" ? mounted.openRepair(appId) : mounted.openUninstall(appId);
}
