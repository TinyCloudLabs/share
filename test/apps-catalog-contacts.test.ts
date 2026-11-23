import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { summarizeAccess } from "../src/apps/access.ts";
import { catalog } from "../src/apps/catalog.ts";

// The access a person approves for Contacts was reviewed as exactly the list below: key-value get, put and list on these
// paths of the applications space, and nothing else. Both the manifest and the rows the apps page shows from it are
// compared whole, so any widening (a put on a folder, a new path inside the prefix, a new action, a new field on an entry)
// fails here and the wider ask becomes a reviewed change of this list and not a catalog update that slips through.
const REVIEWED_PERMISSIONS: ReadonlyArray<{ readonly path: string; readonly actions: readonly string[] }> = [
  { path: "catalog", actions: ["get", "put"] },
  { path: "catalog/person", actions: ["get", "put"] },
  { path: "catalog/me", actions: ["get", "put"] },
  { path: "catalog/note", actions: ["get", "put"] },
  { path: "catalog/history", actions: ["get", "put"] },
  { path: "person/", actions: ["get", "list", "put"] },
  { path: "me/me", actions: ["get", "put"] },
  { path: "note/", actions: ["get", "list", "put"] },
  { path: "history/", actions: ["get", "list", "put"] },
];
const APP_ID = "xyz.tinycloud.tinyapps.contacts";
const entries = catalog.apps.filter((app) => app.app_id === APP_ID);

describe("Contacts in the apps catalog", () => {
  it("is listed, from the TinyCloud publisher", () => {
    expect(entries.length).toBeGreaterThan(0);
    expect(entries.every((entry) => entry.publisher.name === "TinyCloud")).toBe(true);
  });

  for (const [index, entry] of entries.entries()) {
    const label = `${index === 0 ? "the current version" : `earlier version ${index}`} (${entry.bundle.digest.slice(0, 12)})`;
    const manifest = JSON.parse(readFileSync(join("public", entry.bundle.root, entry.manifest.path), "utf8")) as Record<string, unknown>;

    it(`${label} asks for exactly the reviewed key-value permissions in its own folder of the applications space`, () => {
      expect(manifest["app_id"]).toBe(APP_ID);
      expect(manifest["space"]).toBe("applications");
      expect(manifest["defaults"]).toBe(false);
      expect(manifest["includePublicSpace"]).toBe(false);
      expect(manifest["secrets"]).toBeUndefined();
      expect(manifest["prefix"] === undefined || manifest["prefix"] === APP_ID).toBe(true);
      expect(manifest["keys_app_id"]).toBe("xyz.tinycloud.share");
      expect(manifest["keys"]).toEqual([
        { path: "apps/xyz.tinycloud.share/xyz.tinycloud.tinyapps.contacts/seal-v1", abilities: ["decrypt", "key.create"] },
      ]);
      const permissions = manifest["permissions"] as Array<Record<string, unknown>>;
      // Every entry has these four fields and no others (no space, skipPrefix, did or other service-specific field).
      expect(permissions.map((permission) => Object.keys(permission).sort())).toEqual(REVIEWED_PERMISSIONS.map(() => ["actions", "description", "path", "service"]));
      expect(permissions.map((permission) => ({ service: permission["service"], path: permission["path"], actions: permission["actions"] }))).toEqual(
        REVIEWED_PERMISSIONS.map((permission) => ({ service: "tinycloud.kv", path: permission.path, actions: permission.actions })),
      );
    });

    it(`${label} shows the person exactly the reviewed rows: key-value under its own folder, no delete, no other service`, () => {
      const access = summarizeAccess(manifest);
      const row = (item: { service: string; space: string | null; target: string; path: string; actions: string[] }) => ({ service: item.service, space: item.space, target: item.target, path: item.path, actions: item.actions });
      const own = (path: string, actions: string[]) => ({ service: "Key-value", space: null, target: `${APP_ID}/${path}`, path: `${APP_ID}/${path}`, actions });
      expect(Object.keys(access).sort()).toEqual(["change", "read"]);
      expect(access.read.map(row)).toEqual([
        ...REVIEWED_PERMISSIONS.map((permission) => own(permission.path, permission.actions.filter((action) => action !== "put"))),
        // The one row that is not Contacts' own folder: the automatic list of its own permissions in the applications space.
        { service: "Capabilities", space: null, target: "applications", path: "", actions: ["read"] },
      ]);
      expect(access.change.map(row)).toEqual(REVIEWED_PERMISSIONS.map((permission) => own(permission.path, ["put"])));
    });
  }
});
