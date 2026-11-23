import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { summarizeAccess } from "../src/apps/access.ts";
import { catalog } from "../src/apps/catalog.ts";

// The access a person approves for Contacts was reviewed as: key-value get, list and put under the app's own folder
// in the applications space, and nothing else. A later pin of a different Contacts release that asks for more fails here,
// so the wider ask is a reviewed decision and not a catalog update that slips through.
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

    it(`${label} asks only for key-value get, list and put in its own folder of the applications space`, () => {
      expect(manifest["app_id"]).toBe(APP_ID);
      expect(manifest["space"]).toBe("applications");
      expect(manifest["defaults"]).toBe(false);
      expect(manifest["includePublicSpace"]).toBe(false);
      expect(manifest["secrets"]).toBeUndefined();
      expect(manifest["prefix"] === undefined || manifest["prefix"] === APP_ID).toBe(true);
      const permissions = manifest["permissions"] as Array<Record<string, unknown>>;
      expect(permissions.length).toBeGreaterThan(0);
      for (const permission of permissions) {
        expect(permission["service"], JSON.stringify(permission)).toBe("tinycloud.kv");
        expect(permission["space"] === undefined || permission["space"] === "applications", JSON.stringify(permission)).toBe(true);
        expect(permission["skipPrefix"], JSON.stringify(permission)).toBeUndefined();
        expect(permission["did"], JSON.stringify(permission)).toBeUndefined();
        for (const action of permission["actions"] as string[]) expect(["get", "list", "put"], `${String(permission["path"])} ${action}`).toContain(action);
        // A relative path, never the whole folder as an empty path and never one that climbs out of it.
        const path = String(permission["path"]);
        expect(path.length).toBeGreaterThan(0);
        expect(path.startsWith("/") || path.split("/").includes("..")).toBe(false);
      }
    });

    it(`${label} shows the person nothing outside its folder, no delete and no other service`, () => {
      const access = summarizeAccess(manifest);
      const own = access.read.concat(access.change).filter((item) => item.service !== "Capabilities");
      expect(own.length).toBeGreaterThan(0);
      for (const item of own) {
        expect(item.service).toBe("Key-value");
        expect(item.space).toBeNull();
        expect(item.target.startsWith(`${APP_ID}/`), item.target).toBe(true);
      }
      expect(access.change.every((item) => item.service === "Key-value")).toBe(true);
    });
  }
});
