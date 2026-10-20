import { composeManifestRequest } from "@tinycloud/sdk-core";
import { describe, expect, it } from "vitest";

import { INSTALL_SPACE, installRecordKey, resourceMismatch, type RequestedResource } from "../src/apps/install-plan.ts";
import { type UninstallPorts, type UninstallProgress, runUninstall } from "../src/apps/uninstall.ts";
import {
  ACCOUNT_SPACE,
  MAX_LIST_PAGES,
  UNINSTALL_IDENTITY_ID,
  UninstallError,
  assertPlainAppId,
  deleteOrder,
  expectedUninstallResources,
  folderPrefixes,
  isOwnedKey,
  registryKey,
  uninstallAppName,
  uninstallManifest,
  uninstallScope,
} from "../src/apps/uninstall-plan.ts";

const app = { app_id: "todo", name: "Todo" };
const RECORD = installRecordKey("todo");

describe("assertPlainAppId", () => {
  it.each(["", "..", "a/b", "a\\b", "%2e%2e", "a..b", " todo", "-todo", "todo/", "../todo"])("refuses %j", (appId) => {
    expect(() => assertPlainAppId(appId)).toThrow(UninstallError);
  });

  it.each(["todo", "a.b-c_1", "Todo2"])("accepts %j", (appId) => {
    expect(() => assertPlainAppId(appId)).not.toThrow();
  });
});

describe("isOwnedKey: the two folders, and nothing that only starts like them", () => {
  it.each([
    "todo/app/index.html",
    "todo/app/js/main.js",
    "todo/knowledge/index.md",
    RECORD,
  ])("owns %s", (key) => {
    expect(isOwnedKey("todo", key)).toBe(true);
  });

  it.each([
    "todo2/app/index.html", // sibling id with the same prefix
    "todo/app", // folder without its trailing slash
    "todo/app/", // empty name
    "todo/appx/a", // same start, different folder
    "todo/knowledge", // folder name alone
    "todo/prefs/theme.json", // app preferences are kept
    "todo/data.sqlite", // SQL databases are kept
    "todo/files/photo.jpg", // the person's files are kept
    "applications/todo", // the registry is removed last, by its own step
    "../todo/app/x", // leading traversal
    "todo/app/../prefs/x", // traversal out of the folder
    "todo/app/./x", // dot segment
    "todo/app/%2e%2e/x", // percent-escaped dot segment
    "todo/app/%2E%2E/x", // upper-case escape
    "todo/app/a%2fb", // escaped slash inside a segment
    "todo/app/a%5cb", // escaped backslash
    "todo/app/a\\b", // literal backslash
    "todo/app//x", // empty segment
    "todo/app/a\u0000b", // control character
  ])("refuses %j", (key) => {
    expect(isOwnedKey("todo", key)).toBe(false);
  });

  it("refuses every key for a non-plain app id", () => {
    expect(() => isOwnedKey("../todo", "../todo/app/x")).toThrow(UninstallError);
  });
});

describe("folder and registry keys", () => {
  it("names exactly the two folders, with trailing slashes", () => {
    expect(folderPrefixes("todo")).toEqual(["todo/app/", "todo/knowledge/"]);
  });

  it("keeps a sibling id's folders apart", () => {
    const sibling = folderPrefixes("todo2");
    for (const prefix of folderPrefixes("todo")) expect(sibling).not.toContain(prefix);
    expect(isOwnedKey("todo", "todo2/app/index.html")).toBe(false);
  });

  it("names the one registry key for the app", () => {
    expect(registryKey("todo")).toBe("applications/todo");
    expect(registryKey("todo2")).not.toBe(registryKey("todo"));
  });

  it("refuses to build keys for an unsafe id", () => {
    expect(() => folderPrefixes("")).toThrow(UninstallError);
    expect(() => registryKey("todo/../x")).toThrow(UninstallError);
  });
});

describe("deleteOrder", () => {
  it("puts the knowledge index first and the install record second, then the rest sorted", () => {
    const order = deleteOrder("todo", ["todo/app/js/main.js", "todo/knowledge/notes.md", RECORD, "todo/app/index.html", "todo/knowledge/index.md"]);
    expect(order).toEqual(["todo/knowledge/index.md", RECORD, "todo/app/index.html", "todo/app/js/main.js", "todo/knowledge/notes.md"]);
  });

  it("drops duplicate listings", () => {
    expect(deleteOrder("todo", ["todo/app/a", "todo/app/a"])).toEqual(["todo/app/a"]);
  });

  it("ignores listed keys outside the folders instead of deleting or refusing them", () => {
    expect(deleteOrder("todo", ["todo/app/a", "todo/prefs/theme.json", "todo2/app/x"])).toEqual(["todo/app/a"]);
  });

  it.each(["todo2/app/x", "todo/app/../../evil", "todo/app/%2e%2e/x", "todo/appx", "todo", "todo/", "todo/prefs/units.json", "todo/knowledge/"])("ignores the listed key %j", (key) => {
    expect(deleteOrder("todo", ["todo/app/a", key])).toEqual(["todo/app/a"]);
  });
});

describe("the uninstall manifest and scope", () => {
  it("signs in as the maintenance identity and sets the app as the prefix", () => {
    const manifest = uninstallManifest(app);
    expect(manifest.app_id).toBe(UNINSTALL_IDENTITY_ID);
    expect(manifest.app_id).not.toBe("todo");
    expect(manifest.prefix).toBe("todo");
  });

  it("asks only for list and delete on the folders, and delete on the one registry key", () => {
    const manifest = uninstallManifest(app);
    const paths = manifest.permissions?.map((permission) => ({ path: permission.path, actions: permission.actions }));
    expect(paths).toEqual([
      { path: "app/", actions: ["list", "del"] },
      { path: "knowledge/", actions: ["list", "del"] },
      { path: "applications/todo", actions: ["del"] },
    ]);
  });

  it("scopes the registry key to exactly applications/<id>", () => {
    expect(uninstallScope("todo").allowedPathPrefixes).toEqual([
      { space: INSTALL_SPACE, prefix: "todo/app/" },
      { space: INSTALL_SPACE, prefix: "todo/knowledge/" },
      { space: ACCOUNT_SPACE, prefix: "applications/todo" },
    ]);
  });

  it("gives a short sign-in label", () => {
    expect(uninstallAppName("Todo")).toBe("TinyCloud Share: uninstall Todo");
    expect(uninstallAppName("   ")).toBe("TinyCloud Share: uninstall Tiny app");
    expect(uninstallAppName("x".repeat(200)).length).toBeLessThanOrEqual(64);
  });
});

describe("ReCap equals the confirm sheet", () => {
  function requestFor(options?: { includeAccountRegistryPermissions?: boolean }): { resources: RequestedResource[]; delegations: unknown[] } {
    const composed = composeManifestRequest([uninstallManifest(app)], options);
    return {
      resources: composed.resources.map((resource): RequestedResource => ({ service: resource.service, space: resource.space, path: resource.path, actions: [...resource.actions] })),
      delegations: [...composed.delegationTargets],
    };
  }

  it("matches resource for resource, with no delegation, when the registry grants are left out", () => {
    const request = requestFor({ includeAccountRegistryPermissions: false });
    expect(request.delegations).toEqual([]);
    expect(resourceMismatch(expectedUninstallResources("todo"), request.resources)).toBeNull();
  });

  it("is not satisfied by the default request, which adds the apps-list grants", () => {
    const request = requestFor();
    expect(resourceMismatch(expectedUninstallResources("todo"), request.resources)).not.toBeNull();
  });
});

type WorldOptions = {
  pageSize?: number;
  alwaysTruncated?: boolean;
  truncatedWithoutCursor?: boolean;
  failDelOn?: string;
  failRegistry?: boolean;
};

/** An in-memory account: one key set holds the folders, the data keys, and the registry entries. `log` records each mutation in order. */
function world(keys: readonly string[], initial: WorldOptions = {}) {
  const store = new Set(keys);
  const log: string[] = [];
  const options: WorldOptions = { ...initial };
  let disposed = 0;
  const ports: UninstallPorts = {
    async openSession() {
      return {
        async list(prefix, cursor) {
          log.push(`list:${prefix}`);
          if (options.truncatedWithoutCursor) return { keys: [], truncated: true };
          if (options.alwaysTruncated) return { keys: [], truncated: true, nextCursor: `${cursor ?? ""}+` };
          const all = [...store].filter((key) => key.startsWith(prefix)).sort();
          const size = options.pageSize ?? all.length;
          const start = cursor === undefined ? 0 : Number(cursor);
          const next = start + size;
          return next < all.length ? { keys: all.slice(start, next), truncated: true, nextCursor: String(next) } : { keys: all.slice(start), truncated: false };
        },
        async del(key) {
          if (key === options.failDelOn) throw new Error("boom");
          log.push(`del:${key}`);
          store.delete(key);
        },
        async removeRegistry(appId) {
          if (options.failRegistry) throw new Error("registry down");
          log.push(`registry:${appId}`);
          store.delete(`applications/${appId}`);
        },
        async dispose() {
          disposed += 1;
        },
      };
    },
  };
  return { ports, store, log, options, disposed: () => disposed };
}

const KEYS = [
  "todo/app/index.html",
  RECORD,
  "todo/app/js/main.js",
  "todo/knowledge/index.md",
  "todo/knowledge/notes.md",
  "todo/prefs/theme.json",
  "todo/data.sqlite",
  "todo/files/photo.jpg",
  "todo2/app/index.html",
  "applications/todo",
  "applications/todo2",
];

const DATA_KEYS = ["todo/prefs/theme.json", "todo/data.sqlite", "todo/files/photo.jpg", "todo2/app/index.html", "applications/todo2"];

describe("runUninstall", () => {
  it("lists the two folders only, deletes code and notes in plan order, keeps data, and removes the registry entry last", async () => {
    const w = world(KEYS);
    const result = await runUninstall(app, w.ports, () => undefined);

    expect(w.log).toEqual([
      "list:todo/app/",
      "list:todo/knowledge/",
      "del:todo/knowledge/index.md",
      `del:${RECORD}`,
      "del:todo/app/index.html",
      "del:todo/app/js/main.js",
      "del:todo/knowledge/notes.md",
      "registry:todo",
    ]);
    expect(result).toEqual({ removed: 5, registry: "removed" });
    expect([...w.store].sort()).toEqual([...DATA_KEYS].sort());
    expect(w.disposed()).toBe(1);
  });

  it("follows the listing across pages", async () => {
    const w = world(KEYS, { pageSize: 2 });
    const result = await runUninstall(app, w.ports, () => undefined);
    expect(result).toEqual({ removed: 5, registry: "removed" });
    expect([...w.store].sort()).toEqual([...DATA_KEYS].sort());
  });

  it("refuses a listing still truncated at the page cap, before any delete", async () => {
    const w = world(KEYS, { alwaysTruncated: true });
    await expect(runUninstall(app, w.ports, () => undefined)).rejects.toMatchObject({ reason: "truncated" });
    expect(w.log.some((entry) => entry.startsWith("del:") || entry.startsWith("registry:"))).toBe(false);
    expect(MAX_LIST_PAGES).toBeGreaterThan(1);
  });

  it("refuses a truncated page that has no cursor to follow", async () => {
    const w = world(KEYS, { truncatedWithoutCursor: true });
    await expect(runUninstall(app, w.ports, () => undefined)).rejects.toMatchObject({ reason: "truncated" });
    expect(w.log.some((entry) => entry.startsWith("del:"))).toBe(false);
  });

  it("never deletes a listed key that escapes the folders, and still removes every owned key in order", async () => {
    const w = world([...KEYS, "todo/app/../prefs/x", "todo/app/%2e%2e/x", "todo2/app/x"]);
    await runUninstall(app, w.ports, () => undefined);
    const dels = w.log.filter((entry) => entry.startsWith("del:")).map((entry) => entry.slice("del:".length));
    expect(dels.every((key) => isOwnedKey("todo", key))).toBe(true);
    expect(dels.slice(0, 2)).toEqual(["todo/knowledge/index.md", RECORD]);
    expect(dels).toEqual(expect.arrayContaining(KEYS.filter((key) => isOwnedKey("todo", key))));
  });

  it.each(["", "..", "%2e%2e", "a/b", "a\\b", "todo/", "../todo"])("refuses the app id %j before any sign-in or delete", async (appId) => {
    const w = world(KEYS);
    await expect(runUninstall({ app_id: appId, name: "x" }, w.ports, () => undefined)).rejects.toMatchObject({ reason: "refused" });
    expect(w.log).toEqual([]);
  });

  it("stops at a failed delete, reports the keys already deleted, and a retry finishes the rest", async () => {
    const w = world(KEYS, { failDelOn: "todo/app/js/main.js" });
    await expect(runUninstall(app, w.ports, () => undefined)).rejects.toMatchObject({
      reason: "write-failed",
      deleted: ["todo/knowledge/index.md", RECORD, "todo/app/index.html"],
    });
    expect(w.log).not.toContain("registry:todo");

    delete w.options.failDelOn;
    const retry = await runUninstall(app, w.ports, () => undefined);
    expect(retry).toEqual({ removed: 2, registry: "removed" });
    expect([...w.store].sort()).toEqual([...DATA_KEYS].sort());
  });

  it("a failed registry removal does not undo the file deletes; the retry removes only the entry", async () => {
    const w = world(KEYS, { failRegistry: true });
    const first = await runUninstall(app, w.ports, () => undefined);
    expect(first).toEqual({ removed: 5, registry: "failed" });
    expect(w.store.has("applications/todo")).toBe(true);
    expect(w.store.has("todo/app/index.html")).toBe(false);

    w.options.failRegistry = false;
    const retry = await runUninstall(app, w.ports, () => undefined);
    expect(retry).toEqual({ removed: 0, registry: "removed" });
    expect(w.log.filter((entry) => entry.startsWith("del:"))).toHaveLength(5);
    expect(w.store.has("applications/todo")).toBe(false);
  });

  it("running again after a finished uninstall is a no-op that still succeeds", async () => {
    const w = world(KEYS);
    await runUninstall(app, w.ports, () => undefined);
    const again = await runUninstall(app, w.ports, () => undefined);
    expect(again).toEqual({ removed: 0, registry: "removed" });
    expect([...w.store].sort()).toEqual([...DATA_KEYS].sort());
  });

  it("a reinstall writes the code back and the next uninstall removes it, keeping the data", async () => {
    const w = world(KEYS);
    await runUninstall(app, w.ports, () => undefined);
    w.store.add("todo/app/index.html");
    w.store.add(RECORD);
    w.store.add("applications/todo");
    const result = await runUninstall(app, w.ports, () => undefined);
    expect(result).toEqual({ removed: 2, registry: "removed" });
    expect(w.store.has("todo/prefs/theme.json")).toBe(true);
    expect(w.store.has("todo/data.sqlite")).toBe(true);
  });

  it("a cancelled sign-in deletes and lists nothing", async () => {
    const log: string[] = [];
    const ports: UninstallPorts = {
      async openSession() {
        log.push("open");
        throw new UninstallError("cancelled");
      },
    };
    await expect(runUninstall(app, ports, () => undefined)).rejects.toMatchObject({ reason: "cancelled" });
    expect(log).toEqual(["open"]);
  });

  it("reports the phases in order", async () => {
    const phases: UninstallProgress[] = [];
    await runUninstall(app, world(KEYS).ports, (progress) => phases.push(progress));
    const seen = phases.map((progress) => progress.phase).filter((phase, index, all) => index === 0 || phase !== all[index - 1]);
    expect(seen).toEqual(["signing-in", "checking", "removing", "registry"]);
  });
});
