// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { OWNER_LIBRARY_LIMIT, OWNER_LIBRARY_RESERVED_PREFIXES, ownerLibraryEntries } from "../src/share/composer.js";
import { filesForYouPermissions, historyPermissions, ownerSpacePermissions, SHARE_APPLICATION_PREFIX, SHARE_APPLICATION_SPACE } from "../src/share/openkey-session.js";

/** The library is the sender's own TinyCloud applications-space listing. */
describe("owner library entries", () => {
  it("offers each object without inventing a prefix authority", () => {
    expect(ownerLibraryEntries(["shares/abc/report.md"])).toEqual([
      { path: "shares/abc/report.md", kind: "exact" },
    ]);
  });

  it("offers only exact objects when several keys share directories", () => {
    const entries = ownerLibraryEntries(["shares/abc/report.md", "shares/abc/notes.md", "shares/def/plan.md"]);
    expect(entries).toEqual([
      { path: "shares/abc/report.md", kind: "exact" },
      { path: "shares/abc/notes.md", kind: "exact" },
      { path: "shares/def/plan.md", kind: "exact" },
    ]);
  });

  it("offers a top-level object without inventing a folder for it", () => {
    expect(ownerLibraryEntries(["report.md"])).toEqual([{ path: "report.md", kind: "exact" }]);
  });

  it("does not repeat an exact object", () => {
    const entries = ownerLibraryEntries(["a/one.md", "a/two.md", "a/one.md"]);
    expect(entries.map((entry) => entry.path)).toEqual(["a/one.md", "a/two.md"]);
  });

  it("drops keys the signed resource boundary cannot address rather than repairing them", () => {
    expect(ownerLibraryEntries(["", "/", "a//b", "a/./b", "a/../b", ".", ".."])).toEqual([]);
    expect(ownerLibraryEntries([`bad${String.fromCharCode(0)}key`])).toEqual([]);
    expect(ownerLibraryEntries([`bad${String.fromCharCode(31)}key`])).toEqual([]);
    expect(ownerLibraryEntries([`bad${String.fromCharCode(127)}key`])).toEqual([]);
    expect(ownerLibraryEntries([`bad${String.fromCharCode(92)}key`])).toEqual([]);
  });

  it("normalizes a trailing slash to the object it names", () => {
    expect(ownerLibraryEntries(["a/b/"])).toEqual([
      { path: "a/b", kind: "exact" },
    ]);
  });

  it("bounds the listing it asks the space for", () => {
    expect(OWNER_LIBRARY_LIMIT).toBe(1000);
  });

  it("never offers the app's own vault bookkeeping as something to share", () => {
    // The first run against a real space listing offered exactly these.
    expect(ownerLibraryEntries([
      "vault/sender-history/v1/entries/8214704210425/676f182b014b47cbb0daa3c8bed97dbe",
      "vault/sender-history/v1/entries/8214704218100/7496617d69d54866b4b7dcf8985414d4",
    ])).toEqual([]);
    expect(OWNER_LIBRARY_RESERVED_PREFIXES).toEqual(["vault/"]);
  });

  it("still offers a sender object whose name merely starts with the reserved word", () => {
    expect(ownerLibraryEntries(["vaults/plan.md"]).map((entry) => entry.path)).toEqual(["vaults/plan.md"]);
  });
});

/*
 * The recap encoder and the node's resource matcher, transcribed from the
 * versions this app signs against.
 *
 * `encodeRecapResource` mirrors `SessionConfig::into_message`
 * (tinycloud-sdk-wasm/src/session.rs) composed with `impl Display for
 * ResourceId` (tinycloud-auth/src/resource.rs): an empty path becomes `None`
 * and so emits no path component at all; any other path is appended verbatim
 * after a "/". `extendsGrant` mirrors `ResourceId::extends` in that same
 * resource.rs — a granted path of `None` covers everything, a granted path
 * ending in "/" is a plain byte prefix, and any other granted path matches
 * only on a segment boundary.
 */
function encodeRecapResource(space: string, service: string, path: string): string {
  return path.length === 0 ? `${space}/${service}` : `${space}/${service}/${path}`;
}

function extendsGrant(grant: string, requested: string): boolean {
  const base = grant.split("/").slice(2).join("/");
  const self = requested.split("/").slice(2).join("/");
  if (grant.split("/").length === 2) return true;
  if (!self.startsWith(base)) return false;
  return base.endsWith("/") || self.length === base.length || self[base.length] === "/";
}

describe("owner space permissions", () => {
  it("grants the exact current sender-history Vault prefix", () => {
    expect(historyPermissions()).toEqual([
      { service: "tinycloud.vault", space: SHARE_APPLICATION_SPACE, path: "sender-history/v2/records/", actions: ["put", "get", "list", "del"], skipPrefix: true },
    ]);
  });

  it("limits recipient imports to the versioned Files for you prefix", () => {
    expect(filesForYouPermissions()).toEqual([
      { service: "tinycloud.kv", space: "files-for-you", path: "v1/", actions: ["get", "put", "list"], skipPrefix: true },
    ]);
  });

  it("reads the Share application namespace but writes only under its shares/ child", () => {
    expect(ownerSpacePermissions()).toEqual([
      { service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: SHARE_APPLICATION_PREFIX, actions: ["get", "list", "metadata"], skipPrefix: true },
      { service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: `${SHARE_APPLICATION_PREFIX}shares/`, actions: ["put"], skipPrefix: true },
    ]);
  });

  it("never grants put outside shares/", () => {
    // TC-351. Every write this app makes on this grant is under `shares/`:
    // `shares/<shareId>` for a folder share, `shares/<shareId>/<filename>` for
    // an object, and a pass-through branch already gated on `shares/`. If
    // `put` is ever re-widened back to the whole space this fails.
    for (const entry of ownerSpacePermissions()) {
      if (entry.actions.includes("put")) expect(entry.path).toBe(`${SHARE_APPLICATION_PREFIX}shares/`);
    }
  });

  it("never grants del at all", () => {
    for (const entry of ownerSpacePermissions()) expect(entry.actions).not.toContain("del");
  });

  it("uses a canonical trailing-slash application prefix for reads, never '/'", () => {
    for (const entry of ownerSpacePermissions()) expect(entry.path).not.toBe("/");
    const read = ownerSpacePermissions().find((entry) => entry.actions.includes("get"))!;
    expect(read.path).toBe(SHARE_APPLICATION_PREFIX);
    expect(encodeRecapResource("space", "kv", read.path)).toBe(`space/kv/${SHARE_APPLICATION_PREFIX}`);
    expect(encodeRecapResource("space", "kv", "/")).toBe("space/kv//");
  });

  it("encodes the write grant as a prefix the write targets actually extend", () => {
    const write = ownerSpacePermissions().find((entry) => entry.actions.includes("put"))!;
    const grant = encodeRecapResource("space", "kv", write.path);
    expect(grant).toBe(`space/kv/${SHARE_APPLICATION_PREFIX}shares/`);
    // The three write targets the owner path produces.
    expect(extendsGrant(grant, encodeRecapResource("space", "kv", `${SHARE_APPLICATION_PREFIX}shares/abc`))).toBe(true);
    expect(extendsGrant(grant, encodeRecapResource("space", "kv", `${SHARE_APPLICATION_PREFIX}shares/abc/report.md`))).toBe(true);
    expect(extendsGrant(grant, encodeRecapResource("space", "kv", `${SHARE_APPLICATION_PREFIX}shares/abc/nested/report.md`))).toBe(true);
    // And what it deliberately no longer reaches.
    expect(extendsGrant(grant, encodeRecapResource("space", "kv", "report.md"))).toBe(false);
    expect(extendsGrant(grant, encodeRecapResource("space", "kv", "vault/sender-history/v1/entries/1/2"))).toBe(false);
    // "/" would have encoded to a prefix nothing can extend.
    expect(extendsGrant(encodeRecapResource("space", "kv", "/"), encodeRecapResource("space", "kv", "shares/abc"))).toBe(false);
  });

  it("keeps the read grant covering every key the picker can offer", () => {
    const read = ownerSpacePermissions().find((entry) => entry.actions.includes("get"))!;
    const grant = encodeRecapResource("space", "kv", read.path);
    for (const key of [`${SHARE_APPLICATION_PREFIX}report.md`, `${SHARE_APPLICATION_PREFIX}shares/abc/report.md`, `${SHARE_APPLICATION_PREFIX}a/b/c`]) {
      expect(extendsGrant(grant, encodeRecapResource("space", "kv", key))).toBe(true);
    }
    expect(read.actions).toEqual(["get", "list", "metadata"]);
  });
});
