import { describe, expect, it } from "vitest";
import { OWNER_LIBRARY_LIMIT, OWNER_LIBRARY_RESERVED_PREFIXES, ownerLibraryEntries } from "../src/share/composer.js";
import { ownerSpacePermissions } from "../src/share/openkey-session.js";

/**
 * TC-344. The library picker used to be fed only by `GET
 * /api/share/capabilities`, which returns `[]` for every session in every
 * shape that can legally launch, so it was always empty and every library
 * flow ended at "Choose what to share". It is now derived from the sender's
 * own space listing. These tests pin the two halves of that: what the
 * derivation offers, and the KV authority the session must hold for the
 * owner path to be able to read and write that space at all.
 */
describe("owner library entries", () => {
  it("offers each object and every folder it sits under", () => {
    expect(ownerLibraryEntries(["shares/abc/report.md"])).toEqual([
      { path: "shares/abc/report.md", kind: "exact" },
      { path: "shares/", kind: "prefix" },
      { path: "shares/abc/", kind: "prefix" },
    ]);
  });

  it("offers nested folders, because a folder share copies only direct children", () => {
    const entries = ownerLibraryEntries(["shares/abc/report.md", "shares/abc/notes.md", "shares/def/plan.md"]);
    const prefixes = entries.filter((entry) => entry.kind === "prefix").map((entry) => entry.path);
    // "shares/" has no direct file children at all; only the nested folders do.
    expect(prefixes).toEqual(["shares/", "shares/abc/", "shares/def/"]);
  });

  it("offers a top-level object without inventing a folder for it", () => {
    expect(ownerLibraryEntries(["report.md"])).toEqual([{ path: "report.md", kind: "exact" }]);
  });

  it("does not repeat a folder shared by several objects", () => {
    const entries = ownerLibraryEntries(["a/one.md", "a/two.md", "a/one.md"]);
    expect(entries.map((entry) => entry.path)).toEqual(["a/one.md", "a/", "a/two.md"]);
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
      { path: "a/", kind: "prefix" },
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
    expect(ownerLibraryEntries(["vaults/plan.md"]).map((entry) => entry.path)).toEqual(["vaults/plan.md", "vaults/"]);
  });
});

describe("owner space permissions", () => {
  it("grants the sender read, list and write authority over the sender's own space", () => {
    expect(ownerSpacePermissions()).toEqual([
      { service: "tinycloud.kv", space: "share", path: "", actions: ["get", "put", "list", "metadata"] },
    ]);
  });

  it("uses the empty whole-service path, never '/'", () => {
    // A "/" path is encoded by the recap encoder as `<space>/<service>//`,
    // which the node's byte-prefix resource matching can never extend.
    for (const entry of ownerSpacePermissions()) expect(entry.path).not.toBe("/");
  });
});
