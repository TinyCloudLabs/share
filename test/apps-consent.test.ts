import { readFileSync } from "node:fs";
import { join } from "node:path";
import { composeManifestRequest, resolveManifest } from "@tinycloud/sdk-core";
import { describe, expect, it } from "vitest";

import { summarizeAccess, unsupportedManifest } from "../src/apps/access.ts";
import { type CatalogEntry, catalog as committed } from "../src/apps/catalog.ts";
import { MAX_NOTICE_TEXT_CHARS, SQL_CHANGE_NOTICE, clip, consentFor, reachOf, statementFor } from "../src/apps/consent.ts";

const APP = "t.app";
const OTHER = "other.app";
const entry = (overrides: Partial<CatalogEntry> = {}): CatalogEntry => ({
  app_id: APP, name: "T", description: "d", publisher: { name: "P" },
  source: { repo: "https://example.test/r", tag: null, commit: "c".repeat(40) },
  manifest: { path: "manifest.json", sha256: "a".repeat(64) },
  bundle: { root: `/apps/b/${"b".repeat(64)}/`, files: [], digest: "b".repeat(64) }, knowledge: null, ...overrides,
});
const catalog: CatalogEntry[] = [entry(), entry({ app_id: OTHER, name: "Other App" })];

type Permission = { service: string; path: string; actions: string[]; space?: string; skipPrefix?: boolean };
const manifestOf = (permissions: Permission[], extra: Record<string, unknown> = {}) => ({ app_id: APP, name: "T", defaults: false, includePublicSpace: false, permissions, ...extra });
const noticesOf = (manifest: unknown): string[] => consentFor(entry(), manifest, catalog).notices;

/** Every shape a manifest can give a write or read grant: where it lands, and the sentence the sheet owes for it. */
const SHAPES: { name: string; manifest: unknown; expected: string[] }[] = [
  { name: "key-value write over the whole applications space", manifest: manifestOf([{ service: "tinycloud.kv", path: "", skipPrefix: true, actions: ["put", "del"] }]), expected: ["This app can change or delete any file in your applications space, including other apps' files."] },
  { name: "the same through path '/'", manifest: manifestOf([{ service: "tinycloud.kv", path: "/", skipPrefix: true, actions: ["put"] }]), expected: ["This app can change or delete any file in your applications space, including other apps' files."] },
  { name: "the same through an empty prefix", manifest: manifestOf([{ service: "tinycloud.kv", path: "/", actions: ["put"] }], { prefix: "" }), expected: ["This app can change or delete any file in your applications space, including other apps' files."] },
  { name: "key-value write in another space (everything)", manifest: manifestOf([{ service: "tinycloud.kv", space: "default", path: "", skipPrefix: true, actions: ["put", "del"] }]), expected: ["This app can change or delete every file in your default space."] },
  { name: "key-value write in another space (a folder)", manifest: manifestOf([{ service: "tinycloud.kv", space: "default", path: "notes/", skipPrefix: true, actions: ["put"] }]), expected: ["This app can change or delete files under notes/ in your default space."] },
  { name: "key-value write in another space through the app's prefix", manifest: manifestOf([{ service: "tinycloud.kv", space: "account", path: "prefs/", actions: ["put"] }]), expected: [`This app can change or delete files under ${APP}/prefs/ in your account space.`] },
  { name: "key-value write under another app's folder (skipPrefix)", manifest: manifestOf([{ service: "tinycloud.kv", path: `${OTHER}/photos/`, skipPrefix: true, actions: ["put"] }]), expected: [`This app can change or delete Other App's files under ${OTHER}/photos/.`] },
  { name: "key-value write to a root-level key (skipPrefix, no folder)", manifest: manifestOf([{ service: "tinycloud.kv", path: "settings.json", skipPrefix: true, actions: ["put"] }]), expected: ["This app can change or delete files outside its own folder: settings.json in your applications space."] },
  { name: "key-value write at a root-level path through an empty prefix", manifest: manifestOf([{ service: "tinycloud.kv", path: "data/", actions: ["put"] }], { prefix: "" }), expected: ["This app can change or delete files outside its own folder: data/ in your applications space."] },
  { name: "key-value write under a folder no listed app owns", manifest: manifestOf([{ service: "tinycloud.kv", path: "com.unlisted.app/files/", skipPrefix: true, actions: ["put"] }]), expected: ["This app can change or delete files outside its own folder: com.unlisted.app/files/ in your applications space."] },
  { name: "SQL write on a root database (skipPrefix)", manifest: manifestOf([{ service: "tinycloud.sql", path: "healthlog", skipPrefix: true, actions: ["write"] }]), expected: ["This app can change or delete tables in the database healthlog, which is not inside its own folder."] },
  { name: "SQL write over every database in the applications space", manifest: manifestOf([{ service: "tinycloud.sql", path: "", skipPrefix: true, actions: ["write", "schema"] }]), expected: ["This app can change or delete tables in every SQL database in your applications space, including other apps'."] },
  { name: "SQL write on another app's database", manifest: manifestOf([{ service: "tinycloud.sql", path: `${OTHER}/db`, skipPrefix: true, actions: ["write"] }]), expected: ["This app can change or delete tables in Other App's database (whole database)."] },
  { name: "SQL write on all of another app's databases", manifest: manifestOf([{ service: "tinycloud.sql", path: `${OTHER}/`, skipPrefix: true, actions: ["write"] }]), expected: ["This app can change or delete tables in Other App's database (all of its databases)."] },
  { name: "SQL write in another space", manifest: manifestOf([{ service: "tinycloud.sql", space: "account", path: "ledger", skipPrefix: true, actions: ["write"] }]), expected: ["This app can change or delete tables in the database ledger in your account space."] },
  { name: "SQL write on every database in another space", manifest: manifestOf([{ service: "tinycloud.sql", space: "account", path: "", skipPrefix: true, actions: ["write"] }]), expected: ["This app can change or delete tables in every SQL database in your account space."] },
  { name: "SQL write on its own database", manifest: manifestOf([{ service: "tinycloud.sql", path: "db", actions: ["write"] }]), expected: [SQL_CHANGE_NOTICE] },
  { name: "reads of every file and every database in the applications space", manifest: manifestOf([{ service: "tinycloud.kv", path: "", skipPrefix: true, actions: ["get", "list"] }, { service: "tinycloud.sql", path: "", skipPrefix: true, actions: ["read"] }]), expected: ["This app can read everything in your applications space, including other apps' data.", "This app can read every SQL database in your applications space, including other apps'."] },
  { name: "reads in another space", manifest: manifestOf([{ service: "tinycloud.kv", space: "default", path: "", skipPrefix: true, actions: ["get"] }]), expected: ["This app can read every file in your default space."] },
  { name: "a cross-app read of a whole database", manifest: manifestOf([{ service: "tinycloud.sql", path: `${OTHER}/db`, skipPrefix: true, actions: ["read"] }]), expected: ["This app can read Other App's database (whole database)."] },
  { name: "DuckDB write elsewhere", manifest: manifestOf([{ service: "tinycloud.duckdb", path: "warehouse", skipPrefix: true, actions: ["write"] }]), expected: ["This app can change or delete DuckDB data: warehouse in your applications space."] },
  { name: "a delegation grant", manifest: manifestOf([{ service: "tinycloud.delegation", path: "", skipPrefix: true, actions: ["create"] }]), expected: ["This app can hand access to your data on to other keys."] },
  { name: "a secret write", manifest: { app_id: APP, name: "T", defaults: false, secrets: { API_KEY: ["read", "write"] } }, expected: ["This app can change or delete the secret API_KEY.", "This app can read the secret API_KEY."] },
  { name: "an encryption decrypt grant (a network id, not a folder)", manifest: manifestOf([{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:net1", actions: ["decrypt"] }]), expected: ["This app can decrypt anything encrypted to your TinyCloud encryption network (urn:tinycloud:encryption:net1), including data it did not store."] },
  { name: "encryption network create and revoke", manifest: manifestOf([{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:net1", actions: ["decrypt", "network.create", "tinycloud.encryption/network.revoke"] }]), expected: ["This app can decrypt anything encrypted to your TinyCloud encryption network (urn:tinycloud:encryption:net1), including data it did not store.", "This app can create or revoke encryption networks (urn:tinycloud:encryption:net1)."] },
  { name: "the vault shorthand under the app's prefix", manifest: manifestOf([{ service: "tinycloud.vault", path: "notes/", actions: ["put", "get"] }]), expected: [`This app can change or delete files outside its own folder: vault/${APP}/notes/ in your applications space.`, `This app can read files outside its own folder: vault/${APP}/notes/ in your applications space.`] },
  { name: "the vault shorthand with skipPrefix in another space", manifest: manifestOf([{ service: "tinycloud.vault", space: "default", path: "notes/", skipPrefix: true, actions: ["put"] }]), expected: ["This app can change or delete files under vault/notes/ in your default space."] },
  { name: "scoped secrets", manifest: { app_id: APP, name: "T", defaults: false, secrets: { SESSION: { name: "SESSION_KEY", scope: "chat", actions: "delete" }, TOKEN: true } }, expected: ["This app can change or delete the secret chat/SESSION_KEY.", "This app can read the secret TOKEN."] },
  { name: "the default grants with the app's own folder", manifest: { app_id: APP, name: "T" }, expected: [SQL_CHANGE_NOTICE] },
  { name: "the default grants with no folder at all (prefix '')", manifest: { app_id: APP, name: "T", prefix: "" }, expected: ["This app can change or delete tables in every SQL database in your applications space, including other apps'.", "This app can change or delete any file in your applications space, including other apps' files.", "This app can read everything in your applications space, including other apps' data.", "This app can read every SQL database in your applications space, including other apps'."] },
  { name: "the all-tier defaults add DuckDB", manifest: { app_id: APP, name: "T", defaults: "all" }, expected: [SQL_CHANGE_NOTICE, `This app can change or delete its own DuckDB data.`] },
];

describe("what the sheet says about what an app can do once it is opened", () => {
  it.each(SHAPES.map((shape) => [shape.name, shape]))("%s", (_name, shape) => {
    const notices = noticesOf(shape.manifest);
    expect([...notices].sort()).toEqual([...shape.expected].sort());
  });

  it("an app cannot ask for a reach the sheet does not state: every grant outside its own folder has a sentence, and the lists match what the SDK resolves", () => {
    for (const { name, manifest } of SHAPES) {
      const summary = summarizeAccess(manifest);
      for (const kind of ["read", "change"] as const) {
        for (const item of summary[kind]) {
          const sentence = statementFor(item, kind, APP, (id) => catalog.find((candidate) => candidate.app_id === id)?.name);
          const reach = reachOf(item, APP);
          // Only an ordinary key-value grant on the app's own folder (and the SDK's own permission-list read) goes without one.
          if (sentence === null) expect(item.service === "Capabilities" || (item.service === "Key-value" && reach === "own") || (kind === "read" && reach === "own"), `${name}: ${item.service} ${item.target}`).toBe(true);
        }
      }
      // The mirror, with nothing skipped: what the lists show is what the real resolver resolves, secrets (vault paths in key-value) and encryption included.
      const labels: Record<string, string> = { "Key-value": "tinycloud.kv", "SQL database": "tinycloud.sql", DuckDB: "tinycloud.duckdb", Delegation: "tinycloud.delegation", Secret: "tinycloud.kv", Encryption: "tinycloud.encryption" };
      const normal = (path: string): string => (/^\/*$/.test(path) ? "" : path);
      const shown = new Set([...summary.read, ...summary.change].filter((item) => item.service !== "Capabilities").flatMap((item) => item.actions.map((action) => `${labels[item.service]}|${item.space ?? "applications"}|${normal(item.path)}|${action}`)));
      const resolved = new Set(resolveManifest(manifest as Parameters<typeof resolveManifest>[0]).resources.filter((resource) => resource.service !== "tinycloud.capabilities").flatMap((resource) => resource.actions.map((action) => `${resource.service}|${resource.space}|${normal(resource.path)}|${action.slice(action.lastIndexOf("/") + 1)}`)));
      expect([...shown].sort(), name).toEqual([...resolved].sort());
    }
  });

  describe("shapes the sheet refuses instead of describing", () => {
    const refused: { name: string; manifest: unknown; sdk: (manifest: Parameters<typeof resolveManifest>[0]) => void }[] = [
      { name: "a delegate DID", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"] }], { did: "did:key:z6MkexampleexampleexampleexampleexampleexampleABC" }), sdk: (m) => expect(composeManifestRequest([m]).delegationTargets.length, "the SDK hands every resolved resource to that key").toBeGreaterThan(0) },
      { name: "a prefix that is a number", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"] }], { prefix: 5 }), sdk: (m) => expect(resolveManifest(m).resources[0]?.path, "the SDK uses it as it is").toBe("5/a/") },
      { name: "a null prefix", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"] }], { prefix: null }), sdk: (m) => expect(resolveManifest(m).resources[0]?.path).toBe("null/a/") },
      { name: "a blank manifest space", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"] }], { space: "  " }), sdk: (m) => expect(resolveManifest(m).resources[0]?.space, "the SDK uses it as written").toBe("  ") },
      { name: "a permission with a blank space", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"], space: "  " }]), sdk: (m) => expect(resolveManifest(m).resources[0]?.space).toBe("  ") },
      { name: "a permission whose space is not text", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"], space: 5 as unknown as string }]), sdk: (m) => expect(() => resolveManifest(m), "the SDK refuses it itself").toThrow() },
      { name: "the short-form permission-list read", manifest: manifestOf([{ service: "capabilities", path: "", actions: ["read"] }]), sdk: (m) => expect(resolveManifest(m).resources.some((resource) => resource.service === "capabilities" || resource.service === "tinycloud.capabilities"), "the SDK reads the short form as the same service").toBe(true) },
      { name: "an explicit permission-list read in another space", manifest: manifestOf([{ service: "tinycloud.capabilities", path: "", actions: ["read"], space: "account" }]), sdk: (m) => expect(resolveManifest(m).resources.filter((resource) => resource.service === "tinycloud.capabilities" && resource.space === "account").length, "the SDK would add it anyway; a hand-written one doubles it").toBeGreaterThan(0) },
      { name: "a space that is not text", manifest: manifestOf([{ service: "tinycloud.kv", path: "a/", actions: ["put"] }], { space: ["applications"] }), sdk: (m) => expect(() => resolveManifest(m), "the SDK refuses it itself").toThrow() },
    ];

    it.each(refused.map((shape) => [shape.name, shape]))("%s: refused, and the SDK really does something the lists would not show", (_name, shape) => {
      expect(unsupportedManifest(shape.manifest)).toBeTypeOf("string");
      shape.sdk(shape.manifest as Parameters<typeof resolveManifest>[0]);
    });

    it("no committed catalog manifest is one of them, and an ordinary manifest is not refused", () => {
      for (const app of committed.apps) expect(unsupportedManifest(JSON.parse(readFileSync(join("public", app.bundle.root, "manifest.json"), "utf8"))), app.app_id).toBeNull();
      expect(unsupportedManifest(manifestOf([], { prefix: "" }))).toBeNull();
      expect(unsupportedManifest("not an object")).toBeNull();
    });
  });

  describe("names the page would show as something they are not", () => {
    // One of each class: control, format, surrogate, private-use, unassigned, line/paragraph separator, other spaces, fillers, selectors.
    const CLASSES: [string, string][] = [
      ["zero-width space U+200B", "\u200b"], ["zero-width non-joiner U+200C", "\u200c"], ["word joiner U+2060", "\u2060"], ["next line U+0085", "\u0085"],
      ["zero-width joiner", "\u200d"], ["byte-order mark", "\ufeff"], ["right-to-left override", "\u202e"], ["Hangul filler U+3164", "\u3164"], ["halfwidth Hangul filler U+FFA0", "\uffa0"],
      ["Hangul choseong filler U+115F", "\u115f"], ["Hangul jungseong filler U+1160", "\u1160"], ["Khmer vowel inherent U+17B4", "\u17b4"], ["Khmer vowel inherent U+17B5", "\u17b5"],
      ["Mongolian vowel separator U+180E", "\u180e"], ["no-break space", "\u00a0"], ["em space", "\u2003"], ["line separator", "\u2028"], ["paragraph separator", "\u2029"],
      ["lone surrogate", "\ud800"], ["private use", "\ue000"], ["unassigned", "\u0378"], ["NUL", "\u0000"], ["combining grapheme joiner", "\u034f"], ["variation selector", "\ufe0f"],
      ["tag character", "\u{e0041}"], ["only plain spaces", "   "], ["nothing", ""], ["visible text with a zero-width space inside", "app\u200blications"], ["visible text with a no-break space inside", "my\u00a0space"],
    ];
    const kv = (extra: Record<string, unknown> = {}) => ({ service: "tinycloud.kv", path: "a/", actions: ["put"], ...extra }) as Permission;

    it.each(CLASSES)("a space of %j is refused, in the manifest and in a permission", (_name, space) => {
      expect(unsupportedManifest(manifestOf([kv()], { space })), "manifest space").toBeTypeOf("string");
      expect(unsupportedManifest(manifestOf([kv({ space })])), "permission space").toBeTypeOf("string");
    });

    it("the SDK takes the three characters `trim()` keeps as a space name, written exactly as given: that is why they are refused", () => {
      for (const space of ["\u200b", "\u200c", "\u2060"]) {
        expect(space.trim(), "trim() leaves it").toBe(space);
        expect(resolveManifest(manifestOf([kv({ space })]) as Parameters<typeof resolveManifest>[0]).resources[0]?.space).toBe(space);
        expect(unsupportedManifest(manifestOf([kv({ space })]))).toBeTypeOf("string");
      }
    });

    it.each(CLASSES.filter(([, value]) => value !== "" && value.replaceAll(" ", "") !== ""))("%j in a path, a service, a prefix or a secret's name is refused", (_name, hidden) => {
      expect(unsupportedManifest(manifestOf([kv({ path: `a${hidden}b/` })]))).toBeTypeOf("string");
      expect(unsupportedManifest(manifestOf([kv({ service: `tinycloud.kv${hidden}` })]))).toBeTypeOf("string");
      expect(unsupportedManifest(manifestOf([kv()], { prefix: `p${hidden}` }))).toBeTypeOf("string");
      expect(unsupportedManifest({ app_id: APP, name: "T", defaults: false, secrets: { [`API${hidden}KEY`]: true } })).toBeTypeOf("string");
      expect(unsupportedManifest({ app_id: APP, name: "T", defaults: false, secrets: { API_KEY: { scope: `s${hidden}`, actions: "read" } } })).toBeTypeOf("string");
    });

    it("visible names, in any script, are not refused", () => {
      for (const space of ["applications", "default", "my space", "café", "日本語", "acct-1_x.y"]) {
        expect(unsupportedManifest(manifestOf([kv({ space })], { space })), space).toBeNull();
      }
      expect(unsupportedManifest(manifestOf([kv({ path: "notes café/" })], { prefix: "" }))).toBeNull();
    });
  });

  it("cuts manifest text repeated in a sentence to the cap, with a mark, and leaves short text alone", () => {
    const long = `${OTHER}/${"a/".repeat(2000)}`;
    const notices = noticesOf(manifestOf([{ service: "tinycloud.kv", path: long, skipPrefix: true, actions: ["put"] }, { service: "tinycloud.sql", path: `x${"y".repeat(3000)}`, skipPrefix: true, actions: ["write"] }, { service: "tinycloud.encryption", path: `urn:tinycloud:encryption:${"n".repeat(3000)}`, actions: ["decrypt"] }]));
    expect(notices.length).toBe(3);
    for (const notice of notices) {
      expect(notice.length, notice.slice(0, 60)).toBeLessThan(MAX_NOTICE_TEXT_CHARS + 120);
      expect(notice).toContain("…");
    }
    expect([...clip("x".repeat(MAX_NOTICE_TEXT_CHARS))]).toHaveLength(MAX_NOTICE_TEXT_CHARS);
    expect(clip("x".repeat(MAX_NOTICE_TEXT_CHARS))).not.toContain("…");
    const cut = clip("é".repeat(MAX_NOTICE_TEXT_CHARS + 1));
    expect([...cut]).toHaveLength(MAX_NOTICE_TEXT_CHARS);
    expect(cut.endsWith("…")).toBe(true);
  });

  it("shows an empty path as everything in its space, never as an empty box", () => {
    const summary = summarizeAccess(manifestOf([{ service: "tinycloud.kv", path: "", skipPrefix: true, actions: ["put"] }, { service: "tinycloud.kv", space: "default", path: "/", skipPrefix: true, actions: ["del"] }]));
    expect(summary.change.map((item) => item.target)).toEqual(["everything in the applications space", "everything in the default space"]);
  });
});
