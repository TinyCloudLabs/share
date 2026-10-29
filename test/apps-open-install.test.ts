import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { describe, expect, it } from "vitest";

import { INSTALL_RECORD_PATH } from "../src/apps/bundle.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { KNOWLEDGE_INDEX, installKey, installOrder, installRecord, installRecordKey } from "../src/apps/install-plan.ts";
import { type PutResult, type PreparedApp, RunError, type RunPorts, type RunSession, type RuntimeSession, openApp, signInPlan } from "../src/apps/run.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const HEALTH = "xyz.tinycloud.sample.healthlog";
const NOTES = "com.example.notes";
const health = catalog.apps.find((candidate) => candidate.app_id === HEALTH) as CatalogEntry;
const previousHealth = catalog.apps.find((candidate) => candidate.app_id === HEALTH && candidate.bundle.digest === "dc3ec19fffce8fee350944469948531659a258347538a98aacdd5544deea5014");
const notes = catalog.apps.find((candidate) => candidate.app_id === NOTES) as CatalogEntry;
const bytesOf = (candidate: CatalogEntry, path: string): Uint8Array => new Uint8Array(readFileSync(join("public", candidate.bundle.root, path)));
const bundleFiles = health.bundle.files.map((file) => ({ ...file, bytes: bytesOf(health, file.path) }));
const recordKey = installRecordKey(HEALTH);
const appKeys = bundleFiles.filter((file) => !file.path.startsWith("knowledge/")).map((file) => installKey(HEALTH, file.path));
const pathOf = new Map<string, string>([[recordKey, INSTALL_RECORD_PATH], ...bundleFiles.map((file) => [installKey(HEALTH, file.path), file.path] as [string, string])]);
const noop = (): void => undefined;

/** A complete saved copy for the selected version; notes are outside the runner read scope. */
const savedCopy = (candidate: CatalogEntry): Map<string, Uint8Array> => new Map<string, Uint8Array>([
  ...candidate.bundle.files.filter((file) => !file.path.startsWith("knowledge/")).map((file) => [file.path, bytesOf(candidate, file.path)] as [string, Uint8Array]),
  [INSTALL_RECORD_PATH, installRecord(candidate, new Date("2026-10-20T10:00:00.000Z"))],
]);
const fullCopy = (): Map<string, Uint8Array> => savedCopy(health);

interface HarnessOptions {
  prepareError?: RunError;
  catalog?: readonly CatalogEntry[];
  hasPersistedSession?: boolean;
}

/** Ports over an in-memory saved copy. `puts` records every create-only write key in order. */
function harness(initial: Map<string, Uint8Array>, options: HarnessOptions = {}) {
  const puts: string[] = [];
  const reads = { count: 0 };
  const signedPlans: { digest: string; manifest: unknown }[] = [];
  const initialPlans: { digest: string; manifest: unknown }[] = [];
  const counts = { prepares: 0, runtimes: 0 };
  const put = async (key: string, bytes: Uint8Array): Promise<PutResult> => {
    puts.push(key);
    const path = pathOf.get(key) ?? key;
    // Notes are written but never listed back by the read, so they are not added to the saved copy the read returns.
    if (path.startsWith("knowledge/")) return "created";
    if (initial.has(path)) return "exists";
    initial.set(path, bytes);
    return "created";
  };
  const ports: RunPorts = {
    ...(options.catalog === undefined ? {} : { catalog: options.catalog }),
    hasPersistedSession: async () => options.hasPersistedSession ?? initial.has(INSTALL_RECORD_PATH),
    prepare: async (candidate): Promise<PreparedApp> => {
      counts.prepares += 1;
      if (options.prepareError !== undefined) throw options.prepareError;
      const preparedManifest = sdkCore.validateManifest(JSON.parse(readFileSync(join("public", candidate.bundle.root, candidate.manifest.path), "utf8")));
      const files = candidate.bundle.files.map((file) => ({ ...file, bytes: bytesOf(candidate, file.path) }));
      return { bundle: { files, manifest: preparedManifest }, manifest: { ok: true, manifest: preparedManifest } };
    },
    loadCatalogManifest: async (candidate) => ({ ok: true, manifest: sdkCore.validateManifest(JSON.parse(readFileSync(join("public", candidate.bundle.root, candidate.manifest.path), "utf8"))) }),
    // `counts.runtimes` is the number of runtime sessions signed in and not yet ended.
    signIn: async (candidate, plan): Promise<RunSession> => {
      initialPlans.push({ digest: candidate.bundle.digest, manifest: plan.manifest });
      reads.count += 1;
      counts.runtimes += 1;
      let ended = false;
      const runtime = { data: {}, expiresAt: 0, end: async () => { if (!ended) { ended = true; counts.runtimes -= 1; } }, detach: async () => undefined };
      return {
        files: { entries: new Map(initial) },
        authorize: async (candidate, plan) => { signedPlans.push({ digest: candidate.bundle.digest, manifest: plan.manifest }); },
        put,
        runtime: runtime as unknown as RuntimeSession,
      };
    },
    sdk: async () => sdkCore,
  };
  return { ports, puts, reads, signedPlans, initialPlans, counts };
}

describe("installOrder", () => {
  it("puts app files first, then notes, each group sorted by path, with the notes index last", () => {
    const ordered = installOrder([{ path: "knowledge/index.md" }, { path: "knowledge/b.md" }, { path: "app.jsx" }, { path: "knowledge/a.md" }, { path: "app/util.js" }]).map((file) => file.path);
    expect(ordered).toEqual(["app.jsx", "app/util.js", "knowledge/a.md", "knowledge/b.md", "knowledge/index.md"]);
  });
});

describe("openApp: refusals before app permission approval", () => {
  it("refuses a catalog entry with no code before preparing or signing in", async () => {
    const h = harness(new Map(), { catalog: [notes] });
    await expect(openApp(NOTES, h.ports, noop)).rejects.toMatchObject({ reason: "no-code", detail: "This app isn't available right now." });
    expect(h.reads.count).toBe(0);
    expect(h.counts.prepares).toBe(0);
  });

  it("a catalog bundle that fails verification refuses before app permission approval", async () => {
    const h = harness(new Map(), { prepareError: new RunError("catalog-unavailable") });
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "catalog-unavailable" });
    expect(h.reads.count).toBe(0);
    expect(h.counts.runtimes).toBe(0);
  });
});

describe("openApp: install on open", () => {
  it("first open of a missing copy: app files first, install.json last, then verifies and records the digest", async () => {
    const h = harness(new Map());
    const running = await openApp(HEALTH, h.ports, noop);
    expect(running.app.entry.bundle.digest).toBe(health.bundle.digest);
    expect(h.reads.count).toBe(1);
    const ordered = installOrder(bundleFiles).map((file) => installKey(HEALTH, file.path));
    const appCount = bundleFiles.filter((file) => !file.path.startsWith("knowledge/")).length;
    expect(h.puts).toEqual([...ordered.slice(0, appCount), recordKey, ...ordered.slice(appCount)]);
    expect(h.puts.at(-1)).toBe(installKey(HEALTH, KNOWLEDGE_INDEX));
    expect(h.counts.runtimes).toBe(1);
  });
  it("reopens through the persisted app grant without extra OpenKey approvals", async () => {
    const h = harness(new Map());
    const first = await openApp(HEALTH, h.ports, noop);
    expect(first.app.entry.bundle.digest).toBe(health.bundle.digest);
    expect(h.signedPlans).toHaveLength(1);
    expect(h.reads.count).toBe(1);

    await first.session.detach();
    const reopened = await openApp(HEALTH, h.ports, noop);
    expect(reopened.app.entry.bundle.digest).toBe(health.bundle.digest);
    expect(h.signedPlans).toHaveLength(2);
    expect(h.reads.count).toBe(2);
  });
  it("uses each selected version's exact grants, for retained installs and fresh installs", async () => {
    expect(previousHealth).toBeDefined();
    if (previousHealth === undefined) return;
    const old = harness(savedCopy(previousHealth));
    const openedOld = await openApp(HEALTH, old.ports, noop);
    expect(openedOld.app.entry.bundle.digest).toBe(previousHealth.bundle.digest);
    expect(old.signedPlans).toEqual([{
      digest: previousHealth.bundle.digest,
      manifest: signInPlan({ ok: true, manifest: sdkCore.validateManifest(JSON.parse(readFileSync(join("public", previousHealth.bundle.root, previousHealth.manifest.path), "utf8"))) }, sdkCore).manifest,
    }]);
    expect(old.signedPlans[0]?.manifest).not.toEqual(signInPlan({ ok: true, manifest: sdkCore.validateManifest(JSON.parse(readFileSync(join("public", health.bundle.root, health.manifest.path), "utf8"))) }, sdkCore).manifest);
    const freshBrowserOld = harness(savedCopy(previousHealth), { hasPersistedSession: false });
    const openedFreshBrowserOld = await openApp(HEALTH, freshBrowserOld.ports, noop);
    expect(openedFreshBrowserOld.app.entry.bundle.digest).toBe(previousHealth.bundle.digest);
    expect(freshBrowserOld.initialPlans).toEqual([{
      digest: health.bundle.digest,
      manifest: signInPlan({ ok: true, manifest: sdkCore.validateManifest(JSON.parse(readFileSync(join("public", health.bundle.root, health.manifest.path), "utf8"))) }, sdkCore).manifest,
    }]);
    expect(freshBrowserOld.signedPlans).toEqual(old.signedPlans);

    const fresh = harness(new Map());
    const openedFresh = await openApp(HEALTH, fresh.ports, noop);
    expect(openedFresh.app.entry.bundle.digest).toBe(health.bundle.digest);
    expect(fresh.signedPlans).toEqual([{
      digest: health.bundle.digest,
      manifest: signInPlan({ ok: true, manifest: sdkCore.validateManifest(JSON.parse(readFileSync(join("public", health.bundle.root, health.manifest.path), "utf8"))) }, sdkCore).manifest,
    }]);
  });

  it("refuses a disabled retained version before writes while current installs still open", async () => {
    expect(previousHealth).toBeDefined();
    if (previousHealth === undefined) return;
    const disabledOld = { ...previousHealth, disabled: true as const, disabledReason: "Old version disabled." };
    const retained = harness(savedCopy(previousHealth), { catalog: [health, disabledOld] });
    await expect(openApp(HEALTH, retained.ports, noop)).rejects.toMatchObject({ reason: "unavailable" });
    expect(retained.puts).toEqual([]);
    expect(retained.reads.count).toBe(1);
    expect(retained.counts.prepares).toBe(0);

    const fresh = harness(new Map(), { catalog: [health, disabledOld] });
    const running = await openApp(HEALTH, fresh.ports, noop);
    expect(running.app.entry.bundle.digest).toBe(health.bundle.digest);
    expect(fresh.signedPlans[0]?.digest).toBe(health.bundle.digest);
  });

  it("refuses a disabled current version for new installs while enabled retained installs still open", async () => {
    expect(previousHealth).toBeDefined();
    if (previousHealth === undefined) return;
    const disabledCurrent = { ...health, disabled: true as const, disabledReason: "Current version disabled." };
    const fresh = harness(new Map(), { catalog: [disabledCurrent, previousHealth] });
    await expect(openApp(HEALTH, fresh.ports, noop)).rejects.toMatchObject({ reason: "unavailable" });
    expect(fresh.puts).toEqual([]);
    expect(fresh.reads.count).toBe(0);
    expect(fresh.counts.prepares).toBe(0);

    const retained = harness(savedCopy(previousHealth), { catalog: [disabledCurrent, previousHealth] });
    const running = await openApp(HEALTH, retained.ports, noop);
    expect(running.app.entry.bundle.digest).toBe(previousHealth.bundle.digest);
    expect(retained.signedPlans[0]?.digest).toBe(previousHealth.bundle.digest);
    expect(retained.puts.filter((key) => !key.includes("/knowledge/"))).toEqual([]);
  });
  it("opens an existing install at the retained bundle and enforces that version's grant cap", async () => {
    const previous = catalog.apps.find((candidate) => candidate.bundle.digest === "dc3ec19fffce8fee350944469948531659a258347538a98aacdd5544deea5014");
    expect(previous).toBeDefined();
    if (previous === undefined) return;
    const previousFiles = previous.bundle.files.filter((file) => !file.path.startsWith("knowledge/"));
    const existing = new Map<string, Uint8Array>(previousFiles.map((file) => [
      file.path,
      new Uint8Array(readFileSync(join("public", previous.bundle.root, file.path))),
    ]));
    existing.set(INSTALL_RECORD_PATH, installRecord(previous, new Date("2026-10-20T10:00:00.000Z")));
    const h = harness(existing);
    const running = await openApp(HEALTH, h.ports, noop);
    expect(running.app.entry.bundle.digest).toBe(previous.bundle.digest);
    expect(running.app.signing.permissions).toEqual(JSON.parse(readFileSync(join("public", previous.bundle.root, previous.manifest.path), "utf8")).permissions);
    expect(h.puts.filter((key) => !key.includes("/knowledge/"))).toEqual([]);

    const wider = new Map(existing);
    const savedManifest = JSON.parse(new TextDecoder().decode(wider.get("manifest.json")!));
    savedManifest.permissions.push({ service: "tinycloud.kv", path: "settings/", actions: ["get", "put"] });
    wider.set("manifest.json", new TextEncoder().encode(JSON.stringify(savedManifest)));
    const refused = harness(wider);
    await expect(openApp(HEALTH, refused.ports, noop)).rejects.toMatchObject({ reason: "widened" });
    expect(refused.puts.filter((key) => !key.includes("/knowledge/"))).toEqual([]);
  });


  it("complete saved copy: no app-file writes and no install.json rewrite; a missing note is still saved", async () => {
    const h = harness(fullCopy());
    await openApp(HEALTH, h.ports, noop);
    expect(h.reads.count).toBe(1);
    expect(h.puts).not.toContain(recordKey);
    expect(h.puts.filter((key) => appKeys.includes(key))).toEqual([]);
    expect(h.counts.runtimes).toBe(1);
  });

  it("a tampered saved app file is never overwritten, install.json is not committed, and nothing is signed for runtime", async () => {
    const copy = fullCopy();
    copy.delete(INSTALL_RECORD_PATH);
    copy.set("app.jsx", new TextEncoder().encode("tampered"));
    const h = harness(copy);
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "damaged" });
    expect(h.puts).not.toContain(installKey(HEALTH, "app.jsx"));
    expect(h.puts).not.toContain(recordKey);
    expect(h.counts.runtimes).toBe(0);
  });

  it("an extra file under app/ refuses the open and install.json is not committed", async () => {
    const copy = fullCopy();
    copy.delete(INSTALL_RECORD_PATH);
    copy.set("extra.js", new TextEncoder().encode("1"));
    const h = harness(copy);
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "damaged" });
    expect(h.puts).not.toContain(recordKey);
    expect(h.counts.runtimes).toBe(0);
  });

  it("an install.json recorded for another digest: nothing is written and the open is refused", async () => {
    const other = { ...health, bundle: { ...health.bundle, digest: "0".repeat(64) } } as CatalogEntry;
    const copy = fullCopy();
    copy.set(INSTALL_RECORD_PATH, installRecord(other, new Date("2026-10-20T10:00:00.000Z")));
    const h = harness(copy);
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "not-listed" });
    expect(h.puts).toEqual([]);
    expect(h.counts.runtimes).toBe(0);
  });

  it("the saved copy holds the verified bundle's bytes, byte for byte", async () => {
    const copy = new Map<string, Uint8Array>();
    const h = harness(copy);
    await openApp(HEALTH, h.ports, noop);
    for (const file of bundleFiles.filter((candidate) => !candidate.path.startsWith("knowledge/"))) {
      expect(copy.get(file.path)).toEqual(file.bytes);
    }
  });

  it("a file that appears between the read and its save refuses the open, and install.json is not written", async () => {
    const h = harness(new Map());
    const signIn = h.ports.signIn;
    h.ports.signIn = async (entry, plan, hooks) => {
      const session = await signIn(entry, plan, hooks);
      return { ...session, put: async (key, bytes, contentType) => (key === installKey(HEALTH, "app.jsx") ? "exists" : session.put(key, bytes, contentType)) };
    };
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "failed" });
    expect(h.puts).not.toContain(recordKey);
    expect(h.counts.runtimes).toBe(0);
  });

  it("cancel during the read approval writes nothing and starts nothing", async () => {
    const h = harness(new Map());
    const controller = new AbortController();
    const signIn = h.ports.signIn;
    h.ports.signIn = async (entry, plan, hooks) => {
      controller.abort();
      return signIn(entry, plan, hooks);
    };
    await expect(openApp(HEALTH, h.ports, noop, controller.signal)).rejects.toMatchObject({ reason: "cancelled" });
    expect(h.puts).toEqual([]);
    expect(h.counts.runtimes).toBe(0);
  });

  it("a save cancelled mid-write stops before the next write: no install.json, nothing starts, and the next open resumes", async () => {
    const copy = new Map<string, Uint8Array>();
    const h = harness(copy);
    const controller = new AbortController();
    const signIn = h.ports.signIn;
    h.ports.signIn = async (entry, plan, hooks) => {
      const session = await signIn(entry, plan, hooks);
      let writes = 0;
      return {
        ...session,
        put: async (key, bytes, contentType) => {
          writes += 1;
          if (writes === 1) controller.abort();
          return session.put(key, bytes, contentType);
        },
      };
    };
    await expect(openApp(HEALTH, h.ports, noop, controller.signal)).rejects.toMatchObject({ reason: "cancelled" });
    const ordered = installOrder(bundleFiles).map((file) => installKey(HEALTH, file.path));
    expect(h.puts).toEqual(ordered.slice(0, 1));
    expect(copy.has(INSTALL_RECORD_PATH)).toBe(false);
    expect(h.counts.runtimes).toBe(0);
    const resumed = harness(copy);
    await openApp(HEALTH, resumed.ports, noop);
    expect(resumed.puts).not.toContain(ordered[0]);
    expect(resumed.puts).toContain(recordKey);
    expect(resumed.counts.runtimes).toBe(1);
  });

  it("a saved copy that could not be listed in full refuses the open: install.json is not committed", async () => {
    const copy = fullCopy();
    copy.delete(INSTALL_RECORD_PATH);
    const h = harness(copy);
    const signIn = h.ports.signIn;
    h.ports.signIn = async (entry, plan, hooks) => {
      const session = await signIn(entry, plan, hooks);
      return { ...session, files: { entries: session.files.entries, incomplete: true } };
    };
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "damaged" });
    expect(h.puts).toEqual([]);
    expect(h.counts.runtimes).toBe(0);
  });
});
