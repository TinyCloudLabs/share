import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as sdkCore from "@tinycloud/sdk-core";
import { describe, expect, it } from "vitest";

import { INSTALL_RECORD_PATH } from "../src/apps/bundle.ts";
import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { installKey, installOrder, installRecord, installRecordKey } from "../src/apps/install-plan.ts";
import { type PutResult, type PreparedApp, RunError, type RunPorts, type RuntimeSession, openApp } from "../src/apps/run.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const HEALTH = "xyz.tinycloud.sample.healthlog";
const NOTES = "com.example.notes";
const health = catalog.apps.find((candidate) => candidate.app_id === HEALTH) as CatalogEntry;
const notes = catalog.apps.find((candidate) => candidate.app_id === NOTES) as CatalogEntry;
const bytesOf = (path: string): Uint8Array => new Uint8Array(readFileSync(join("public", health.bundle.root, path)));
const bundleFiles = health.bundle.files.map((file) => ({ ...file, bytes: bytesOf(file.path) }));
const manifest = JSON.parse(readFileSync(join("public", health.bundle.root, health.manifest.path), "utf8")) as unknown;
const recordKey = installRecordKey(HEALTH);
const appKeys = bundleFiles.filter((file) => !file.path.startsWith("knowledge/")).map((file) => installKey(HEALTH, file.path));
const pathOf = new Map<string, string>([[recordKey, INSTALL_RECORD_PATH], ...bundleFiles.map((file) => [installKey(HEALTH, file.path), file.path] as [string, string])]);
const noop = (): void => undefined;

/** A complete saved copy as the read returns it: the code files under `app/` and install.json. Notes are outside the read scope. */
const fullCopy = (): Map<string, Uint8Array> => new Map<string, Uint8Array>([
  ...bundleFiles.filter((file) => !file.path.startsWith("knowledge/")).map((file) => [file.path, file.bytes] as [string, Uint8Array]),
  [INSTALL_RECORD_PATH, installRecord(health, new Date("2026-10-20T10:00:00.000Z"))],
]);

interface HarnessOptions {
  hint?: string;
  prepareError?: RunError;
  catalog?: readonly CatalogEntry[];
}

/** Ports over an in-memory saved copy. `puts` records every create-only write key in order. */
function harness(initial: Map<string, Uint8Array>, options: HarnessOptions = {}) {
  const puts: string[] = [];
  const reads: boolean[] = [];
  const hints = new Map<string, string>(options.hint === undefined ? [] : [[HEALTH, options.hint]]);
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
    prepare: async (): Promise<PreparedApp> => {
      counts.prepares += 1;
      if (options.prepareError !== undefined) throw options.prepareError;
      return { bundle: { files: bundleFiles, manifest }, manifest: { ok: true, manifest: manifest as never } };
    },
    readStored: async (_entry, _hooks, { install }) => {
      reads.push(install);
      return { files: { entries: new Map(initial) }, ...(install ? { put } : {}), end: async () => undefined };
    },
    openRuntime: async () => {
      counts.runtimes += 1;
      return { data: {}, expiresAt: 0, end: async () => undefined } as unknown as RuntimeSession;
    },
    sdk: async () => sdkCore,
    hints: {
      get: (appId) => hints.get(appId),
      set: (appId, digest) => { hints.set(appId, digest); },
      clear: (appId) => { hints.delete(appId); },
    },
  };
  return { ports, puts, reads, hints, counts };
}

describe("installOrder", () => {
  it("puts app files first, then notes, each group sorted by path", () => {
    const ordered = installOrder([{ path: "knowledge/b.md" }, { path: "app.jsx" }, { path: "knowledge/a.md" }, { path: "app/util.js" }]).map((file) => file.path);
    expect(ordered).toEqual(["app.jsx", "app/util.js", "knowledge/a.md", "knowledge/b.md"]);
  });
});

describe("openApp: refusals before any approval", () => {
  it("refuses a catalog entry with no code, before the read approval", async () => {
    const h = harness(new Map(), { catalog: [notes] });
    await expect(openApp(NOTES, h.ports, noop)).rejects.toMatchObject({ reason: "unavailable", detail: expect.stringContaining("no code") });
    expect(h.reads).toEqual([]);
    expect(h.counts.prepares).toBe(0);
  });

  it("a catalog bundle that fails verification refuses before the read approval", async () => {
    const h = harness(new Map(), { prepareError: new RunError("catalog-unavailable") });
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toMatchObject({ reason: "catalog-unavailable" });
    expect(h.reads).toEqual([]);
    expect(h.counts.runtimes).toBe(0);
  });
});

describe("openApp: install on open", () => {
  it("first open of a missing copy: app files first, install.json last, then verifies and records the digest", async () => {
    const h = harness(new Map());
    const running = await openApp(HEALTH, h.ports, noop);
    expect(running.app).toBeDefined();
    expect(h.reads).toEqual([true]);
    expect(h.puts).toEqual([...installOrder(bundleFiles).map((file) => installKey(HEALTH, file.path)), recordKey]);
    expect(h.counts.runtimes).toBe(1);
    expect(h.hints.get(HEALTH)).toBe(health.bundle.digest);
  });

  it("complete saved copy on a device with no hint: no app-file writes, no install.json rewrite", async () => {
    const h = harness(fullCopy());
    await openApp(HEALTH, h.ports, noop);
    expect(h.reads).toEqual([true]);
    expect(h.puts).not.toContain(recordKey);
    expect(h.puts.filter((key) => appKeys.includes(key))).toEqual([]);
    expect(h.counts.runtimes).toBe(1);
  });

  it("matching device hint: plain read with no write grants and no writes", async () => {
    const h = harness(fullCopy(), { hint: health.bundle.digest });
    await openApp(HEALTH, h.ports, noop);
    expect(h.reads).toEqual([false]);
    expect(h.puts).toEqual([]);
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
    expect(h.hints.has(HEALTH)).toBe(false);
  });

  it("an install.json recorded for another digest: nothing is written and the open is refused", async () => {
    const other = { ...health, bundle: { ...health.bundle, digest: "0".repeat(64) } } as CatalogEntry;
    const copy = new Map<string, Uint8Array>([[INSTALL_RECORD_PATH, installRecord(other, new Date("2026-10-20T10:00:00.000Z"))]]);
    const h = harness(copy);
    await expect(openApp(HEALTH, h.ports, noop)).rejects.toBeInstanceOf(RunError);
    expect(h.puts).toEqual([]);
    expect(h.counts.runtimes).toBe(0);
  });
});
