import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createD1Adapter, createSqliteAdapter, type Adapter } from "./support/adapters.ts";
import {
  VECTORS_SHA256,
  fileSha256,
  loadVectors,
  runServiceVectors,
  summarize,
  vectorsPath,
  type VectorResult,
} from "./support/vectors.ts";

describe("shared vector file (contract Appendix B)", () => {
  it("the committed copy matches its pinned SHA-256", () => {
    expect(fileSha256(vectorsPath())).toBe(VECTORS_SHA256);
  });
});

describe("service-level vectors, both adapters (conformance 22)", () => {
  const results: Record<string, VectorResult[]> = {};
  const adapters: Adapter[] = [];

  beforeAll(async () => {
    const vectors = loadVectors();
    for (const create of [createSqliteAdapter, createD1Adapter]) {
      const adapter = await create();
      adapters.push(adapter);
      results[adapter.name] = await runServiceVectors(vectors, adapter);
    }
  }, 280_000);
  afterAll(async () => {
    await Promise.all(adapters.map((a) => a.close()));
  });

  it.each(["sqlite", "d1"])("every service-level vector passes on the %s adapter", (name) => {
    const failed = (results[name] ?? []).filter((r) => !r.ok);
    expect(failed).toEqual([]);
    expect((results[name] ?? []).length).toBeGreaterThan(250);
  });

  it("both adapters return identical results for every vector", () => {
    expect(results["d1"]?.map((r) => [r.group, r.name, r.ok])).toEqual(results["sqlite"]?.map((r) => [r.group, r.name, r.ok]));
    expect(Object.keys(summarize(results["sqlite"] ?? [])).sort()).toEqual(
      [
        "addressBuckets", "admission", "bodyHash", "constants", "create", "delete", "ed25519Strict", "headers", "ids",
        "nonceStore", "nonceSweep", "rateLimits.windowSequences", "read", "records (size boundaries)", "signatures",
      ].sort(),
    );
  });
});
