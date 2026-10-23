import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ADDRESS_LIVE_CAP, TYPE_CONFIG } from "../src/config.ts";
import type { LinkStorage } from "../src/storage.ts";
import { ADAPTER_FACTORIES, type Adapter } from "./support/adapters.ts";
import { NOW, makeRecord, seedRows } from "./support/fixtures.ts";

/** Storage conformance 1 to 21 (contract 9.2); test 22 (the vectors) is in vectors.test.ts. Both adapters run all of them. */
describe.each(ADAPTER_FACTORIES)("storage conformance: $name adapter", ({ create }) => {
  let adapter: Adapter;
  let storage: LinkStorage;

  beforeAll(async () => {
    adapter = await create();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    storage = adapter.storage();
  });

  it("1. put then get returns identical header bytes, signature and body bytes (all 256 values)", async () => {
    const body = Uint8Array.from({ length: 256 }, (_, i) => i);
    const record = makeRecord({ body, size: 256, headerJcs: '{"a":"\\u00e9","b":1}', signature: "abc_-" });
    expect(await storage.put(record, NOW)).toBe("ok");
    const got = await storage.get(record.id, NOW);
    expect(got).toEqual(record);
    expect(Array.from(got?.body ?? [])).toEqual(Array.from(body));
  });

  it("2. put twice with one id: second is exists, first intact", async () => {
    const first = makeRecord();
    expect(await storage.put(first, NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ id: first.id, issuer: "did:key:other" }), NOW)).toBe("exists");
    expect((await storage.get(first.id, NOW))?.issuer).toBe(first.issuer);
  });

  it("3. get at now == expiresAt is null; one second earlier returns the record", async () => {
    const record = makeRecord({ expiresAt: NOW + 100 });
    await storage.put(record, NOW);
    expect(await storage.get(record.id, NOW + 99)).not.toBeNull();
    expect(await storage.get(record.id, NOW + 100)).toBeNull();
  });

  it("4. unknown and expired ids are indistinguishable", async () => {
    const record = makeRecord({ expiresAt: NOW + 10 });
    await storage.put(record, NOW);
    expect(await storage.get(record.id, NOW + 11)).toBeNull();
    expect(await storage.get(makeRecord().id, NOW + 11)).toBeNull();
  });

  it("5. take returns the record once; ten concurrent takes yield exactly one", async () => {
    const record = makeRecord({ type: "openkey-login" });
    await storage.put(record, NOW);
    expect(await storage.take(record.id, NOW)).toEqual(record);
    expect(await storage.take(record.id, NOW)).toBeNull();
    const again = makeRecord({ type: "openkey-login" });
    await storage.put(again, NOW);
    const results = await Promise.all(Array.from({ length: 10 }, () => storage.take(again.id, NOW)));
    expect(results.filter((r) => r !== null)).toHaveLength(1);
  });

  it("6. get never returns or removes a read-once record; take never returns or removes a multi-read record", async () => {
    const once = makeRecord({ type: "openkey-login" });
    const multi = makeRecord({ type: "courier" });
    await storage.put(once, NOW);
    await storage.put(multi, NOW);
    expect(await storage.get(once.id, NOW)).toBeNull();
    expect(await storage.take(multi.id, NOW)).toBeNull();
    expect(await storage.take(once.id, NOW)).not.toBeNull();
    expect(await storage.get(multi.id, NOW)).not.toBeNull();
  });

  it("7. delete(id, issuer, now): match true then get null; second false; other issuer false and intact; expired and unknown false", async () => {
    const record = makeRecord();
    await storage.put(record, NOW);
    expect(await storage.delete(record.id, "did:key:other", NOW)).toBe(false);
    expect(await storage.get(record.id, NOW)).not.toBeNull();
    expect(await storage.delete(record.id, record.issuer, NOW)).toBe(true);
    expect(await storage.get(record.id, NOW)).toBeNull();
    expect(await storage.delete(record.id, record.issuer, NOW)).toBe(false);
    const expired = makeRecord({ expiresAt: NOW + 5 });
    await storage.put(expired, NOW);
    expect(await storage.delete(expired.id, expired.issuer, NOW + 5)).toBe(false);
    expect(await storage.delete(makeRecord().id, record.issuer, NOW)).toBe(false);
  });

  it("8. sweep removes expired records, nonces and counters, keeps live ones, reports the count", async () => {
    const dead = makeRecord({ expiresAt: NOW + 10 });
    const live = makeRecord({ expiresAt: NOW + 1000 });
    await storage.put(dead, NOW);
    await storage.put(live, NOW);
    await storage.claimNonce("s", "dead", 10, NOW);
    await storage.claimNonce("s", "live", 1000, NOW);
    await storage.hit("old", 5, 10, NOW);
    await storage.hit("new", 5, 100_000, NOW);
    expect(await storage.sweep(NOW + 20)).toBe(3);
    expect(await storage.get(live.id, NOW + 20)).not.toBeNull();
    expect(await storage.claimNonce("s", "live", 1000, NOW + 20)).toBe(false);
    expect(await storage.sweep(NOW + 20)).toBe(0);
  });

  it("9. claimNonce: first true, second false, other scope true, true after TTL; 50 concurrent claims yield one true", async () => {
    expect(await storage.claimNonce("a", "n", 300, NOW)).toBe(true);
    expect(await storage.claimNonce("a", "n", 300, NOW + 1)).toBe(false);
    expect(await storage.claimNonce("b", "n", 300, NOW + 1)).toBe(true);
    expect(await storage.claimNonce("a", "n", 300, NOW + 300)).toBe(true);
    const results = await Promise.all(Array.from({ length: 50 }, () => storage.claimNonce("c", "same", 300, NOW)));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("10. a sweep never removes a nonce before its TTL ends, also with concurrent sweeps and claims", async () => {
    expect(await storage.claimNonce("a", "n", 300, NOW)).toBe(true);
    await storage.sweep(NOW + 299);
    expect(await storage.claimNonce("a", "n", 300, NOW + 299)).toBe(false);
    await storage.sweep(NOW + 300);
    expect(await storage.claimNonce("a", "n", 300, NOW + 300)).toBe(true);

    expect(await storage.claimNonce("a", "m", 300, NOW + 1000)).toBe(true);
    const mixed = await Promise.all(
      Array.from({ length: 30 }, (_, i) =>
        i % 2 === 0 ? storage.sweep(NOW + 1299).then(() => null) : storage.claimNonce("a", "m", 300, NOW + 1299),
      ),
    );
    expect(mixed.filter((r) => r === true)).toHaveLength(0);
  });

  it("11. hit: allowed through the limit, refused after, retryAfter to the window end, new bucket resets; 50 concurrent hits at limit 10 allow 10", async () => {
    const results = [];
    for (let i = 0; i < 4; i++) {
      results.push((await storage.hit("k", 3, 60, NOW + i)).allowed);
    }
    expect(results).toEqual([true, true, true, false]);
    const refused = await storage.hit("k", 3, 60, 1_799_999_990 + 5);
    expect(refused.retryAfter).toBe(60 - ((1_799_999_990 + 5) % 60));
    expect((await storage.hit("k", 3, 60, NOW + 60)).allowed).toBe(true);
    const burst = await Promise.all(Array.from({ length: 50 }, () => storage.hit("burst", 10, 60, NOW)));
    expect(burst.filter((r) => r.allowed)).toHaveLength(10);
  });

  it("12. type quota by rows and by bytes; another type unaffected; concurrent puts never exceed it", async () => {
    const quota = TYPE_CONFIG["openkey-login"];
    await seedRows(adapter.driver, { idPrefix: "a", type: "openkey-login", count: quota.quotaRows - 1, size: 1, address: "filler" });
    expect(await storage.put(makeRecord({ type: "openkey-login", addressHash: "x1" }), NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ type: "openkey-login", addressHash: "x2" }), NOW)).toBe("type_quota");
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "x3" }), NOW)).toBe("ok");
    await adapter.reset();
    await seedRows(adapter.driver, { idPrefix: "b", type: "openkey-login", count: quota.quotaRows - 5, size: 1, address: "filler" });
    const outcomes = await Promise.all(
      Array.from({ length: 20 }, (_, i) => storage.put(makeRecord({ type: "openkey-login", addressHash: `c${i}` }), NOW)),
    );
    expect(outcomes.filter((o) => o === "ok")).toHaveLength(5);
    expect(outcomes.filter((o) => o === "type_quota")).toHaveLength(15);
    await adapter.reset();
    await seedRows(adapter.driver, { idPrefix: "d", type: "openkey-login", count: 1, size: quota.quotaBytes - 64, address: "filler" });
    expect(await storage.put(makeRecord({ type: "openkey-login", addressHash: "y1" }), NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ type: "openkey-login", addressHash: "y2" }), NOW)).toBe("type_quota");
  });

  it("13. per-address live cap: 100th admitted, 101st refused; bytes likewise; independent hashes; 20 concurrent at 99 admit one; deleted and expired stop counting", async () => {
    await seedRows(adapter.driver, { idPrefix: "a", type: "courier", count: ADDRESS_LIVE_CAP.rows - 1, size: 1, address: "h" });
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "h" }), NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "h" }), NOW)).toBe("address_live_cap");
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "other" }), NOW)).toBe("ok");

    await adapter.reset();
    await seedRows(adapter.driver, { idPrefix: "b", type: "courier", count: ADDRESS_LIVE_CAP.rows - 1, size: 1, address: "g" });
    const burst = await Promise.all(Array.from({ length: 20 }, () => storage.put(makeRecord({ type: "courier", addressHash: "g" }), NOW)));
    expect(burst.filter((o) => o === "ok")).toHaveLength(1);

    await adapter.reset();
    await seedRows(adapter.driver, { idPrefix: "c", type: "courier", count: 1, size: ADDRESS_LIVE_CAP.bytes - 64, address: "b" });
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "b" }), NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "b" }), NOW)).toBe("address_live_cap");

    await adapter.reset();
    await seedRows(adapter.driver, { idPrefix: "e", type: "courier", count: ADDRESS_LIVE_CAP.rows - 1, size: 1, address: "x", expiresAt: NOW + 5 });
    const last = makeRecord({ type: "courier", addressHash: "x" });
    expect(await storage.put(last, NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "x" }), NOW + 5)).toBe("ok");
    expect(await storage.delete(last.id, last.issuer, NOW + 5)).toBe(true);
    expect(await storage.put(makeRecord({ type: "courier", addressHash: "x" }), NOW + 5)).toBe("ok");
  });

  it("14. type reserve: at 80% a bucket with 9 live records is admitted and one with 10 is refused", async () => {
    const quota = TYPE_CONFIG.share;
    await seedRows(adapter.driver, { idPrefix: "t", type: "share", count: quota.quotaRows * 0.8, size: 1, address: "filler" });
    await seedRows(adapter.driver, { idPrefix: "n", type: "courier", count: 9, size: 1, address: "nine" });
    await seedRows(adapter.driver, { idPrefix: "m", type: "courier", count: 10, size: 1, address: "ten" });
    expect(await storage.put(makeRecord({ addressHash: "nine" }), NOW)).toBe("ok");
    expect(await storage.put(makeRecord({ addressHash: "ten" }), NOW)).toBe("reserve");
  });

  it("15. isBlocked, setBlocked, clearBlocked for both kinds", async () => {
    for (const kind of ["issuer", "address"] as const) {
      expect(await storage.isBlocked(kind, "k")).toBe(false);
      await storage.setBlocked(kind, "k", "note", NOW);
      expect(await storage.isBlocked(kind, "k")).toBe(true);
      expect(await storage.isBlocked(kind === "issuer" ? "address" : "issuer", "other")).toBe(false);
      await storage.clearBlocked(kind, "k");
      expect(await storage.isBlocked(kind, "k")).toBe(false);
    }
  });

  it("16. apiKey returns the stored hash by keyId; a revoked key returns null; a third active key per service is refused", async () => {
    const key = { keyId: "tstkey01", service: "openkey", allowedTypes: ["openkey-login"] as const, secretSha256: "hash" };
    expect(await storage.addApiKey(key, NOW)).toBe(true);
    expect(await storage.apiKey("tstkey01")).toEqual(key);
    expect(await storage.apiKey("nokeyid1")).toBeNull();
    expect(await storage.addApiKey({ ...key, keyId: "tstkey02" }, NOW)).toBe(true);
    expect(await storage.addApiKey({ ...key, keyId: "tstkey03" }, NOW)).toBe(false);
    await storage.revokeApiKey("tstkey01", NOW);
    expect(await storage.apiKey("tstkey01")).toBeNull();
    expect(await storage.addApiKey({ ...key, keyId: "tstkey03" }, NOW)).toBe(true);
  });

  it("17. stats counts live rows and bytes per type, excluding expired", async () => {
    await storage.put(makeRecord({ type: "share", body: new Uint8Array(10), size: 10 }), NOW);
    await storage.put(makeRecord({ type: "share", body: new Uint8Array(20), size: 20, expiresAt: NOW + 5 }), NOW);
    await storage.put(makeRecord({ type: "courier", body: new Uint8Array(7), size: 7 }), NOW);
    expect(await storage.stats(NOW)).toEqual({
      "openkey-login": { rows: 0, bytes: 0 },
      courier: { rows: 1, bytes: 7 },
      share: { rows: 2, bytes: 30 },
    });
    expect((await storage.stats(NOW + 5)).share).toEqual({ rows: 1, bytes: 10 });
  });

  it("18. count and readCounts: concurrent adds are not lost; read-and-reset returns the totals once", async () => {
    await Promise.all(Array.from({ length: 40 }, () => storage.count("creates.share", 1)));
    await storage.count("reads.hit", 5);
    expect(await storage.readCounts()).toEqual({ "creates.share": 40, "reads.hit": 5 });
    expect(await storage.readCounts()).toEqual({});
  });

  it("19. sweep never removes a live record and no operation returns an expired one", async () => {
    const live = makeRecord({ expiresAt: NOW + 100 });
    const dead = makeRecord({ expiresAt: NOW + 10 });
    await storage.put(live, NOW);
    await storage.put(dead, NOW);
    await storage.sweep(NOW + 50);
    expect(await storage.get(live.id, NOW + 50)).not.toBeNull();
    expect(await storage.get(dead.id, NOW + 50)).toBeNull();
    expect(await storage.take(dead.id, NOW + 50)).toBeNull();
    expect(await storage.delete(dead.id, dead.issuer, NOW + 50)).toBe(false);
  });

  it("20. get, take and delete give the same result for an expired id and one that never existed, also while sweep runs", async () => {
    const expiredOnce = makeRecord({ type: "openkey-login", expiresAt: NOW + 5 });
    const expiredMulti = makeRecord({ expiresAt: NOW + 5 });
    await storage.put(expiredOnce, NOW);
    await storage.put(expiredMulti, NOW);
    const never = makeRecord().id;
    const probe = async (id: string, issuer: string) =>
      [await storage.get(id, NOW + 6), await storage.take(id, NOW + 6), await storage.delete(id, issuer, NOW + 6)];
    const results = await Promise.all([
      storage.sweep(NOW + 6),
      probe(expiredOnce.id, expiredOnce.issuer),
      probe(expiredMulti.id, expiredMulti.issuer),
      probe(never, expiredMulti.issuer),
      storage.sweep(NOW + 6),
    ]);
    for (const outcome of [results[1], results[2], results[3]]) {
      expect(outcome).toEqual([null, null, false]);
    }
  });

  it("21. a type accepts a record exactly at its quota and refuses the next", async () => {
    const quota = TYPE_CONFIG["openkey-login"];
    await seedRows(adapter.driver, { idPrefix: "q", type: "openkey-login", count: quota.quotaRows - 1, size: 0, address: "filler" });
    expect(await storage.put(makeRecord({ type: "openkey-login", addressHash: "z1" }), NOW)).toBe("ok");
    expect((await storage.stats(NOW))["openkey-login"].rows).toBe(quota.quotaRows);
    expect(await storage.put(makeRecord({ type: "openkey-login", addressHash: "z2" }), NOW)).toBe("type_quota");
  });
});
