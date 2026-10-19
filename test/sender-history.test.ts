import { describe, expect, it } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { SENDER_HISTORY_FETCH_CONCURRENCY, SENDER_HISTORY_PREFIX, SenderHistoryRepository, importSenderHistoryRecord, type SenderHistoryItem } from "../src/share/sender-history.js";
import type { SenderShareRecord } from "@tinycloud/share-sdk";

function fakeVault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix, limit }: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => ({ ok: true, data: { keys: [...store.keys()].filter((key) => key.startsWith(prefix)).slice(0, limit).map((key) => removePrefix ? key.slice(prefix.length) : key), truncated: false } }),
  } as unknown as IDataVaultService;
}

function record(overrides: Partial<SenderShareRecord> = {}): SenderShareRecord {
  return {
    shareId: "share-history-1",
    target: { origin: "https://share.example.invalid", nodeAudience: "did:web:node.example.invalid", spaceId: "space-1" },
    resource: { kind: "exact", path: "notes.md" },
    actions: ["tinycloud.kv/get"],
    recipientMatcher: { kind: "bearer" },
    targetKind: "bearer",
    registeredAt: "2026-07-24T12:00:00.000Z",
    expiresAt: "2026-07-31T12:00:00.000Z",
    link: "https://share.example.invalid/viewer#tc1=opaque",
    filename: "notes.md",
    ...overrides,
  };
}

describe("canonical sender history adapter", () => {
  it("persists canonical records through encrypted Vault storage and redacts list/show", async () => {
    const repository = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    await repository.save(record());
    const page = await repository.page();
    expect(page.items[0]).toMatchObject({ state: "ready", record: { shareId: "share-history-1" }, view: { target: "bearer", revoked: false } });
    const listed = await repository.records.list();
    expect(listed[0]).not.toHaveProperty("type");
    expect(await repository.show("share-history-1")).not.toHaveProperty("link");
    expect(await repository.show("share-history-1", true)).toHaveProperty("link");
  });

  it("uses canonical recipient redaction for DID and email targets", async () => {
    const repository = new SenderHistoryRepository(fakeVault());
    await repository.save(record({ shareId: "did-share", recipientMatcher: { kind: "recipientDid", value: "did:key:holder" }, targetKind: "recipientDid" }));
    await repository.save(record({ shareId: "domain-share", recipientMatcher: { kind: "emailDomain", value: "example.invalid" }, targetKind: "emailDomain" }));
    const page = await repository.page();
    const views = page.items.filter((item): item is Extract<typeof item, { readonly view: unknown }> => "view" in item).map((item) => item.view);
    expect(views.map((view) => view.target).sort()).toEqual(["email-domain", "recipient-did"]);
    expect(views.every((view) => !Object.hasOwn(view, "link"))).toBe(true);
  });

  it("keeps revocation and paging reload-safe", async () => {
    const vault = fakeVault();
    const repository = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    await repository.save({ ...record({ shareId: "first" }), registeredAt: "2026-07-26T12:00:00.000Z" });
    await repository.save({ ...record({ shareId: "second" }), registeredAt: "2026-07-25T12:00:00.000Z" });
    await repository.markRevoked({ ...record({ shareId: "first" }), registeredAt: "2026-07-26T12:00:00.000Z" });
    const reloaded = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    const firstPage = await reloaded.page(undefined, 1);
    expect(firstPage.truncated).toBe(true);
    expect(firstPage.items[0]?.state).toBe("revoked");
    const second = (await reloaded.page(firstPage.nextCursor, 1)).items[0];
    const secondId = second !== undefined && "record" in second ? second.record.shareId : undefined;
    expect(secondId).toBe("second");
  });

  it("imports a possessed link as a canonical bearer record", () => {
    const imported = importSenderHistoryRecord("https://share.example.invalid/viewer#tc1=tc1%3Atest", new Date("2026-07-27T00:00:00.000Z"));
    expect(imported.recipientMatcher).toEqual({ kind: "bearer" });
    expect(imported.targetKind).toBe("bearer");
    expect(imported.registeredAt).toBe("2026-07-27T00:00:00.000Z");
  });
});


/** A vault that pages its key listing like the node does and records what the repository asks of it. */
function instrumentedVault(options: { readonly serverPageLimit?: number; readonly getDelay?: (key: string) => number; readonly failGet?: (key: string) => "missing" | "throw" | undefined } = {}) {
  const store = new Map<string, unknown>();
  const stats = { listCalls: 0, gets: [] as string[], inFlight: 0, maxInFlight: 0 };
  const vault = {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => {
      stats.gets.push(key);
      // The response reflects the store when the request is made, so a write that lands during the delay does not show up in it.
      const present = store.has(key);
      const snapshot = store.get(key);
      stats.inFlight += 1; stats.maxInFlight = Math.max(stats.maxInFlight, stats.inFlight);
      try {
        await new Promise((resolve) => setTimeout(resolve, options.getDelay?.(key) ?? 1));
        const failure = options.failGet?.(key);
        if (failure === "throw") throw new Error("vault-unreachable");
        return present && failure === undefined ? { ok: true, data: snapshot } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } };
      } finally { stats.inFlight -= 1; }
    },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix, limit, cursor }: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => {
      stats.listCalls += 1;
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix)).sort();
      const start = cursor === undefined ? 0 : Number(cursor);
      const size = Math.min(limit, options.serverPageLimit ?? limit);
      const page = keys.slice(start, start + size);
      const truncated = start + size < keys.length;
      return { ok: true, data: { keys: page.map((key) => removePrefix ? key.slice(prefix.length) : key), truncated, ...(truncated ? { nextCursor: String(start + size) } : {}) } };
    },
  } as unknown as IDataVaultService;
  const seed = (records: readonly SenderShareRecord[]) => { for (const entry of records) store.set(`${SENDER_HISTORY_PREFIX}${entry.shareId}`, entry); };
  return { vault, stats, seed, store };
}

function manyRecords(count: number): SenderShareRecord[] {
  const base = Date.parse("2026-07-01T00:00:00.000Z");
  return Array.from({ length: count }, (_, index) => record({ shareId: `share-${String(index).padStart(5, "0")}`, registeredAt: new Date(base + index * 60_000).toISOString(), expiresAt: "2026-09-01T00:00:00.000Z" }));
}

const NOW = () => Date.parse("2026-07-27T00:00:00.000Z");
const ids = (items: readonly SenderHistoryItem[]) => items.map((item) => "record" in item ? item.record.shareId : item.key);

describe("sender history load path", () => {
  it("follows the listing cursor so a sender with more than 1000 records sees all of them", async () => {
    const { vault, seed, stats } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(1250));
    const repository = new SenderHistoryRepository(vault, NOW);
    expect(await repository.records.list()).toHaveLength(1250);
    expect(stats.listCalls).toBe(2);

    const seen: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await repository.page(cursor, 100);
      seen.push(...ids(page.items));
      cursor = page.nextCursor;
    } while (cursor !== undefined);
    expect(new Set(seen).size).toBe(1250);
    // newest first: the oldest share, which the first listing page alone would have dropped past 1000 keys, is last
    expect(seen[0]).toBe("share-01249");
    expect(seen.at(-1)).toBe("share-00000");
  }, 30_000);

  it("fails instead of returning a partial list when a truncated page has no cursor", async () => {
    const { vault } = instrumentedVault();
    (vault as unknown as { listPage: unknown }).listPage = async () => ({ ok: true, data: { keys: ["a"], truncated: true } });
    await expect(new SenderHistoryRepository(vault, NOW).page()).rejects.toThrow("sender-history-list-failed");
  });

  it("never has more than the concurrency cap in flight, and does use it", async () => {
    const { vault, seed, stats } = instrumentedVault();
    seed(manyRecords(60));
    await new SenderHistoryRepository(vault, NOW).page(undefined, 60);
    expect(stats.maxInFlight).toBeLessThanOrEqual(SENDER_HISTORY_FETCH_CONCURRENCY);
    expect(stats.maxInFlight).toBe(SENDER_HISTORY_FETCH_CONCURRENCY);
  });

  it("orders by registeredAt whatever order the fetches finish in", async () => {
    // Older records answer fastest, so completion order is the reverse of display order.
    const { vault, seed } = instrumentedVault({ getDelay: (key) => 30 - Number(key.slice(-5)) * 2 });
    seed(manyRecords(12));
    const repository = new SenderHistoryRepository(vault, NOW);
    const listed = await repository.records.list();
    expect(listed.map((entry) => entry.shareId)).toEqual(manyRecords(12).map((entry) => entry.shareId));
    const page = await repository.page(undefined, 5);
    expect(ids(page.items)).toEqual(["share-00011", "share-00010", "share-00009", "share-00008", "share-00007"]);
    expect(page.nextCursor).toBe("5");
  });

  it("reads each record once on open, and Load more reads only the rows it shows", async () => {
    const { vault, seed, stats } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(40));
    const repository = new SenderHistoryRepository(vault, NOW);
    const first = await repository.page();
    expect(first.items).toHaveLength(25);
    expect(stats.gets).toHaveLength(40);
    expect(stats.listCalls).toBe(1);
    const second = await repository.page(first.nextCursor);
    expect(second.items).toHaveLength(15);
    expect(second.truncated).toBe(false);
    expect(stats.gets).toHaveLength(55);
    expect(stats.listCalls).toBe(1);
    // a fresh first page (revoke, import, retry) re-lists the keys and re-reads only the 25 rows it shows
    await repository.page();
    expect(stats.gets).toHaveLength(80);
    expect(stats.listCalls).toBe(2);
  });

  it("never holds a bearer link or delivery material outside the vault, until a click reads it", async () => {
    const { vault, seed } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(30).map((entry) => ({ ...entry, link: `https://share.example.invalid/viewer#tc1=LINK-${entry.shareId}`, deliveryMaterial: { marker: `MATERIAL-${entry.shareId}` }, deliveredRecipients: [`mailbox-${entry.shareId}`] }) as unknown as SenderShareRecord));
    const repository = new SenderHistoryRepository(vault, NOW);
    // Everything the repository retains between calls, excluding the vault handle itself.
    const retained = (): string => {
      const seen = new Set<unknown>();
      const walk = (value: unknown): unknown => {
        if (typeof value !== "object" || value === null || seen.has(value)) return typeof value === "object" ? null : value;
        seen.add(value);
        if (value instanceof Map) return [...value].map(([key, entry]) => [walk(key), walk(entry)]);
        if (value instanceof Set) return [...value].map(walk);
        if (Array.isArray(value)) return value.map(walk);
        return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "vault").map(([key, entry]) => [key, walk(entry)]));
      };
      return JSON.stringify(walk(repository));
    };
    const first = await repository.page();
    const second = await repository.page(first.nextCursor);
    for (const item of [...first.items, ...second.items]) expect(JSON.stringify(item)).not.toMatch(/LINK-|MATERIAL-|mailbox-/);
    expect(first.items[0]).toMatchObject({ record: { shareId: "share-00029", filename: "notes.md", recipientMatcher: { kind: "bearer" } } });
    expect(retained()).not.toMatch(/LINK-|MATERIAL-|mailbox-/);
    expect(retained()).toContain("share-00029"); // the index of ids is kept
    // Open/Copy and Revoke read the one record they need
    const shown = await repository.show("share-00029", true);
    expect(shown.link).toContain("LINK-share-00029");
    expect((await repository.records.get("share-00029"))?.deliveryMaterial).toEqual({ marker: "MATERIAL-share-00029" });
    expect(retained()).not.toMatch(/LINK-|MATERIAL-|mailbox-/);
  });

  it("shows a revoke immediately, never as active, on the first page and on Load more", async () => {
    const { vault, seed } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(30));
    const repository = new SenderHistoryRepository(vault, NOW);
    const first = await repository.page();
    const target = first.items[2];
    if (target === undefined || !("record" in target)) throw new Error("expected a record row");
    expect(target.state).toBe("ready");
    await repository.markRevoked(target.record);
    await repository.markRevoked(manyRecords(30)[0] as SenderShareRecord); // oldest: on the "Load more" page
    expect((await repository.page()).items[2]).toMatchObject({ state: "revoked", view: { revoked: true } });
    expect((await repository.page("25")).items.at(-1)).toMatchObject({ state: "revoked", view: { revoked: true } });
    // a new session sees the stored revocation too
    expect((await new SenderHistoryRepository(vault, NOW).page()).items[2]).toMatchObject({ state: "revoked" });
  });

  it("shows a revoke made by another writer on the next first page", async () => {
    const { vault, seed, store } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(3));
    const repository = new SenderHistoryRepository(vault, NOW);
    expect((await repository.page()).items[0]).toMatchObject({ state: "ready" });
    const key = `${SENDER_HISTORY_PREFIX}share-00002`;
    store.set(key, { ...(store.get(key) as SenderShareRecord), revokedAt: "2026-07-26T00:00:00.000Z" });
    expect((await repository.page()).items[0]).toMatchObject({ state: "revoked", view: { revoked: true } });
  });

  it("shows a saved record and drops a removed one on the next load", async () => {
    const { vault, seed, stats } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(10));
    const repository = new SenderHistoryRepository(vault, NOW);
    await repository.page();
    await repository.save(record({ shareId: "imported-1", registeredAt: "2026-08-01T00:00:00.000Z", expiresAt: "2026-09-01T00:00:00.000Z" }));
    await repository.remove("share-00009");
    const page = await repository.page(undefined, 50);
    expect(ids(page.items)[0]).toBe("imported-1");
    expect(ids(page.items)).not.toContain("share-00009");
    expect(page.items).toHaveLength(10);
    expect(stats.gets).toHaveLength(20); // 10 on open, then the 10 rows shown; the index needed no fetch for the save or remove
  });

  it("picks up shares added or removed by another writer on a fresh load, fetching only the new one for the index", async () => {
    const { vault, seed, stats, store } = instrumentedVault({ getDelay: () => 0 });
    seed(manyRecords(5));
    const repository = new SenderHistoryRepository(vault, NOW);
    await repository.page();
    seed([record({ shareId: "from-elsewhere", registeredAt: "2026-08-01T00:00:00.000Z", expiresAt: "2026-09-01T00:00:00.000Z" })]);
    store.delete(`${SENDER_HISTORY_PREFIX}share-00000`);
    const page = await repository.page();
    expect(ids(page.items)).toContain("from-elsewhere");
    expect(ids(page.items)).not.toContain("share-00000");
    expect(stats.gets).toHaveLength(10); // 5 on open, 1 new record, 4 other rows re-read
  });

  it("does not show a record as active when a read that began before a revoke returns after it", async () => {
    const { vault, seed } = instrumentedVault({ getDelay: (key) => key.endsWith("share-00001") ? 25 : 0 });
    seed(manyRecords(3));
    const repository = new SenderHistoryRepository(vault, NOW);
    const loading = repository.page();
    await new Promise((resolve) => setTimeout(resolve, 5));
    await repository.markRevoked(manyRecords(3)[1] as SenderShareRecord);
    const page = await loading;
    expect(page.items.find((item) => item.key.endsWith("share-00001"))).toMatchObject({ state: "revoked" });
    expect((await repository.page()).items.find((item) => item.key.endsWith("share-00001"))).toMatchObject({ state: "revoked" });
  });

  it("fails instead of looping when the listing cursors cycle", async () => {
    const { vault } = instrumentedVault();
    const pages: Record<string, { keys: string[]; nextCursor: string }> = { start: { keys: ["a"], nextCursor: "A" }, A: { keys: ["b"], nextCursor: "B" }, B: { keys: ["c"], nextCursor: "A" } };
    let calls = 0;
    (vault as unknown as { listPage: unknown }).listPage = async ({ cursor }: { cursor?: string }) => {
      calls += 1;
      if (calls > 20) throw new Error("runaway listing");
      return { ok: true, data: { truncated: true, ...pages[cursor ?? "start"] } };
    };
    await expect(new SenderHistoryRepository(vault, NOW).page()).rejects.toThrow("sender-history-list-failed");
    expect(calls).toBe(3);
  });

  it("skips unreadable records as before and retries them on the next load", async () => {
    let broken: "missing" | "throw" | undefined = "missing";
    const { vault, seed, stats } = instrumentedVault({ getDelay: () => 0, failGet: (key) => key.endsWith("share-00002") ? broken : undefined });
    seed(manyRecords(4));
    const repository = new SenderHistoryRepository(vault, NOW);
    expect(ids((await repository.page()).items).sort()).toEqual(["share-00000", "share-00001", "share-00003"]);
    broken = undefined;
    expect(await repository.page().then((page) => page.items)).toHaveLength(4);
    expect(stats.gets.filter((key) => key.endsWith("share-00002"))).toHaveLength(2);
  });

  it("rejects the load when a read throws, and a retry succeeds", async () => {
    let broken: "missing" | "throw" | undefined = "throw";
    const { vault, seed } = instrumentedVault({ getDelay: () => 0, failGet: (key) => key.endsWith("share-00001") ? broken : undefined });
    seed(manyRecords(3));
    const repository = new SenderHistoryRepository(vault, NOW);
    await expect(repository.page()).rejects.toThrow("vault-unreachable");
    broken = undefined;
    expect((await repository.page()).items).toHaveLength(3);
  });
});
