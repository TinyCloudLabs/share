import { describe, expect, it } from "vitest";
import { createSenderHistoryRecord, redactSenderHistoryRecord, SenderHistoryRepository, validateSenderHistoryRecord, type SenderHistoryRecord } from "../src/share/sender-history.js";
import type { IDataVaultService } from "@tinycloud/web-sdk";

function fakeVault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, limit }: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => {
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix)).slice(0, limit);
      return { ok: true, data: { keys, truncated: false } };
    },
  } as unknown as IDataVaultService;
}

const base = {
  id: "sender-entry-00000001",
  url: "https://share.tinycloud.xyz/s/bafkreigdyrzt2abcde#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  cid: "bafybeigdyrzt5example",
  format: "compact" as const,
  createdAt: "2026-07-24T12:00:00.000Z",
  expiresAt: "2026-07-31T12:00:00.000Z",
  name: "notes.md",
  mediaType: "text/markdown",
  sourceKind: "upload" as const,
  recipient: { kind: "bearer" as const },
  actions: ["read"] as const,
  delegationCid: null,
  revokedAt: null,
};

describe("sender history records", () => {
  it("canonicalizes and round-trips an exact link inside the record", async () => {
    const record = await createSenderHistoryRecord(base);
    expect(record.url).toBe(base.url);
    expect(record.urlDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(validateSenderHistoryRecord(record)).toEqual(record);
  });

  it("rejects unknown fields, invalid timestamps, and invalid recipient enums", () => {
    expect(() => validateSenderHistoryRecord({ ...base, type: "future", version: 1, urlDigest: "x" })).toThrow(/invalid/i);
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", createdAt: "not-a-time" })).toThrow(/invalid/i);
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", recipient: { kind: "exactEmail", value: "" } })).toThrow(/invalid/i);
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", url: base.url.replace("https:", "http:") })).toThrow(/invalid/i);
  });

  it("bounds oversized URLs before persistence", () => {
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", url: `https://share.tinycloud.xyz/s/${"a".repeat(70_000)}` })).toThrow(/invalid/i);
  });

  it("rejects an empty-string delegationCid and a non-canonical revokedAt", () => {
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", delegationCid: "" })).toThrow(/invalid/i);
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", revokedAt: "not-a-time" })).toThrow(/invalid/i);
  });

  it("accepts a delegation-backed addressed record", async () => {
    const record = await createSenderHistoryRecord({ ...base, delegationCid: "bafyreidelegationexample" });
    expect(record.delegationCid).toBe("bafyreidelegationexample");
    expect(validateSenderHistoryRecord(record)).toEqual(record);
  });

  it("keeps bearer links out of the default history projection", async () => {
    const record = await createSenderHistoryRecord(base);
    const redacted = redactSenderHistoryRecord(record);
    expect(redacted).not.toHaveProperty("url");
    expect(redactSenderHistoryRecord(record, true).url).toBe(record.url);
  });
});

describe("sender history revocation is reload-safe", () => {
  it("marks a delegation-backed record revoked and persists it across a fresh repository instance pointed at the same vault", async () => {
    const vault = fakeVault();
    const repo = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    const record = await createSenderHistoryRecord({ ...base, delegationCid: "bafyreidelegationexample" });
    await repo.save(record);

    let page = await repo.page();
    expect(page.items).toEqual([{ key: SenderHistoryRepository.keyFor(record), record, state: "ready" }]);

    await repo.markRevoked(record);

    // Simulate a page reload: a brand-new repository instance over the same
    // durable vault must still observe the revocation.
    const reloaded = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    page = await reloaded.page();
    expect(page.items).toHaveLength(1);
    const [item] = page.items;
    expect(item?.state).toBe("revoked");
    expect((item as { record: SenderHistoryRecord }).record.revokedAt).not.toBeNull();
  });
});
