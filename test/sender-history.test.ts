import { describe, expect, it } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { SenderHistoryRepository, importSenderHistoryRecord } from "../src/share/sender-history.js";
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
    link: "https://share.example.invalid/s/test",
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
    const imported = importSenderHistoryRecord("https://share.example.invalid/s/test", new Date("2026-07-27T00:00:00.000Z"));
    expect(imported.recipientMatcher).toEqual({ kind: "bearer" });
    expect(imported.targetKind).toBe("bearer");
    expect(imported.registeredAt).toBe("2026-07-27T00:00:00.000Z");
  });
});
