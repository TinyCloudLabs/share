import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { mountSenderHome } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import type { SenderShareRecord } from "@tinycloud/share-sdk";

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); });

function fakeVault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, limit }: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => ({ ok: true, data: { keys: [...store.keys()].filter((key) => key.startsWith(prefix)).slice(0, limit), truncated: false } }),
  } as unknown as IDataVaultService;
}

function record(shareId: string, recipientMatcher: SenderShareRecord["recipientMatcher"] = { kind: "exactEmail", value: "person@example.invalid" }): SenderShareRecord {
  return {
    shareId,
    target: { origin: "https://share.example.invalid", nodeAudience: "did:web:node.example.invalid", spaceId: "space-1" },
    resource: { kind: "exact", path: `${shareId}.md` },
    actions: ["tinycloud.kv/get"],
    recipientMatcher,
    targetKind: recipientMatcher.kind === "exactEmail" ? "email" : recipientMatcher.kind === "emailDomain" ? "emailDomain" : recipientMatcher.kind === "recipientDid" ? "recipientDid" : "bearer",
    registeredAt: "2026-07-24T12:00:00.000Z",
    expiresAt: "2026-07-31T12:00:00.000Z",
    ...(recipientMatcher.kind === "bearer" ? {} : { enforcementDelegationCid: `delegation-${shareId}` }),
    link: "https://share.example.invalid/s/test",
    filename: `${shareId}.md`,
  };
}

const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;

describe("sender home canonical lifecycle adapters", () => {
  it("uses target-aware revokeShare and persists only the affected record", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const vault = fakeVault();
    const history = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("revoke-me"));
    await history.save(record("leave-me", { kind: "recipientDid", value: "did:key:holder" }));
    const revokeDelegation = vi.fn(async () => ({ ok: true as const, data: {} }));
    vi.spyOn(window, "confirm").mockReturnValue(true);

    mountSenderHome(root, { session, tinycloud: { revokeDelegation } as unknown as ShareTinyCloud, history, onNavigate: () => undefined });
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row")).toHaveLength(2));
    root.querySelector<HTMLButtonElement>('button[aria-label="Revoke revoke-me.md"]')!.click();
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(revokeDelegation).toHaveBeenCalledWith("delegation-revoke-me");
    expect(root.querySelector('button[aria-label="Revoke leave-me.md"]')).not.toBeNull();
  });

  it("explains why bearer retention cannot be revoked", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("bearer", { kind: "bearer" }));
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined });
    await vi.waitFor(() => expect(root.querySelector("button.sender-revoke")).not.toBeNull());
    expect(root.querySelector<HTMLButtonElement>("button.sender-revoke")?.disabled).toBe(true);
    expect(root.querySelector<HTMLButtonElement>("button.sender-revoke")?.title).toContain("can't be revoked");
  });

  it("routes toolbar and empty-state actions without mounting a second composer", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    const onNavigate = vi.fn();
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate });
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".sender-empty-state")?.hidden).toBe(false));
    root.querySelector<HTMLButtonElement>('button:not(.sender-empty-import)')?.click();
    expect(onNavigate).toHaveBeenCalledWith("#/new");
    expect(root.querySelector(".composer-form")).toBeNull();
  });

  it("opens a stored share in the current tab without a popup handoff", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("open-me", { kind: "bearer" }));
    vi.spyOn(window, "open").mockReturnValue(window);
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined });
    await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>('button[aria-label="Open open-me.md"]')).not.toBeNull());
    root.querySelector<HTMLButtonElement>('button[aria-label="Open open-me.md"]')!.click();
    await vi.waitFor(() => expect(window.open).toHaveBeenCalled());
    expect(window.open).toHaveBeenCalledWith("https://share.example.invalid/s/test", "_self", "noreferrer");
  });
});
