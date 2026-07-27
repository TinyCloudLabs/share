import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { createSenderHistoryRecord, SenderHistoryRepository } from "../src/share/sender-history.js";
import { mountSenderHome } from "../src/share/sender-home.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); });

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

describe("sender home revoke action is reload-safe", () => {
  it("revokes an addressed share through the node before marking it revoked, and the revocation survives a fresh mount", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const vault = fakeVault();
    const history = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    const record = await createSenderHistoryRecord({
      id: "sender-entry-00000002",
      url: "https://share.tinycloud.xyz/s/bafkreigdyrzt2abcde#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      cid: "bafybeigdyrzt5example",
      format: "compact",
      createdAt: "2026-07-24T12:00:00.000Z",
      expiresAt: "2026-07-31T12:00:00.000Z",
      name: "notes.md",
      mediaType: "text/markdown",
      sourceKind: "upload",
      recipient: { kind: "exactEmail", value: "reviewer@example.edu" },
      actions: ["read"],
      delegationCid: "bafyreidelegationexample",
      revokedAt: null,
    });
    await history.save(record);

    const revokeDelegation = vi.fn(async (cid: string) => { expect(cid).toBe("bafyreidelegationexample"); return { ok: true as const, data: { cid, revokedAt: new Date().toISOString() } }; });
    const tinycloud = { revokeDelegation } as unknown as ShareTinyCloud;
    const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;
    vi.spyOn(window, "confirm").mockReturnValue(true);

    mountSenderHome(root, { session, tinycloud, history, capabilities: [], composer: { origin: "https://share.tinycloud.xyz" } });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const revokeButton = root.querySelector<HTMLButtonElement>("button.sender-revoke");
    expect(revokeButton).not.toBeNull();
    revokeButton!.click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(revokeDelegation).toHaveBeenCalledWith("bafyreidelegationexample");
    expect(root.querySelector("td.sender-status-text.revoked")).not.toBeNull();

    // A fresh mount against the same durable vault must still show the
    // revocation: revoke is reload-safe, not an in-memory UI flag.
    const reloadedRoot = document.createElement("div");
    document.body.append(reloadedRoot);
    const reloadedHistory = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    mountSenderHome(reloadedRoot, { session, tinycloud, history: reloadedHistory, capabilities: [], composer: { origin: "https://share.tinycloud.xyz" } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(reloadedRoot.querySelector("td.sender-status-text.revoked")).not.toBeNull();
    expect(reloadedRoot.querySelector("button.sender-revoke")).toBeNull();
  });

  it("does not offer revoke for a bearer (possession-only) share, which carries no delegation to revoke", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const vault = fakeVault();
    const history = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    const record = await createSenderHistoryRecord({
      id: "sender-entry-00000003",
      url: "https://share.tinycloud.xyz/s/bafkreigdyrzt2abcde#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      cid: "bafybeigdyrzt5example",
      format: "compact",
      createdAt: "2026-07-24T12:00:00.000Z",
      expiresAt: "2026-07-31T12:00:00.000Z",
      name: "notes.md",
      mediaType: "text/markdown",
      sourceKind: "upload",
      recipient: { kind: "bearer" },
      actions: ["read"],
      delegationCid: null,
      revokedAt: null,
    });
    await history.save(record);
    const tinycloud = { revokeDelegation: vi.fn() } as unknown as ShareTinyCloud;
    const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;

    mountSenderHome(root, { session, tinycloud, history, capabilities: [], composer: { origin: "https://share.tinycloud.xyz" } });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(root.querySelector("button.sender-revoke")).toBeNull();
  });
});
