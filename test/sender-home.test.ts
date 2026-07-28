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

    mountSenderHome(root, { session, tinycloud, history, onNavigate: () => undefined });
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
    mountSenderHome(reloadedRoot, { session, tinycloud, history: reloadedHistory, onNavigate: () => undefined });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(reloadedRoot.querySelector("td.sender-status-text.revoked")).not.toBeNull();
    expect(reloadedRoot.querySelector("button.sender-revoke")).toBeNull();
  });

  it("revoking one addressed share leaves an unrelated share in the same library untouched, before and after reload", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const vault = fakeVault();
    const history = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    const revokedRecord = await createSenderHistoryRecord({
      id: "sender-entry-00000004",
      url: "https://share.tinycloud.xyz/s/bafkreigdyrzt2abcde#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      cid: "bafybeigdyrzt5example",
      format: "compact",
      createdAt: "2026-07-24T12:00:00.000Z",
      expiresAt: "2026-07-31T12:00:00.000Z",
      name: "revoke-me.md",
      mediaType: "text/markdown",
      sourceKind: "upload",
      recipient: { kind: "exactEmail", value: "reviewer@example.edu" },
      actions: ["read"],
      delegationCid: "bafyreidelegationrevokeme",
      revokedAt: null,
    });
    const unrelatedRecord = await createSenderHistoryRecord({
      id: "sender-entry-00000005",
      url: "https://share.tinycloud.xyz/s/bafkreigdyrzt2fghij#k=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      cid: "bafybeigdyrzt5unrelated",
      format: "compact",
      createdAt: "2026-07-24T12:00:00.000Z",
      expiresAt: "2026-07-31T12:00:00.000Z",
      name: "unrelated.md",
      mediaType: "text/markdown",
      sourceKind: "upload",
      recipient: { kind: "exactEmail", value: "other@example.edu" },
      actions: ["read"],
      delegationCid: "bafyreidelegationunrelated",
      revokedAt: null,
    });
    await history.save(revokedRecord);
    await history.save(unrelatedRecord);

    const revokeDelegation = vi.fn(async (cid: string) => ({ ok: true as const, data: { cid, revokedAt: new Date().toISOString() } }));
    const tinycloud = { revokeDelegation } as unknown as ShareTinyCloud;
    const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;
    vi.spyOn(window, "confirm").mockReturnValue(true);

    mountSenderHome(root, { session, tinycloud, history, onNavigate: () => undefined });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const revokeButtons = [...root.querySelectorAll<HTMLButtonElement>("button.sender-revoke")];
    expect(revokeButtons).toHaveLength(2);
    const targetButton = revokeButtons.find((button) => button.getAttribute("aria-label") === "Revoke revoke-me.md")!;
    expect(targetButton).toBeDefined();
    targetButton.click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(revokeDelegation).toHaveBeenCalledTimes(1);
    expect(revokeDelegation).toHaveBeenCalledWith("bafyreidelegationrevokeme");

    const rows = [...root.querySelectorAll(".sender-history-row")];
    const revokedRow = rows.find((candidate) => candidate.textContent?.includes("revoke-me.md"));
    const unrelatedRow = rows.find((candidate) => candidate.textContent?.includes("unrelated.md"));
    expect(revokedRow?.querySelector(".sender-status-text.revoked")).not.toBeNull();
    expect(unrelatedRow?.querySelector(".sender-status-text.ready")).not.toBeNull();
    expect(unrelatedRow?.querySelector("button.sender-revoke")).not.toBeNull();

    // Reload-safe and isolated: a fresh mount over the same durable vault
    // must still show exactly one revoked share and the unrelated share
    // fully intact with its own revoke action still available.
    const reloadedRoot = document.createElement("div");
    document.body.append(reloadedRoot);
    const reloadedHistory = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    mountSenderHome(reloadedRoot, { session, tinycloud, history: reloadedHistory, onNavigate: () => undefined });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const reloadedRows = [...reloadedRoot.querySelectorAll(".sender-history-row")];
    const reloadedRevokedRow = reloadedRows.find((candidate) => candidate.textContent?.includes("revoke-me.md"));
    const reloadedUnrelatedRow = reloadedRows.find((candidate) => candidate.textContent?.includes("unrelated.md"));
    expect(reloadedRevokedRow?.querySelector(".sender-status-text.revoked")).not.toBeNull();
    expect(reloadedRevokedRow?.querySelector("button.sender-revoke")).toBeNull();
    expect(reloadedUnrelatedRow?.querySelector(".sender-status-text.ready")).not.toBeNull();
    expect(reloadedUnrelatedRow?.querySelector("button.sender-revoke")).not.toBeNull();
  });

  it("explains, rather than hides, why a bearer (possession-only) share cannot be revoked", async () => {
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

    mountSenderHome(root, { session, tinycloud, history, onNavigate: () => undefined });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const revoke = root.querySelector<HTMLButtonElement>("button.sender-revoke");
    expect(revoke).not.toBeNull();
    expect(revoke!.disabled).toBe(true);
    expect(revoke!.title).toBe("Link-only shares can't be revoked early.");
  });
});

describe("sender home is the router's home screen", () => {
  it("routes to the composer instead of mounting it, from the toolbar and from the empty state", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    const onNavigate = vi.fn();
    const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate });
    await new Promise((resolve) => setTimeout(resolve, 0));

    [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "New share")!.click();
    expect(onNavigate).toHaveBeenCalledWith("#/new");
    [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Share a file")!.click();
    expect(onNavigate).toHaveBeenCalledTimes(2);
    expect(root.querySelector(".composer-form")).toBeNull();
  });

  it("hides the table entirely on a first run and leads with sharing, not importing", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const empty = root.querySelector<HTMLElement>(".sender-empty-state")!;
    expect(empty.hidden).toBe(false);
    // The E2E harness waits on this exact string.
    expect(empty.textContent).toContain("No shares yet");
    expect(root.querySelector<HTMLTableElement>("table.sender-history-table")!.hidden).toBe(true);
    expect(root.querySelector("thead")!.closest("table")!.hidden).toBe(true);
    const buttons = [...empty.querySelectorAll("button")].map((button) => button.textContent);
    expect(buttons).toEqual(["Share a file", "Import a link you already have"]);
  });
});
