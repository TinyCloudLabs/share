import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { mountSenderHome, nodeReproducibleRevocationTime } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import type { SenderShareRecord } from "@tinycloud/share-sdk";

const { getPolicyRootStatusV3, revokePolicyRootV3 } = vi.hoisted(() => ({
  getPolicyRootStatusV3: vi.fn(async (): Promise<{ readonly state: "active" | "revoked" }> => ({ state: "active" })),
  revokePolicyRootV3: vi.fn(async () => ({})),
}));
vi.mock("@tinycloud/sdk-core", () => ({ getPolicyRootStatusV3, revokePolicyRootV3 }));

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); vi.useRealTimers(); });

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
    ...(recipientMatcher.kind === "bearer" ? {} : { enforcementDelegationCid: `delegation-${shareId}`, ownerDid: "did:pkh:eip155:1:0x1234567890abcdef" }),
    link: "https://share.example.invalid/viewer#tc1=opaque",
    filename: `${shareId}.md`,
  };
}

const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;

/** The Node's RFC 3339 formatter (the `time` crate): trailing zeros of the fraction are dropped. */
const nodeFormat = (text: string) => text.replace(/\.(\d*?)0*Z$/, (_match, digits: string) => digits.length > 0 ? `.${digits}Z` : "Z");

describe("TC-601 revocation time", () => {
  it("stamps every millisecond in a form the Node reproduces exactly, at most 1 ms late", () => {
    const refused: number[] = [];
    for (let millisecond = 0; millisecond < 1000; millisecond += 1) {
      const now = new Date(Date.UTC(2026, 9, 4, 6, 0, 0, millisecond));
      const stamp = nodeReproducibleRevocationTime(now);
      if (nodeFormat(stamp.toISOString()) !== stamp.toISOString()) refused.push(millisecond);
      expect(stamp.getTime() - now.getTime()).toBeGreaterThanOrEqual(0);
      expect(stamp.getTime() - now.getTime()).toBeLessThanOrEqual(1);
    }
    expect(refused).toEqual([]);
  });
});

describe("sender home canonical lifecycle adapters", () => {
  it("uses target-aware revokeShare and persists only the affected record", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const vault = fakeVault();
    const history = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("revoke-me"));
    await history.save(record("leave-me", { kind: "recipientDid", value: "did:key:holder" }));
    const revokeDelegation = vi.fn(async () => ({ ok: true as const, data: {} }));
    vi.spyOn(window, "confirm").mockReturnValue(true);

    mountSenderHome(root, { session, tinycloud: {
      revokeDelegation,
      credentialHolderDid: "did:pkh:eip155:1:0x1234567890abcdef",
      activeNodeIdentity: async () => ({ origin: "https://share.example.invalid", nodeDid: "did:web:node.example.invalid" }),
      signSessionBytes: async () => new Uint8Array(64),
    } as unknown as ShareTinyCloud, history, onNavigate: () => undefined });
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row")).toHaveLength(2));
    // Revoke at a millisecond ending in 0, which the Node would refuse as is.
    // waitFor's 50 ms ticks keep the last digit 0, so the nudge always runs.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-07-27T06:00:00.120Z"));
    root.querySelector<HTMLButtonElement>('button[aria-label="Revoke revoke-me.md"]')!.click();
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(revokeDelegation).not.toHaveBeenCalled();
    expect(revokePolicyRootV3).toHaveBeenCalledWith(expect.objectContaining({
      nodeOrigin: "https://share.example.invalid",
      nodeAudience: "did:web:node.example.invalid",
      rootCid: "delegation-revoke-me",
      targetRole: "policy-enforcement",
      ownerDid: "did:pkh:eip155:1:0x1234567890abcdef",
      now: expect.any(Date),
    }));
    // TC-601: the stamp Share hands the SDK survives the Node's formatter.
    const { now } = (revokePolicyRootV3.mock.calls.at(-1) as unknown as [{ readonly now: Date }])[0];
    expect(now.getUTCMilliseconds() % 10).toBe(1);
    expect(nodeFormat(now.toISOString())).toBe(now.toISOString());
    expect(root.querySelector('button[aria-label="Revoke leave-me.md"]')).not.toBeNull();
  });

  it("explains why an imported bearer link without delegation authority cannot be revoked", async () => {
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
    expect(window.open).toHaveBeenCalledWith("https://share.example.invalid/viewer#tc1=opaque", "_self", "noreferrer");
  });
});

describe("TC-657 revoke retry after a lost response", () => {
  const irreversible = () => Object.assign(new Error("policy root revocation rejected: HTTP 409 - root-revocation-irreversible"), { status: 409 });
  const stillActive = "Revoke didn't go through — the share is still active. Try again.";

  async function clickRevoke() {
    getPolicyRootStatusV3.mockClear(); revokePolicyRootV3.mockClear();
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("retry-me"));
    vi.spyOn(window, "confirm").mockReturnValue(true);
    mountSenderHome(root, { session, tinycloud: {
      revokeDelegation: vi.fn(),
      credentialHolderDid: "did:pkh:eip155:1:0x1234567890abcdef",
      activeNodeIdentity: async () => ({ origin: "https://share.example.invalid", nodeDid: "did:web:node.example.invalid" }),
      signSessionBytes: async () => new Uint8Array(64),
    } as unknown as ShareTinyCloud, history, onNavigate: () => undefined });
    await vi.waitFor(() => expect(root.querySelector('button[aria-label="Revoke retry-me.md"]')).not.toBeNull());
    // The list reload replaces the live message, so record every message shown.
    const live = root.querySelector<HTMLElement>(".sender-live")!; const messages: string[] = [];
    new MutationObserver(() => messages.push(live.textContent ?? "")).observe(live, { childList: true, characterData: true, subtree: true });
    root.querySelector<HTMLButtonElement>('button[aria-label="Revoke retry-me.md"]')!.click();
    return { root, history, live, messages };
  }

  it("treats a 409 for a root the Node reports revoked as a successful revoke", async () => {
    revokePolicyRootV3.mockRejectedValueOnce(irreversible());
    getPolicyRootStatusV3.mockResolvedValueOnce({ state: "revoked" });
    const { root, history, messages } = await clickRevoke();
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(messages).toContain("Share revoked.");
    expect(messages).not.toContain(stillActive);
    expect(getPolicyRootStatusV3).toHaveBeenCalledWith({
      nodeOrigin: "https://share.example.invalid",
      rootCid: "delegation-retry-me",
      expectedNodeAudience: "did:web:node.example.invalid",
    });
    expect((await history.records.get("retry-me"))?.revokedAt).toEqual(expect.any(String));
    expect(root.querySelector('button[aria-label="Revoke retry-me.md"]')).toBeNull();
  });

  it.each([
    ["a 409 for a root that is still active", () => { revokePolicyRootV3.mockRejectedValueOnce(irreversible()); getPolicyRootStatusV3.mockResolvedValueOnce({ state: "active" }); }, true],
    ["a 409 whose status read fails", () => { revokePolicyRootV3.mockRejectedValueOnce(irreversible()); getPolicyRootStatusV3.mockRejectedValueOnce(new Error("policy root status rejected: HTTP 503")); }, true],
    ["a non-409 failure", () => { revokePolicyRootV3.mockRejectedValueOnce(Object.assign(new Error("policy root revocation rejected: HTTP 403"), { status: 403 })); }, false],
  ])("keeps the share active after %s", async (_name, arrange, readsStatus) => {
    arrange();
    const { root, history, live } = await clickRevoke();
    await vi.waitFor(() => expect(live.textContent).toBe(stillActive));
    expect(getPolicyRootStatusV3).toHaveBeenCalledTimes(readsStatus ? 1 : 0);
    expect(root.querySelector<HTMLButtonElement>('button[aria-label="Revoke retry-me.md"]')?.disabled).toBe(false);
    expect(root.querySelector(".sender-status-text.revoked")).toBeNull();
    expect((await history.records.get("retry-me"))?.revokedAt).toBeUndefined();
  });
});
