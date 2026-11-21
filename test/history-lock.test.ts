import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { defaultEncryptionNetworkForOwner, type SenderShareRecord } from "@tinycloud/share-sdk";
import { mountSenderHome } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import { decryptNetworkPermission, HISTORY_UNLOCK_MS, historyLock } from "../src/share/history-unlock.js";
import { HISTORY_LOCKED, HISTORY_UNLOCK, HISTORY_UNLOCK_NOTE } from "../src/share/history-copy.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("@tinycloud/sdk-core", () => ({ revokePolicyRootV3: vi.fn(async () => ({})), EXPIRY: { SESSION_MS: 30 * 24 * 60 * 60 * 1000 } }));

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); });

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const session = { address: ADDRESS } as unknown as OpenKeyShareSession;
const DECRYPT_NETWORK = { service: "tinycloud.encryption", path: defaultEncryptionNetworkForOwner({ address: ADDRESS }), actions: ["decrypt"], skipPrefix: true };

function fakeVault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix }: { prefix: string; removePrefix: boolean }) => {
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix)).sort();
      return { ok: true, data: { keys: keys.map((key) => removePrefix ? key.slice(prefix.length) : key), truncated: false } };
    },
  } as unknown as IDataVaultService;
}

function record(shareId: string): SenderShareRecord {
  return {
    shareId,
    target: { origin: "https://share.example.invalid", nodeAudience: "did:web:node.example.invalid", spaceId: "space-1" },
    resource: { kind: "exact", path: `${shareId}.md` },
    actions: ["tinycloud.kv/get"],
    recipientMatcher: { kind: "exactEmail", value: "person@example.invalid" },
    targetKind: "email",
    registeredAt: "2026-07-24T12:00:00.000Z",
    expiresAt: "2026-07-31T12:00:00.000Z",
    enforcementDelegationCid: `delegation-${shareId}`,
    ownerDid: "did:pkh:eip155:1:0x1234567890abcdef",
    link: "https://share.example.invalid/viewer#tc1=opaque",
    filename: `${shareId}.md`,
  };
}

interface FakeClient {
  readonly state: { live: boolean; approve: boolean };
  readonly hasPermissions: Mock<() => boolean>;
  readonly requestPermissions: Mock<() => Promise<{ approved: boolean }>>;
  readonly client: ShareTinyCloud;
}

/** A client whose decrypt grant is live or not; `approve` is what OpenKey answers when asked. */
function fakeClient(options: { live: boolean; approve?: boolean }): FakeClient {
  const state = { live: options.live, approve: options.approve ?? true };
  const hasPermissions = vi.fn(() => state.live);
  const requestPermissions = vi.fn(async () => {
    if (state.approve) state.live = true;
    return { approved: state.approve };
  });
  return { state, hasPermissions, requestPermissions, client: { hasPermissions, requestPermissions } as unknown as ShareTinyCloud };
}

async function library(fake: FakeClient, extra: { readonly onSendAgain?: () => void } = {}) {
  const root = document.createElement("div"); document.body.append(root);
  const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
  await history.save(record("one"));
  const reads = { page: vi.spyOn(history, "page"), get: vi.spyOn(history.records, "get"), show: vi.spyOn(history, "show") };
  const mount = (): void => mountSenderHome(root, { session, tinycloud: fake.client, history, historyLock: historyLock(fake.client, session), onNavigate: () => undefined, onSendAgain: extra.onSendAgain ?? (() => undefined) });
  mount();
  return { root, reads, mount };
}

/** The Unlock button, only while the lock panel is showing. */
const unlockButton = (root: HTMLElement): HTMLButtonElement | undefined => [...root.querySelectorAll<HTMLButtonElement>(".sender-history-locked:not([hidden]) button")].find((button) => button.textContent === HISTORY_UNLOCK);
const rows = (root: HTMLElement): number => root.querySelectorAll(".sender-history-row").length;

describe("the sent-shares list while the decrypt grant is not live", () => {
  it("shows the lock with its three lines and reads nothing", async () => {
    const fake = fakeClient({ live: false });
    const { root, reads } = await library(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    const panel = unlockButton(root)!.closest<HTMLElement>(".sender-history-locked")!;
    expect(panel.hidden).toBe(false);
    expect(panel.getAttribute("role")).toBe("status");
    expect(panel.textContent).toContain(HISTORY_LOCKED);
    expect(panel.textContent).toContain(HISTORY_UNLOCK_NOTE);
    expect(unlockButton(root)!.tagName).toBe("BUTTON");
    expect(reads.page).not.toHaveBeenCalled();
    expect(rows(root)).toBe(0);
    expect(root.querySelector<HTMLElement>(".sender-history-table")!.hidden).toBe(true);
    expect(fake.requestPermissions).not.toHaveBeenCalled();
  });

  it("asks only when the button is pressed: OpenKey for decrypt on the network, for exactly one hour, then loads", async () => {
    const fake = fakeClient({ live: false });
    const { root, reads } = await library(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    expect(HISTORY_UNLOCK_MS).toBe(3_600_000);
    expect(decryptNetworkPermission(ADDRESS)).toEqual(DECRYPT_NETWORK);
    unlockButton(root)!.click();
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    expect(fake.requestPermissions).toHaveBeenCalledTimes(1);
    expect(fake.requestPermissions).toHaveBeenCalledWith([DECRYPT_NETWORK], { expiryMs: 3_600_000 });
    expect(reads.page).toHaveBeenCalledTimes(1);
    expect(root.querySelector<HTMLElement>(".sender-history-locked")!.hidden).toBe(true);
  });

  it("stays locked, keeps the button and shows no error when the request is declined", async () => {
    const fake = fakeClient({ live: false, approve: false });
    const { root, reads } = await library(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    unlockButton(root)!.click();
    await vi.waitFor(() => expect(fake.requestPermissions).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(unlockButton(root)!.disabled).toBe(false));
    expect(root.querySelector<HTMLElement>(".sender-history-locked")!.hidden).toBe(false);
    expect(root.querySelector('[role="alert"]:not([hidden])')).toBeNull();
    expect(reads.page).not.toHaveBeenCalled();
    expect(rows(root)).toBe(0);
  });

  it("stays locked when the OpenKey window is closed on the request", async () => {
    const fake = fakeClient({ live: false });
    fake.requestPermissions.mockRejectedValueOnce(new Error("closed"));
    const { root, reads } = await library(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    unlockButton(root)!.click();
    await vi.waitFor(() => expect(fake.requestPermissions).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(unlockButton(root)!.disabled).toBe(false));
    expect(root.querySelector<HTMLElement>(".sender-history-locked")!.hidden).toBe(false);
    expect(reads.page).not.toHaveBeenCalled();
    // And pressing it again asks again.
    unlockButton(root)!.click();
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    expect(fake.requestPermissions).toHaveBeenCalledTimes(2);
  });
});

describe("the sent-shares list while the decrypt grant is live", () => {
  it("loads at once, with no button and no request", async () => {
    const fake = fakeClient({ live: true });
    const { root, reads } = await library(fake);
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    expect(unlockButton(root)).toBeUndefined();
    expect(root.querySelector<HTMLElement>(".sender-history-locked")!.hidden).toBe(true);
    expect(reads.page).toHaveBeenCalledTimes(1);
    expect(fake.requestPermissions).not.toHaveBeenCalled();
  });

  it("stays unlocked when the sender leaves the library and comes back", async () => {
    const fake = fakeClient({ live: false });
    const { root, reads, mount } = await library(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    unlockButton(root)!.click();
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    // The composer replaces the library, then the library is mounted again.
    root.replaceChildren();
    mount();
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    expect(unlockButton(root)).toBeUndefined();
    expect(fake.requestPermissions).toHaveBeenCalledTimes(1);
    expect(reads.page).toHaveBeenCalledTimes(2);
  });

  it("shows the lock again, and reads nothing, once the grant has ended", async () => {
    const fake = fakeClient({ live: true });
    const { root, reads, mount } = await library(fake);
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    fake.state.live = false;
    // Coming back to the library after the grant ended.
    root.replaceChildren();
    reads.page.mockClear();
    mount();
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    expect(reads.page).not.toHaveBeenCalled();
    expect(rows(root)).toBe(0);
    // Pressing the button asks again and the list returns.
    unlockButton(root)!.click();
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    expect(fake.requestPermissions).toHaveBeenCalledTimes(1);
  });

  it("shows the lock when the sender returns to a tab whose grant ended", async () => {
    const fake = fakeClient({ live: true });
    const { root } = await library(fake);
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    fake.state.live = false;
    window.dispatchEvent(new Event("focus"));
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    expect(rows(root)).toBe(0);
  });
});

describe("rows that read a saved share, once the grant has ended", () => {
  async function lapsed() {
    const fake = fakeClient({ live: true });
    const onSendAgain = vi.fn();
    const mounted = await library(fake, { onSendAgain });
    await vi.waitFor(() => expect(rows(mounted.root)).toBe(1));
    mounted.reads.get.mockClear(); mounted.reads.show.mockClear();
    fake.state.live = false;
    return { ...mounted, fake, onSendAgain };
  }

  it("Copy link does not read; the lock shows", async () => {
    const { root, reads } = await lapsed();
    root.querySelector<HTMLButtonElement>('button[aria-label="Copy link for one.md"]')!.click();
    expect(reads.show).not.toHaveBeenCalled();
    expect(reads.get).not.toHaveBeenCalled();
    expect(unlockButton(root)).toBeDefined();
  });

  it("Open does not read; the lock shows", async () => {
    const { root, reads } = await lapsed();
    root.querySelector<HTMLButtonElement>('button[aria-label="Open one.md"]')!.click();
    expect(reads.show).not.toHaveBeenCalled();
    expect(unlockButton(root)).toBeDefined();
  });

  it("Send the link again does not read; the lock shows", async () => {
    const { root, reads, onSendAgain } = await lapsed();
    root.querySelector<HTMLButtonElement>(".sender-send-again")!.click();
    expect(reads.get).not.toHaveBeenCalled();
    expect(onSendAgain).not.toHaveBeenCalled();
    expect(unlockButton(root)).toBeDefined();
  });

  it("Revoke does not read or open its confirmation; the lock shows", async () => {
    const { root, reads } = await lapsed();
    root.querySelector<HTMLButtonElement>('button[aria-label="Revoke one.md"]')!.click();
    expect(root.querySelector(".sender-confirm-dialog")).toBeNull();
    expect(reads.get).not.toHaveBeenCalled();
    expect(unlockButton(root)).toBeDefined();
  });

  it("Revoke started before the grant ended does not read when it is confirmed after", async () => {
    const fake = fakeClient({ live: true });
    const { root, reads } = await library(fake);
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    root.querySelector<HTMLButtonElement>('button[aria-label="Revoke one.md"]')!.click();
    await vi.waitFor(() => expect(root.querySelector(".sender-confirm-dialog .sender-confirm-revoke")).not.toBeNull());
    fake.state.live = false;
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    expect(reads.get).not.toHaveBeenCalled();
  });
});
