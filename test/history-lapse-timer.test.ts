/**
 * The sent-shares list locks itself when the one-hour grant ends, without a click, and the ids read under the grant are
 * dropped. Fake timers drive the clock; the library, the repository and the lock are the real ones.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { defaultEncryptionNetworkForOwner, type SenderShareRecord } from "@tinycloud/share-sdk";
import { endSenderLibrary, mountSenderHome } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import { HISTORY_UNLOCK_MS, historyLock, type HistoryLock } from "../src/share/history-unlock.js";
import { HISTORY_UNLOCK } from "../src/share/history-copy.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("@tinycloud/sdk-core", () => ({ revokePolicyRootV3: vi.fn(async () => ({})), EXPIRY: { SESSION_MS: 30 * 24 * 60 * 60 * 1000 } }));

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const session = { address: ADDRESS } as unknown as OpenKeyShareSession;
const NETWORK = defaultEncryptionNetworkForOwner({ address: ADDRESS });

beforeEach(() => { vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] }); vi.setSystemTime(new Date("2026-07-27T00:00:00.000Z")); });
afterEach(() => { endSenderLibrary(); document.body.replaceChildren(); vi.useRealTimers(); vi.restoreAllMocks(); });

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

/** A client whose grant is live from the moment OpenKey approves until `grantMs` later. */
function fakeClient(grantMs: number) {
  const state = { liveUntil: 0 };
  const hasPermissions = vi.fn(() => Date.now() < state.liveUntil);
  const requestPermissions = vi.fn(async () => { state.liveUntil = Date.now() + grantMs; return { approved: true }; });
  return { state, hasPermissions, requestPermissions, client: { hasPermissions, requestPermissions } as unknown as ShareTinyCloud };
}

async function mount(fake: ReturnType<typeof fakeClient>) {
  const root = document.createElement("div"); document.body.append(root);
  const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
  await history.save(record("one"));
  const forget = vi.spyOn(history, "forgetIndex");
  const lock = historyLock(fake.client, session);
  const show = (): void => mountSenderHome(root, { session, tinycloud: fake.client, history, historyLock: lock, onNavigate: () => undefined, onSendAgain: () => undefined });
  show();
  return { root, forget, show, lock };
}

const unlockButton = (root: HTMLElement): HTMLButtonElement | undefined => [...root.querySelectorAll<HTMLButtonElement>(".sender-history-locked:not([hidden]) button")].find((button) => button.textContent === HISTORY_UNLOCK);
const rows = (root: HTMLElement): number => root.querySelectorAll(".sender-history-row").length;
const lockShown = (root: HTMLElement): boolean => !root.querySelector<HTMLElement>(".sender-history-locked")!.hidden;

async function unlock(root: HTMLElement): Promise<void> {
  unlockButton(root)!.click();
  await vi.waitFor(() => expect(rows(root)).toBe(1));
}

/** `vi.waitFor` moves the fake clock, so time is counted from the end the library was told of, not from the click. */
async function advanceToLapse(lock: HistoryLock, offsetMs: number): Promise<void> {
  await vi.advanceTimersByTimeAsync(lock.lapsesAt()! + offsetMs - Date.now());
}

describe("the grant ending while the list is open", () => {
  it("locks the list at the end of the hour with no click, and drops the ids it read", async () => {
    const fake = fakeClient(HISTORY_UNLOCK_MS);
    const { root, forget, lock } = await mount(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    await unlock(root);
    forget.mockClear();
    expect(lockShown(root)).toBe(false);
    expect(lock.lapsesAt()! - Date.now()).toBeLessThanOrEqual(HISTORY_UNLOCK_MS);
    expect(lock.lapsesAt()! - Date.now()).toBeGreaterThan(HISTORY_UNLOCK_MS - 1_000);

    await advanceToLapse(lock, -1);
    expect(rows(root)).toBe(1);
    expect(lockShown(root)).toBe(false);
    expect(forget).not.toHaveBeenCalled();

    await advanceToLapse(lock, 0);
    expect(lockShown(root)).toBe(true);
    expect(rows(root)).toBe(0);
    expect(unlockButton(root)).toBeDefined();
    expect(forget).toHaveBeenCalled();
  });

  it("looks again a moment later when the SDK's own end of the grant is a little behind", async () => {
    const fake = fakeClient(HISTORY_UNLOCK_MS + 1_500);
    const { root, lock } = await mount(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    await unlock(root);
    await advanceToLapse(lock, 0);
    expect(lockShown(root)).toBe(false);
    await advanceToLapse(lock, 2_000);
    expect(lockShown(root)).toBe(true);
  });

  it("is cleared when the library is left: nothing fires afterwards", async () => {
    const fake = fakeClient(HISTORY_UNLOCK_MS);
    const { root, forget, lock } = await mount(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    await unlock(root);
    forget.mockClear();
    const before = vi.getTimerCount();
    expect(before).toBeGreaterThan(0);
    endSenderLibrary();
    expect(vi.getTimerCount()).toBeLessThan(before);
    await advanceToLapse(lock, HISTORY_UNLOCK_MS);
    expect(forget).not.toHaveBeenCalled();
  });

  it("is armed again when the library is opened again during the grant, and for the time that is left", async () => {
    const fake = fakeClient(HISTORY_UNLOCK_MS);
    const { root, forget, show, lock } = await mount(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    await unlock(root);
    forget.mockClear();
    // To the composer and back, ten minutes in.
    await vi.advanceTimersByTimeAsync(600_000);
    endSenderLibrary();
    show();
    await vi.waitFor(() => expect(rows(root)).toBe(1));
    expect(unlockButton(root)).toBeUndefined();
    await advanceToLapse(lock, -1);
    expect(lockShown(root)).toBe(false);
    await advanceToLapse(lock, 0);
    expect(lockShown(root)).toBe(true);
    expect(forget).toHaveBeenCalled();
  });

  it("a fresh unlock after the lock schedules a new end", async () => {
    const fake = fakeClient(HISTORY_UNLOCK_MS);
    const { root, lock } = await mount(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    await unlock(root);
    await advanceToLapse(lock, 0);
    expect(lockShown(root)).toBe(true);

    await unlock(root);
    expect(fake.requestPermissions).toHaveBeenCalledTimes(2);
    expect(lockShown(root)).toBe(false);
    await advanceToLapse(lock, -1);
    expect(lockShown(root)).toBe(false);
    await advanceToLapse(lock, 0);
    expect(lockShown(root)).toBe(true);
  });

  it("asks for the network grant the same way as before", async () => {
    const fake = fakeClient(HISTORY_UNLOCK_MS);
    const { root } = await mount(fake);
    await vi.waitFor(() => expect(unlockButton(root)).toBeDefined());
    await unlock(root);
    expect(fake.requestPermissions).toHaveBeenCalledWith([{ service: "tinycloud.encryption", path: NETWORK, actions: ["decrypt"], skipPrefix: true }], { expiryMs: HISTORY_UNLOCK_MS });
  });
});
