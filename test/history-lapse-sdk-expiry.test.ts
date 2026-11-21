/**
 * When the unlocked list locks again: at the earliest end among the delegations the SDK issued for the grant, and only
 * without one at the requested hour from the moment the approval came back. Fake timers drive the clock; the library,
 * the repository, the lock and the step-up are the real ones.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { type SenderShareRecord } from "@tinycloud/share-sdk";
import { endSenderLibrary, mountSenderHome } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import { HISTORY_UNLOCK_MS, historyLock } from "../src/share/history-unlock.js";
import { HISTORY_UNLOCK } from "../src/share/history-copy.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("@tinycloud/sdk-core", () => ({ revokePolicyRootV3: vi.fn(async () => ({})), EXPIRY: { SESSION_MS: 30 * 24 * 60 * 60 * 1000 } }));

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const session = { address: ADDRESS } as unknown as OpenKeyShareSession;
const START = new Date("2026-07-27T00:00:00.000Z");

beforeEach(() => { vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] }); vi.setSystemTime(START); });
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

/**
 * A client whose grant is live from the approval until the earliest of the expiries it hands back (or, with none, until
 * `fallbackMs` later: what the node would do, which is the requested hour).
 */
function fakeClient(delegations: ReadonlyArray<{ expiry?: unknown }> | undefined, fallbackMs = HISTORY_UNLOCK_MS) {
  const state = { liveUntil: 0 };
  const hasPermissions = vi.fn(() => Date.now() < state.liveUntil);
  const requestPermissions = vi.fn(async () => {
    const ends = (delegations ?? []).map(({ expiry }) => expiry instanceof Date ? expiry.getTime() : typeof expiry === "string" ? Date.parse(expiry) : Number.NaN).filter(Number.isFinite);
    state.liveUntil = ends.length > 0 ? Math.min(...ends) : Date.now() + fallbackMs;
    return { approved: true, ...(delegations === undefined ? {} : { delegations }) };
  });
  return { hasPermissions, requestPermissions, client: { hasPermissions, requestPermissions } as unknown as ShareTinyCloud };
}

async function mountAndUnlock(fake: ReturnType<typeof fakeClient>) {
  const root = document.createElement("div"); document.body.append(root);
  const history = new SenderHistoryRepository(fakeVault(), () => START.getTime());
  await history.save(record("one"));
  const lock = historyLock(fake.client, session);
  mountSenderHome(root, { session, tinycloud: fake.client, history, historyLock: lock, onNavigate: () => undefined, onSendAgain: () => undefined });
  const button = (): HTMLButtonElement | undefined => [...root.querySelectorAll<HTMLButtonElement>(".sender-history-locked:not([hidden]) button")].find((candidate) => candidate.textContent === HISTORY_UNLOCK);
  await vi.waitFor(() => expect(button()).toBeDefined());
  button()!.click();
  await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row").length).toBe(1));
  const lockShown = (): boolean => !root.querySelector<HTMLElement>(".sender-history-locked")!.hidden;
  return { lock, lockShown };
}

/** Moves the clock to an absolute time (`vi.waitFor` also moves it, so offsets from the click would drift). */
const advanceTo = (at: number): Promise<unknown> => vi.advanceTimersByTimeAsync(at - Date.now());

describe("the lock shows again at the end the SDK gave the grant", () => {
  it("fires at an expiry earlier than the hour (the session ends first), not at +1h", async () => {
    const early = START.getTime() + 20 * 60_000;
    const { lock, lockShown } = await mountAndUnlock(fakeClient([{ expiry: new Date(early) }]));
    expect(lock.lapsesAt()).toBe(early);
    await advanceTo(early - 1);
    expect(lockShown()).toBe(false);
    await advanceTo(early);
    expect(lockShown()).toBe(true);
  });

  it("takes the earliest of several delegations", async () => {
    const soonest = START.getTime() + 15 * 60_000;
    const delegations = [{ expiry: new Date(START.getTime() + 50 * 60_000) }, { expiry: new Date(soonest) }, { expiry: new Date(START.getTime() + 30 * 60_000) }];
    const { lock, lockShown } = await mountAndUnlock(fakeClient(delegations));
    expect(lock.lapsesAt()).toBe(soonest);
    await advanceTo(soonest - 1);
    expect(lockShown()).toBe(false);
    await advanceTo(soonest);
    expect(lockShown()).toBe(true);
  });

  it("reads an expiry that arrives as an ISO string", async () => {
    const early = START.getTime() + 10 * 60_000;
    const { lock } = await mountAndUnlock(fakeClient([{ expiry: new Date(early).toISOString() }]));
    expect(lock.lapsesAt()).toBe(early);
  });

  it("ignores an expiry that cannot be read, and uses the ones that can", async () => {
    const usable = START.getTime() + 25 * 60_000;
    const { lock } = await mountAndUnlock(fakeClient([{ expiry: "not a date" }, { expiry: undefined }, { expiry: new Date(usable) }, { expiry: 12 }]));
    expect(lock.lapsesAt()).toBe(usable);
  });

  it("falls back to the requested hour from the moment the approval came back only when no delegation carries a usable expiry", async () => {
    for (const delegations of [undefined, [], [{ expiry: "nonsense" }, {}]]) {
      document.body.replaceChildren(); endSenderLibrary();
      vi.setSystemTime(START);
      const { lock, lockShown } = await mountAndUnlock(fakeClient(delegations));
      const at = lock.lapsesAt()!;
      expect(at - Date.now()).toBeLessThanOrEqual(HISTORY_UNLOCK_MS);
      expect(at - Date.now()).toBeGreaterThan(HISTORY_UNLOCK_MS - 1_000);
      await advanceTo(at - 1);
      expect(lockShown()).toBe(false);
      await advanceTo(at);
      expect(lockShown()).toBe(true);
    }
  });
});
