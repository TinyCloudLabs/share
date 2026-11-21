/**
 * The vault refusing to decrypt while the list loads (the grant ended between the check and the read) shows the lock,
 * not an empty list. A record that is missing or damaged is still skipped.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { mountSenderHome, endSenderLibrary } from "../src/share/sender-home.js";
import { HistoryLockedError, SenderHistoryRepository } from "../src/share/sender-history.js";
import { historyLock } from "../src/share/history-unlock.js";
import { HISTORY_LOCKED, HISTORY_UNLOCK } from "../src/share/history-copy.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("@tinycloud/sdk-core", () => ({ revokePolicyRootV3: vi.fn(async () => ({})), EXPIRY: { SESSION_MS: 30 * 24 * 60 * 60 * 1000 } }));

afterEach(() => { endSenderLibrary(); document.body.replaceChildren(); vi.restoreAllMocks(); });

const ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";
const session = { address: ADDRESS } as unknown as OpenKeyShareSession;

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

/** A vault that lists one share and answers its read with `refusal`. */
function vaultAnswering(refusal: unknown): IDataVaultService {
  return {
    put: async () => ({ ok: true, data: undefined }),
    get: async () => ({ ok: false, error: refusal }),
    delete: async () => ({ ok: true, data: undefined }),
    listPage: async ({ prefix, removePrefix }: { prefix: string; removePrefix: boolean }) => ({ ok: true, data: { keys: [removePrefix ? "one" : `${prefix}one`], truncated: false } }),
  } as unknown as IDataVaultService;
}

const REFUSALS: ReadonlyArray<readonly [string, unknown]> = [
  ["permission denied", { code: "PERMISSION_DENIED", message: "refused" }],
  ["decrypt denied", { code: "DECRYPTION_FAILED", message: "refused", cause: { code: "DECRYPT_DENIED" } }],
];
const SKIPPED: ReadonlyArray<readonly [string, unknown]> = [
  ["missing", { code: "KEY_NOT_FOUND", key: "one" }],
  ["not found", { code: "NOT_FOUND", message: "missing" }],
  ["damaged", { code: "DECRYPTION_FAILED", message: "bad envelope", cause: new Error("bad") }],
  ["integrity", { code: "INTEGRITY_ERROR" }],
];

describe("the repository", () => {
  it.each(REFUSALS)("fails the page with HistoryLockedError when the vault says %s", async (_name, refusal) => {
    const history = new SenderHistoryRepository(vaultAnswering(refusal));
    await expect(history.page()).rejects.toBeInstanceOf(HistoryLockedError);
  });

  it.each(SKIPPED)("still skips a record that is %s", async (_name, refusal) => {
    const history = new SenderHistoryRepository(vaultAnswering(refusal));
    await expect(history.page()).resolves.toMatchObject({ items: [] });
  });
});

describe("the library when the vault refuses mid-load", () => {
  it.each(REFUSALS)("shows the lock, not an empty list or an error (%s), while the grant still looks live", async (_name, refusal) => {
    const root = document.createElement("div"); document.body.append(root);
    const tinycloud = { hasPermissions: vi.fn(() => true), requestPermissions: vi.fn(async () => ({ approved: true })) } as unknown as ShareTinyCloud;
    const history = new SenderHistoryRepository(vaultAnswering(refusal));
    mountSenderHome(root, { session, tinycloud, history, historyLock: historyLock(tinycloud, session), onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".sender-history-locked")!.hidden).toBe(false));
    const panel = root.querySelector<HTMLElement>(".sender-history-locked")!;
    expect(panel.textContent).toContain(HISTORY_LOCKED);
    expect([...panel.querySelectorAll("button")].map((button) => button.textContent)).toContain(HISTORY_UNLOCK);
    expect(root.querySelector<HTMLElement>(".sender-history-table")!.hidden).toBe(true);
    expect(root.querySelector<HTMLElement>(".sender-empty-state")!.hidden).toBe(true);
    expect(root.querySelector<HTMLElement>(".sender-status[role=alert]")!.hidden).toBe(true);
    expect(root.querySelectorAll(".sender-history-row")).toHaveLength(0);
  });

  it("a missing record is not a lock: the list is simply empty", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const tinycloud = { hasPermissions: vi.fn(() => true), requestPermissions: vi.fn(async () => ({ approved: true })) } as unknown as ShareTinyCloud;
    const history = new SenderHistoryRepository(vaultAnswering({ code: "KEY_NOT_FOUND", key: "one" }));
    mountSenderHome(root, { session, tinycloud, history, historyLock: historyLock(tinycloud, session), onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".sender-empty-state")!.hidden).toBe(false));
    expect(root.querySelector<HTMLElement>(".sender-history-locked")!.hidden).toBe(true);
  });
});
