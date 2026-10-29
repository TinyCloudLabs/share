import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { endSenderLibrary, FRESHNESS_UNCONFIRMED, mountSenderHome } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import type { NodeStatusReader } from "../src/share/node-status.js";
import { readFileSync } from "node:fs";

afterEach(() => { endSenderLibrary(); document.body.replaceChildren(); vi.restoreAllMocks(); });

const NOW = Date.parse("2026-10-20T04:00:00.000Z");
const id = (index: number): string => `share-${String(index).padStart(3, "0")}`;
const names = (count: number): string[] => Array.from({ length: count }, (_, index) => `${id(count - index - 1)}.md`);
const rows = (root: HTMLElement): HTMLTableRowElement[] => [...root.querySelectorAll<HTMLTableRowElement>(".sender-history-row")];
const rowNames = (root: HTMLElement): Array<string | null> => rows(root).map((row) => row.querySelector("strong")!.textContent);
const more = (root: HTMLElement): HTMLButtonElement => root.querySelector<HTMLButtonElement>(".sender-load-more")!;
const alert = (root: HTMLElement): HTMLElement => root.querySelector<HTMLElement>('[role="alert"]')!;

async function library(count: number, statusReader?: NodeStatusReader) {
  const store = new Map<string, unknown>();
  let beforeGet: (key: string) => Promise<void> = async () => undefined;
  const vault = {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => { await beforeGet(key); return store.has(key) ? { ok: true, data: store.get(key) } : { ok: false }; },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix, cursor }: { prefix: string; removePrefix: boolean; cursor?: string }) => {
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix)).sort();
      const start = Number(cursor ?? 0);
      const selected = keys.slice(start, start + 10);
      const truncated = start + selected.length < keys.length;
      return { ok: true, data: { keys: selected.map((key) => removePrefix ? key.slice(prefix.length) : key), truncated, ...(truncated ? { nextCursor: String(start + selected.length) } : {}) } };
    },
  } as unknown as IDataVaultService;
  const history = new SenderHistoryRepository(vault, () => NOW);
  for (let index = 0; index < count; index += 1) {
    const shareId = id(index);
    const record: SenderShareRecord = {
      shareId,
      target: { origin: "https://node.example.invalid", nodeAudience: "did:key:node", spaceId: "space-1" },
      resource: { kind: "exact", path: `${shareId}.md` },
      actions: ["tinycloud.kv/get"], recipientMatcher: { kind: "bearer" }, targetKind: "bearer",
      registeredAt: new Date(NOW - (count - index) * 60_000).toISOString(),
      expiresAt: "2026-12-01T00:00:00.000Z", filename: `${shareId}.md`,
      ownerDelegationCid: `cid-${shareId}`, link: "https://share.example.invalid/viewer#tc1=synthetic",
    };
    await history.save(record);
  }
  const page = vi.spyOn(history, "page");
  const root = document.createElement("div"); document.body.append(root);
  mountSenderHome(root, {
    session: { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession,
    tinycloud: {} as unknown as ShareTinyCloud, history,
    onNavigate: () => undefined, onSendAgain: () => undefined,
    ...(statusReader === undefined ? {} : { statusReader }),
  });
  await vi.waitFor(() => expect(rowNames(root)).toEqual(names(count).slice(0, 25)));
  return { root, history, page, onGet: (read: typeof beforeGet) => { beforeGet = read; } };
}

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}

describe("TC-1740 sender pagination", () => {
  it("renders Load more only while a next page remains", async () => {
    const { root } = await library(44);
    const style = document.createElement("style"); style.textContent = readFileSync("src/email-share/sender.css", "utf8"); root.prepend(style);
    expect(getComputedStyle(more(root)).display).not.toBe("none");
    more(root).click();
    await vi.waitFor(() => expect(rowNames(root)).toEqual(names(44)));
    expect(getComputedStyle(more(root)).display).toBe("none");
  });

  it.each([1, 25, 44, 51])("exhausts %i canonical shares without repeating a page", async (count) => {
    const { root } = await library(count);
    while (!more(root).hidden) {
      const firstNew = rows(root).length;
      more(root).click();
      await vi.waitFor(() => expect(rows(root).length).toBe(Math.min(firstNew + 25, count)));
      expect(document.activeElement).toBe(rows(root)[firstNew]);
    }
    expect(rowNames(root)).toEqual(names(count));
    expect(new Set(rowNames(root)).size).toBe(count);
    expect(more(root).hidden).toBe(true);
    const kept = rows(root);
    more(root).click();
    await vi.waitFor(() => expect(root.querySelector("[aria-busy]")).toBeNull());
    expect(rowNames(root)).toEqual(names(count));
    expect(rows(root)).toEqual(kept);
  });

  it("appends a delayed next page once when Load more is clicked twice", async () => {
    const { root, page, onGet } = await library(51);
    const held = gate();
    onGet(() => held.promise);
    const kept = rows(root);
    more(root).click(); more(root).click();
    expect(rows(root)).toEqual(kept);
    expect(root.querySelector("table")?.getAttribute("aria-busy")).toBe("true");
    held.release();
    await vi.waitFor(() => expect(rowNames(root)).toEqual(names(51).slice(0, 50)));
    expect(page.mock.calls.map(([cursor]) => cursor)).toEqual([undefined, "25"]);
    expect(rows(root).slice(0, 25)).toEqual(kept);
    expect(document.activeElement).toBe(rows(root)[25]);
    more(root).click();
    await vi.waitFor(() => expect(rowNames(root)).toEqual(names(51)));
    expect(more(root).hidden).toBe(true);
  });

  it("retains rows and node-confirmed revocation while Retry resumes the failed page", async () => {
    let firstStatus = true;
    const statusReader: NodeStatusReader = async (records) => {
      if (!firstStatus) throw new Error("synthetic status unavailable");
      firstStatus = false;
      return new Map(records.map((record) => [record.shareId, { state: record.shareId === id(43) ? "revoked" as const : "active" as const }]));
    };
    const { root, page, onGet } = await library(44, statusReader);
    const kept = rows(root);
    await vi.waitFor(() => expect(kept[0]!.querySelector(".status-label")?.textContent).toBe("Revoked"));
    const selected = kept[2]!.querySelector<HTMLButtonElement>("button")!;
    selected.focus();
    onGet(async () => { throw new Error("synthetic history unavailable"); });
    more(root).click();
    await vi.waitFor(() => expect(alert(root).hidden).toBe(false));
    expect(rowNames(root)).toEqual(names(44).slice(0, 25));
    expect(document.activeElement).toBe(selected);
    expect(root.querySelector("[aria-busy]")).toBeNull();
    expect(root.querySelector(".sender-freshness")?.textContent).toMatch(/^Statuses confirmed/);
    const held = gate();
    onGet(() => held.promise);
    alert(root).querySelector<HTMLButtonElement>("button")!.click();
    expect(rows(root)).toEqual(kept);
    expect(document.activeElement).toBe(selected);
    expect(alert(root).hidden).toBe(true);
    expect(root.querySelector(".sender-skeleton-row")).toBeNull();
    held.release();
    await vi.waitFor(() => expect(rowNames(root)).toEqual(names(44)));
    expect(page.mock.calls.map(([cursor]) => cursor)).toEqual([undefined, "25", "25"]);
    expect(rows(root).slice(0, 25)).toEqual(kept);
    expect(kept[0]!.querySelector(".status-label")?.textContent).toBe("Revoked");
    expect(kept[0]!.querySelector(".sender-revoke")).toBeNull();
    expect(more(root).hidden).toBe(true);
    expect(alert(root).hidden).toBe(true);
    await vi.waitFor(() => expect(root.querySelector(".sender-freshness")?.textContent).toBe("Some statuses may be out of date."));
    expect(root.textContent).not.toContain(FRESHNESS_UNCONFIRMED);
  });
});
