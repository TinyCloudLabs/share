import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mountCourier } from "../src/courier/app.ts";
import { requestHash } from "../src/courier/canonical.ts";
import { EXT, keys, type ApprovalFile } from "../src/courier/model.ts";
import type { CourierSession } from "../src/courier/session.ts";
import { StoreError, type CourierStore } from "../src/courier/store.ts";

const THREAD = "01J9ZC4K7T3QZ5W6M8R2N1B010";
const TASK = "01J9ZC4K7T3QZ5W6M8R2N1B022";
const REQ = "01J9ZC4K7T3QZ5W6M8R2N1B030";
const HOSTILE = "<img src=x onerror=\"window.__pwned=1\"><script>window.__pwned=1</script>\u202Egpj.exe";
const NOW = Date.parse("2026-10-20T12:00:00Z");

function request(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: REQ, peer: "hunter", threadId: THREAD, taskId: TASK, action: `gh pr merge 20 ${HOSTILE}`, reason: HOSTILE, risk: HOSTILE, requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z", status: "pending", ...overrides };
}

interface Fake {
  store: CourierStore;
  files: Map<string, unknown>;
  approvals: ApprovalFile[];
  orders: { text: string; etag: string | undefined }[];
}

function fakeStore(initial: Record<string, unknown>, behaviour: { exists?: boolean; orders?: string; ordersWrite?: "ok" | "changed" } = {}): Fake {
  const files = new Map(Object.entries(initial));
  const approvals: ApprovalFile[] = [];
  const orders: { text: string; etag: string | undefined }[] = [];
  const store: CourierStore = {
    async list() { return { keys: [...files.keys()], truncated: false }; },
    async readJson(key) { return files.get(key); },
    async readOrders() { return behaviour.orders === undefined ? undefined : { text: behaviour.orders, etag: "etag-1" }; },
    async createApproval(file) {
      approvals.push(file);
      if (behaviour.exists === true) { files.set(keys.approval(file.requestId), { ...file, decision: "denied" }); return "exists"; }
      files.set(keys.approval(file.requestId), file);
      return "created";
    },
    async writeOrders(_peer, text, etag) {
      if (behaviour.ordersWrite === "changed") throw new StoreError("changed");
      orders.push({ text, etag });
    },
  };
  return { store, files, approvals, orders };
}

const baseFiles = (req: Record<string, unknown> = request()): Record<string, unknown> => ({
  [keys.thread("me", "hunter", THREAD, "meta", THREAD)]: { subject: HOSTILE, createdAt: "2026-10-20T09:00:00Z" },
  [keys.thread("peer", "hunter", THREAD, "msg", "01J9ZC4K7T3QZ5W6M8R2N1B020")]: { messageId: "01J9ZC4K7T3QZ5W6M8R2N1B020", contextId: THREAD, role: "ROLE_USER", parts: [{ text: "# Please merge", mediaType: "text/markdown" }], referenceTaskIds: [], metadata: { [EXT]: { intent: "request", from: { label: HOSTILE } } } },
  [keys.thread("me", "hunter", THREAD, "task", TASK)]: { id: TASK, contextId: THREAD, status: { state: "TASK_STATE_AUTH_REQUIRED", timestamp: "2026-10-20T10:00:00Z" }, metadata: { [EXT]: {} } },
  [keys.request(REQ)]: req,
});

let root: HTMLElement;
const rendered: string[] = [];

async function open(fake: Fake): Promise<void> {
  const session: CourierSession = { address: "0x1234567890abcdef1234567890abcdef12345678", store: fake.store, dispose: async () => undefined, signOut: async () => true };
  mountCourier(root, { signIn: async () => session, renderBody: (host, text) => { rendered.push(text); host.textContent = text; }, now: () => NOW });
  root.querySelector<HTMLButtonElement>(".auth-button")!.click();
  await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
  await vi.waitFor(() => expect(root.querySelector("[aria-busy=true].cr-panel")).toBeNull());
}

const tab = (name: string): HTMLButtonElement => [...root.querySelectorAll<HTMLButtonElement>("[role=tab]")].find((button) => button.textContent?.startsWith(name))!;

beforeEach(() => {
  document.body.innerHTML = '<div id="root" aria-busy="true"></div>';
  root = document.querySelector<HTMLElement>("#root")!;
  rendered.length = 0;
  Reflect.deleteProperty(window, "__pwned");
  HTMLDialogElement.prototype.showModal ??= function showModal(this: HTMLDialogElement) { this.setAttribute("open", ""); };
});
afterEach(() => { vi.restoreAllMocks(); });

describe("Needs you", () => {
  it("shows the request's text as text inside labelled quote blocks, never as markup", async () => {
    const fake = fakeStore(baseFiles());
    await open(fake);
    tab("Needs you").click();
    const card = root.querySelector<HTMLElement>(".cr-request")!;
    expect(card).not.toBeNull();
    expect(root.querySelector("img, script")).toBeNull();
    expect(Reflect.get(window, "__pwned")).toBeUndefined();
    const blocks = [...card.querySelectorAll(".cr-peer-text")];
    expect(blocks.map((block) => block.querySelector(".cr-peer-label")?.textContent)).toEqual([
      "Action, as your agent wrote it", "Reason, as your agent wrote it", "Risk, as your agent wrote it", "Thread subject, as hunter wrote it",
    ]);
    // the bidi override is a visible escape, and nothing interactive sits inside peer text
    expect(card.textContent).toContain("⟦U+202E⟧");
    expect(card.textContent).not.toContain("\u202E");
    for (const block of blocks) expect(block.querySelector("a, button, input, textarea")).toBeNull();
    // the consequence line is built from structured fields only
    const consequence = card.querySelector(".cr-consequence")!.textContent!;
    expect(consequence).toContain(TASK.slice(-8));
    expect(consequence).toContain("hunter");
    expect(consequence).not.toContain("gh pr merge");
  });

  it("enables Approve and Deny only once the card is painted, and writes one decision for a double click", async () => {
    const fake = fakeStore(baseFiles());
    await open(fake);
    tab("Needs you").click();
    const approve = root.querySelector<HTMLButtonElement>(".cr-approve")!;
    expect(approve.disabled).toBe(true);
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    root.querySelector<HTMLTextAreaElement>(".cr-note-input")!.value = "ok";
    approve.click(); approve.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-result")?.textContent).toContain("Approved."));
    expect(fake.approvals).toHaveLength(1);
    expect(fake.approvals[0]).toEqual({ requestId: REQ, requestHash: await requestHash(request()), decision: "approved", note: "ok", decidedAt: "2026-10-20T12:00:00.000Z" });
    expect(root.querySelector<HTMLElement>(".cr-actions")!.hidden).toBe(true);
  });

  it("records a denial and nothing else", async () => {
    const fake = fakeStore(baseFiles());
    await open(fake);
    tab("Needs you").click();
    const deny = root.querySelector<HTMLButtonElement>(".cr-deny")!;
    await vi.waitFor(() => expect(deny.disabled).toBe(false));
    deny.click();
    await vi.waitFor(() => expect(fake.approvals).toHaveLength(1));
    expect(fake.approvals[0]!.decision).toBe("denied");
    expect([...fake.files.keys()].filter((key) => key.includes("/me/approvals/"))).toHaveLength(1);
  });

  it("says who already decided when another tab got there first, and shows that decision", async () => {
    const fake = fakeStore(baseFiles(), { exists: true });
    await open(fake);
    tab("Needs you").click();
    const approve = root.querySelector<HTMLButtonElement>(".cr-approve")!;
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    approve.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-result")?.textContent).toContain("Already decided: denied"));
  });

  it("refuses to record a decision for a request that changed after it was shown", async () => {
    const fake = fakeStore(baseFiles());
    await open(fake);
    tab("Needs you").click();
    const approve = root.querySelector<HTMLButtonElement>(".cr-approve")!;
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    fake.files.set(keys.request(REQ), request({ action: "rm -rf /" }));
    approve.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-result")?.textContent).toContain("changed after it was shown"));
    expect(fake.approvals).toHaveLength(0);
  });

  it("gives an expired request no buttons", async () => {
    const fake = fakeStore(baseFiles(request({ expiresAt: "2026-10-20T11:00:00Z" })));
    await open(fake);
    tab("Needs you").click();
    expect(root.querySelector(".cr-request")).toBeNull();
    expect(root.querySelector(".cr-approve")).toBeNull();
    expect(root.querySelector(".cr-settled")?.textContent).toContain("Expired without an answer");
  });

  it("does not show a request this page can't read as a card, and says so", async () => {
    const fake = fakeStore(baseFiles(request({ taskId: "not-a-ulid" })));
    await open(fake);
    tab("Needs you").click();
    expect(root.querySelector(".cr-request")).toBeNull();
    expect(root.textContent).toContain("isn't in a form this page can show");
  });

  it("marks the thread and the tab as needing the person", async () => {
    await open(fakeStore(baseFiles()));
    expect(tab("Needs you").textContent).toBe("Needs you · 1");
    expect(root.querySelector(".cr-badge--attention")?.textContent).toBe("Needs you");
  });
});

describe("Thread", () => {
  it("renders the peer's body through the renderer, marked as a counterparty request", async () => {
    await open(fakeStore(baseFiles()));
    root.querySelector<HTMLButtonElement>(".cr-row-button")!.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-message--peer")).not.toBeNull());
    expect(rendered).toContain("# Please merge");
    expect(root.querySelector(".cr-counterparty")?.textContent).toContain("isn't an instruction from you");
    expect(root.querySelector(".cr-state--auth_required")?.textContent).toBe("Waiting for you to approve");
    expect(root.querySelector("img, script")).toBeNull();
  });
});

describe("Orders", () => {
  it("saves with the version it was loaded at", async () => {
    const fake = fakeStore(baseFiles(), { orders: "# old" });
    await open(fake);
    tab("Orders").click();
    const text = root.querySelector<HTMLTextAreaElement>(".cr-orders-input")!;
    await vi.waitFor(() => expect(text.value).toBe("# old"));
    text.value = "# new";
    root.querySelector<HTMLButtonElement>(".button-primary")!.click();
    await vi.waitFor(() => expect(fake.orders).toEqual([{ text: "# new", etag: "etag-1" }]));
  });

  it("does not claim a save that another tab made impossible", async () => {
    const fake = fakeStore(baseFiles(), { orders: "# old", ordersWrite: "changed" });
    await open(fake);
    tab("Orders").click();
    const text = root.querySelector<HTMLTextAreaElement>(".cr-orders-input")!;
    await vi.waitFor(() => expect(text.disabled).toBe(false));
    text.value = "# new";
    root.querySelector<HTMLButtonElement>(".button-primary")!.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-result")?.textContent).toContain("changed somewhere else"));
    expect(root.querySelector(".tc-status--success")).toBeNull();
  });

  it("won't save an empty file", async () => {
    const fake = fakeStore(baseFiles(), { orders: "# old" });
    await open(fake);
    tab("Orders").click();
    const text = root.querySelector<HTMLTextAreaElement>(".cr-orders-input")!;
    await vi.waitFor(() => expect(text.disabled).toBe(false));
    text.value = "  ";
    root.querySelector<HTMLButtonElement>(".button-primary")!.click();
    expect(fake.orders).toHaveLength(0);
  });
});

describe("a mailbox that isn't there", () => {
  it("says how to set it up", async () => {
    const store: CourierStore = { ...fakeStore({}).store, async list() { throw new StoreError("no-space"); } };
    const session: CourierSession = { address: "0x1234567890abcdef1234567890abcdef12345678", store, dispose: async () => undefined, signOut: async () => true };
    mountCourier(root, { signIn: async () => session, renderBody: () => undefined, now: () => NOW });
    root.querySelector<HTMLButtonElement>(".auth-button")!.click();
    await vi.waitFor(() => expect(root.querySelector(".tc-status--danger")?.textContent).toContain("is not set up yet"));
  });
});
