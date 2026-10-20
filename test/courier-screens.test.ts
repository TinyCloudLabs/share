import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mountCourier } from "../src/courier/app.ts";
import { requestHash } from "../src/courier/canonical.ts";
import { EXT, keys, type ApprovalFile } from "../src/courier/model.ts";
import type { CourierSession } from "../src/courier/session.ts";
import { StoreError, type CourierStore } from "../src/courier/store.ts";

const THREAD = "01J9ZC4K7T3QZ5W6M8R2N1B010";
const TASK = "01J9ZC4K7T3QZ5W6M8R2N1B022";
const REQ = "01J9ZC4K7T3QZ5W6M8R2N1B030";
const MARKUP = "<img src=x onerror=\"window.__pwned=1\"><script>window.__pwned=1</script>";
// A bidi override in a field the approval depends on makes the request unreviewable; in a label it is shown as a visible escape.
const HOSTILE = `${MARKUP}\u202Egpj.exe`;
const NOW = Date.parse("2026-10-20T12:00:00Z");

function request(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: REQ, peer: "hunter", threadId: THREAD, taskId: TASK, verb: "merge", target: "tinycloudlabs/eliza#20", summary: "Docs-only README change", action: `gh pr merge 20 ${MARKUP}`, reason: MARKUP, risk: MARKUP, requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z", status: "pending", ...overrides };
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
      "Action, as your agent wrote it", "Reason, as your agent wrote it", "Risk, as your agent wrote it", "Thread subject, as your agent wrote it",
    ]);
    // the bidi override is a visible escape, and nothing interactive sits inside peer text
    expect(card.textContent).toContain("⟦U+202E⟧");
    expect(card.textContent).not.toContain("\u202E");
    for (const block of blocks) expect(block.querySelector("a, button, input, textarea")).toBeNull();
    // what approving allows is a fixed sentence around the structured fields, never built from the free text
    // It is the owner's OWN agent that acts, for the peer (Opus B1): the sentence never says the peer's agent does.
    const line = card.querySelector(".cr-consequence")!;
    expect(line.querySelector(".cr-sentence")?.textContent).toBe("Approving lets your agent merge tinycloudlabs/eliza#20 for hunter:");
    expect(line.querySelector(".cr-summary")?.textContent).toBe("\u201CDocs-only README change\u201D");
    expect(line.textContent).not.toContain("gh pr merge");
    expect(line.textContent).not.toContain("hunter's agent");
    expect([...line.querySelectorAll("strong")].map((node) => node.textContent)).toEqual(["hunter"]);
    const target = line.querySelector("code")!;
    expect([target.textContent, target.getAttribute("dir")]).toEqual(["tinycloudlabs/eliza#20", "ltr"]);
    // the summary sits in its own box, not in the sentence
    expect(line.querySelector(".cr-sentence")?.contains(line.querySelector(".cr-summary"))).toBe(false);
    expect(line.querySelector(".cr-summary bdi")?.textContent).toBe("Docs-only README change");
    expect(card.textContent).toContain(TASK.slice(-8));
    // ids and the fingerprint are behind a disclosure, not in the card's copy
    const hash = await requestHash(request());
    const details = card.querySelector(".cr-details")!;
    expect(details.hasAttribute("open")).toBe(false);
    expect(details.textContent).toContain(REQ);
    expect(details.textContent).toContain(`first 8 digits: ${hash.slice(0, 8)}`);
    expect([...card.children].filter((child) => !child.classList.contains("cr-details")).map((child) => child.textContent).join(" ")).not.toContain(REQ);
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

  it("won't stamp a decision earlier than the request when this device's clock is behind it", async () => {
    const fake = fakeStore(baseFiles(request({ createdAt: "2026-10-20T12:30:00Z", expiresAt: "2026-10-21T12:30:00Z" })));
    await open(fake);
    tab("Needs you").click();
    const approve = root.querySelector<HTMLButtonElement>(".cr-approve")!;
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    approve.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-result")?.textContent).toContain("clock is earlier"));
    expect(fake.approvals).toHaveLength(0);
    await vi.waitFor(() => expect(approve.disabled).toBe(false)); // the person can fix the clock and try again
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

  it("won't save a note the agent side would refuse, and doesn't change it either", async () => {
    const fake = fakeStore(baseFiles());
    await open(fake);
    tab("Needs you").click();
    const approve = root.querySelector<HTMLButtonElement>(".cr-approve")!;
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    const note = root.querySelector<HTMLTextAreaElement>(".cr-note-input")!;
    note.value = "ok\u200Bgo";
    approve.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-result")?.textContent).toContain("can't be saved"));
    expect(fake.approvals).toHaveLength(0);
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    note.value = "ok\ngo, caf\u00E9";
    approve.click();
    await vi.waitFor(() => expect(fake.approvals).toHaveLength(1));
    expect(fake.approvals[0]!.note).toBe("ok\ngo, caf\u00E9"); // exactly as typed
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

  it("renders verb, target and summary as inert text: no markup, no link, no markdown", async () => {
    const fake = fakeStore(baseFiles(request({ verb: "other", target: "https://evil.example/<img src=x onerror=window.__pwned=1>", summary: "README.md / javascript:alert(1)" })));
    await open(fake);
    tab("Needs you").click();
    const line = root.querySelector(".cr-consequence")!;
    expect(line.querySelector(".cr-sentence")?.textContent).toBe("Approving lets your agent do something outside the usual kinds (other) with https://evil.example/<img src=x onerror=window.__pwned=1> for hunter:");
    expect(line.querySelector(".cr-summary")?.textContent).toBe("\u201CREADME.md / javascript:alert(1)\u201D");
    expect(line.querySelector("a, img, script, em")).toBeNull();
    expect(Reflect.get(window, "__pwned")).toBeUndefined();
    // `other` is never presented as an ordinary action
    expect(root.querySelector(".cr-request .tc-status--warning")?.textContent).toContain("isn't one of the usual kinds");
  });

  it("keeps right-to-left text in its own isolate so it can't reorder the sentence", async () => {
    const fake = fakeStore(baseFiles(request({ summary: "\u05D1\u05D3\u05D9\u05E7\u05D4 \u05E9\u05DC \u05DE\u05D6\u05D2" })));
    await open(fake);
    tab("Needs you").click();
    const line = root.querySelector(".cr-consequence")!;
    expect(line.querySelector("bdi")?.textContent).toBe("\u05D1\u05D3\u05D9\u05E7\u05D4 \u05E9\u05DC \u05DE\u05D6\u05D2");
    expect(line.querySelector("bdi")?.parentElement).toBe(line.querySelector(".cr-summary"));
    expect(line.querySelector("code")?.getAttribute("dir")).toBe("ltr");
  });

  const unreviewable: [string, Record<string, unknown>][] = [
    ["no verb", { verb: undefined }],
    ["a verb outside the set", { verb: "delete-everything" }],
    ["a verb in the wrong case", { verb: "Merge" }],
    ["no target", { target: undefined }],
    ["an empty target", { target: "" }],
    ["a target over the cap", { target: "x".repeat(201) }],
    ["a target with a line break", { target: "repo#1\nrepo#2" }],
    ["a target with a bidi override", { target: "repo#1\u202E2#oper" }],
    ["no summary", { summary: undefined }],
    ["a summary over the cap", { summary: "y".repeat(201) }],
    ["a summary that is not a string", { summary: ["a"] }],
    ["a summary with surrounding space", { summary: " padded " }],
    // invisible and look-alike characters (Opus B2): all refused, none repaired
    ["a summary hiding text in tag characters", { summary: `Docs only${String.fromCodePoint(0xe0061, 0xe0062)}` }],
    ["a summary with a zero-width space", { summary: "Docs\u200Bonly" }],
    ["a summary with a variation selector", { summary: "Docs only\uFE0F" }],
    ["a summary with a combining grapheme joiner", { summary: "Docs\u034Fonly" }],
    ["a summary with Khmer vowel fillers", { summary: "Docs\u17B4only" }],
    ["a summary that is not in NFC", { summary: "Cafe\u0301" }],
    ["a summary with stacked combining marks", { summary: `a${"\u0301".repeat(5)}` }],
    ["a summary with a lone surrogate", { summary: "Docs\uD800only" }],
    ["a summary with a private-use character", { summary: "Docs\uE000only" }],
    ["a summary with a bidi override", { summary: "Docs\u202Eylno" }],
    ["a target with a Cyrillic look-alike letter", { target: "TinyCloudLabs/\u0435liza#20" }],
    ["a merge target that is not owner/repo#N", { target: "just some words" }],
    ["a publish target in the wrong shape", { verb: "publish", target: "tinycloudlabs/eliza#20" }],
    ["an other target with no kind", { verb: "other", target: "no kind here" }],
    // the CLI's canonical spelling is the only one it accepts as stored (Opus N4)
    ["a merge target with leading zeros", { target: "tinycloudlabs/eliza#0139" }],
    ["a merge target of #00", { target: "tinycloudlabs/eliza#00" }],
    ["a merge PR number over 9 digits", { target: "tinycloudlabs/eliza#1234567890" }],
    ["a secrets target with a double space", { verb: "other", target: "secrets:A  bB" }],
    ["a workflow target with an upper-case repo", { verb: "other", target: "workflow:O/R:ci.yml" }],
    ["a summary holding markup punctuation", { summary: "**bold** [click](javascript:alert(1)) <script>window.__pwned=1</script>" }],
    // quotes could end the summary's quotation early (Opus N3)
    ["a summary with a straight double quote", { summary: 'docs fix" and also "nothing' }],
    ["a summary with curly quotes", { summary: "docs fix\u201D and also \u201Cnothing" }],
    ["a summary with a low double quote", { summary: "docs \u201Efix" }],
    ["a summary with angle quotes", { summary: "docs \u00ABfix\u00BB" }],
    ["a summary with a fullwidth quote", { summary: "docs \uFF02fix" }],
    // the last invisible filler (Opus N5)
    ["a summary with the Khitan small script filler", { summary: "Docs\u{16FE4}only" }],
    ["a summary with a Braille blank", { summary: "Docs\u2800only" }],
    ["a summary with an object replacement character", { summary: "Docs\uFFFConly" }],
    ["a summary with a musical null notehead", { summary: `Docs${String.fromCodePoint(0x1d159)}only` }],
    // the closed set of keys the CLI writes (Opus N2): what is hashed is what is shown
    ["an extra key", { sneaky: "approve everything" }],
    ["a missing status", { status: undefined }],
    ["a status that isn't pending", { status: "approved" }],
    ["an extra key inside requestedBy", { requestedBy: { owner: "did:pkh:x", agent: "did:key:y", role: "admin" } }],
    ["a requestedBy that isn't an object", { requestedBy: "did:key:y" }],
    ["a summary with a no-break space", { summary: "Docs\u00A0only" }],
    ["a summary with an ideographic space", { summary: "Docs\u3000only" }],
    ["an upper-case merge target (the CLI writes it lower-case)", { target: "TinyCloudLabs/eliza#20" }],
    ["a publish target without a version", { verb: "publish", target: "npm:@tinycloud/courier" }],
    ["a deploy target that isn't a known kind", { verb: "deploy", target: "ssh:prod-box" }],
  ];
  for (const [name, overrides] of unreviewable) {
    it(`shows a request with ${name} as unreviewable, without Approve or Deny`, async () => {
      const fake = fakeStore(baseFiles(request(overrides)));
      await open(fake);
      tab("Needs you").click();
      const card = root.querySelector<HTMLElement>(".cr-request")!;
      expect(card.textContent).toMatch(/doesn't say what it would approve|isn't exactly the request/);
      expect(card.querySelector(".cr-consequence, .cr-approve, .cr-deny, textarea, button")).toBeNull();
      expect(fake.approvals).toHaveLength(0);
    });
  }

  // A quoted field the approval depends on must be shown exactly or the request can't be decided: never shortened (Opus B1).
  const tail = " && gh pr merge 999 --admin";
  it("won't name a peer the request isn't matched to: a task the owner's agent never wrote for that peer and thread", async () => {
    const OTHER = "01J9ZC4K7T3QZ5W6M8R2N1B040";
    const cases: [string, Record<string, unknown>][] = [
      ["another peer", { peer: "mallory" }],
      ["another thread", { threadId: OTHER }],
      ["another task", { taskId: OTHER }],
    ];
    for (const [name, overrides] of cases) {
      document.body.innerHTML = '<div id="root" aria-busy="true"></div>';
      root = document.querySelector<HTMLElement>("#root")!;
      const fake = fakeStore(baseFiles(request(overrides)));
      await open(fake);
      tab("Needs you").click();
      const card = root.querySelector<HTMLElement>(".cr-request")!;
      expect(card.textContent, name).toContain("isn't in your mailbox for that conversation");
      expect(card.querySelector(".cr-consequence, .cr-approve, .cr-deny, button"), name).toBeNull();
      expect(card.textContent, name).not.toContain("mallory");
      expect(tab("Needs you").textContent, name).toBe("Needs you");
    }
  });

  it("shows every field the hash covers, in a collapsed list", async () => {
    await open(fakeStore(baseFiles()));
    tab("Needs you").click();
    const details = root.querySelector<HTMLElement>(".cr-request .cr-details")!;
    expect(details.hasAttribute("open")).toBe(false);
    const rows = Object.fromEntries([...details.querySelectorAll("dt")].map((term) => [term.textContent, term.nextElementSibling?.textContent]));
    expect(rows).toMatchObject({ Request: REQ, Thread: THREAD, Task: TASK, Status: "pending", "Filed by owner": "did:pkh:x", "Filed by agent": "did:key:y" });
    const hash = await requestHash(request());
    expect(rows[`Fingerprint (first 8 digits: ${hash.slice(0, 8)})`]).toBe(hash);
  });

  it("labels the thread subject by the side it came from", async () => {
    const files = baseFiles();
    delete files[keys.thread("me", "hunter", THREAD, "meta", THREAD)];
    files[keys.thread("peer", "hunter", THREAD, "meta", THREAD)] = { subject: "From the peer", createdAt: "2026-10-20T09:00:00Z" };
    await open(fakeStore(files));
    tab("Needs you").click();
    expect(root.querySelector(".cr-peer-subject .cr-peer-label")?.textContent).toBe("Thread subject, as hunter wrote it");
  });

  it("decides a request that has none of the optional free text, as the CLI's reader does", async () => {
    const files = baseFiles();
    const { action: _a, reason: _r, risk: _k, ...bare } = request();
    files[keys.request(REQ)] = bare;
    await open(fakeStore(files));
    tab("Needs you").click();
    expect(root.querySelector(".cr-approve")).not.toBeNull();
    expect(root.querySelector(".cr-peer-action, .cr-peer-reason, .cr-peer-risk")).toBeNull();
  });

  it("shows a long action in full and lets it be decided", async () => {
    const action = `gh pr merge 20 ${"x".repeat(640)}${tail}`;
    await open(fakeStore(baseFiles(request({ action }))));
    tab("Needs you").click();
    expect(root.querySelector(".cr-peer-action .cr-peer-body")?.textContent).toBe(action);
    expect(root.querySelector(".cr-approve")).not.toBeNull();
  });

  const unreviewableText: [string, Record<string, unknown>][] = [
    ["an action over the cap", { action: `gh pr merge 20 ${"x".repeat(2000)}${tail}` }],
    ["a reason over the cap", { reason: "r".repeat(2001) }],
    ["a risk over the cap", { risk: "k".repeat(2001) }],
    ["an action smuggling text in tag characters", { action: `gh pr merge 12${[..."also deploy"].map((letter) => String.fromCodePoint(0xe0000 + letter.charCodeAt(0))).join("")}` }],
    ["an action with a zero-width joiner", { action: "gh pr merge 12\u200D 99" }],
    ["a reason with a bidi override", { reason: "approved\u202Edetorppa" }],
    ["an action with a carriage return", { action: "gh pr merge 12\r&& rm -rf /" }],
    ["a risk that is not text", { risk: { nested: true } }],
    ["a hidden character in a field the card doesn't show (the whole request is swept)", { requestedBy: { owner: "did:pkh:x", agent: "did:key:y\u200B" } }],
    ["a hidden character in a key", { ["note\u200B"]: "x" }],
    ["an empty action", { action: "" }],
    ["an empty risk", { risk: "" }],
    ["a no-break space in a reason", { reason: "a\u00A0b" }],
  ];
  for (const [name, overrides] of unreviewableText) {
    it(`shows a request with ${name} as unreviewable, with what is hidden made visible`, async () => {
      const fake = fakeStore(baseFiles(request(overrides)));
      await open(fake);
      tab("Needs you").click();
      const card = root.querySelector<HTMLElement>(".cr-request")!;
      expect(card.textContent).toMatch(/too long or holds characters you can't see|isn't exactly the request/);
      expect(card.querySelector(".cr-consequence, .cr-approve, .cr-deny, textarea, button")).toBeNull();
      // what can't be seen is shown as an escape, not passed through
      expect(card.textContent).not.toMatch(/[\u200D\u202E\r]|[\u{E0000}-\u{E007F}]/u);
      expect(fake.approvals).toHaveLength(0);
    });
  }

  it("shows the tag-character escapes for a smuggled action", async () => {
    const smuggled = `gh pr merge 12${String.fromCodePoint(0xe0061)}`;
    await open(fakeStore(baseFiles(request({ action: smuggled }))));
    tab("Needs you").click();
    expect(root.querySelector(".cr-peer-action")?.textContent).toContain("⟦U+E0061⟧");
  });

  it("treats a field the hash can't cover as one unreviewable card and still shows every other request", async () => {
    const OTHER = "01J9ZC4K7T3QZ5W6M8R2N1B031";
    const DEEP = "01J9ZC4K7T3QZ5W6M8R2N1B032";
    let nested: unknown = 1;
    for (let level = 0; level < 70; level += 1) nested = { nested };
    const fake = fakeStore({
      ...baseFiles(),
      [keys.request(OTHER)]: request({ id: OTHER, extra: Infinity }),
      [keys.request(DEEP)]: request({ id: DEEP, extra: nested }),
    });
    await open(fake);
    tab("Needs you").click();
    expect(root.querySelector(".tc-status--danger")).toBeNull(); // the page did not fail to load
    const cards = [...root.querySelectorAll<HTMLElement>(".cr-request")];
    expect(cards).toHaveLength(3);
    const decidable = cards.filter((card) => card.querySelector(".cr-approve") !== null);
    expect(decidable).toHaveLength(1);
    const refused = cards.filter((card) => card.querySelector(".cr-approve") === null);
    for (const card of refused) expect(card.querySelector(".cr-card-title")?.textContent).toBe("Request can't be reviewed here");
    expect(tab("Needs you").textContent).toBe("Needs you · 1");
  });

  it("doesn't count a request that can't be decided as needing the person", async () => {
    await open(fakeStore(baseFiles(request({ verb: undefined }))));
    expect(tab("Needs you").textContent).toBe("Needs you");
    expect(root.querySelector(".cr-badge--attention")).toBeNull();
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

describe("what the page keeps and opens", () => {
  it("leaves no storage, cookie, address-bar change or network call behind after reading, deciding and saving", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const href = location.href;
    const fake = fakeStore(baseFiles(), { orders: "# old" });
    await open(fake);
    root.querySelector<HTMLButtonElement>(".cr-row-button")!.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-message--peer")).not.toBeNull());
    tab("Needs you").click();
    const approve = root.querySelector<HTMLButtonElement>(".cr-approve")!;
    await vi.waitFor(() => expect(approve.disabled).toBe(false));
    approve.click();
    await vi.waitFor(() => expect(fake.approvals).toHaveLength(1));
    tab("Orders").click();
    const text = root.querySelector<HTMLTextAreaElement>(".cr-orders-input")!;
    await vi.waitFor(() => expect(text.disabled).toBe(false));
    text.value = "# new";
    root.querySelector<HTMLButtonElement>(".button-primary")!.click();
    await vi.waitFor(() => expect(fake.orders).toHaveLength(1));
    expect([localStorage.length, sessionStorage.length, document.cookie, location.href]).toEqual([0, 0, "", href]);
    expect(fetchSpy).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("never turns mailbox text into a link", async () => {
    const files = baseFiles(request({ summary: "see https://evil.example/ and javascript:alert(1)", action: "open https://evil.example/x", reason: "mailto:a@b.c" }));
    files[keys.thread("peer", "hunter", THREAD, "msg", "01J9ZC4K7T3QZ5W6M8R2N1B020")] = { messageId: "01J9ZC4K7T3QZ5W6M8R2N1B020", contextId: THREAD, role: "ROLE_USER", parts: [{ url: "https://evil.example/file", name: "https://evil.example/file" }], referenceTaskIds: [], metadata: { [EXT]: { intent: "request", from: { label: "https://evil.example/" } } } };
    await open(fakeStore(files));
    root.querySelector<HTMLButtonElement>(".cr-row-button")!.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-message--peer")).not.toBeNull());
    tab("Needs you").click();
    expect(root.querySelectorAll("main a, main [href], main [src]")).toHaveLength(0);
  });
});

describe("a mailbox that isn't there", () => {
  it("says how to set it up", async () => {
    const store: CourierStore = { ...fakeStore({}).store, async list() { throw new StoreError("no-space"); } };
    const session: CourierSession = { address: "0x1234567890abcdef1234567890abcdef12345678", store, dispose: async () => undefined, signOut: async () => true };
    mountCourier(root, { signIn: async () => session, renderBody: () => undefined, now: () => NOW });
    root.querySelector<HTMLButtonElement>(".auth-button")!.click();
    await vi.waitFor(() => expect(root.querySelector(".tc-status--danger")?.textContent).toBe("No Courier space yet."));
    expect(root.querySelector(".cr-panel")?.textContent).toContain("Run tc courier init once on your machine, then reload this page.");
  });
});
