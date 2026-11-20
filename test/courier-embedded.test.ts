import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mountCourier } from "../src/courier/app.ts";
import { COURIER_EMBED_SCOPE, agentsSpaceOf, connectEmbedded, readOnlyStore, type EmbeddedSdk } from "../src/courier/embedded.ts";
import { EXT, keys } from "../src/courier/model.ts";
import { StoreError, type CourierKv } from "../src/courier/store.ts";
import { renderMarkdownInto } from "../src/viewer/render.ts";

const ONE = "https://tinycloud.one";
const OWNER = "0xabc0000000000000000000000000000000000001";
const SPACE = agentsSpaceOf({ ownerAddress: OWNER, chainId: 1 });
const THREAD = "01J9ZC4K7T3QZ5W6M8R2N1B010";
const MSG = "01J9ZC4K7T3QZ5W6M8R2N1B020";
const TASK = "01J9ZC4K7T3QZ5W6M8R2N1B022";
const REQ = "01J9ZC4K7T3QZ5W6M8R2N1B030";
const NOW = Date.parse("2026-10-20T12:00:00Z");
const HOSTILE = "# Hi\n\n<script>window.__pwned=1</script><img src=x onerror=\"window.__pwned=1\">\n\n[click me](javascript:window.__pwned=1) [out](https://evil.example/steal?x=1)\n\n<a href=\"https://evil.example\">raw</a>";

const request = { id: REQ, peer: "hunter", threadId: THREAD, taskId: TASK, verb: "merge", target: "tinycloudlabs/eliza#20", summary: "Docs-only README change", action: "gh pr merge 20", reason: "r", risk: "low", requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z", status: "pending" };

function mailbox(message = HOSTILE): Record<string, unknown> {
  return {
    [keys.thread("me", "hunter", THREAD, "meta", THREAD)]: { subject: "Release", createdAt: "2026-10-20T09:00:00Z" },
    [keys.thread("peer", "hunter", THREAD, "msg", MSG)]: { messageId: MSG, contextId: THREAD, role: "ROLE_USER", parts: [{ text: message, mediaType: "text/markdown" }], referenceTaskIds: [], metadata: { [EXT]: { intent: "request", from: { label: "hunter" } } } },
    [keys.thread("me", "hunter", THREAD, "task", TASK)]: { id: TASK, contextId: THREAD, status: { state: "TASK_STATE_AUTH_REQUIRED", timestamp: "2026-10-20T10:00:00Z" }, metadata: { [EXT]: {} } },
    [keys.request(REQ)]: request,
  };
}

interface Posted { message: Record<string, unknown>; targetOrigin: string }

/** A framed window under One, a fake SDK holding the owner's delegation, and a DelegatedAccess over `files`. */
function frame(files: Record<string, unknown>, options: { spaceId?: string; refuse?: boolean } = {}) {
  const posted: Posted[] = [];
  const parent = { postMessage: (message: Record<string, unknown>, targetOrigin: string) => { posted.push({ message, targetOrigin }); } };
  let listener: ((event: MessageEvent) => void) | undefined;
  const opened: unknown[][] = [];
  const win = {
    parent,
    location: { search: "?embed=one", pathname: "/courier/", origin: "https://share.tinycloud.xyz" },
    document: { referrer: `${ONE}/`, documentElement: { dataset: {} as Record<string, string> } },
    addEventListener: (_type: string, fn: (event: MessageEvent) => void) => { listener = fn; },
    removeEventListener: () => { listener = undefined; },
    open: (...args: unknown[]) => { opened.push(args); return null; },
  };
  const calls = { get: [] as { key: string; options: unknown }[], list: [] as { options: unknown }[], put: 0 };
  const kv = {
    get: async (key: string, getOptions: unknown) => {
      calls.get.push({ key, options: getOptions });
      if (options.refuse === true) return { ok: false, error: { code: "AUTH_UNAUTHORIZED", service: "kv", message: "nope", meta: { status: 401 } } };
      return key in files ? { ok: true, data: { data: files[key], headers: {} } } : { ok: false, error: { code: "KV_NOT_FOUND", service: "kv", message: "", meta: { status: 404 } } };
    },
    list: async (listOptions: unknown) => {
      calls.list.push({ options: listOptions });
      if (options.refuse === true) return { ok: false, error: { code: "AUTH_UNAUTHORIZED", service: "kv", message: "nope", meta: { status: 401 } } };
      return { ok: true, data: { keys: Object.keys(files), truncated: false } };
    },
    put: async () => { calls.put += 1; return { ok: true, data: { data: undefined, headers: {} } }; },
  };
  const access = { spaceId: options.spaceId ?? SPACE, kv };
  const used: unknown[] = [];
  const sdk: EmbeddedSdk = {
    client: { sessionDid: "did:key:z6Mkchild#z6Mkchild", useDelegation: async (delegation) => { used.push(delegation); return access as never; } },
    deserialize: (serialized) => JSON.parse(serialized),
  };
  const grantFor = (nonce: string, spaceId = SPACE, delegation: unknown = JSON.stringify({ ownerAddress: OWNER, chainId: 1 })) => ({
    v: 1, type: "tc-embed/grant", nonce, expiresAt: Date.now() + 3_600_000, theme: "dark",
    grants: [{ spaceId, delegation, cid: "bafy" }],
  });
  const deliver = (data: unknown, from: { origin?: string; source?: unknown } = {}): void => {
    listener?.({ data, origin: from.origin ?? ONE, source: "source" in from ? from.source : parent } as unknown as MessageEvent);
  };
  const embedded = connectEmbedded(win as unknown as Window, { loadSdk: async () => sdk });
  const nonceOf = (index: number): string => String(posted[index]?.message["nonce"]);
  return { embedded, posted, opened, calls, used, grantFor, deliver, win, nonceOf };
}

let root: HTMLElement;
beforeEach(() => {
  document.body.innerHTML = '<div id="root" aria-busy="true"></div>';
  root = document.querySelector<HTMLElement>("#root")!;
  Reflect.deleteProperty(window, "__pwned");
  HTMLDialogElement.prototype.showModal ??= function showModal(this: HTMLDialogElement) { this.setAttribute("open", ""); };
});
afterEach(() => { vi.restoreAllMocks(); });

async function mount(run: ReturnType<typeof frame>, deps: { renderBody?: (host: HTMLElement, markdown: string) => void; signIn?: () => Promise<never> } = {}): Promise<void> {
  mountCourier(root, {
    embedded: run.embedded!,
    embeddedWaitMs: 50,
    signIn: deps.signIn ?? (() => Promise.reject(new Error("OpenKey must not open inside the frame"))),
    renderBody: deps.renderBody ?? ((host, markdown) => { host.textContent = markdown; }),
    now: () => NOW,
  });
  await vi.waitFor(() => expect(run.posted).toHaveLength(1));
  run.deliver(run.grantFor(run.nonceOf(0)));
}

describe("embedded connection", () => {
  it("is null outside One's frame", () => {
    const run = frame({});
    const top = { ...run.win } as { parent: unknown };
    top.parent = top;
    expect(connectEmbedded(top as unknown as Window)).toBeNull();
    expect(connectEmbedded({ ...run.win, location: { ...run.win.location, search: "" } } as unknown as Window)).toBeNull();
    expect(connectEmbedded({ ...run.win, document: { ...run.win.document, referrer: "https://evil.example/" } } as unknown as Window)).toBeNull();
  });

  it("asks for kv get and list on the courier prefix of the agents space, and nothing else", () => {
    expect(COURIER_EMBED_SCOPE).toEqual([{ service: "tinycloud.kv", space: "agents", path: "xyz.tinycloud.courier/", actions: ["get", "list"] }]);
  });

  it("says hello with the session DID to One's exact origin, then reads the mailbox through the delegation with absolute keys", async () => {
    const run = frame(mailbox());
    await mount(run);
    expect(run.posted[0]?.targetOrigin).toBe(ONE);
    expect(run.posted[0]?.message).toMatchObject({ type: "tc-embed/hello", appId: "xyz.tinycloud.courier", sessionDid: "did:key:z6Mkchild#z6Mkchild" });
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    await vi.waitFor(() => expect(root.querySelector("[aria-busy=true].cr-panel")).toBeNull());
    expect(run.used).toHaveLength(1);
    expect(run.calls.list[0]?.options).toMatchObject({ prefix: "xyz.tinycloud.courier/" });
    expect(run.calls.get.length).toBeGreaterThan(0);
    for (const call of run.calls.get) {
      expect(call.key.startsWith("xyz.tinycloud.courier/")).toBe(true);
      expect(call.options).toMatchObject({ prefix: "" });
    }
    expect(root.querySelector(".sender-account")?.textContent).toContain(OWNER.slice(0, 6));
    expect(run.win.document.documentElement.dataset["theme"]).toBe("dark");
    // Only the contract's messages went to the parent.
    expect(run.posted.map((entry) => entry.message["type"])).toEqual(["tc-embed/hello"]);
  });

  it("ignores a delegation for a space that is not the owner's own agents space", async () => {
    const run = frame(mailbox());
    mountCourier(root, { embedded: run.embedded!, embeddedWaitMs: 5_000, signIn: () => Promise.reject(new Error("no")), renderBody: () => undefined, now: () => NOW });
    await vi.waitFor(() => expect(run.posted).toHaveLength(1));
    for (const spaceId of ["tinycloud:pkh:eip155:1:0xdef0000000000000000000000000000000000002:agents", `${SPACE}x`, "tinycloud:pkh:eip155:1:" + OWNER + ":secrets"]) {
      run.deliver(run.grantFor(run.nonceOf(run.posted.length - 1), spaceId));
      for (let turn = 0; turn < 20; turn += 1) await Promise.resolve();
    }
    expect(run.used).toHaveLength(0);
    expect(root.querySelector(".cr-tabs")).toBeNull();
  });

  it("asks once for exactly the courier scope when a grant carries no usable agents space, then ends", async () => {
    const run = frame(mailbox());
    mountCourier(root, { embedded: run.embedded!, embeddedWaitMs: 5_000, signIn: () => Promise.reject(new Error("no")), renderBody: () => undefined, now: () => NOW });
    await vi.waitFor(() => expect(run.posted).toHaveLength(1));
    run.deliver(run.grantFor(run.nonceOf(0), "tinycloud:pkh:eip155:1:" + OWNER + ":secrets"));
    await vi.waitFor(() => expect(run.posted).toHaveLength(2));
    expect(run.posted[1]?.message).toMatchObject({ type: "tc-embed/request", permissions: [{ service: "tinycloud.kv", space: "agents", path: "xyz.tinycloud.courier/", actions: ["get", "list"] }] });
    expect(run.posted[1]?.targetOrigin).toBe(ONE);
    run.deliver(run.grantFor(run.nonceOf(1), "tinycloud:pkh:eip155:1:" + OWNER + ":secrets"));
    await vi.waitFor(() => expect(root.querySelector(".auth-button")).not.toBeNull());
    expect(run.posted).toHaveLength(2);
  });

  it("asks once for exactly the courier scope when One holds nothing yet (an empty grant)", async () => {
    const run = frame(mailbox());
    mountCourier(root, { embedded: run.embedded!, embeddedWaitMs: 5_000, signIn: () => Promise.reject(new Error("no")), renderBody: () => undefined, now: () => NOW });
    await vi.waitFor(() => expect(run.posted).toHaveLength(1));
    run.deliver({ ...run.grantFor(run.nonceOf(0)), grants: [] });
    await vi.waitFor(() => expect(run.posted).toHaveLength(2));
    expect(run.posted[1]?.message).toMatchObject({ type: "tc-embed/request", permissions: COURIER_EMBED_SCOPE });
    expect(run.posted[1]?.targetOrigin).toBe(ONE);
    expect(run.used).toHaveLength(0);
  });

  it("a refused read (401) asks One once, and a denial returns the existing signed-out state", async () => {
    const run = frame(mailbox(), { refuse: true });
    await mount(run);
    await vi.waitFor(() => expect(run.posted.map((entry) => entry.message["type"])).toEqual(["tc-embed/hello", "tc-embed/request"]));
    expect(run.posted[1]?.message["permissions"]).toEqual(COURIER_EMBED_SCOPE);
    run.deliver({ v: 1, type: "tc-embed/denied", nonce: run.nonceOf(1) });
    await vi.waitFor(() => expect(root.querySelector(".auth-button")?.textContent).toBe("Continue with OpenKey"));
    expect(root.querySelector(".cr-tabs")).toBeNull();
  });

  it("revoke clears the session and shows the signed-out state; a late grant with the old nonce is dropped", async () => {
    const run = frame(mailbox());
    await mount(run);
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    run.deliver({ v: 1, type: "tc-embed/revoke" }, { origin: "https://evil.example" });
    expect(root.querySelector(".cr-tabs")).not.toBeNull();
    run.deliver({ v: 1, type: "tc-embed/revoke" });
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).toBeNull());
    expect(root.querySelector(".auth-button")).not.toBeNull();
    run.deliver(run.grantFor(run.nonceOf(0)));
    for (let turn = 0; turn < 20; turn += 1) await Promise.resolve();
    expect(root.querySelector(".cr-tabs")).toBeNull();
  });

  it("shows the signed-out state when One never answers", async () => {
    const run = frame(mailbox());
    mountCourier(root, { embedded: run.embedded!, embeddedWaitMs: 20, signIn: () => Promise.reject(new Error("no")), renderBody: () => undefined, now: () => NOW });
    await vi.waitFor(() => expect(root.querySelector(".auth-button")).not.toBeNull());
  });
});

describe("embedded mode is read-only", () => {
  it("the store refuses both writes and never touches kv put", async () => {
    const put = vi.fn();
    const store = readOnlyStore({ get: vi.fn(), list: vi.fn(), put } as unknown as CourierKv);
    await expect(store.createApproval({ requestId: REQ, requestHash: "0".repeat(64), decision: "approved", note: "", decidedAt: "2026-10-20T12:00:00.000Z" })).rejects.toBeInstanceOf(StoreError);
    await expect(store.writeOrders("hunter", "x", undefined)).rejects.toBeInstanceOf(StoreError);
    expect(put).not.toHaveBeenCalled();
  });

  it("Approve and Deny open this same path standalone in a new tab and write nothing", async () => {
    const run = frame(mailbox());
    await mount(run);
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    [...root.querySelectorAll<HTMLButtonElement>("[role=tab]")].find((tab) => tab.textContent?.startsWith("Needs you"))!.click();
    await vi.waitFor(() => expect(root.querySelector(".cr-approve")).not.toBeNull());
    expect(root.querySelector(".cr-approve")?.textContent).toBe("Approve");
    expect(root.querySelector(".cr-deny")?.textContent).toBe("Deny");
    expect(root.querySelector(".cr-note-input")).toBeNull();
    root.querySelector<HTMLButtonElement>(".cr-approve")!.click();
    root.querySelector<HTMLButtonElement>(".cr-deny")!.click();
    expect(run.opened).toEqual([
      ["https://share.tinycloud.xyz/courier/", "_blank", "noopener,noreferrer"],
      ["https://share.tinycloud.xyz/courier/", "_blank", "noopener,noreferrer"],
    ]);
    expect(run.calls.put).toBe(0);
  });

  it("Orders are read-only and Save opens the page standalone", async () => {
    const run = frame({ ...mailbox(), [keys.orders("hunter")]: "# My orders" });
    await mount(run);
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    [...root.querySelectorAll<HTMLButtonElement>("[role=tab]")].find((tab) => tab.textContent?.startsWith("Orders"))!.click();
    const text = await vi.waitFor(() => { const field = root.querySelector<HTMLTextAreaElement>(".cr-orders-input"); expect(field?.value).toBe("# My orders"); return field!; });
    expect(text.readOnly).toBe(true);
    const save = [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent === "Save orders")!;
    await vi.waitFor(() => expect(save.disabled).toBe(false));
    save.click();
    expect(run.opened).toHaveLength(1);
    expect(run.calls.put).toBe(0);
  });

  it("the signed-out Continue with OpenKey opens the page standalone and never starts a sign-in", async () => {
    const run = frame({});
    const signIn = vi.fn(() => Promise.reject(new Error("no")));
    mountCourier(root, { embedded: run.embedded!, embeddedWaitMs: 10, signIn, renderBody: () => undefined, now: () => NOW });
    await vi.waitFor(() => expect(root.querySelector(".auth-button")).not.toBeNull());
    root.querySelector<HTMLButtonElement>(".auth-button")!.click();
    expect(signIn).not.toHaveBeenCalled();
    expect(run.opened).toEqual([["https://share.tinycloud.xyz/courier/", "_blank", "noopener,noreferrer"]]);
  });

  it("offers no Sign out: One owns the session", async () => {
    const run = frame(mailbox());
    await mount(run);
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    expect(root.querySelector(".sender-signout")).toBeNull();
  });
});

describe("a peer's message is inert data in embedded mode", () => {
  it("renders HTML, script and links as inert text through the real renderer, as it does standalone, and posts none of it to the parent", async () => {
    const run = frame(mailbox());
    const rendered: Promise<void>[] = [];
    await mount(run, { renderBody: (host, markdown) => { rendered.push(renderMarkdownInto(host, markdown, "document")); } });
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    await vi.waitFor(() => expect(root.querySelector(".cr-thread-row, .cr-list li, .cr-thread-link, button.cr-row")).not.toBeNull());
    const open = root.querySelector<HTMLElement>(".cr-list li button, .cr-list li a, .cr-thread-link, button.cr-row")!;
    open.click();
    await vi.waitFor(() => expect(rendered.length).toBeGreaterThan(0));
    await Promise.all(rendered);

    const frames = [...root.querySelectorAll("iframe")];
    expect(frames.length).toBeGreaterThan(0);
    for (const preview of frames) {
      expect(preview.getAttribute("sandbox") ?? "").not.toContain("allow-scripts");
      const doc = preview.srcdoc;
      expect(doc).not.toMatch(/<script/i);
      expect(doc).not.toMatch(/onerror/i);
      expect(doc).not.toMatch(/javascript:/i);
      expect(doc).not.toMatch(/<img/i);
    }
    // Nothing from the message became live markup in the page itself.
    expect(root.querySelector("script, img, a[href^='javascript:'], [onerror]")).toBeNull();
    expect(Reflect.get(window, "__pwned")).toBeUndefined();
    // Nothing the mailbox holds went to the parent window.
    for (const entry of run.posted) expect(JSON.stringify(entry.message)).not.toMatch(/evil\.example|__pwned|hunter|Release/);
    expect(run.posted.map((entry) => entry.message["type"])).toEqual(["tc-embed/hello"]);
  });
});

describe("kv values: JSON stored as text, and values the SDK already parsed", () => {
  it("reads a mailbox whose files come back as text, the same as one that comes back parsed", async () => {
    const asText = Object.fromEntries(Object.entries(mailbox("plain")).map(([key, value]) => [key, JSON.stringify(value)]));
    const run = frame(asText);
    await mount(run);
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    await vi.waitFor(() => expect([...root.querySelectorAll("[role=tab]")].map((tab) => tab.textContent)).toContain("Needs you · 1"));
  });

  it("shows orders that look like JSON as the text they hold", async () => {
    const run = frame({ ...mailbox("plain"), [keys.orders("hunter")]: { rule: "ask first" } });
    await mount(run);
    await vi.waitFor(() => expect(root.querySelector(".cr-tabs")).not.toBeNull());
    [...root.querySelectorAll<HTMLButtonElement>("[role=tab]")].find((tab) => tab.textContent?.startsWith("Orders"))!.click();
    await vi.waitFor(() => expect(root.querySelector<HTMLTextAreaElement>(".cr-orders-input")?.value).toBe('{"rule":"ask first"}'));
  });
});
