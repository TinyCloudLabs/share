import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { freshnessConfirmed, FRESHNESS_UNCONFIRMED, mountSenderHome, REVOKE_CONFIRM_CAVEAT, REVOKE_CONFIRM_STORED } from "../src/share/sender-home.js";
import { createNodeStatusReader, type NodeShareState, type NodeStatusReader } from "../src/share/node-status.js";
import { resetRevokeFlights } from "../src/share/revoke-flight.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("@tinycloud/sdk-core", () => ({ getPolicyRootStatusV3: vi.fn(async () => ({ state: "active" })), revokePolicyRootV3: vi.fn(async () => ({})), verifyEip191MessageSignature: async () => true }));

afterEach(() => { resetRevokeFlights(); document.body.replaceChildren(); vi.restoreAllMocks(); vi.useRealTimers(); });

const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const NODE = { origin: "https://node.example.invalid", nodeDid: "did:key:z6MkNode" };
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;
const K1 = "did:key:z6MkCreatingSession";
const K2 = "did:key:z6MkLaterSession";

function vault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix }: { prefix: string; removePrefix: boolean }) => ({ ok: true, data: { keys: [...store.keys()].filter((key) => key.startsWith(prefix)).map((key) => removePrefix ? key.slice(prefix.length) : key), truncated: false } }),
  } as unknown as IDataVaultService;
}

const bearer = (id: string, filename = `${id}.md`, over: Partial<SenderShareRecord> = {}): SenderShareRecord => ({
  shareId: id,
  target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: SPACE },
  resource: { kind: "exact", path: `xyz.tinycloud.share/shares/${id}/${filename}` },
  actions: ["tinycloud.kv/get"],
  recipientMatcher: { kind: "bearer" },
  targetKind: "bearer",
  registeredAt: "2026-10-20T01:23:00.000Z",
  expiresAt: "2099-10-27T01:23:00.000Z",
  enforcementDelegationCid: `cid-${id}`,
  link: "https://share.example.invalid/viewer#tc1=opaque",
  filename,
  ...over,
});

const addressed = (id: string, over: Partial<SenderShareRecord> = {}): SenderShareRecord => ({
  ...bearer(id), recipientMatcher: { kind: "exactEmail", value: "person@example.invalid" }, targetKind: "email", ownerDelegationCid: `root-${id}`, enforcementDelegationCid: `enforce-${id}`, ownerDid: K1, ...over,
});

type Row = Record<string, unknown>;
const grant = (id: string, path: string, status = "active", over: Row = {}): Row => ({
  cid: id, direction: "granted", delegatorDid: K1, delegateDid: "did:key:z6MkShareKey",
  resources: [{ resource: `${SPACE}/kv/${path}`, actions: ["tinycloud.kv/get"], caveats: [] }],
  parents: ["session"], issuedAt: null, notBefore: null, expiresAt: null, status, ...over,
});

interface Fake { readonly query: ReturnType<typeof vi.fn>; readonly tinycloud: ShareTinyCloud }
function fakeTinyCloud(rows: readonly Row[], over: { queryOk?: boolean; revokeDelegation?: (cid: string) => unknown; status?: (cid: string) => unknown; node?: typeof NODE } = {}): Fake {
  const query = vi.fn(async () => over.queryOk === false
    ? { ok: false, error: { code: "NETWORK_ERROR", message: "down" } }
    : { ok: true, data: { schemaVersion: 2, items: rows } });
  const tinycloud = {
    credentialHolderDid: K2,
    activeNodeIdentity: async () => over.node ?? NODE,
    signSessionBytes: async () => new Uint8Array(64),
    revokeDelegation: vi.fn(async (cid: string) => over.revokeDelegation === undefined ? { ok: true, data: { revoked: true, cid } } : over.revokeDelegation(cid)),
    delegations: { query, status: vi.fn(async (cid: string) => over.status === undefined ? { ok: true, data: { cid, status: "active" } } : over.status(cid)) },
  } as unknown as ShareTinyCloud;
  return { query, tinycloud };
}

const flush = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));
function deferred<T>(): { readonly promise: Promise<T>; readonly resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("TC-1584 createNodeStatusReader", () => {
  const reader = (rows: readonly Row[], over: Parameters<typeof fakeTinyCloud>[1] = {}) => { const fake = fakeTinyCloud(rows, over); return { ...fake, read: createNodeStatusReader(fake.tinycloud, ADDRESS) }; };

  it("reads revoked, ancestor-revoked and expired from the node, and active only from a complete listing", async () => {
    const { read } = reader([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "revoked"), grant("cid-b", "xyz.tinycloud.share/shares/b/b.md", "ancestor_revoked"), grant("cid-c", "xyz.tinycloud.share/shares/c/c.md", "expired"), grant("cid-d", "xyz.tinycloud.share/shares/d/d.md", "active")]);
    const states = await read(["a", "b", "c", "d"].map((id) => bearer(id)));
    expect([...states]).toEqual([["a", "revoked"], ["b", "revoked"], ["c", "expired"], ["d", "active"]]);
  });

  it("uses the policy root of an addressed share, whose enforcement root the account does not list", async () => {
    const { read } = reader([grant("root-x", "xyz.tinycloud.share/shares/x/x.md", "revoked")]);
    expect((await read([addressed("x")])).get("x")).toBe("revoked");
    const live = reader([grant("root-y", "xyz.tinycloud.share/shares/y/y.md", "active")]);
    expect((await live.read([addressed("y")])).get("y")).toBe("active");
  });

  it("never reports a share it cannot find, or could not list, as active", async () => {
    expect((await reader([]).read([bearer("gone")])).get("gone")).toBe("unknown");
    const down = reader([], { queryOk: false });
    expect((await down.read([bearer("a")])).get("a")).toBe("unknown");
  });

  it("asks only about this account's shares on the node it is signed in to, and sends nothing for the rest", async () => {
    const foreign = bearer("f", "f.md", { target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: "tinycloud:pkh:eip155:1:0x9999999999999999999999999999999999999999:applications" } });
    const elsewhere = bearer("e", "e.md", { target: { origin: "https://other.example.invalid", nodeAudience: NODE.nodeDid, spaceId: SPACE } });
    const { read, query } = reader([]);
    const states = await read([foreign, elsewhere]);
    expect(query).not.toHaveBeenCalled();
    expect([...states.values()]).toEqual(["unknown", "unknown"]);
  });
});

async function mount(records: readonly SenderShareRecord[], statusReader: NodeStatusReader | undefined, extra: { tinycloud?: ShareTinyCloud; session?: OpenKeyShareSession } = {}) {
  const root = document.createElement("div"); document.body.append(root);
  const history = new SenderHistoryRepository(vault(), () => Date.parse("2026-10-20T04:00:00.000Z"));
  for (const record of records) await history.save(record);
  const tinycloud = extra.tinycloud ?? fakeTinyCloud([]).tinycloud;
  mountSenderHome(root, { session: extra.session ?? ({ address: ADDRESS, openkey: { disconnect: vi.fn() } } as unknown as OpenKeyShareSession), tinycloud, history, onNavigate: () => undefined, ...(statusReader === undefined ? {} : { statusReader }) });
  await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row").length).toBe(records.length));
  return { root, history, tinycloud };
}

const label = (root: HTMLElement, name: string): string => root.querySelector<HTMLElement>(`button[aria-label="Revoke ${name}"]`)?.closest("tr")?.querySelector(".status-label")?.textContent ?? "";
const rowOf = (root: HTMLElement, name: string): HTMLElement => Array.from(root.querySelectorAll<HTMLElement>(".sender-history-row")).find((row) => row.textContent?.includes(name))!;
const statesOf = (map: Record<string, NodeShareState>): NodeStatusReader => async (records) => new Map(records.map((record) => [record.shareId, map[record.shareId] ?? "unknown"]));

describe("TC-1584 library status comes from the node, not only from this browser", () => {
  it("shows a share the node reports revoked as Revoked, with no Revoke action, though the saved record says Ready", async () => {
    const { root } = await mount([bearer("a", "a.md"), bearer("b", "b.md")], statesOf({ a: "revoked", b: "active" }));
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked"));
    expect(rowOf(root, "a.md").querySelector(".sender-status-text")?.classList.contains("revoked")).toBe(true);
    expect(rowOf(root, "a.md").querySelector(".status-expiry")?.textContent).toBe("Access ended");
    expect(rowOf(root, "a.md").querySelector(".sender-revoke")).toBeNull();
    expect(rowOf(root, "b.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(rowOf(root, "b.md").querySelector(".sender-revoke")).not.toBeNull();
    await vi.waitFor(() => expect(root.querySelector(".sender-freshness")?.textContent).toMatch(/^Statuses confirmed with TinyCloud at /));
  });

  it("shows a share the node reports expired as Expired", async () => {
    const { root } = await mount([bearer("a", "a.md")], statesOf({ a: "expired" }));
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Expired"));
  });

  it("says plainly that statuses may be out of date when the node cannot confirm them, and keeps Ready rows usable", async () => {
    const { root } = await mount([bearer("a", "a.md")], async () => { throw new Error("offline"); });
    await vi.waitFor(() => expect(root.querySelector(".sender-freshness")?.textContent).toBe(FRESHNESS_UNCONFIRMED));
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(rowOf(root, "a.md").querySelector<HTMLButtonElement>(".sender-revoke")?.disabled).toBe(false);
  });

  it("does not promise anything when no status reader is given", async () => {
    const { root } = await mount([bearer("a", "a.md")], undefined);
    expect(root.querySelector<HTMLElement>(".sender-freshness")!.hidden).toBe(true);
    expect(root.querySelector<HTMLElement>(".sender-recheck")!.hidden).toBe(true);
  });

  it("asks again on 'Check status' and when the sender comes back to the tab", async () => {
    let answer: Record<string, NodeShareState> = { a: "active" };
    const reader = vi.fn<NodeStatusReader>(async (records) => statesOf(answer)(records));
    const { root } = await mount([bearer("a", "a.md")], reader);
    await vi.waitFor(() => expect(reader).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>(".sender-recheck")!.disabled).toBe(false));
    answer = { a: "revoked" };
    root.querySelector<HTMLButtonElement>(".sender-recheck")!.click();
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked"));
    expect(reader).toHaveBeenCalledTimes(2);

    // Back in the tab within 15 s: no new request. After that: a new one.
    const now = Date.now();
    window.dispatchEvent(new Event("focus")); await flush();
    expect(reader).toHaveBeenCalledTimes(2);
    vi.spyOn(Date, "now").mockReturnValue(now + 20_000);
    window.dispatchEvent(new Event("focus"));
    await vi.waitFor(() => expect(reader).toHaveBeenCalledTimes(3));
  });

  it("stops listening for tab focus once the library is mounted again", async () => {
    const first = vi.fn<NodeStatusReader>(async (records) => statesOf({})(records));
    const { root } = await mount([bearer("a", "a.md")], first);
    await vi.waitFor(() => expect(first).toHaveBeenCalledTimes(1));
    const second = vi.fn<NodeStatusReader>(async (records) => statesOf({})(records));
    const history = new SenderHistoryRepository(vault(), () => Date.now()); await history.save(bearer("a", "a.md"));
    mountSenderHome(root, { session: { address: ADDRESS, openkey: {} } as unknown as OpenKeyShareSession, tinycloud: fakeTinyCloud([]).tinycloud, history, onNavigate: () => undefined, statusReader: second });
    await vi.waitFor(() => expect(second).toHaveBeenCalledTimes(1));
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 60_000);
    window.dispatchEvent(new Event("focus"));
    await vi.waitFor(() => expect(second).toHaveBeenCalledTimes(2));
    expect(first).toHaveBeenCalledTimes(1);
  });

  it("formats the confirmation time", () => {
    expect(freshnessConfirmed(new Date("2026-10-20T04:05:00"))).toMatch(/^Statuses confirmed with TinyCloud at .*\.$/);
  });
});

describe("TC-1423 library rows: audience and kind", () => {
  it("labels an HTML, JSX and TSX file as an artifact, a document as a file, and a folder as a folder", async () => {
    const { root } = await mount([bearer("h", "page.html"), bearer("j", "app.jsx"), bearer("t", "app.tsx"), bearer("m", "notes.md"), bearer("f", "docs-folder", { resource: { kind: "prefix", path: "xyz.tinycloud.share/shares/f/" } })], undefined);
    const kind = (name: string): string => rowOf(root, name).querySelector(".sender-item-type")?.textContent ?? "";
    expect(kind("page.html")).toBe("Artifact · HTML");
    expect(kind("app.jsx")).toBe("Artifact · JSX");
    expect(kind("app.tsx")).toBe("Artifact · TSX");
    expect(kind("notes.md")).toBe("File");
    expect(kind("docs-folder")).toBe("Folder");
  });

  it("names the audience of every share", async () => {
    const { root } = await mount([bearer("a", "a.md"), addressed("p"), addressed("d", { recipientMatcher: { kind: "emailDomain", value: "example.com" } })], undefined);
    expect(rowOf(root, "a.md").querySelector(".sender-audience")?.textContent).toBe("Anyone with link");
    expect(rowOf(root, "p.md").querySelector(".sender-audience")?.textContent).toBe("Only p***@example.invalid");
    expect(rowOf(root, "d.md").querySelector(".sender-audience")?.textContent).toBe("Anyone at example.com");
  });
});

describe("TC-1423/TC-1583 revoke confirmation copy", () => {
  it("for a link: cuts off whoever it was passed to, says the stored copy stays, and warns that a link holder can revoke", async () => {
    const { root } = await mount([bearer("a", "a.md")], undefined);
    root.querySelector<HTMLButtonElement>(".sender-revoke")!.click();
    const text = root.querySelector(".sender-confirm-dialog")?.textContent ?? "";
    expect(text).toContain("Everyone who has the link loses access right away, including anyone they passed it to");
    expect(text).toContain(REVOKE_CONFIRM_STORED);
    expect(text).toContain(REVOKE_CONFIRM_CAVEAT);
    expect(text).toContain("Share can't delete it yet");
    expect(text).not.toMatch(/\b(?:node|space|delegation|capabilit)/i);
  });

  it("for a named recipient: no link-holder warning, still says the stored copy stays", async () => {
    const { root } = await mount([addressed("p")], undefined);
    root.querySelector<HTMLButtonElement>(".sender-revoke")!.click();
    const text = root.querySelector(".sender-confirm-dialog")?.textContent ?? "";
    expect(text).not.toContain(REVOKE_CONFIRM_CAVEAT);
    expect(text).toContain(REVOKE_CONFIRM_STORED);
  });
});

describe("TC-1583/5 revoke approval hint lifecycle in the library", () => {
  const rows = [grant("cid-a", "xyz.tinycloud.share/shares/a/a.md")];
  async function startRevoke(over: Parameters<typeof fakeTinyCloud>[1], disconnect = vi.fn()) {
    const fake = fakeTinyCloud(rows, over);
    const mounted = await mount([bearer("a", "a.md")], undefined, { tinycloud: fake.tinycloud, session: { address: ADDRESS, openkey: { disconnect } } as unknown as OpenKeyShareSession });
    mounted.root.querySelector<HTMLButtonElement>(".sender-revoke")!.click();
    mounted.root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    return { ...mounted, fake, disconnect };
  }

  it("shows the hint with Cancel while the wallet window is open; Cancel closes the OpenKey window", async () => {
    const gate = deferred<unknown>();
    const { root, disconnect } = await startRevoke({ revokeDelegation: () => gate.promise });
    await vi.waitFor(() => expect(root.querySelector(".sender-row-hint")?.textContent).toBe("Approve in the OpenKey window to revoke"));
    root.querySelector<HTMLButtonElement>(".sender-approval-cancel")!.click();
    expect(disconnect).toHaveBeenCalledTimes(1);
    gate.resolve({ ok: true, data: { revoked: true, cid: "cid-a" } });
    await vi.waitFor(() => expect(label(root, "a.md")).toBe(""));
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked");
  });

  it("removes the hint when the approval closes even though the revoke is still finishing, and never beside 'Share revoked.'", async () => {
    const check = deferred<unknown>();
    const { root } = await startRevoke({
      revokeDelegation: async () => ({ ok: false, error: { code: "REVOCATION_FAILED", message: "HTTP 500" } }),
      status: () => check.promise,
    });
    await vi.waitFor(() => expect(root.querySelector(".sender-row-hint")).toBeNull());
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoking…"));
    // The node confirms the revocation: the row finishes, with no hint.
    check.resolve({ ok: true, data: { cid: "cid-a", status: "revoked" } });
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked"));
    expect(root.querySelector(".sender-live")?.textContent).toBe("Share revoked.");
    expect(root.querySelector(".sender-approval")).toBeNull();
    expect(root.querySelector(".sender-row-hint")).toBeNull();
  });

  it("leaves no hint after a failed revoke, and the row is Ready again with its Revoke action", async () => {
    const { root } = await startRevoke({ revokeDelegation: async () => ({ ok: false, error: { code: "REVOCATION_FAILED", message: "HTTP 500" } }), status: () => ({ ok: true, data: { cid: "cid-a", status: "active" } }) });
    await vi.waitFor(() => expect(root.querySelector(".sender-row-error")).not.toBeNull());
    expect(root.querySelector(".sender-approval")).toBeNull();
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(root.querySelector<HTMLButtonElement>(".sender-revoke")?.disabled).toBe(false);
  });
});


