import { afterEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { CHECK_AGAIN_LABEL, CHECK_STATUS_LABEL, endSenderLibrary, freshnessConfirmed, FRESHNESS_CHECKING, FRESHNESS_PARTIAL, FRESHNESS_TIMEOUT, FRESHNESS_UNCONFIRMED, mountSenderHome, REVOKE_CONFIRM_CAVEAT, REVOKE_CONFIRM_STORED, STATUS_CHECK_BUDGET_MS } from "../src/share/sender-home.js";
import { createNodeStatusReader, STATUS_REQUEST_TIMEOUT_MS, type NodeShareState, type NodeStatusReader } from "../src/share/node-status.js";
import { activeFlight, flightKey, resetRevokeFlights, RevokeFlight, withWalletApproval } from "../src/share/revoke-flight.js";
import { resetWalletApproval, trackWalletApproval, walletApprovalOpen } from "../src/share/wallet-approval.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

vi.mock("@tinycloud/sdk-core", () => ({ getPolicyRootStatusV3: vi.fn(async () => ({ state: "active" })), revokePolicyRootV3: vi.fn(async () => ({})), verifyEip191MessageSignature: async () => true }));

afterEach(() => { endSenderLibrary(); resetRevokeFlights(); resetWalletApproval(); document.body.replaceChildren(); vi.restoreAllMocks(); vi.useRealTimers(); });

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
    expect([...states].map(([id, status]) => [id, status.state])).toEqual([["a", "revoked"], ["b", "revoked"], ["c", "expired"], ["d", "active"]]);
  });

  it("uses the policy root of an addressed share, whose enforcement root the account does not list", async () => {
    const { read } = reader([grant("root-x", "xyz.tinycloud.share/shares/x/x.md", "revoked")]);
    expect((await read([addressed("x")])).get("x")?.state).toBe("revoked");
    const live = reader([grant("root-y", "xyz.tinycloud.share/shares/y/y.md", "active")]);
    expect((await live.read([addressed("y")])).get("y")?.state).toBe("active");
  });

  it("never reports a share it cannot find, or could not list, as active", async () => {
    expect((await reader([]).read([bearer("gone")])).get("gone")?.state).toBe("unknown");
    const down = reader([], { queryOk: false });
    expect((await down.read([bearer("a")])).get("a")?.state).toBe("unknown");
  });

  it("asks only about this account's shares on the node it is signed in to, and sends nothing for the rest", async () => {
    const foreign = bearer("f", "f.md", { target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: "tinycloud:pkh:eip155:1:0x9999999999999999999999999999999999999999:applications" } });
    const elsewhere = bearer("e", "e.md", { target: { origin: "https://other.example.invalid", nodeAudience: NODE.nodeDid, spaceId: SPACE } });
    const { read, query } = reader([]);
    const states = await read([foreign, elsewhere]);
    expect(query).not.toHaveBeenCalled();
    expect([...states.values()].map((status) => status.state)).toEqual(["unknown", "unknown"]);
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
const statesOf = (map: Record<string, NodeShareState>): NodeStatusReader => async (records) => new Map(records.map((record) => [record.shareId, { state: map[record.shareId] ?? "unknown" }]));

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

  it("shows the name the sender chose, not the safe name the file is stored under (TC-1610)", async () => {
    const { root } = await mount([bearer("a", "q3 report.md", { resource: { kind: "exact", path: "xyz.tinycloud.share/shares/a/q3-report.md" } })], undefined);
    const row = rowOf(root, "q3 report.md");
    expect(row.querySelector(".sender-item-cell strong")?.textContent).toBe("q3 report.md");
    expect(row.querySelector("button[aria-label='Open q3 report.md']")).not.toBeNull();
    expect(row.textContent).not.toContain("q3-report.md");
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
    // A named recipient cannot pass the share on, so the copy must not say anyone they passed it to loses access.
    expect(text).not.toContain("passed it to");
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
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked"));
    expect(rowOf(root, "a.md").querySelector(".sender-revoke")).toBeNull();
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



describe("TC-1584 the status read is bounded and one at a time", () => {
  const freshnessOf = (root: HTMLElement): string => root.querySelector(".sender-freshness")?.textContent ?? "";
  /** Mounts with a first check that answers at once, then switches the clock to fake time so the next check's deadline is exact. */
  async function mountThenHang(next: NodeStatusReader) {
    let behave: NodeStatusReader = statesOf({});
    const reader = vi.fn<NodeStatusReader>((records, signal) => behave(records, signal));
    const mounted = await mount([bearer("a", "a.md")], reader);
    const recheck = mounted.root.querySelector<HTMLButtonElement>(".sender-recheck")!;
    await vi.waitFor(() => expect(recheck.disabled).toBe(false));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behave = next;
    return { ...mounted, reader, recheck };
  }

  it("gives up on a node that does not answer in 20 seconds, says statuses may be out of date, and 'Check again' asks once more", async () => {
    let seen: AbortSignal | undefined;
    let hang = true;
    const { root, reader, recheck } = await mountThenHang((records, signal) => {
      if (!hang) return statesOf({ a: "active" })(records);
      seen = signal;
      return new Promise(() => undefined);
    });
    recheck.click();
    expect(freshnessOf(root)).toBe(FRESHNESS_CHECKING);
    expect(recheck.disabled).toBe(true);
    await vi.advanceTimersByTimeAsync(STATUS_CHECK_BUDGET_MS - 1);
    expect(freshnessOf(root)).toBe(FRESHNESS_CHECKING);
    expect(seen?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(2);
    expect(freshnessOf(root)).toBe(FRESHNESS_TIMEOUT);
    expect(freshnessOf(root)).toContain("may be out of date");
    expect(seen?.aborted).toBe(true);
    expect(recheck.disabled).toBe(false);
    expect(recheck.textContent).toBe(CHECK_AGAIN_LABEL);
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(rowOf(root, "a.md").querySelector<HTMLButtonElement>(".sender-revoke")?.disabled).toBe(false);
    // A node that stays silent is asked once, not again and again.
    const asked = reader.mock.calls.length;
    await vi.advanceTimersByTimeAsync(120_000);
    expect(reader).toHaveBeenCalledTimes(asked);
    hang = false;
    recheck.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(reader).toHaveBeenCalledTimes(asked + 1);
    expect(freshnessOf(root)).toMatch(/^Statuses confirmed with TinyCloud at /);
    expect(recheck.textContent).toBe(CHECK_STATUS_LABEL);
  });

  it("ignores an answer that arrives after the deadline", async () => {
    const late = deferred<ReadonlyMap<string, { readonly state: NodeShareState }>>();
    const { root, recheck } = await mountThenHang(() => late.promise);
    recheck.click();
    await vi.advanceTimersByTimeAsync(STATUS_CHECK_BUDGET_MS + 1);
    expect(freshnessOf(root)).toBe(FRESHNESS_TIMEOUT);
    late.resolve(new Map([["a", { state: "revoked" }]]));
    await vi.advanceTimersByTimeAsync(0);
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(freshnessOf(root)).toBe(FRESHNESS_TIMEOUT);
  });

  it("never has two status reads in flight: a focus or a second check while one is open waits for it", async () => {
    let open = 0; let mostOpen = 0;
    const gate = deferred<void>();
    const reader = vi.fn<NodeStatusReader>(async (records) => {
      open += 1; mostOpen = Math.max(mostOpen, open);
      await gate.promise;
      open -= 1;
      return statesOf({})(records);
    });
    const { root } = await mount([bearer("a", "a.md")], reader);
    await vi.waitFor(() => expect(reader).toHaveBeenCalledTimes(1));
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 60_000);
    window.dispatchEvent(new Event("focus")); window.dispatchEvent(new Event("focus"));
    document.dispatchEvent(new Event("visibilitychange"));
    await flush();
    expect(reader).toHaveBeenCalledTimes(1);
    expect(root.querySelector<HTMLButtonElement>(".sender-recheck")!.disabled).toBe(true);
    gate.resolve();
    // The rows may have changed while it was open: one follow-up read, after the first ended.
    await vi.waitFor(() => expect(reader).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>(".sender-recheck")!.disabled).toBe(false));
    expect(mostOpen).toBe(1);
  });
});

describe("TC-1584 what counts as confirmed", () => {
  const down = (rows: readonly Row[], over: Parameters<typeof fakeTinyCloud>[1] = {}): ShareTinyCloud => {
    const fake = fakeTinyCloud(rows, over);
    (fake.tinycloud as unknown as { activeNodeIdentity: () => Promise<never> }).activeNodeIdentity = async () => { throw new Error("no node"); };
    return fake.tinycloud;
  };
  const endless = (rows: readonly Row[]) => {
    const query = vi.fn(async () => ({ ok: true, data: { schemaVersion: 2, items: rows, nextCursor: "more" } }));
    const tinycloud = { ...fakeTinyCloud([]).tinycloud, delegations: { query } } as unknown as ShareTinyCloud;
    return { query, tinycloud };
  };

  it("a failed node lookup confirms nothing: every share stays unknown and no listing is read", async () => {
    const tinycloud = down([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "active")]);
    const states = await createNodeStatusReader(tinycloud, ADDRESS)([bearer("a")]);
    expect(states.get("a")?.state).toBe("unknown");
    expect(tinycloud.delegations.query).not.toHaveBeenCalled();
  });

  it("the library says statuses may be out of date when the node lookup failed, never that they were confirmed", async () => {
    const tinycloud = down([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "revoked")]);
    const { root } = await mount([bearer("a", "a.md")], createNodeStatusReader(tinycloud, ADDRESS));
    await vi.waitFor(() => expect(root.querySelector(".sender-freshness")?.textContent).toBe(FRESHNESS_UNCONFIRMED));
    expect(root.querySelector(".sender-freshness")?.textContent).toContain("may be out of date");
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(root.querySelector<HTMLButtonElement>(".sender-recheck")?.textContent).toBe(CHECK_AGAIN_LABEL);
  });

  it("a listing that was not read to its end never makes a share active, though it still shows a revocation it did read", async () => {
    const { query, tinycloud } = endless([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "active"), grant("cid-b", "xyz.tinycloud.share/shares/b/b.md", "revoked")]);
    const states = await createNodeStatusReader(tinycloud, ADDRESS)([bearer("a"), bearer("b")]);
    expect(query.mock.calls.length).toBeGreaterThan(1);
    expect(states.get("a")?.state).toBe("unknown");
    expect(states.get("b")?.state).toBe("revoked");
  });

  it("the library says statuses may be out of date for an incomplete listing, never 'confirmed'", async () => {
    const { tinycloud } = endless([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "active")]);
    const { root } = await mount([bearer("a", "a.md")], createNodeStatusReader(tinycloud, ADDRESS));
    await vi.waitFor(() => expect(root.querySelector(".sender-freshness")?.textContent).toBe(FRESHNESS_UNCONFIRMED));
    expect(root.querySelector(".sender-freshness")?.textContent).not.toMatch(/^Statuses confirmed/);
  });

  it("a revoke does not finish as Revoked when the node lookup fails; the row is Ready again with the reason", async () => {
    const { root } = await mount([bearer("a", "a.md")], undefined, { tinycloud: down([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "active")]) });
    root.querySelector<HTMLButtonElement>(".sender-revoke")!.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(root.querySelector(".sender-row-error")).not.toBeNull());
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(root.querySelector(".sender-live")?.textContent).not.toBe("Share revoked.");
    expect(root.querySelector<HTMLButtonElement>(".sender-revoke")?.disabled).toBe(false);
  });
});

describe("TC-1584 an expired share shows the earlier end, never a later saved date", () => {
  const endOf = (root: HTMLElement): string => root.querySelector(".status-expiry")?.textContent ?? "";
  const SAVED = "2099-10-27T01:23:00.000Z";

  it("reads the node's end from the listing, and none when the node gave none", async () => {
    const rows = [grant("cid-a", "xyz.tinycloud.share/shares/a/a.md", "expired", { expiresAt: new Date("2026-10-21T00:00:00.000Z") }), grant("cid-b", "xyz.tinycloud.share/shares/b/b.md", "expired")];
    const states = await createNodeStatusReader(fakeTinyCloud(rows).tinycloud, ADDRESS)([bearer("a"), bearer("b")]);
    expect(states.get("a")).toEqual({ state: "expired", expiredAt: "2026-10-21T00:00:00.000Z" });
    expect(states.get("b")).toEqual({ state: "expired" });
  });

  it("says just 'Expired' when the node did not say when, whatever date was saved", async () => {
    const { root } = await mount([bearer("a", "a.md", { expiresAt: SAVED })], statesOf({ a: "expired" }));
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Expired"));
    expect(endOf(root)).toBe("Expired");
  });

  it("shows the node's date when it is earlier than the saved one", async () => {
    const { root } = await mount([bearer("a", "a.md", { expiresAt: SAVED })], async () => new Map([["a", { state: "expired" as const, expiredAt: "2026-10-21T12:00:00.000Z" }]]));
    await vi.waitFor(() => expect(endOf(root)).toBe(`Expired ${new Date("2026-10-21T12:00:00.000Z").toLocaleDateString()}`));
  });

  it("shows the saved date when that is the earlier one", async () => {
    const { root } = await mount([bearer("a", "a.md", { expiresAt: "2026-10-22T12:00:00.000Z" })], async () => new Map([["a", { state: "expired" as const, expiredAt: "2026-11-30T12:00:00.000Z" }]]));
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Expired"));
    expect(endOf(root)).toBe(`Expired ${new Date("2026-10-22T12:00:00.000Z").toLocaleDateString()}`);
  });
});

describe("TC-1583 sign-out frees every in-flight guard", () => {
  const ok = (cid: string) => ({ ok: true, data: { revoked: true, cid } });
  const ADDRESS_B = "0x9999999999999999999999999999999999999999";
  const SPACE_B = `tinycloud:pkh:eip155:1:${ADDRESS_B}:applications`;
  const sessionOf = (address: string): OpenKeyShareSession => ({ address, openkey: { disconnect: vi.fn() } }) as unknown as OpenKeyShareSession;
  const recordB = (id: string): SenderShareRecord => bearer(id, `${id}.md`, { target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: SPACE_B } });
  const grantB = (id: string): Row => grant(`cid-${id}`, `xyz.tinycloud.share/shares/${id}/${id}.md`, "active", { resources: [{ resource: `${SPACE_B}/kv/xyz.tinycloud.share/shares/${id}/${id}.md`, actions: ["tinycloud.kv/get"], caveats: [] }] });
  /** What the page does when the sender signs out (main.ts), without the sign-in wall. */
  const signOut = (root: HTMLElement): void => { resetRevokeFlights(); resetWalletApproval(); endSenderLibrary(); root.remove(); };
  const revoke = (root: HTMLElement, name: string): void => {
    root.querySelector<HTMLButtonElement>(`button[aria-label="Revoke ${name}"]`)!.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
  };
  const hintOf = (root: HTMLElement): string | undefined => root.querySelector(".sender-row-hint")?.textContent ?? undefined;
  const HINT = "Approve in the OpenKey window to revoke";

  it("the next account's Revoke is not blocked, and a late answer from the abandoned approval changes nothing of theirs", async () => {
    const gateA = deferred<unknown>(); const gateB = deferred<unknown>();
    const fakeA = fakeTinyCloud([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md")], { revokeDelegation: () => trackWalletApproval(() => gateA.promise) });
    const first = await mount([bearer("a", "a.md")], undefined, { tinycloud: fakeA.tinycloud });
    revoke(first.root, "a.md");
    await vi.waitFor(() => expect(hintOf(first.root)).toBe(HINT));
    expect(walletApprovalOpen()).toBe(true);

    signOut(first.root);
    expect(walletApprovalOpen()).toBe(false);
    expect(activeFlight(flightKey(ADDRESS, "a"))).toBeUndefined();

    const fakeB = fakeTinyCloud([grantB("b1"), grantB("b2")], { revokeDelegation: (cid) => cid === "cid-b1" ? trackWalletApproval(() => gateB.promise) : ok(cid) });
    const second = await mount([recordB("b1"), recordB("b2")], undefined, { tinycloud: fakeB.tinycloud, session: sessionOf(ADDRESS_B) });
    revoke(second.root, "b1.md");
    await vi.waitFor(() => expect(hintOf(second.root)).toBe(HINT));
    expect(second.root.querySelector(".sender-row-note")).toBeNull();
    expect(fakeB.tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);

    // The first account's request answers late: it must not release the lock or the count that now belong to the second account.
    gateA.resolve(ok("cid-a"));
    await flush(); await flush();
    expect(walletApprovalOpen()).toBe(true);
    expect(hintOf(second.root)).toBe(HINT);
    expect(rowOf(second.root, "b1.md").querySelector(".status-label")?.textContent).toBe("Revoking…");
    revoke(second.root, "b2.md");
    await vi.waitFor(() => expect(second.root.querySelector(".sender-row-note")?.textContent).toContain("Another approval is waiting"));
    expect(fakeB.tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);

    gateB.resolve(ok("cid-b1"));
    await vi.waitFor(() => expect(rowOf(second.root, "b1.md").querySelector(".status-label")?.textContent).toBe("Revoked"));
    expect(walletApprovalOpen()).toBe(false);
    expect(second.root.querySelector(".sender-approval")).toBeNull();
  });

  it("the same account signing in again sees its share Ready, not stuck on Revoking…, and the old revoke's late end does not drop a new one", async () => {
    const gates = [deferred<unknown>(), deferred<unknown>()]; let call = 0;
    const fake = fakeTinyCloud([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md")], { revokeDelegation: () => trackWalletApproval(() => gates[call++]!.promise) });
    const first = await mount([bearer("a", "a.md")], undefined, { tinycloud: fake.tinycloud });
    revoke(first.root, "a.md");
    await vi.waitFor(() => expect(hintOf(first.root)).toBe(HINT));
    signOut(first.root);

    const second = await mount([bearer("a", "a.md")], undefined, { tinycloud: fake.tinycloud });
    expect(rowOf(second.root, "a.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(second.root.querySelector<HTMLButtonElement>(".sender-revoke")!.disabled).toBe(false);
    expect(second.root.querySelector(".sender-approval")).toBeNull();
    revoke(second.root, "a.md");
    await vi.waitFor(() => expect(hintOf(second.root)).toBe(HINT));
    const running = activeFlight(flightKey(ADDRESS, "a"));
    expect(running).toBeDefined();

    gates[0]!.resolve(ok("cid-a"));
    await flush(); await flush();
    expect(activeFlight(flightKey(ADDRESS, "a"))).toBe(running);
    expect(rowOf(second.root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoking…");
    gates[1]!.resolve(ok("cid-a"));
    await vi.waitFor(() => expect(rowOf(second.root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked"));
  });

  it("a revoke that was between steps at sign-out never reaches the wallet afterwards", async () => {
    const verify = deferred<void>();
    const rows = [grant("cid-a", "xyz.tinycloud.share/shares/a/a.md")];
    const fake = fakeTinyCloud(rows);
    (fake.tinycloud.delegations as unknown as { query: unknown }).query = vi.fn(async () => { await verify.promise; return { ok: true, data: { schemaVersion: 2, items: rows } }; });
    const { root } = await mount([bearer("a", "a.md")], undefined, { tinycloud: fake.tinycloud });
    revoke(root, "a.md");
    await vi.waitFor(() => expect(activeFlight(flightKey(ADDRESS, "a"))).toBeDefined());
    const flight = activeFlight(flightKey(ADDRESS, "a"))!;
    signOut(root);
    verify.resolve();
    const outcome = await flight.done;
    expect(outcome.revoked).toBe(false);
    expect((outcome.failure as Error).message).toBe("revoke-session-ended");
    expect(fake.tinycloud.revokeDelegation).not.toHaveBeenCalled();
    expect(walletApprovalOpen()).toBe(false);
  });

  it("signing out ends an open status check, and a focus afterwards asks nothing", async () => {
    const seen: AbortSignal[] = [];
    const reader = vi.fn<NodeStatusReader>((_records, signal) => { if (signal !== undefined) seen.push(signal); return new Promise(() => undefined); });
    const { root } = await mount([bearer("a", "a.md")], reader);
    await vi.waitFor(() => expect(reader).toHaveBeenCalledTimes(1));
    signOut(root);
    expect(seen[0]?.aborted).toBe(true);
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 60_000);
    window.dispatchEvent(new Event("focus"));
    await flush();
    expect(reader).toHaveBeenCalledTimes(1);
  });
});

describe("TC-1584 an aborted status read asks for nothing more", () => {
  it("stops paging through the listing once its signal has fired", async () => {
    const controller = new AbortController();
    const query = vi.fn(async () => {
      if (query.mock.calls.length === 2) controller.abort();
      return { ok: true, data: { schemaVersion: 2, items: [], nextCursor: "more" } };
    });
    const tinycloud = { ...fakeTinyCloud([]).tinycloud, delegations: { query } } as unknown as ShareTinyCloud;
    const states = await createNodeStatusReader(tinycloud, ADDRESS)([bearer("a")], controller.signal);
    expect(query).toHaveBeenCalledTimes(2);
    expect(states.get("a")?.state).toBe("unknown");
  });
});

describe("TC-1583 a revoke abandoned at sign-out cannot undo what the next sign-in took in the same moment", () => {
  const hang = (): Promise<never> => new Promise<never>(() => undefined);

  it("does not release the wallet lock the next sign-in holds", async () => {
    const abandoned = new RevokeFlight("0xa/a", (flight) => withWalletApproval(flight, hang));
    resetRevokeFlights(); resetWalletApproval();
    // The next sign-in takes the lock before the abandoned request has finished unwinding.
    const next = new RevokeFlight("0xb/b", (flight) => withWalletApproval(flight, hang));
    expect((await abandoned.done).failure).toEqual(new Error("revoke-session-ended"));
    const third = new RevokeFlight("0xb/c", (flight) => withWalletApproval(flight, async () => undefined));
    expect((await third.done).failure).toEqual(new Error("revoke-another-approval"));
    expect(activeFlight("0xb/b")).toBe(next);
  });

  it("does not drop a new revoke of the same share from the table", async () => {
    const abandoned = new RevokeFlight("0xa/same", (flight) => withWalletApproval(flight, hang));
    resetRevokeFlights();
    const next = new RevokeFlight("0xa/same", (flight) => withWalletApproval(flight, hang));
    await abandoned.done;
    expect(activeFlight("0xa/same")).toBe(next);
  });
});

describe("TC-1583 the Revoke button's accessible name contains its visible text", () => {
  it("reads 'Revoking a.md' while it says 'Revoking…', and 'Revoke a.md' again after a failed revoke", async () => {
    const gate = deferred<unknown>();
    const fake = fakeTinyCloud([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md")], { revokeDelegation: () => gate.promise, status: () => ({ ok: true, data: { cid: "cid-a", status: "active" } }) });
    const { root } = await mount([bearer("a", "a.md")], undefined, { tinycloud: fake.tinycloud });
    const button = root.querySelector<HTMLButtonElement>(".sender-revoke")!;
    button.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(button.textContent).toBe("Revoking…"));
    expect(button.getAttribute("aria-label")).toBe("Revoking a.md");
    gate.resolve({ ok: false, error: { code: "REVOCATION_FAILED", message: "HTTP 500" } });
    await vi.waitFor(() => expect(button.textContent).toBe("Revoke"));
    expect(button.getAttribute("aria-label")).toBe("Revoke a.md");
  });
});

/**
 * TC-1494. The node takes 1.5 to 3 seconds per call, and one status read is
 * several calls. Each call has its own limit; the whole read has a budget.
 */
describe("the status read is bounded per request and in all", () => {
  const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
  /** A node that answers the identity call and each page after `delayMs`; a page in `silent` never answers. */
  function slowNode(delayMs: number, pages: readonly (readonly Row[])[], silent: readonly number[] = []) {
    const query = vi.fn(async (request: { cursor?: string }) => {
      const index = request.cursor === undefined ? 0 : Number(request.cursor);
      if (silent.includes(index)) return new Promise<never>(() => undefined);
      await sleep(delayMs);
      return { ok: true, data: { schemaVersion: 2, items: pages[index] ?? [], ...(index + 1 < pages.length ? { nextCursor: String(index + 1) } : {}) } };
    });
    const tinycloud = { ...fakeTinyCloud([]).tinycloud, activeNodeIdentity: async () => { await sleep(delayMs); return NODE; }, delegations: { query } } as unknown as ShareTinyCloud;
    return { query, tinycloud };
  }
  const pageOf = (id: string, status: string): Row[] => [grant(`cid-${id}`, `xyz.tinycloud.share/shares/${id}/${id}.md`, status)];
  const freshnessOf = (root: HTMLElement): string => root.querySelector(".sender-freshness")?.textContent ?? "";
  async function mountThenSwitch(records: readonly SenderShareRecord[], next: NodeStatusReader) {
    let behave: NodeStatusReader = statesOf({});
    const mounted = await mount(records, (rows, signal) => behave(rows, signal));
    const recheck = mounted.root.querySelector<HTMLButtonElement>(".sender-recheck")!;
    await vi.waitFor(() => expect(recheck.disabled).toBe(false));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behave = next;
    return { ...mounted, recheck };
  }

  it("the reader: 3 seconds per call over 4 calls (12 s, past the old 4 s limit) completes with every status", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const { query, tinycloud } = slowNode(3_000, [pageOf("a", "active"), pageOf("b", "active"), pageOf("c", "revoked")]);
    let result: ReadonlyMap<string, { readonly state: NodeShareState }> | undefined;
    void createNodeStatusReader(tinycloud, ADDRESS)(["a", "b", "c"].map((id) => bearer(id))).then((states) => { result = states; });
    await vi.advanceTimersByTimeAsync(11_999);
    expect(result).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(query).toHaveBeenCalledTimes(3);
    expect([...result!].map(([id, status]) => [id, status.state])).toEqual([["a", "active"], ["b", "active"], ["c", "revoked"]]);
  });

  it("the reader: a call that does not answer in 8 seconds ends the read with what the earlier pages showed", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const { tinycloud } = slowNode(3_000, [pageOf("a", "revoked"), pageOf("b", "active")], [1]);
    let result: ReadonlyMap<string, { readonly state: NodeShareState }> | undefined;
    void createNodeStatusReader(tinycloud, ADDRESS)(["a", "b"].map((id) => bearer(id))).then((states) => { result = states; });
    await vi.advanceTimersByTimeAsync(6_000 + STATUS_REQUEST_TIMEOUT_MS - 1);
    expect(result).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    // The revoked share was on the page that arrived; the other is not called active from an unfinished listing.
    expect([...result!].map(([id, status]) => [id, status.state])).toEqual([["a", "revoked"], ["b", "unknown"]]);
  });

  it("the reader: an aborted read stops waiting at once and keeps what it had", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const { query, tinycloud } = slowNode(3_000, [pageOf("a", "revoked"), pageOf("b", "active")], [1]);
    const stop = new AbortController();
    let result: ReadonlyMap<string, { readonly state: NodeShareState }> | undefined;
    void createNodeStatusReader(tinycloud, ADDRESS)(["a", "b"].map((id) => bearer(id)), stop.signal).then((states) => { result = states; });
    await vi.advanceTimersByTimeAsync(7_000);
    expect(result).toBeUndefined();
    stop.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(result?.get("a")?.state).toBe("revoked");
    expect(query).toHaveBeenCalledTimes(2);
  });

  it("the library: a node at 3 seconds per call (12 s in all) ends 'confirmed', with no 'out of date' banner at any point", async () => {
    const { tinycloud } = slowNode(3_000, [pageOf("a", "active"), pageOf("b", "active"), pageOf("c", "revoked")]);
    const { root, recheck } = await mountThenSwitch([bearer("a", "a.md"), bearer("c", "c.md")], createNodeStatusReader(tinycloud, ADDRESS));
    recheck.click();
    expect(freshnessOf(root)).toBe(FRESHNESS_CHECKING);
    for (let second = 0; second < 12; second += 1) { await vi.advanceTimersByTimeAsync(1_000); expect(freshnessOf(root)).not.toContain("out of date"); }
    expect(freshnessOf(root)).toMatch(/^Statuses confirmed with TinyCloud at /);
    expect(rowOf(root, "c.md").querySelector(".status-label")?.textContent).toBe("Revoked");
    expect(recheck.textContent).toBe(CHECK_STATUS_LABEL);
  });

  it("the library: a node that gives nothing in 20 seconds says statuses may be out of date, and 'Check again' asks once more", async () => {
    let hang = true;
    const reader = (records: Parameters<NodeStatusReader>[0], signal?: AbortSignal) => hang ? new Promise<never>(() => undefined) : statesOf({ a: "active" })(records, signal);
    const { root, recheck } = await mountThenSwitch([bearer("a", "a.md")], reader);
    recheck.click();
    await vi.advanceTimersByTimeAsync(STATUS_CHECK_BUDGET_MS - 1);
    expect(freshnessOf(root)).toBe(FRESHNESS_CHECKING);
    await vi.advanceTimersByTimeAsync(2);
    expect(freshnessOf(root)).toBe(FRESHNESS_TIMEOUT);
    expect(recheck.textContent).toBe(CHECK_AGAIN_LABEL);
    hang = false;
    recheck.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(freshnessOf(root)).toMatch(/^Statuses confirmed with TinyCloud at /);
  });

  it("the library: a partial answer shows the rows that were read and a small note, not the 'did not answer' banner", async () => {
    // Identity 3 s, page 1 3 s (a is revoked), page 2 silent: its own 8 s limit ends the read at 14 s, inside the 20 s budget.
    const { tinycloud } = slowNode(3_000, [pageOf("a", "revoked"), pageOf("b", "active")], [1]);
    const { root, recheck } = await mountThenSwitch([bearer("a", "a.md"), bearer("b", "b.md")], createNodeStatusReader(tinycloud, ADDRESS));
    recheck.click();
    await vi.advanceTimersByTimeAsync(14_000);
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked");
    expect(rowOf(root, "b.md").querySelector(".status-label")?.textContent).toBe("Ready");
    expect(freshnessOf(root)).toBe(FRESHNESS_PARTIAL);
    expect(freshnessOf(root)).not.toBe(FRESHNESS_TIMEOUT);
    expect(recheck.textContent).toBe(CHECK_AGAIN_LABEL);
    expect(recheck.disabled).toBe(false);
  });

  it("the library: the budget ending mid-read keeps what had arrived", async () => {
    // A reader that honours the signal: at the budget it hands back the one answer it has.
    const reader: NodeStatusReader = (records, signal) => new Promise((resolve) => {
      signal?.addEventListener("abort", () => resolve(new Map(records.map((record) => [record.shareId, { state: record.shareId === "a" ? "revoked" : "unknown" } as const]))), { once: true });
    });
    const { root, recheck } = await mountThenSwitch([bearer("a", "a.md"), bearer("b", "b.md")], reader);
    recheck.click();
    await vi.advanceTimersByTimeAsync(STATUS_CHECK_BUDGET_MS);
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoked");
    expect(freshnessOf(root)).toBe(FRESHNESS_PARTIAL);
  });

  it("the library: a share the node already ended stays ended, and a later check that cannot reach the node leaves only a small note", async () => {
    let behave: NodeStatusReader = statesOf({ a: "expired" });
    const reader: NodeStatusReader = (records, signal) => behave(records, signal);
    const { root } = await mount([bearer("a", "a.md"), bearer("b", "b.md")], reader);
    const recheck = root.querySelector<HTMLButtonElement>(".sender-recheck")!;
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Expired"));
    await vi.waitFor(() => expect(recheck.disabled).toBe(false));
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    behave = () => new Promise(() => undefined);
    recheck.click();
    await vi.advanceTimersByTimeAsync(STATUS_CHECK_BUDGET_MS + 1);
    expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Expired");
    expect(freshnessOf(root)).toBe(FRESHNESS_PARTIAL);
  });
});

describe("TC-1583 the spoken region between the approval closing and the revoke ending", () => {
  it("is empty while the revoke is still being confirmed with the node, then says 'Share revoked.'", async () => {
    const check = deferred<unknown>();
    const fake = fakeTinyCloud([grant("cid-a", "xyz.tinycloud.share/shares/a/a.md")], { revokeDelegation: async () => ({ ok: false, error: { code: "REVOCATION_FAILED", message: "HTTP 500" } }), status: () => check.promise });
    const { root } = await mount([bearer("a", "a.md")], undefined, { tinycloud: fake.tinycloud, session: { address: ADDRESS, openkey: { disconnect: vi.fn() } } as unknown as OpenKeyShareSession });
    const spoken = (): string => root.querySelector(".sender-announce")?.textContent ?? "";
    root.querySelector<HTMLButtonElement>(".sender-revoke")!.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
    await vi.waitFor(() => expect(rowOf(root, "a.md").querySelector(".status-label")?.textContent).toBe("Revoking…"));
    await vi.waitFor(() => expect(root.querySelector(".sender-row-hint")).toBeNull());
    // Long enough for a statement queued when the approval opened to have been spoken.
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(spoken()).toBe("");
    check.resolve({ ok: true, data: { cid: "cid-a", status: "revoked" } });
    await vi.waitFor(() => expect(spoken()).toBe("Share revoked."));
  });
});
