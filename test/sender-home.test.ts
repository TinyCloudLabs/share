import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { mountSenderHome, nodeReproducibleRevocationTime } from "../src/share/sender-home.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { buildShortLink } from "../src/short-links/codec.js";
import { API_ORIGIN, ISSUER_DID, mockLinks, SHARE_ORIGIN, signWithIssuer } from "./fixtures/link-material.js";

const { getPolicyRootStatusV3, revokePolicyRootV3 } = vi.hoisted(() => ({
  getPolicyRootStatusV3: vi.fn(async (): Promise<{ readonly state: "active" | "revoked" }> => ({ state: "active" })),
  revokePolicyRootV3: vi.fn(async () => ({})),
}));
vi.mock("@tinycloud/sdk-core", () => ({ getPolicyRootStatusV3, revokePolicyRootV3 }));

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); vi.useRealTimers(); });

type ListPage = { ok: boolean; data?: { keys: string[]; truncated: boolean; nextCursor?: string } };

/** `serverPageLimit` pages the key listing like the node does; `listing` replaces it so a test can fail or cycle it. */
function fakeVault(options: { readonly serverPageLimit?: number; readonly listing?: (cursor: string | undefined) => ListPage | Promise<ListPage> } = {}): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix, limit, cursor }: { prefix: string; removePrefix: boolean; limit: number; cursor?: string }) => {
      if (options.listing !== undefined) return options.listing(cursor);
      const keys = [...store.keys()].filter((key) => key.startsWith(prefix)).sort();
      const start = cursor === undefined ? 0 : Number(cursor);
      const size = Math.min(limit, options.serverPageLimit ?? limit);
      const truncated = start + size < keys.length;
      return { ok: true, data: { keys: keys.slice(start, start + size).map((key) => removePrefix ? key.slice(prefix.length) : key), truncated, ...(truncated ? { nextCursor: String(start + size) } : {}) } };
    },
  } as unknown as IDataVaultService;
}

function record(shareId: string, recipientMatcher: SenderShareRecord["recipientMatcher"] = { kind: "exactEmail", value: "person@example.invalid" }): SenderShareRecord {
  return {
    shareId,
    target: { origin: "https://share.example.invalid", nodeAudience: "did:web:node.example.invalid", spaceId: "space-1" },
    resource: { kind: "exact", path: `${shareId}.md` },
    actions: ["tinycloud.kv/get"],
    recipientMatcher,
    targetKind: recipientMatcher.kind === "exactEmail" ? "email" : recipientMatcher.kind === "emailDomain" ? "emailDomain" : recipientMatcher.kind === "recipientDid" ? "recipientDid" : "bearer",
    registeredAt: "2026-07-24T12:00:00.000Z",
    expiresAt: "2026-07-31T12:00:00.000Z",
    ...(recipientMatcher.kind === "bearer" ? {} : { enforcementDelegationCid: `delegation-${shareId}`, ownerDid: "did:pkh:eip155:1:0x1234567890abcdef" }),
    link: "https://share.example.invalid/viewer#tc1=opaque",
    filename: `${shareId}.md`,
  };
}

const session = { address: "0x1234567890abcdef" } as unknown as OpenKeyShareSession;

/** The Node's RFC 3339 formatter (the `time` crate): trailing zeros of the fraction are dropped. */
const nodeFormat = (text: string) => text.replace(/\.(\d*?)0*Z$/, (_match, digits: string) => digits.length > 0 ? `.${digits}Z` : "Z");

describe("TC-601 revocation time", () => {
  it("stamps every millisecond in a form the Node reproduces exactly, at most 1 ms late", () => {
    const refused: number[] = [];
    for (let millisecond = 0; millisecond < 1000; millisecond += 1) {
      const now = new Date(Date.UTC(2026, 9, 4, 6, 0, 0, millisecond));
      const stamp = nodeReproducibleRevocationTime(now);
      if (nodeFormat(stamp.toISOString()) !== stamp.toISOString()) refused.push(millisecond);
      expect(stamp.getTime() - now.getTime()).toBeGreaterThanOrEqual(0);
      expect(stamp.getTime() - now.getTime()).toBeLessThanOrEqual(1);
    }
    expect(refused).toEqual([]);
  });
});

/** Presses "Revoke share" in the in-page confirmation. */
function confirmInPage(root: HTMLElement): void {
  const button = root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke");
  if (button === null) throw new Error("no in-page revoke confirmation is open");
  button.click();
}

describe("sender home canonical lifecycle adapters", () => {
  it("uses target-aware revokeShare and persists only the affected record", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const vault = fakeVault();
    const history = new SenderHistoryRepository(vault, () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("revoke-me"));
    await history.save(record("leave-me", { kind: "recipientDid", value: "did:key:holder" }));
    const revokeDelegation = vi.fn(async () => ({ ok: true as const, data: {} }));
    // A native dialog that is dismissed (automation, embedded webview) must not matter.
    const nativeConfirm = vi.spyOn(window, "confirm").mockReturnValue(false);

    mountSenderHome(root, { session, tinycloud: {
      revokeDelegation,
      credentialHolderDid: "did:pkh:eip155:1:0x1234567890abcdef",
      activeNodeIdentity: async () => ({ origin: "https://share.example.invalid", nodeDid: "did:web:node.example.invalid" }),
      signSessionBytes: async () => new Uint8Array(64),
    } as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row")).toHaveLength(2));
    // Revoke at a millisecond ending in 0, which the Node would refuse as is.
    // waitFor's 50 ms ticks keep the last digit 0, so the nudge always runs.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-07-27T06:00:00.120Z"));
    root.querySelector<HTMLButtonElement>('button[aria-label="Revoke revoke-me.md"]')!.click();
    confirmInPage(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(revokeDelegation).not.toHaveBeenCalled();
    expect(revokePolicyRootV3).toHaveBeenCalledWith(expect.objectContaining({
      nodeOrigin: "https://share.example.invalid",
      nodeAudience: "did:web:node.example.invalid",
      rootCid: "delegation-revoke-me",
      targetRole: "policy-enforcement",
      ownerDid: "did:pkh:eip155:1:0x1234567890abcdef",
      now: expect.any(Date),
    }));
    // TC-601: the stamp Share hands the SDK survives the Node's formatter.
    const { now } = (revokePolicyRootV3.mock.calls.at(-1) as unknown as [{ readonly now: Date }])[0];
    expect(now.getUTCMilliseconds() % 10).toBe(1);
    expect(nodeFormat(now.toISOString())).toBe(now.toISOString());
    expect(root.querySelector('button[aria-label="Revoke leave-me.md"]')).not.toBeNull();
    expect(nativeConfirm).not.toHaveBeenCalled();
  });

  it("explains why an imported bearer link without delegation authority cannot be revoked", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("bearer", { kind: "bearer" }));
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelector("button.sender-revoke")).not.toBeNull());
    expect(root.querySelector<HTMLButtonElement>("button.sender-revoke")?.disabled).toBe(true);
    expect(root.querySelector<HTMLButtonElement>("button.sender-revoke")?.title).toContain("can't be revoked");
  });

  it("routes toolbar and empty-state actions without mounting a second composer", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    const onNavigate = vi.fn();
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".sender-empty-state")?.hidden).toBe(false));
    root.querySelector<HTMLButtonElement>('button:not(.sender-empty-import)')?.click();
    expect(onNavigate).toHaveBeenCalledWith("#/new");
    expect(root.querySelector(".composer-form")).toBeNull();
  });

  it("opens a stored share in the current tab without a popup handoff", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
    await history.save(record("open-me", { kind: "bearer" }));
    vi.spyOn(window, "open").mockReturnValue(window);
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelector<HTMLButtonElement>('button[aria-label="Open open-me.md"]')).not.toBeNull());
    root.querySelector<HTMLButtonElement>('button[aria-label="Open open-me.md"]')!.click();
    await vi.waitFor(() => expect(window.open).toHaveBeenCalled());
    expect(window.open).toHaveBeenCalledWith("https://share.example.invalid/viewer#tc1=opaque", "_self", "noreferrer");
  });
});

const LINK_ID = "lqdw5iopqq2tkkvjj6gbbi5vbv";
const SHORT_LINK = buildShortLink({ origin: SHARE_ORIGIN, type: "share", id: LINK_ID, key: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo", cid: "bafkreiewixmt5nwgi3ych6durcsheaql3ybswbplpjmpbdhfkvdkidzt5u" });
/** The requests the sender page sent to the links API, in order. */
function linkDeletes(spy: { readonly mock: { readonly calls: ReadonlyArray<Parameters<typeof fetch>> } }) {
  return spy.mock.calls.filter(([url]) => String(url) === `${API_ORIGIN}/v1/links/${LINK_ID}/delete`);
}
/** Routes the page's fetch to a mock links API that holds this share's link. */
function linksApiFor(spy: { mockImplementation(fn: typeof fetch): unknown }) {
  const links = mockLinks();
  links.api.state.records.set(LINK_ID, { type: "share", issuer: ISSUER_DID, expiresAt: new Date(Date.now() + 86_400_000).toISOString() });
  spy.mockImplementation(links.fetchFn);
  return links;
}

/** Mounts the library with one revocable email share. Native `confirm` is dismissed, as automation and embedded webviews do. */
async function mountRevoke(link: string | undefined = undefined) {
  getPolicyRootStatusV3.mockClear(); revokePolicyRootV3.mockClear();
  const root = document.createElement("div"); document.body.append(root);
  const history = new SenderHistoryRepository(fakeVault(), () => Date.parse("2026-07-27T00:00:00.000Z"));
  await history.save({ ...record("retry-me"), ownerDid: ISSUER_DID, ...(link === undefined ? {} : { link }) });
  const nativeConfirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  mountSenderHome(root, { session, tinycloud: {
    revokeDelegation: vi.fn(),
    credentialHolderDid: ISSUER_DID,
    activeNodeIdentity: async () => ({ origin: "https://share.example.invalid", nodeDid: "did:web:node.example.invalid" }),
    signSessionBytes: signWithIssuer,
    spaceId: "space-1",
  } as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
  await vi.waitFor(() => expect(root.querySelector('button[aria-label="Revoke retry-me.md"]')).not.toBeNull());
  const live = root.querySelector<HTMLElement>(".sender-live")!; const messages: string[] = [];
  new MutationObserver(() => messages.push(live.textContent ?? "")).observe(live, { childList: true, characterData: true, subtree: true });
  return { root, history, live, messages, nativeConfirm };
}

async function clickRevoke(link?: string) {
  const mounted = await mountRevoke(link);
  mounted.root.querySelector<HTMLButtonElement>('button[aria-label="Revoke retry-me.md"]')!.click();
  confirmInPage(mounted.root);
  return mounted;
}

describe("TC-657 revoke retry after a lost response", () => {
  const irreversible = () => Object.assign(new Error("policy root revocation rejected: HTTP 409 - root-revocation-irreversible"), { status: 409 });

  it("treats a 409 for a root the Node reports revoked as a successful revoke", async () => {
    revokePolicyRootV3.mockRejectedValueOnce(irreversible());
    getPolicyRootStatusV3.mockResolvedValueOnce({ state: "revoked" });
    const { root, history, messages } = await clickRevoke();
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(messages).toContain("Share revoked.");
    expect(root.querySelector(".sender-row-error")).toBeNull();
    expect(getPolicyRootStatusV3).toHaveBeenCalledWith({
      nodeOrigin: "https://share.example.invalid",
      rootCid: "delegation-retry-me",
      expectedNodeAudience: "did:web:node.example.invalid",
    });
    expect((await history.records.get("retry-me"))?.revokedAt).toEqual(expect.any(String));
    expect(root.querySelector('button[aria-label="Revoke retry-me.md"]')).toBeNull();
  });

  it.each([
    ["a 409 for a root that is still active", () => { revokePolicyRootV3.mockRejectedValueOnce(irreversible()); getPolicyRootStatusV3.mockResolvedValueOnce({ state: "active" }); }, true],
    ["a 409 whose status read fails", () => { revokePolicyRootV3.mockRejectedValueOnce(irreversible()); getPolicyRootStatusV3.mockRejectedValueOnce(new Error("policy root status rejected: HTTP 503")); }, true],
    ["a non-409 failure", () => { revokePolicyRootV3.mockRejectedValueOnce(Object.assign(new Error("policy root revocation rejected: HTTP 403"), { status: 403 })); }, false],
  ])("keeps the share active after %s", async (_name, arrange, readsStatus) => {
    arrange();
    const { root, history } = await clickRevoke();
    await vi.waitFor(() => expect(root.querySelector(".sender-row-error")).not.toBeNull());
    expect(getPolicyRootStatusV3).toHaveBeenCalledTimes(readsStatus ? 1 : 0);
    expect(root.querySelector<HTMLButtonElement>('button[aria-label="Revoke retry-me.md"]')?.disabled).toBe(false);
    expect(root.querySelector(".sender-status-text.revoked")).toBeNull();
    expect((await history.records.get("retry-me"))?.revokedAt).toBeUndefined();
  });
});

describe("TC-1737 revoke removes the stored link with a signed delete", () => {
  beforeEach(() => { vi.stubEnv("VITE_SHARE_ORIGIN", SHARE_ORIGIN); });
  afterEach(() => { vi.unstubAllEnvs(); });

  it("sends no link delete when the node revoke is refused", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    linksApiFor(fetchSpy);
    revokePolicyRootV3.mockRejectedValueOnce(Object.assign(new Error("policy root revocation rejected: HTTP 403"), { status: 403 }));
    const { root, history } = await clickRevoke(SHORT_LINK);
    await vi.waitFor(() => expect(root.querySelector(".sender-row-error")).not.toBeNull());
    expect(linkDeletes(fetchSpy)).toEqual([]);
    expect(root.querySelector(".sender-status-text.revoked")).toBeNull();
    expect((await history.records.get("retry-me"))?.revokedAt).toBeUndefined();
  });

  it("deletes the link with an issuer-signed request that carries no key and no token", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const links = linksApiFor(fetchSpy);
    const { root, messages } = await clickRevoke(SHORT_LINK);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    await vi.waitFor(() => expect(links.api.state.records.has(LINK_ID)).toBe(false));
    expect(messages).toContain("Share revoked.");
    expect(root.querySelector(".sender-row-note")).toBeNull();
    const [, init] = linkDeletes(fetchSpy)[0]!;
    const body = JSON.parse(String(init!.body));
    expect(Object.keys(body).sort()).toEqual(["request", "signature"]);
    expect(body.request).toMatchObject({ op: "delete", id: LINK_ID, issuer: ISSUER_DID, audience: API_ORIGIN });
    expect(String(init!.body)).not.toContain("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo");
    expect(new Headers(init!.headers).has("authorization")).toBe(false);
  });

  it.each([
    ["a 500", (): Response => new Response(null, { status: 500 })],
    ["a network error", (): Response => { throw new TypeError("Failed to fetch"); }],
  ])("revokes the share and shows a note when the link delete fails with %s", async (_name, respond) => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => respond());
    const { root, messages } = await clickRevoke(SHORT_LINK);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(messages).toContain("Share revoked.");
    expect(root.querySelector(".sender-row-note")?.textContent).toBe("The short link stops resolving when the share expires.");
    expect(linkDeletes(fetchSpy)).toHaveLength(1);
  });

  it("shows no note when the link is already gone (the delete answers 404)", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({ error: "not_found" }), { status: 404 }));
    const { root, messages } = await clickRevoke(SHORT_LINK);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(messages).toContain("Share revoked.");
    expect(root.querySelector(".sender-row-note")).toBeNull();
  });

  it("sends nothing for a share whose history holds a full link or an older link form", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(null, { status: 204 }));
    const { root } = await clickRevoke(`${SHARE_ORIGIN}/s/full#v=4&k=WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo&r=e30`);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("TC-721 revoke is confirmed, shown and never silent", () => {
  // By class, not name: while a revoke is pending the button's name is "Revoking retry-me.md".
  const revokeButton = (root: HTMLElement) => root.querySelector<HTMLButtonElement>(".sender-revoke");
  const dialog = (root: HTMLElement) => root.querySelector<HTMLElement>(".sender-confirm-dialog");

  it("opens an in-page confirmation even when native dialogs are suppressed, and revokes nothing until it is confirmed", async () => {
    const { root, nativeConfirm } = await mountRevoke();
    revokeButton(root)!.click();
    expect(nativeConfirm).not.toHaveBeenCalled();
    expect(dialog(root)?.textContent).toContain("Revoke this share?");
    // An addressed share cannot be passed on, and only its owner or signer can revoke it: no link-holder caveat.
    expect(dialog(root)?.textContent).toContain("The people you shared it with lose access right away");
    expect(dialog(root)?.textContent).toContain("The encrypted copy stays in your TinyCloud until you delete it");
    expect(dialog(root)?.textContent).toContain("Share can't delete it yet");
    expect(dialog(root)?.textContent).not.toContain("Anyone holding a share link can also revoke it.");
    expect(revokePolicyRootV3).not.toHaveBeenCalled();
    confirmInPage(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(revokePolicyRootV3).toHaveBeenCalledTimes(1);
    expect(dialog(root)).toBeNull();
  });

  it("Cancel and Escape close the confirmation and leave the share untouched", async () => {
    const { root } = await mountRevoke();
    revokeButton(root)!.click();
    root.querySelector<HTMLButtonElement>(".sender-confirm-dialog button.button-secondary")!.click();
    expect(dialog(root)).toBeNull();
    revokeButton(root)!.click();
    dialog(root)!.dispatchEvent(new Event("cancel", { cancelable: true }));
    expect(dialog(root)).toBeNull();
    await Promise.resolve();
    expect(revokePolicyRootV3).not.toHaveBeenCalled();
    expect(revokeButton(root)?.disabled).toBe(false);
    expect(root.querySelector(".sender-row-error")).toBeNull();
  });

  it("shows a pending state on the row until the node answers, then Revoked", async () => {
    let finish: () => void = () => undefined;
    revokePolicyRootV3.mockImplementationOnce(() => new Promise<Record<string, never>>((resolve) => { finish = () => resolve({}); }));
    const { root, live } = await mountRevoke();
    revokeButton(root)!.click(); confirmInPage(root);
    await vi.waitFor(() => expect(revokeButton(root)?.textContent).toBe("Revoking…"));
    expect(revokeButton(root)?.disabled).toBe(true);
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Revoking…");
    expect(live.textContent).toBe("Revoking…");
    finish();
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked .status-label")?.textContent).toBe("Revoked"));
    expect(revokeButton(root)).toBeNull();
    expect(live.textContent).toBe("Share revoked.");
  });

  it.each([
    ["a 403", Object.assign(new Error("policy root revocation rejected: HTTP 403 - hidden-body"), { status: 403 }), "TinyCloud refused the request (HTTP 403)"],
    ["a 500", Object.assign(new Error("policy root revocation rejected: HTTP 500 - hidden-body"), { status: 500 }), "TinyCloud is having trouble right now (HTTP 500)"],
    ["a 404", Object.assign(new Error("policy root revocation rejected: HTTP 404 - hidden-body"), { status: 404 }), "could not find this share (HTTP 404)"],
    ["a dropped connection", new TypeError("Failed to fetch hidden-body"), "Couldn't reach TinyCloud"],
    ["an unknown failure", new Error("hidden-body"), "Something unexpected went wrong"],
  ])("shows why a revoke failed after %s, without the response text", async (_name, failure, reason) => {
    revokePolicyRootV3.mockRejectedValueOnce(failure);
    const { root } = await mountRevoke();
    revokeButton(root)!.click(); confirmInPage(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-row-error")).not.toBeNull());
    const error = root.querySelector<HTMLElement>(".sender-row-error")!;
    expect(error.getAttribute("role")).toBe("alert");
    expect(error.textContent).toContain("Could not revoke:");
    expect(error.textContent).toContain(reason);
    expect(root.textContent).not.toContain("hidden-body");
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Ready");
    expect(revokeButton(root)?.textContent).toBe("Revoke");
    expect(revokeButton(root)?.disabled).toBe(false);
  });

  it("clears the error and revokes on a retry", async () => {
    revokePolicyRootV3.mockRejectedValueOnce(Object.assign(new Error("rejected"), { status: 503 }));
    const { root } = await mountRevoke();
    revokeButton(root)!.click(); confirmInPage(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-row-error")).not.toBeNull());
    revokeButton(root)!.click();
    expect(root.querySelector(".sender-row-error")).toBeNull();
    confirmInPage(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
  });
});

describe("sender home load states", () => {
  const NOW = () => Date.parse("2026-07-27T00:00:00.000Z");
  const mount = (history: SenderHistoryRepository) => {
    const root = document.createElement("div"); document.body.append(root);
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
    return root;
  };
  const failingListing = () => ({ ok: false as const });
  const rowIds = (root: HTMLElement) => [...root.querySelectorAll(".sender-item-cell strong")].map((cell) => cell.textContent);

  it("shows only the error, with no skeleton or busy state, when the load fails, and a retry shows loading again then clears the error", async () => {
    const history = new SenderHistoryRepository(fakeVault({ listing: failingListing }), NOW);
    const root = mount(history);
    // The skeleton is on screen while the load is pending.
    expect(root.querySelector(".sender-skeleton-row")).not.toBeNull();
    expect(root.querySelector("table")?.getAttribute("aria-busy")).toBe("true");

    await vi.waitFor(() => expect(root.querySelector<HTMLElement>('[role="alert"]')?.hidden).toBe(false), { timeout: 4000 });
    const alert = root.querySelector<HTMLElement>('[role="alert"]')!;
    expect(alert.textContent).toContain("Could not load shares");
    expect(root.querySelector(".sender-skeleton-row, .sender-skeleton-cell")).toBeNull();
    expect(root.querySelector("table")?.hidden).toBe(true);
    expect(root.querySelector("[aria-busy]")).toBeNull();
    expect(root.querySelector<HTMLElement>(".sender-load-more")?.hidden).toBe(true);
    const retry = alert.querySelector<HTMLButtonElement>("button")!;
    expect(retry.textContent).toBe("Retry");

    // Retry: the loading state returns and the error leaves while the load is pending.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const retryHistory = vi.spyOn(history, "page").mockImplementation(async () => { await gate; return { items: [], truncated: false }; });
    retry.click();
    expect(alert.hidden).toBe(true);
    expect(root.querySelector(".sender-skeleton-row")).not.toBeNull();
    expect(root.querySelector("table")?.hidden).toBe(false);
    expect(root.querySelector("table")?.getAttribute("aria-busy")).toBe("true");
    release();
    await vi.waitFor(() => expect(root.querySelector("[aria-busy]")).toBeNull());
    expect(retryHistory).toHaveBeenCalledTimes(1);
    expect(alert.hidden).toBe(true);
    expect(root.querySelector(".sender-skeleton-row")).toBeNull();
  });

  it("recovers to a list when a retry succeeds after the error", async () => {
    let failing = true;
    const vault = fakeVault();
    const inner = vault as unknown as { listPage: (o: unknown) => Promise<ListPage> };
    const real = inner.listPage;
    inner.listPage = async (request) => failing ? failingListing() : real(request);
    const history = new SenderHistoryRepository(vault, NOW);
    await history.save(record("kept"));
    const root = mount(history);
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>('[role="alert"]')?.hidden).toBe(false), { timeout: 4000 });
    failing = false;
    root.querySelector<HTMLButtonElement>('[role="alert"] button')!.click();
    await vi.waitFor(() => expect(rowIds(root)).toEqual(["kept.md"]));
    expect(root.querySelector<HTMLElement>('[role="alert"]')?.hidden).toBe(true);
    expect(root.querySelector("table")?.hidden).toBe(false);
    expect(root.querySelector(".sender-skeleton-row")).toBeNull();
    expect(root.querySelector("[aria-busy]")).toBeNull();
  });

  it("renders a revoked share as revoked, without a Revoke action", async () => {
    const history = new SenderHistoryRepository(fakeVault(), NOW);
    await history.save({ ...record("gone"), revokedAt: "2026-07-26T00:00:00.000Z" });
    await history.save(record("live"));
    const root = mount(history);
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row")).toHaveLength(2));
    const gone = [...root.querySelectorAll(".sender-history-row")].find((row) => row.textContent?.includes("gone.md"))!;
    expect(gone.querySelector(".sender-status-text.revoked .status-label")?.textContent).toBe("Revoked");
    expect(gone.querySelector("button.sender-revoke")).toBeNull();
    expect(root.querySelector('button[aria-label="Revoke live.md"]')).not.toBeNull();
    expect(root.querySelector('button[aria-label="Revoke gone.md"]')).toBeNull();
  });

  it("pages through more than one page with the real cursor and the node's listing cursor", async () => {
    const cursors: Array<string | undefined> = [];
    const vault = fakeVault({ serverPageLimit: 10 });
    const inner = vault as unknown as { listPage: (o: { cursor?: string }) => Promise<ListPage> };
    const real = inner.listPage;
    inner.listPage = async (request) => { cursors.push(request.cursor); return real(request); };
    const history = new SenderHistoryRepository(vault, NOW);
    const base = Date.parse("2026-07-01T00:00:00.000Z");
    for (let index = 0; index < 30; index += 1) await history.save({ ...record(`s${String(index).padStart(2, "0")}`), registeredAt: new Date(base + index * 60_000).toISOString() });
    const pageSpy = vi.spyOn(history, "page");
    const root = mount(history);
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row")).toHaveLength(25));
    // The listing followed the node's own cursor across its three pages.
    expect(cursors).toEqual([undefined, "10", "20"]);
    const more = root.querySelector<HTMLButtonElement>(".sender-load-more")!;
    expect(more.hidden).toBe(false);
    expect(rowIds(root)[0]).toBe("s29.md");

    more.click();
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-history-row")).toHaveLength(30));
    expect(pageSpy.mock.calls.map(([cursor]) => cursor)).toEqual([undefined, "25"]);
    expect(new Set(rowIds(root)).size).toBe(30);
    expect(rowIds(root).at(-1)).toBe("s00.md");
    expect(more.hidden).toBe(true);
    // Load more reuses the index rather than listing again.
    expect(cursors).toEqual([undefined, "10", "20"]);
    expect(root.querySelector("[aria-busy]")).toBeNull();
  });

  it("shows the error, not a partial list, when the listing repeats a cursor", async () => {
    const pages: Record<string, { keys: string[]; nextCursor: string }> = { start: { keys: ["a"], nextCursor: "A" }, A: { keys: ["b"], nextCursor: "B" }, B: { keys: ["c"], nextCursor: "A" } };
    const history = new SenderHistoryRepository(fakeVault({ listing: (cursor) => ({ ok: true, data: { truncated: true, ...pages[cursor ?? "start"]! } }) }), NOW);
    const root = mount(history);
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>('[role="alert"]')?.hidden).toBe(false), { timeout: 4000 });
    expect(root.querySelector('[role="alert"]')?.textContent).toContain("Could not load shares");
    expect(root.querySelectorAll(".sender-history-row")).toHaveLength(0);
    expect(root.querySelector(".sender-skeleton-row")).toBeNull();
    expect(root.querySelector("table")?.hidden).toBe(true);
    expect(root.querySelector("[aria-busy]")).toBeNull();
  });
});

describe("Send the link again", () => {
  const BEFORE_EXPIRY = Date.parse("2026-07-27T00:00:00.000Z");
  const AFTER_EXPIRY = Date.parse("2026-08-05T00:00:00.000Z");
  const button = (root: HTMLElement): HTMLButtonElement | null => root.querySelector<HTMLButtonElement>(".sender-send-again");

  async function mountWith(saved: SenderShareRecord, now: number, onSendAgain = vi.fn()) {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(fakeVault(), () => now);
    await history.save(saved);
    mountSenderHome(root, { session, tinycloud: {} as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain });
    await vi.waitFor(() => expect(root.querySelector(".sender-history-row")).not.toBeNull());
    return { root, onSendAgain, history };
  }

  it("is shown, with Sam's wording, on a share that has expired", async () => {
    const { root } = await mountWith(record("old"), AFTER_EXPIRY);
    expect(button(root)?.hidden).toBe(false);
    expect(button(root)?.textContent).toBe("Send the link again");
  });

  it("is hidden on a share that is still live", async () => {
    const { root } = await mountWith(record("live"), BEFORE_EXPIRY);
    expect(button(root)).not.toBeNull();
    expect(button(root)?.hidden).toBe(true);
  });

  it("is not offered on a revoked share, or on one made for a single OpenKey device", async () => {
    const revoked = await mountWith({ ...record("gone"), revokedAt: "2026-07-26T00:00:00.000Z" }, AFTER_EXPIRY);
    expect(button(revoked.root)).toBeNull();
    document.body.replaceChildren();
    const device = await mountWith(record("device", { kind: "recipientDid", value: "did:key:z6MkDevice" }), AFTER_EXPIRY);
    expect(button(device.root)?.hidden).toBe(true);
  });

  it("opens the composer with who it was for, how long it lasted and the file name, and nothing else", async () => {
    const saved: SenderShareRecord = { ...record("old"), deliveryMaterial: { envelope: { version: 3 }, sealedEnvelope: "SEALED", envelopeKey: "KEY", shareCid: "bafy" }, deliveredRecipients: ["person@example.invalid"] };
    const { root, onSendAgain } = await mountWith(saved, AFTER_EXPIRY);
    button(root)!.click();
    await vi.waitFor(() => expect(onSendAgain).toHaveBeenCalledTimes(1));
    const prefill = onSendAgain.mock.calls[0]![0];
    expect(prefill).toEqual({ recipient: { kind: "exactEmail", value: "person@example.invalid" }, deliveryEmails: ["person@example.invalid"], expiry: "7d", filename: "old.md" });
    expect(JSON.stringify(prefill)).not.toMatch(/SEALED|KEY|bafy/);
  });

  it("says so when the saved share cannot be read", async () => {
    const { root, onSendAgain, history } = await mountWith(record("old"), AFTER_EXPIRY);
    const failing = vi.spyOn(history.records, "get").mockRejectedValue(new Error("vault down"));
    button(root)!.click();
    await vi.waitFor(() => expect(root.querySelector(".sender-live")?.textContent).toBe("We couldn't open this share to send it again. Try again."));
    expect(onSendAgain).not.toHaveBeenCalled();
    failing.mockRestore();
  });
});
