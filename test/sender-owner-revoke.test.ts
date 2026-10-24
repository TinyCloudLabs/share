import { afterEach, describe, expect, it, vi, type Mock } from "vitest";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import { endSenderLibrary, mountSenderHome } from "../src/share/sender-home.js";
import { resetRevokeFlights } from "../src/share/revoke-flight.js";
import { SenderHistoryRepository } from "../src/share/sender-history.js";
import { ObservedOpenKeyProvider, ownerEncryptionNetwork, registerWalletApprovalObserver, type OpenKeyShareSession, type ShareTinyCloud } from "../src/share/openkey-session.js";
import type { SenderShareRecord } from "@tinycloud/share-sdk";

const { getPolicyRootStatusV3, revokePolicyRootV3 } = vi.hoisted(() => ({
  getPolicyRootStatusV3: vi.fn(async (): Promise<{ readonly state: "active" | "revoked" }> => ({ state: "active" })),
  revokePolicyRootV3: vi.fn(async () => ({})),
}));
vi.mock("@tinycloud/sdk-core", () => ({ getPolicyRootStatusV3, revokePolicyRootV3, verifyEip191MessageSignature: async () => true }));

afterEach(() => { resetRevokeFlights(); document.body.replaceChildren(); vi.restoreAllMocks(); vi.useRealTimers(); revokePolicyRootV3.mockClear(); getPolicyRootStatusV3.mockClear(); });

/**
 * The share app makes a new session key on every sign-in. A share is signed by
 * the session key of the page that created it, so `record.ownerDid` is that
 * key (K1) while a later sign-in of the same account holds another key (K2).
 * Both belong to the same address. The older fixtures gave both values one
 * account DID, which cannot produce this case.
 */
const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const OTHER_ADDRESS = "0x9999999999999999999999999999999999999999";
const K1 = "did:key:z6MkCreatingSession";
const K2 = "did:key:z6MkLaterSession";
const NODE = { origin: "https://node.example.invalid", nodeDid: "did:key:z6MkNode" };
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;
const PATH = "xyz.tinycloud.share/shares/s1/qa.txt";

function vault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix }: { prefix: string; removePrefix: boolean }) => ({ ok: true, data: { keys: [...store.keys()].filter((key) => key.startsWith(prefix)).map((key) => removePrefix ? key.slice(prefix.length) : key), truncated: false } }),
  } as unknown as IDataVaultService;
}

const addressedRecord = (over: Partial<SenderShareRecord> = {}): SenderShareRecord => ({
  shareId: "s1",
  target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: SPACE },
  resource: { kind: "exact", path: PATH },
  actions: ["tinycloud.kv/get"],
  recipientMatcher: { kind: "exactEmail", value: "person@example.invalid" },
  targetKind: "email",
  registeredAt: "2026-10-20T01:23:00.000Z",
  expiresAt: "2026-10-27T01:23:00.000Z",
  ownerDelegationCid: "policy-root",
  enforcementDelegationCid: "enforcement-root",
  ownerDid: K1,
  link: "https://share.example.invalid/viewer#tc1=opaque",
  filename: "qa.txt",
  ...over,
});

const bearerRecord = (): SenderShareRecord => ({
  shareId: "bearer-1",
  target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: SPACE },
  resource: { kind: "exact", path: "xyz.tinycloud.share/shares/b1/qa.txt" },
  actions: ["tinycloud.kv/get"],
  recipientMatcher: { kind: "bearer" },
  targetKind: "bearer",
  registeredAt: "2026-10-20T01:23:00.000Z",
  expiresAt: "2026-10-27T01:23:00.000Z",
  enforcementDelegationCid: "bearer-delegation",
  link: "https://share.example.invalid/viewer#tc1=opaque",
  filename: "qa.txt",
});

type Row = Record<string, unknown>;

/** The Node 20 test runtime has no `Promise.withResolvers`. */
function deferred<T>(): { readonly promise: Promise<T>; readonly resolve: (value: T) => void } {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
/** What `/delegation/query` returns for the share's policy root: signed by the creating session key K1. */
const policyRootRow = (over: Row = {}): Row => ({
  cid: "policy-root", direction: "granted", delegatorDid: K1, delegateDid: "did:key:z6MkEnforcer",
  resources: [
    { resource: `${SPACE}/kv/${PATH}`, actions: ["tinycloud.kv/get", "tinycloud.kv/metadata"], caveats: [] },
    { resource: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/decrypt"], caveats: [] },
  ],
  parents: [], issuedAt: null, notBefore: null, expiresAt: null, status: "active", ...over,
});
const bearerRow = (over: Row = {}): Row => ({
  cid: "bearer-delegation", direction: "granted", delegatorDid: K1, delegateDid: "did:key:z6MkShareKey",
  resources: [{ resource: `${SPACE}/kv/xyz.tinycloud.share/shares/b1/qa.txt`, actions: ["tinycloud.kv/get"], caveats: [] }],
  parents: ["session-delegation"], issuedAt: null, notBefore: null, expiresAt: null, status: "active", ...over,
});
/** The wallet-signed delegation that created the current session: never a share. */
const sessionDelegationRow = (over: Row = {}): Row => ({
  cid: "session-delegation", direction: "granted", delegatorDid: `did:pkh:eip155:1:${ADDRESS}`, delegateDid: K2,
  resources: [
    { resource: `${SPACE}/kv/xyz.tinycloud.share/`, actions: ["tinycloud.kv/get", "tinycloud.kv/list"], caveats: [] },
    { resource: `${SPACE}/kv/xyz.tinycloud.share/shares/`, actions: ["tinycloud.kv/put"], caveats: [] },
    { resource: `${SPACE}/vault/sender-history/v2/records/`, actions: ["tinycloud.vault/put"], caveats: [] },
  ],
  parents: [], issuedAt: null, notBefore: null, expiresAt: null, status: "active", ...over,
});

interface Harness {
  readonly root: HTMLElement;
  /** Mounts the library again on the same page, as leaving it and coming back does. */
  readonly remount: () => Promise<void>;
  readonly history: SenderHistoryRepository;
  readonly tinycloud: { revokeDelegation: Mock; delegations: { query: Mock; status: Mock } };
}

interface HarnessOptions {
  readonly record?: SenderShareRecord;
  readonly rows?: readonly Row[];
  readonly queryOk?: boolean;
  /** Holds each node listing (numbered from 1, in the order the page asks) until the test lets it answer. */
  readonly beforeQuery?: (call: number) => Promise<void> | undefined;
  /** More saved shares of the same account. */
  readonly extra?: readonly SenderShareRecord[];
  readonly address?: string;
  readonly node?: { origin: string; nodeDid: string };
  readonly revokeDelegation?: (cid: string) => Promise<unknown> | unknown;
  readonly status?: (cid: string) => Promise<unknown> | unknown;
  readonly pageSize?: number;
}

/** The real `mountSenderHome`, signed in as K2 of ADDRESS. Only the TinyCloud client is faked. */
async function mountAs(options: HarnessOptions = {}): Promise<Harness> {
  const record = options.record ?? addressedRecord();
  const root = document.createElement("div"); document.body.append(root);
  const store = vault();
  const history = new SenderHistoryRepository(store, () => Date.parse("2026-10-20T04:00:00.000Z"));
  await history.save(record);
  for (const more of options.extra ?? []) await history.save(more);
  const rows = options.rows ?? [policyRootRow()];
  const pageSize = options.pageSize ?? 100;
  let queries = 0;
  const tinycloud = {
    revokeDelegation: vi.fn(async (cid: string) => options.revokeDelegation === undefined ? { ok: true, data: { revoked: true, cid } } : options.revokeDelegation(cid)),
    credentialHolderDid: K2,
    activeNodeIdentity: async () => options.node ?? NODE,
    signSessionBytes: async () => new Uint8Array(64),
    delegations: {
      query: vi.fn(async (query: { cursor?: string; space?: string } = {}) => {
        queries += 1;
        await options.beforeQuery?.(queries);
        if (options.queryOk === false) return { ok: false, error: { code: "NETWORK_ERROR", message: "Network error during delegation query" } };
        const start = query.cursor === undefined ? 0 : Number(query.cursor);
        const items = rows.slice(start, start + pageSize);
        return { ok: true, data: { schemaVersion: 2, items, ...(start + pageSize < rows.length ? { nextCursor: String(start + pageSize) } : {}) } };
      }),
      status: vi.fn(async (cid: string) => options.status === undefined ? { ok: true, data: { cid, status: "active", exists: true, active: true, revoked: false, expired: false } } : options.status(cid)),
    },
  };
  const mount = async (): Promise<void> => {
    mountSenderHome(root, { session: { address: options.address ?? ADDRESS } as unknown as OpenKeyShareSession, tinycloud: tinycloud as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(root.querySelector(".sender-history-row")).not.toBeNull());
  };
  await mount();
  return { root, history, tinycloud, remount: mount };
}

const revokeButton = (root: HTMLElement) => root.querySelector<HTMLButtonElement>(".sender-revoke");
const errorText = (root: HTMLElement) => root.querySelector(".sender-row-error")?.textContent ?? null;
const noteText = (root: HTMLElement) => root.querySelector(".sender-row-note")?.textContent ?? null;
const confirm = (root: HTMLElement) => root.querySelector<HTMLButtonElement>(".sender-confirm-dialog .sender-confirm-revoke")!.click();
async function revoke(root: HTMLElement): Promise<void> { revokeButton(root)!.click(); confirm(root); }
const settled = (root: HTMLElement) => vi.waitFor(() => expect(root.querySelector(".sender-row-error, .sender-row-note, .sender-status-text.revoked")).not.toBeNull());
const OLD_COPY = "different account or TinyCloud node";
const EARLIER = "This share was created in an earlier sign-in, and Share can't revoke it from this one yet. The share is still active.";

describe("revoking a share made in an earlier sign-in (same account, new session key)", () => {
  it("the creating session still revokes through the session-signed route, with no wallet approval", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const history = new SenderHistoryRepository(vault(), () => Date.parse("2026-10-20T04:00:00.000Z"));
    await history.save(addressedRecord());
    const revokeDelegation = vi.fn();
    mountSenderHome(root, { session: { address: ADDRESS } as unknown as OpenKeyShareSession, tinycloud: { revokeDelegation, credentialHolderDid: K1, activeNodeIdentity: async () => NODE, signSessionBytes: async () => new Uint8Array(64) } as unknown as ShareTinyCloud, history, onNavigate: () => undefined, onSendAgain: () => undefined });
    await vi.waitFor(() => expect(revokeButton(root)).not.toBeNull());
    await revoke(root); await settled(root);
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
    expect(revokePolicyRootV3).toHaveBeenCalledTimes(1);
    expect(revokeDelegation).not.toHaveBeenCalled();
  });

  it("a new session of the same address revokes the policy root with one owner-wallet revocation, and shows Revoked", async () => {
    const { root, history, tinycloud } = await mountAs();
    await revoke(root); await settled(root);
    expect(errorText(root)).toBeNull();
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledWith("policy-root");
    expect(revokePolicyRootV3).not.toHaveBeenCalled();
    expect(root.querySelector(".sender-status-text.revoked .status-label")?.textContent).toBe("Revoked");
    expect(revokeButton(root)).toBeNull();
    // The saved record is marked revoked, so a reload keeps showing Revoked.
    expect((await history.records.get("s1"))?.revokedAt).toBeDefined();
  });

  it("verifies the root on the node before asking for the wallet: space filter, delegator, resources", async () => {
    const { root, tinycloud } = await mountAs();
    let queriedBeforeSigning = false;
    tinycloud.revokeDelegation.mockImplementationOnce(async (cid: string) => { queriedBeforeSigning = tinycloud.delegations.query.mock.calls.length > 0; return { ok: true, data: { revoked: true, cid } }; });
    await revoke(root); await settled(root);
    expect(queriedBeforeSigning).toBe(true);
    expect(tinycloud.delegations.query).toHaveBeenCalledWith(expect.objectContaining({ direction: "granted", space: SPACE }));
  });

  it("finds the root on a later page of the node's listing", async () => {
    const filler = Array.from({ length: 4 }, (_, index) => sessionDelegationRow({ cid: `other-${index}` }));
    const { root, tinycloud } = await mountAs({ rows: [...filler, policyRootRow()], pageSize: 2 });
    await revoke(root); await settled(root);
    expect(tinycloud.delegations.query.mock.calls.length).toBeGreaterThan(1);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledWith("policy-root");
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
  });

  it("shows the approval hint while the wallet window is open, and not before the node has verified the share", async () => {
    const gate = deferred<unknown>();
    const { root, tinycloud } = await mountAs({ revokeDelegation: () => gate.promise });
    await revoke(root);
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    expect(root.querySelector(".sender-row-hint")?.textContent).toBe("Approve in the OpenKey window to revoke");
    // The inserted node is not announced reliably; the spoken-only region says it, and the visible live line does not repeat it.
    await vi.waitFor(() => expect(root.querySelector(".sender-announce")?.textContent).toBe("Approve in the OpenKey window to revoke."));
    expect(root.querySelector(".sender-announce")?.className).toContain("sr-only");
    expect(root.querySelector(".sender-live")?.textContent).not.toContain("OpenKey");
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Revoking…");
    gate.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await settled(root);
    expect(root.querySelector(".sender-row-hint")).toBeNull();
  });
});

describe("a share that belongs to another account or node keeps the 'different account' message, and signs nothing", () => {
  it.each([
    ["a space owned by another address", { target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: `tinycloud:pkh:eip155:1:${OTHER_ADDRESS}:applications` } }],
    ["another node origin", { target: { origin: "https://other-node.example.invalid", nodeAudience: NODE.nodeDid, spaceId: SPACE } }],
    ["another node audience", { target: { origin: NODE.origin, nodeAudience: "did:key:z6MkOtherNode", spaceId: SPACE } }],
  ])("%s", async (_name, override) => {
    const { root, tinycloud } = await mountAs({ record: addressedRecord(override as Partial<SenderShareRecord>) });
    await revoke(root); await settled(root);
    expect(errorText(root)).toContain(OLD_COPY);
    expect(tinycloud.delegations.query).not.toHaveBeenCalled();
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
    expect(revokePolicyRootV3).not.toHaveBeenCalled();
    expect(revokeButton(root)?.disabled).toBe(false);
  });
});

describe("a forged or stale saved record never reaches the wallet", () => {
  const refuses = async (options: HarnessOptions, expectation: string = EARLIER) => {
    const { root, tinycloud } = await mountAs(options);
    await revoke(root); await settled(root);
    expect(errorText(root)).toContain(expectation);
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
    expect(revokePolicyRootV3).not.toHaveBeenCalled();
    expect(root.querySelector(".sender-row-hint")).toBeNull();
    expect(root.querySelector(".sender-status-text.revoked")).toBeNull();
    expect(revokeButton(root)?.disabled).toBe(false);
  };

  it("a CID that is not in this account's delegations (someone else's delegation)", () => refuses({ record: addressedRecord({ ownerDelegationCid: "someone-elses-cid" }) }));
  it("the CID of the owner's own session delegation (a wallet-signed delegation, not a share)", () => refuses({ record: addressedRecord({ ownerDelegationCid: "session-delegation", ownerDid: `did:pkh:eip155:1:${ADDRESS}`, resource: { kind: "prefix", path: "xyz.tinycloud.share/shares/" } }), rows: [sessionDelegationRow(), policyRootRow()] }));
  it("a CID whose delegator is not the key the record names", () => refuses({ rows: [policyRootRow({ delegatorDid: "did:key:z6MkSomebodyElse" })] }));
  it("a delegation for another path than the record's", () => refuses({ rows: [policyRootRow({ resources: [{ resource: `${SPACE}/kv/xyz.tinycloud.share/shares/other/qa.txt`, actions: ["tinycloud.kv/get"], caveats: [] }] })] }));
  it("a delegation that also grants something outside the share's own object", () => refuses({ rows: [policyRootRow({ resources: [{ resource: `${SPACE}/kv/${PATH}`, actions: ["tinycloud.kv/get"], caveats: [] }, { resource: `${SPACE}/kv/documents/`, actions: ["tinycloud.kv/get"], caveats: [] }] })] }));
  it("a delegation in another space", () => refuses({ rows: [policyRootRow({ resources: [{ resource: `tinycloud:pkh:eip155:1:${ADDRESS}:account/kv/${PATH}`, actions: ["tinycloud.kv/get"], caveats: [] }] })] }));
  it("a record path outside the share app's own folder", () => refuses({ record: addressedRecord({ resource: { kind: "exact", path: "documents/secret.txt" } }), rows: [policyRootRow({ resources: [{ resource: `${SPACE}/kv/documents/secret.txt`, actions: ["tinycloud.kv/get"], caveats: [] }] })] }));
  it("a received delegation (somebody else granted it to this account)", () => refuses({ rows: [policyRootRow({ direction: "received" })] }));
  it("a root that has a parent (shares' roots have none)", () => refuses({ rows: [policyRootRow({ parents: ["session-delegation"] })] }));
  it("a record with no policy root CID", () => refuses({ record: ({ ...addressedRecord(), ownerDelegationCid: undefined } as unknown as SenderShareRecord) }));
  it("a node that cannot answer the listing", () => refuses({ queryOk: false }));
  it("a listing that never contains the CID", () => refuses({ rows: [sessionDelegationRow()] }));
});

describe("the node check cannot be satisfied by a different space name, or by the encryption network alone", () => {
  it("a share in a space with another name than applications is refused", async () => {
    const other = `tinycloud:pkh:eip155:1:${ADDRESS}:documents`;
    const { root, tinycloud } = await mountAs({
      record: addressedRecord({ target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: other } }),
      rows: [policyRootRow({ resources: [{ resource: `${other}/kv/${PATH}`, actions: ["tinycloud.kv/get"], caveats: [] }, { resource: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/decrypt"], caveats: [] }] })],
    });
    await revoke(root); await settled(root);
    expect(errorText(root)).toContain(EARLIER);
    expect(tinycloud.delegations.query).not.toHaveBeenCalled();
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
  });

  it("a delegation that grants only the account's encryption network, and none of the share's object, is refused", async () => {
    const { root, tinycloud } = await mountAs({ rows: [policyRootRow({ resources: [{ resource: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/decrypt"], caveats: [] }] })] });
    await revoke(root); await settled(root);
    expect(errorText(root)).toContain(EARLIER);
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
  });

  it("a listing longer than the pages read says Share could not read the whole permissions list, not that the share is from an earlier sign-in", async () => {
    // 25 pages of one row each: more than the pages the page will read.
    const rows = [...Array.from({ length: 24 }, (_, index) => sessionDelegationRow({ cid: `filler-${index}` })), policyRootRow()];
    const { root, tinycloud } = await mountAs({ rows, pageSize: 1 });
    await revoke(root); await settled(root);
    expect(errorText(root)).toBe("Could not revoke: Share couldn't read your whole permissions list, so it can't find this share. Try again or contact support. The share is still active.");
    expect(root.textContent).not.toContain("earlier sign-in");
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
  });
});


describe("what happens around the wallet approval", () => {
  it("an already revoked root (node status) is a success and asks for no approval", async () => {
    const { root, tinycloud } = await mountAs({ rows: [policyRootRow({ status: "revoked" })] });
    await revoke(root); await settled(root);
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
    expect(errorText(root)).toBeNull();
  });

  it("a root revoked through its ancestor counts as revoked too", async () => {
    const { root, tinycloud } = await mountAs({ rows: [policyRootRow({ status: "ancestor_revoked" })] });
    await revoke(root); await settled(root);
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
  });

  it("a revoke that lost the race (another tab) is a success when the node reports the root revoked", async () => {
    const { root, tinycloud } = await mountAs({
      revokeDelegation: () => ({ ok: false, error: { code: "REVOCATION_FAILED", message: "Failed to revoke delegation: 403 - hidden-body" } }),
      status: (cid) => ({ ok: true, data: { cid, status: "revoked", exists: true, active: false, revoked: true, expired: false } }),
    });
    await revoke(root); await settled(root);
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
    expect(tinycloud.delegations.status).toHaveBeenCalledWith("policy-root");
    expect(root.textContent).not.toContain("hidden-body");
  });

  it("a node 403 gives a plain reason, never 'sign in again with the account that created this share'", async () => {
    const { root } = await mountAs({ revokeDelegation: () => ({ ok: false, error: { code: "REVOCATION_FAILED", message: "Failed to revoke delegation: 403 - Unauthorized Revoker hidden-body" } }) });
    await revoke(root); await settled(root);
    expect(errorText(root)).toBe("Could not revoke: TinyCloud refused the request (HTTP 403). The share is still active.");
    expect(root.textContent).not.toContain("hidden-body");
    expect(root.textContent).not.toContain("Sign in again");
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Ready");
    expect(revokeButton(root)?.disabled).toBe(false);
  });

  it("a 401 and a 500 are plain too", async () => {
    for (const [status, reason] of [[401, "TinyCloud refused the request (HTTP 401)"], [500, "TinyCloud is having trouble right now (HTTP 500)"]] as const) {
      const { root } = await mountAs({ revokeDelegation: () => ({ ok: false, error: { code: "REVOCATION_FAILED", message: `Failed to revoke delegation: ${status} - hidden-body` } }) });
      await revoke(root); await settled(root);
      expect(errorText(root)).toContain(reason);
      expect(root.textContent).not.toContain("Sign in again");
      document.body.replaceChildren();
    }
  });

  it("a 403 after the 60-second approval window says the approval ran out, not that sign-in is wrong", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-20T04:00:00.000Z"));
    const { root } = await mountAs({ revokeDelegation: () => { vi.setSystemTime(new Date("2026-10-20T04:01:10.000Z")); return { ok: false, error: { code: "REVOCATION_FAILED", message: "Failed to revoke delegation: 403 - expired" } }; } });
    await revoke(root); await settled(root);
    expect(errorText(root)).toBe("Could not revoke: The approval took longer than 60 seconds. The share is still active. Try again and approve within a minute.");
    expect(revokeButton(root)?.disabled).toBe(false);
  });
});

/** The OpenKey window rejects with a plain `{ code }` object. The SDK folds that into "[object Object]", so the page reads it from the provider. */
async function mountWithWallet(outcome: { reject?: unknown; signer?: string }): Promise<Harness & { readonly openkey: { signMessage: Mock } }> {
  const openkey = { signMessage: vi.fn(async () => { if (outcome.reject !== undefined) throw outcome.reject; return { signature: `0x${"11".repeat(65)}` }; }) };
  const provider = new ObservedOpenKeyProvider(openkey as never, { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" } as never, ADDRESS, async (_message, _signature, address) => address.toLowerCase() === (outcome.signer ?? ADDRESS).toLowerCase());
  const harness = await mountAs({
    revokeDelegation: async () => {
      try { await provider.request({ method: "personal_sign", params: ["0x70726f6f66", ADDRESS] }); return { ok: true, data: { revoked: true, cid: "policy-root" } }; } catch (caught) { return { ok: false, error: { code: "NETWORK_ERROR", message: `Network error during delegation revocation: ${String(caught)}` } }; }
    },
  });
  registerWalletApprovalObserver(harness.tinycloud as unknown as ShareTinyCloud, provider);
  return { ...harness, openkey };
}

describe("approval outcomes in the OpenKey window", () => {
  it("cancelling shows 'Revoke cancelled', leaves the share active, and a retry works", async () => {
    const { root, tinycloud, openkey } = await mountWithWallet({ reject: { code: "USER_CANCELLED", message: "User cancelled the request" } });
    await revoke(root); await settled(root);
    // A choice, not a failure: a quiet note, never a red alert.
    expect(noteText(root)).toBe("Revoke cancelled. The share is still active.");
    expect(errorText(root)).toBeNull();
    expect(root.querySelector('.sender-row-actions [role="alert"]')).toBeNull();
    await vi.waitFor(() => expect(root.querySelector(".sender-announce")?.textContent).toBe("Revoke cancelled. The share is still active."));
    expect(root.querySelector(".sender-live")?.textContent).toBe("");
    expect(root.textContent).not.toContain("object Object");
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Ready");
    expect(root.querySelector(".sender-row-hint")).toBeNull();
    expect(revokeButton(root)?.disabled).toBe(false);
    openkey.signMessage.mockImplementation(async () => ({ signature: `0x${"11".repeat(65)}` }));
    await revoke(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(2);
    expect(errorText(root)).toBeNull();
    expect(noteText(root)).toBeNull();
  });

  it("the OpenKey window timing out says so in plain words", async () => {
    const { root } = await mountWithWallet({ reject: { code: "TIMEOUT", message: "timed out" } });
    await revoke(root); await settled(root);
    expect(errorText(root)).toBe("Could not revoke: The approval wasn't completed in time. The share is still active. Try again and approve in the OpenKey window.");
  });

  it("an approval from a different account than the one signed in is refused before anything is sent", async () => {
    const { root } = await mountWithWallet({ signer: OTHER_ADDRESS });
    await revoke(root); await settled(root);
    expect(errorText(root)).toBe("Could not revoke: The approval came from a different account than the one signed in. The share is still active. Approve with the signed-in account.");
    expect(root.querySelector(".sender-status-text.revoked")).toBeNull();
  });
});

describe("one revoke in flight per share", () => {
  it("repeat clicks, Enter and a reopened confirmation during the approval produce exactly one wallet request", async () => {
    const gate = deferred<unknown>();
    const { root, tinycloud } = await mountAs({ revokeDelegation: () => gate.promise });
    const button = revokeButton(root)!;
    button.click(); button.click();
    expect(root.querySelectorAll(".sender-confirm-dialog")).toHaveLength(1);
    confirm(root);
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    // Pending: the control is disabled; a click, an Enter keypress, a form-style activation and a second dispatch all do nothing.
    expect(button.disabled).toBe(true);
    button.click();
    button.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(root.querySelector(".sender-confirm-dialog")).toBeNull();
    // Escape on a stray dialog and a re-click change nothing either.
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    button.click();
    expect(root.querySelector(".sender-confirm-dialog")).toBeNull();
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    gate.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await settled(root);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    expect(revokeButton(root)).toBeNull();
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
  });

  it("while the confirmation is open, a second activation of the same Revoke button opens nothing more", async () => {
    const { root, tinycloud } = await mountAs();
    const button = revokeButton(root)!;
    button.click();
    button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(root.querySelectorAll(".sender-confirm-dialog")).toHaveLength(1);
    confirm(root);
    await settled(root);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
  });

  it("Escape from the confirmation, then Revoke again, is one request after the second confirmation", async () => {
    const { root, tinycloud } = await mountAs();
    revokeButton(root)!.click();
    root.querySelector<HTMLElement>(".sender-confirm-dialog")!.dispatchEvent(new Event("cancel", { cancelable: true }));
    expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
    // The confirmation closes asynchronously; a person cannot press Revoke again before it has.
    await vi.waitFor(() => expect(root.querySelector(".sender-confirm-dialog")).toBeNull());
    await new Promise((resolve) => setTimeout(resolve, 0));
    await revoke(root); await settled(root);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
  });
});

describe("the in-flight guard outlives the library view", () => {
  it("leaving the library and coming back during the approval shows the pending row, and a click sends no second wallet request", async () => {
    const gate = deferred<unknown>();
    const { root, remount, tinycloud } = await mountAs({ revokeDelegation: () => gate.promise });
    await revoke(root);
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    await remount();
    const button = revokeButton(root)!;
    expect(button.disabled).toBe(true);
    expect(button.textContent).toBe("Revoking…");
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Revoking…");
    expect(root.querySelector(".sender-row-hint")?.textContent).toBe("Approve in the OpenKey window to revoke");
    // A screen reader hears the hint again when the view is mounted while the approval is open.
    await vi.waitFor(() => expect(root.querySelector(".sender-announce")?.textContent).toBe("Approve in the OpenKey window to revoke."));
    button.click();
    button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(root.querySelector(".sender-confirm-dialog")).toBeNull();
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    gate.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    // The row of the new view follows the same revoke to its end.
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked .status-label")?.textContent).toBe("Revoked"));
    expect(revokeButton(root)).toBeNull();
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
  });

  it("after a cancel the remounted row offers Revoke again, and once settled a revoke can start again", async () => {
    const gate = deferred<unknown>();
    const { root, remount, tinycloud } = await mountAs({ revokeDelegation: () => gate.promise });
    await revoke(root);
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    gate.resolve({ ok: false, error: { code: "REVOCATION_FAILED", message: "Failed to revoke delegation: 500 - x" } });
    await settled(root);
    await remount();
    expect(revokeButton(root)?.disabled).toBe(false);
  });
});

describe("one wallet approval at a time, and a cancel belongs to the share that asked", () => {
  const second = (): SenderShareRecord => addressedRecord({ shareId: "s2", filename: "second.txt", ownerDelegationCid: "policy-root-2", enforcementDelegationCid: "enforcement-root-2", resource: { kind: "exact", path: "xyz.tinycloud.share/shares/s2/second.txt" } });
  const secondRow = (): Row => policyRootRow({ cid: "policy-root-2", resources: [{ resource: `${SPACE}/kv/xyz.tinycloud.share/shares/s2/second.txt`, actions: ["tinycloud.kv/get"], caveats: [] }, { resource: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/decrypt"], caveats: [] }] });
  const rowOf = (root: HTMLElement, name: string) => [...root.querySelectorAll<HTMLElement>(".sender-history-row")].find((row) => row.textContent?.includes(name))!;

  it("a second share's Revoke during an open approval asks for no second approval, and the cancel lands on the first share only", async () => {
    const gate = deferred<void>();
    const openkey = { signMessage: vi.fn(async () => { await gate.promise; throw { code: "USER_CANCELLED", message: "cancelled" }; }) };
    const provider = new ObservedOpenKeyProvider(openkey as never, { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" } as never, ADDRESS, async () => true);
    const harness = await mountAs({
      extra: [second()], rows: [policyRootRow(), secondRow()],
      revokeDelegation: async () => {
        try { await provider.request({ method: "personal_sign", params: ["0x70726f6f66", ADDRESS] }); return { ok: true, data: {} }; } catch (caught) { return { ok: false, error: { code: "NETWORK_ERROR", message: `Network error during delegation revocation: ${String(caught)}` } }; }
      },
    });
    const { root, tinycloud } = harness;
    registerWalletApprovalObserver(tinycloud as unknown as ShareTinyCloud, provider);
    rowOf(root, "qa.txt").querySelector<HTMLButtonElement>(".sender-revoke")!.click(); confirm(root);
    await vi.waitFor(() => expect(openkey.signMessage).toHaveBeenCalledTimes(1));
    rowOf(root, "second.txt").querySelector<HTMLButtonElement>(".sender-revoke")!.click(); confirm(root);
    await vi.waitFor(() => expect(rowOf(root, "second.txt").querySelector(".sender-row-note")).not.toBeNull());
    expect(rowOf(root, "second.txt").querySelector(".sender-row-note")?.textContent).toContain("Another approval is waiting");
    expect(openkey.signMessage).toHaveBeenCalledTimes(1);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    gate.resolve();
    await vi.waitFor(() => expect(rowOf(root, "qa.txt").querySelector(".sender-row-note")?.textContent).toBe("Revoke cancelled. The share is still active."));
    expect(rowOf(root, "second.txt").textContent).not.toContain("Revoke cancelled");
    // Both shares are untouched and can be revoked again.
    expect(root.querySelectorAll(".sender-status-text.revoked")).toHaveLength(0);
    expect(rowOf(root, "second.txt").querySelector<HTMLButtonElement>(".sender-revoke")?.disabled).toBe(false);
  });
});

describe("link-only (bearer) shares from a new session", () => {
  it("revoke with one wallet approval on the share's own delegation, after node verification", async () => {
    const { root, tinycloud } = await mountAs({ record: bearerRecord(), rows: [sessionDelegationRow(), bearerRow()] });
    await revoke(root); await settled(root);
    expect(tinycloud.delegations.query).toHaveBeenCalledWith(expect.objectContaining({ direction: "granted", space: SPACE }));
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledWith("bearer-delegation");
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
  });

  it("an imported link whose delegation is not this account's, or is the owner's session delegation, never reaches the wallet", async () => {
    for (const [cid, rows] of [["foreign-delegation", [bearerRow()]], ["session-delegation", [sessionDelegationRow(), bearerRow()]]] as const) {
      const { root, tinycloud } = await mountAs({ record: { ...bearerRecord(), enforcementDelegationCid: cid }, rows });
      await revoke(root); await settled(root);
      expect(errorText(root)).toContain(EARLIER);
      expect(tinycloud.revokeDelegation).not.toHaveBeenCalled();
      document.body.replaceChildren();
    }
  });
});

describe("an approval that is never answered cannot hold the page", () => {
  const second = (): SenderShareRecord => addressedRecord({ shareId: "s2", filename: "second.txt", ownerDelegationCid: "policy-root-2", enforcementDelegationCid: "enforcement-root-2", resource: { kind: "exact", path: "xyz.tinycloud.share/shares/s2/second.txt" } });
  const secondRow = (): Row => policyRootRow({ cid: "policy-root-2", resources: [{ resource: `${SPACE}/kv/xyz.tinycloud.share/shares/s2/second.txt`, actions: ["tinycloud.kv/get"], caveats: [] }, { resource: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/decrypt"], caveats: [] }] });
  const rowOf = (root: HTMLElement, name: string) => [...root.querySelectorAll<HTMLElement>(".sender-history-row")].find((row) => row.textContent?.includes(name))!;
  const pressRevoke = (root: HTMLElement, name: string) => { rowOf(root, name).querySelector<HTMLButtonElement>(".sender-revoke")!.click(); confirm(root); };
  const GIVE_UP = "The approval wasn't completed. The share is still active. Try again.";
  const fakeClock = () => vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });

  it("after 60 seconds Share stops waiting: a quiet note, the lock is free, the other share proceeds and the first can be tried again", async () => {
    fakeClock();
    const neverAnswered = deferred<unknown>();
    let firstAsked = false;
    const { root, tinycloud } = await mountAs({
      extra: [second()], rows: [policyRootRow(), secondRow()],
      revokeDelegation: (cid) => { if (cid === "policy-root" && !firstAsked) { firstAsked = true; return neverAnswered.promise; } return { ok: true, data: { revoked: true, cid } }; },
    });
    pressRevoke(root, "qa.txt");
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    // Just inside the window the other share is still told to wait.
    await vi.advanceTimersByTimeAsync(59_000);
    pressRevoke(root, "second.txt");
    await vi.waitFor(() => expect(rowOf(root, "second.txt").querySelector(".sender-row-note")?.textContent).toContain("Another approval is waiting"));
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_500);
    // A quiet note, not an alert; Revoke is back.
    expect(rowOf(root, "qa.txt").querySelector(".sender-row-note")?.textContent).toBe(GIVE_UP);
    expect(rowOf(root, "qa.txt").querySelector(".sender-row-error")).toBeNull();
    expect(rowOf(root, "qa.txt").querySelector(".sender-row-hint")).toBeNull();
    expect(rowOf(root, "qa.txt").querySelector<HTMLButtonElement>(".sender-revoke")?.disabled).toBe(false);
    // The lock is free: the other share's Revoke is a new request and goes through.
    pressRevoke(root, "second.txt");
    await vi.waitFor(() => expect(rowOf(root, "second.txt").querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(tinycloud.revokeDelegation).toHaveBeenLastCalledWith("policy-root-2");
    // The first share can be tried again: a new attempt is a new request, once.
    pressRevoke(root, "qa.txt");
    await vi.waitFor(() => expect(rowOf(root, "qa.txt").querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(tinycloud.revokeDelegation.mock.calls.filter(([cid]) => cid === "policy-root")).toHaveLength(2);
    // The first attempt answers very late: nothing about the revoked row changes and nothing is asked again.
    neverAnswered.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(3);
    expect(rowOf(root, "qa.txt").querySelector(".sender-row-error, .sender-row-note")).toBeNull();
  });

  it("a late answer after Share gave up never turns the row Revoked by itself; the next attempt asks the node and finishes without a new approval", async () => {
    fakeClock();
    const late = deferred<unknown>();
    const rows: Row[] = [policyRootRow()];
    const { root, tinycloud } = await mountAs({ rows, revokeDelegation: () => late.promise });
    revokeButton(root)!.click(); confirm(root);
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(60_500);
    expect(root.querySelector(".sender-row-note")?.textContent).toBe(GIVE_UP);
    // The request did revoke the share after all, and answers late.
    rows[0] = policyRootRow({ status: "revoked" });
    late.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(root.querySelector(".sender-status-text.revoked")).toBeNull();
    expect(root.querySelector(".sender-status-text .status-label")?.textContent).toBe("Ready");
    // Trying again checks the node, sees it revoked, and asks for nothing more.
    await revoke(root);
    await vi.waitFor(() => expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1);
  });

  it("an abandoned request that answers late does not consume the cancel of the attempt that replaced it", async () => {
    fakeClock();
    const firstSigned = deferred<{ signature: string }>();
    const secondCancelled = deferred<void>();
    let asked = 0;
    const openkey = { signMessage: vi.fn(async () => { asked += 1; if (asked === 1) return firstSigned.promise; throw { code: "USER_CANCELLED" }; }) };
    const provider = new ObservedOpenKeyProvider(openkey as never, { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" } as never, ADDRESS, async () => true);
    let calls = 0;
    const { root, tinycloud } = await mountAs({
      revokeDelegation: async () => {
        calls += 1;
        const mine = calls;
        try { await provider.request({ method: "personal_sign", params: ["0x70", ADDRESS] }); } catch (caught) { await secondCancelled.promise; return { ok: false, error: { code: "NETWORK_ERROR", message: `Network error during delegation revocation: ${String(caught)}` } }; }
        return { ok: false, error: { code: "REVOCATION_FAILED", message: `Failed to revoke delegation: 500 - attempt ${mine}` } };
      },
    });
    registerWalletApprovalObserver(tinycloud as unknown as ShareTinyCloud, provider);
    revokeButton(root)!.click(); confirm(root);
    await vi.waitFor(() => expect(openkey.signMessage).toHaveBeenCalledTimes(1));
    await vi.advanceTimersByTimeAsync(60_500);
    expect(root.querySelector(".sender-row-note")?.textContent).toBe(GIVE_UP);
    // The second attempt is cancelled in the OpenKey window; its request is still finishing when the first one answers.
    await revoke(root);
    await vi.waitFor(() => expect(openkey.signMessage).toHaveBeenCalledTimes(2));
    firstSigned.resolve({ signature: `0x${"11".repeat(65)}` });
    await vi.advanceTimersByTimeAsync(100);
    secondCancelled.resolve();
    await vi.waitFor(() => expect(root.querySelector(".sender-row-note")?.textContent).toBe("Revoke cancelled. The share is still active."));
    expect(root.querySelector(".sender-row-error")).toBeNull();
  });

  it("a wallet call that throws frees the lock for the other share", async () => {
    let first = true;
    const { root, tinycloud } = await mountAs({
      extra: [second()], rows: [policyRootRow(), secondRow()],
      revokeDelegation: (cid) => { if (first) { first = false; throw new Error("provider exploded"); } return { ok: true, data: { revoked: true, cid } }; },
    });
    pressRevoke(root, "qa.txt");
    await vi.waitFor(() => expect(rowOf(root, "qa.txt").querySelector(".sender-row-error")).not.toBeNull());
    expect(root.textContent).not.toContain("provider exploded");
    pressRevoke(root, "second.txt");
    await vi.waitFor(() => expect(rowOf(root, "second.txt").querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(2);
  });
});

describe("the provider reads the answer of the approval that is current", () => {
  it("a late cancel of an older approval is not read as the newer approval's answer", async () => {
    const settle: Array<(outcome: { signature?: string; reject?: unknown }) => void> = [];
    const openkey = { signMessage: vi.fn(() => new Promise((resolve, reject) => { settle.push((outcome) => outcome.reject !== undefined ? reject(outcome.reject) : resolve({ signature: outcome.signature })); })) };
    const provider = new ObservedOpenKeyProvider(openkey as never, { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" } as never, ADDRESS, async () => true);
    const older = provider.request({ method: "personal_sign", params: ["0x70", ADDRESS] }).catch(() => undefined);
    const newer = provider.request({ method: "personal_sign", params: ["0x70", ADDRESS] }).catch(() => undefined);
    settle[0]!({ reject: { code: "USER_CANCELLED" } });
    await older;
    expect(provider.takeFailure()).toBeUndefined();
    settle[1]!({ reject: { code: "TIMEOUT" } });
    await newer;
    expect(provider.takeFailure()).toBe("timeout");
  });
});

describe("each wallet request carries the CID of the row that was clicked, whatever order the node checks answer in", () => {
  const second = (): SenderShareRecord => addressedRecord({ shareId: "s2", filename: "second.txt", ownerDelegationCid: "policy-root-2", enforcementDelegationCid: "enforcement-root-2", resource: { kind: "exact", path: "xyz.tinycloud.share/shares/s2/second.txt" } });
  const secondRow = (): Row => policyRootRow({ cid: "policy-root-2", resources: [{ resource: `${SPACE}/kv/xyz.tinycloud.share/shares/s2/second.txt`, actions: ["tinycloud.kv/get"], caveats: [] }, { resource: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/decrypt"], caveats: [] }] });
  const rowOf = (root: HTMLElement, name: string) => [...root.querySelectorAll<HTMLElement>(".sender-history-row")].find((row) => row.textContent?.includes(name))!;
  const pressRevoke = (root: HTMLElement, name: string) => { rowOf(root, name).querySelector<HTMLButtonElement>(".sender-revoke")!.click(); confirm(root); };
  const A = "policy-root";
  const B = "policy-root-2";

  /** Share A (qa.txt) is clicked first, then share B (second.txt), each node check held until released. */
  async function bothChecksPending(revokeDelegation: (cid: string) => Promise<unknown> | unknown) {
    const checks = [deferred<void>(), deferred<void>()];
    const harness = await mountAs({ extra: [second()], rows: [policyRootRow(), secondRow()], beforeQuery: (call) => checks[call - 1]?.promise, revokeDelegation });
    pressRevoke(harness.root, "qa.txt");
    await vi.waitFor(() => expect(harness.tinycloud.delegations.query).toHaveBeenCalledTimes(1));
    pressRevoke(harness.root, "second.txt");
    await vi.waitFor(() => expect(harness.tinycloud.delegations.query).toHaveBeenCalledTimes(2));
    expect(harness.tinycloud.revokeDelegation).not.toHaveBeenCalled();
    return { ...harness, releaseA: () => checks[0]!.resolve(), releaseB: () => checks[1]!.resolve() };
  }
  const cidsAsked = (tinycloud: Harness["tinycloud"]) => tinycloud.revokeDelegation.mock.calls.map(([cid]) => cid);

  it("B's node check answers first, then A's", async () => {
    const { root, tinycloud, releaseA, releaseB } = await bothChecksPending((cid) => ({ ok: true, data: { revoked: true, cid } }));
    releaseB(); await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    releaseA();
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-status-text.revoked")).toHaveLength(2));
    expect(cidsAsked(tinycloud)).toEqual([B, A]);
  });

  it("A's node check answers first, then B's", async () => {
    const { root, tinycloud, releaseA, releaseB } = await bothChecksPending((cid) => ({ ok: true, data: { revoked: true, cid } }));
    releaseA(); await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    releaseB();
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-status-text.revoked")).toHaveLength(2));
    expect(cidsAsked(tinycloud)).toEqual([A, B]);
  });

  it.each([["B then A", "B"], ["A then B", "A"]])("both node checks answer in the same moment, %s", async (_order, firstReleased) => {
    const { root, tinycloud, releaseA, releaseB } = await bothChecksPending((cid) => ({ ok: true, data: { revoked: true, cid } }));
    if (firstReleased === "B") { releaseB(); releaseA(); } else { releaseA(); releaseB(); }
    await vi.waitFor(() => expect(root.querySelectorAll(".sender-status-text.revoked").length + root.querySelectorAll(".sender-row-note").length).toBeGreaterThan(0));
    // Whatever was asked, each request names the row's own CID; a refused row asked nothing.
    for (const cid of cidsAsked(tinycloud)) expect([A, B]).toContain(cid);
    expect(new Set(cidsAsked(tinycloud)).size).toBe(cidsAsked(tinycloud).length);
    for (const [name, cid] of [["qa.txt", A], ["second.txt", B]] as const) {
      const revoked = rowOf(root, name).querySelector(".sender-status-text.revoked") !== null;
      expect(cidsAsked(tinycloud).includes(cid)).toBe(revoked);
    }
  });

  it.each([["B", "A"], ["A", "B"]] as const)("serialised: %s holds the wallet while the other's check answers; the other is told to wait and its retry asks for its own CID", async (holder, other) => {
    const walletGate = deferred<void>();
    let held = false;
    const { root, tinycloud, releaseA, releaseB } = await bothChecksPending(async (cid) => {
      if (!held) { held = true; await walletGate.promise; }
      return { ok: true, data: { revoked: true, cid } };
    });
    const cidOf = (who: string) => who === "A" ? A : B;
    const nameOf = (who: string) => who === "A" ? "qa.txt" : "second.txt";
    (holder === "A" ? releaseA : releaseB)();
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    expect(cidsAsked(tinycloud)).toEqual([cidOf(holder)]);
    (other === "A" ? releaseA : releaseB)();
    await vi.waitFor(() => expect(rowOf(root, nameOf(other)).querySelector(".sender-row-note")?.textContent).toContain("Another approval is waiting"));
    // The wait never sent the other row's CID, nor a second request.
    expect(cidsAsked(tinycloud)).toEqual([cidOf(holder)]);
    walletGate.resolve();
    await vi.waitFor(() => expect(rowOf(root, nameOf(holder)).querySelector(".sender-status-text.revoked")).not.toBeNull());
    pressRevoke(root, nameOf(other));
    await vi.waitFor(() => expect(rowOf(root, nameOf(other)).querySelector(".sender-status-text.revoked")).not.toBeNull());
    expect(cidsAsked(tinycloud)).toEqual([cidOf(holder), cidOf(other)]);
  });
});

/**
 * TC-1583. The spoken-only status region (`.sender-announce`) is a statement about
 * the present: it says to approve while the OpenKey window is open and must
 * never say so afterwards, whatever way the revoke ends.
 */
describe("the spoken status region at every step of a revoke", () => {
  const APPROVE = "Approve in the OpenKey window to revoke.";
  const spoken = (root: HTMLElement): string => root.querySelector(".sender-announce")?.textContent ?? "";
  /** Every distinct non-empty text the region held, in order. */
  function recordSpoken(root: HTMLElement): { readonly texts: string[]; readonly stop: () => void } {
    const region = root.querySelector(".sender-announce")!;
    const texts: string[] = [];
    const observer = new MutationObserver(() => { const text = region.textContent ?? ""; if (text !== "" && texts.at(-1) !== text) texts.push(text); });
    observer.observe(region, { childList: true, characterData: true, subtree: true });
    return { texts, stop: () => observer.disconnect() };
  }
  const waitSpoken = (root: HTMLElement, text: string) => vi.waitFor(() => expect(spoken(root)).toBe(text));

  it("success: says to approve while the window is open, then 'Share revoked.', and the approval text never comes back", async () => {
    const gate = deferred<unknown>();
    const { root, tinycloud } = await mountAs({ revokeDelegation: () => gate.promise });
    const heard = recordSpoken(root);
    expect(spoken(root)).toBe("");
    await revoke(root);
    await vi.waitFor(() => expect(tinycloud.revokeDelegation).toHaveBeenCalledTimes(1));
    await waitSpoken(root, APPROVE);
    gate.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await waitSpoken(root, "Share revoked.");
    // The row is Revoked and the region agrees; nothing later puts the approval text back.
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(spoken(root)).toBe("Share revoked.");
    expect(heard.texts).toEqual([APPROVE, "Share revoked."]);
    heard.stop();
  });

  it("a revoke that fails: the approval text is replaced by the reason", async () => {
    const gate = deferred<unknown>();
    const { root } = await mountAs({ revokeDelegation: () => gate.promise });
    const heard = recordSpoken(root);
    await revoke(root);
    await waitSpoken(root, APPROVE);
    gate.resolve({ ok: false, error: { code: "REVOCATION_FAILED", message: "Failed to revoke delegation: 500 - hidden-body" } });
    await settled(root);
    await waitSpoken(root, errorText(root)!);
    expect(spoken(root)).toContain("TinyCloud is having trouble right now (HTTP 500). The share is still active.");
    expect(heard.texts).toEqual([APPROVE, spoken(root)]);
    heard.stop();
  });

  it("cancelling in the OpenKey window: the approval text is replaced by the cancel note", async () => {
    const { root } = await mountWithWallet({ reject: { code: "USER_CANCELLED", message: "User cancelled the request" } });
    const heard = recordSpoken(root);
    await revoke(root); await settled(root);
    await waitSpoken(root, "Revoke cancelled. The share is still active.");
    // The window may answer before the approval text was ever spoken; either way it is not spoken after the note.
    expect(heard.texts.at(-1)).toBe("Revoke cancelled. The share is still active.");
    expect(heard.texts.slice(1)).not.toContain(APPROVE);
    heard.stop();
  });

  it("an approval nobody answers: after 60 seconds the approval text is replaced by the give-up note", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const { root } = await mountAs({ revokeDelegation: () => new Promise(() => undefined) });
    await revoke(root);
    await vi.advanceTimersByTimeAsync(200);
    expect(spoken(root)).toBe(APPROVE);
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.advanceTimersByTimeAsync(200);
    expect(root.querySelector(".sender-row-note")?.textContent).toBe("The approval wasn't completed. The share is still active. Try again.");
    expect(spoken(root)).toBe("The approval wasn't completed. The share is still active. Try again.");
  });

  it("signing out while the approval is open empties the region, and a late answer does not fill it again", async () => {
    const gate = deferred<unknown>();
    const { root } = await mountAs({ revokeDelegation: () => gate.promise });
    await revoke(root);
    await waitSpoken(root, APPROVE);
    // What the sign-out does: the library ends, then the flights are forgotten.
    endSenderLibrary(); resetRevokeFlights();
    expect(spoken(root)).toBe("");
    gate.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(spoken(root)).toBe("");
  });

  it("a library mounted again after the revoke ended does not carry the old text, and one mounted during the approval says it again", async () => {
    const gate = deferred<unknown>();
    const { root, remount } = await mountAs({ revokeDelegation: () => gate.promise });
    await revoke(root);
    await waitSpoken(root, APPROVE);
    await remount();
    await waitSpoken(root, APPROVE);
    gate.resolve({ ok: true, data: { revoked: true, cid: "policy-root" } });
    await waitSpoken(root, "Share revoked.");
    await remount();
    expect(spoken(root)).toBe("");
    expect(root.querySelector(".sender-status-text.revoked")).not.toBeNull();
  });
});
