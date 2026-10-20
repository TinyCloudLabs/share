/**
 * Browser harness for the sender screens (library and composer) with fakes for
 * OpenKey and the node. The screens, the approval hint, the status check and
 * the revoke flow are the real code; only what they talk to is replaced.
 *
 * Query: `screen=library|composer`, then
 *  - library: `reader=ok|hang|fail|expired` (the node status read), `revoke=hang|fail-listing` (the owner wallet's revoke)
 *  - composer: `create=hang|ok|fail`
 *
 * Timers of a second or more run on a manual clock (`window.__qa.advance(ms)`), so
 * "15 seconds later" and "60 seconds later" are exact and instant.
 */
import "../../../src/email-share/sender.css";
import type { IDataVaultService } from "@tinycloud/web-sdk";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { mountSenderHome, type SenderHomeOptions } from "../../../src/share/sender-home.js";
import { mountShareComposer, type ComposerShareResult } from "../../../src/share/composer.js";
import { mountSenderChrome } from "../../../src/share/sender-chrome.js";
import { registerWalletApprovalObserver, type ObservedOpenKeyProvider, type OpenKeyShareSession, type ShareTinyCloud } from "../../../src/share/openkey-session.js";
import { SenderHistoryRepository } from "../../../src/share/sender-history.js";
import type { NodeStatusReader } from "../../../src/share/node-status.js";
import { fail } from "../../../src/share/sender-failure.js";
import { trackWalletApproval } from "../../../src/share/wallet-approval.js";

interface ManualTimer { readonly id: number; readonly at: number; readonly run: () => void }
const timers: ManualTimer[] = [];
let clock = 0;
let nextTimerId = 9_000_000;
const realSetTimeout = window.setTimeout.bind(window);
const realClearTimeout = window.clearTimeout.bind(window);
window.setTimeout = ((handler: TimerHandler, delay = 0, ...args: unknown[]): number => {
  if (typeof handler !== "function" || delay < 1000) return realSetTimeout(handler, delay, ...args);
  nextTimerId += 1;
  timers.push({ id: nextTimerId, at: clock + delay, run: () => handler(...args) });
  return nextTimerId;
}) as typeof window.setTimeout;
window.clearTimeout = ((id?: number): void => {
  const index = timers.findIndex((timer) => timer.id === id);
  if (index >= 0) timers.splice(index, 1); else realClearTimeout(id);
}) as typeof window.clearTimeout;

const params = new URLSearchParams(location.search);
const screen = params.get("screen") ?? "library";
const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const NODE = { origin: "https://node.example.invalid", nodeDid: "did:key:z6MkNode" };
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;

interface QaControl {
  advance(ms: number): Promise<void>;
  /** The open OpenKey approval answers (approved). */
  approve(): void;
  /** The open OpenKey window is closed by the sender. */
  closed: boolean;
}
const pending: Array<{ readonly resolve: (value: unknown) => void; readonly reject: (reason: unknown) => void }> = [];
const hold = <T>(): Promise<T> => new Promise<T>((resolve, reject) => { pending.push({ resolve: resolve as (value: unknown) => void, reject }); });
const qa: QaControl = {
  async advance(ms) {
    clock += ms;
    for (;;) {
      const due = timers.filter((timer) => timer.at <= clock).sort((a, b) => a.at - b.at)[0];
      if (due === undefined) break;
      timers.splice(timers.indexOf(due), 1);
      due.run();
      await new Promise((resolve) => realSetTimeout(resolve, 0));
    }
    await new Promise((resolve) => realSetTimeout(resolve, 50));
  },
  approve() { for (const request of pending.splice(0)) request.resolve({ ok: true, data: { revoked: true } }); },
  closed: false,
};
(window as unknown as { __qa: QaControl }).__qa = qa;

let approvalFailure: "cancelled" | undefined;
const session = {
  address: ADDRESS,
  openkey: {
    disconnect: () => { qa.closed = true; approvalFailure = "cancelled"; for (const request of pending.splice(0)) request.reject(Object.assign(new Error("closed"), { code: "USER_CANCELLED" })); },
    signOut: async () => ({ requestId: "r", revoked: true }),
  },
  auth: {},
} as unknown as OpenKeyShareSession;

function vault(): IDataVaultService {
  const store = new Map<string, unknown>();
  return {
    put: async (key: string, value: unknown) => { store.set(key, value); return { ok: true, data: undefined }; },
    get: async (key: string) => store.has(key) ? { ok: true, data: store.get(key) } : { ok: false, error: { code: "NOT_FOUND", message: "missing" } },
    delete: async (key: string) => { store.delete(key); return { ok: true, data: undefined }; },
    listPage: async ({ prefix, removePrefix }: { prefix: string; removePrefix: boolean }) => ({ ok: true, data: { keys: [...store.keys()].filter((key) => key.startsWith(prefix)).map((key) => removePrefix ? key.slice(prefix.length) : key), truncated: false } }),
  } as unknown as IDataVaultService;
}

const record = (id: string, filename: string, over: Partial<SenderShareRecord> = {}): SenderShareRecord => ({
  shareId: id,
  target: { origin: NODE.origin, nodeAudience: NODE.nodeDid, spaceId: SPACE },
  resource: { kind: "exact", path: `xyz.tinycloud.share/shares/${id}/${filename}` },
  actions: ["tinycloud.kv/get"],
  recipientMatcher: { kind: "bearer" },
  targetKind: "bearer",
  registeredAt: "2026-10-20T01:23:00.000Z",
  expiresAt: "2026-10-27T01:23:00.000Z",
  enforcementDelegationCid: `cid-${id}`,
  link: "https://share.example.invalid/viewer#tc1=opaque",
  filename,
  ...over,
});

const tinycloud = {
  credentialHolderDid: "did:key:z6MkLaterSession",
  activeNodeIdentity: async () => NODE,
  signSessionBytes: async () => new Uint8Array(64),
  signOut: async () => undefined,
  revokeDelegation: () => params.get("revoke") === "hang"
    ? trackWalletApproval(() => hold()).catch(() => ({ ok: false, error: { code: "REVOCATION_FAILED", message: "closed" } }))
    : Promise.resolve({ ok: true, data: { revoked: true } }),
  delegations: {
    query: async () => params.get("revoke") === "fail-listing"
      // An endless listing that never shows the share's root: a revoke ends with the longest "could not read your whole list" message.
      ? { ok: true, data: { schemaVersion: 2, items: [], nextCursor: "more" } }
      : { ok: true, data: { schemaVersion: 2, items: [{
        cid: "cid-html", direction: "granted", delegatorDid: "did:key:z6MkCreatingSession", delegateDid: "did:key:z6MkShareKey", parents: ["session"], status: "active",
        resources: [{ resource: `${SPACE}/kv/xyz.tinycloud.share/shares/html/quarterly-agent-report-final-reviewed-v2-with-a-very-long-name.html`, actions: ["tinycloud.kv/get"], caveats: [] }],
      }] } },
    status: async () => ({ ok: true, data: { status: "active" } }),
  },
} as unknown as ShareTinyCloud;
// What the OpenKey provider reports about an approval that failed: here only "the sender closed the window".
registerWalletApprovalObserver(tinycloud, { takeFailure: () => { const failure = approvalFailure; approvalFailure = undefined; return failure; } } as unknown as ObservedOpenKeyProvider);

const root = document.getElementById("share-app")!;
const chrome = document.createElement("div");
const view = document.createElement("div");
root.append(chrome, view);
mountSenderChrome(chrome, { session, tinycloud, onSignedOut: () => undefined });

async function library(): Promise<void> {
  const history = new SenderHistoryRepository(vault(), () => Date.parse("2026-10-20T04:00:00.000Z"));
  await history.save(record("html", "quarterly-agent-report-final-reviewed-v2-with-a-very-long-name.html"));
  await history.save(record("email", "notes.md", { recipientMatcher: { kind: "exactEmail", value: "a-person-with-a-long-address@a-long-company-domain.example.invalid" }, targetKind: "email", ownerDelegationCid: "root-email", ownerDid: "did:key:z6MkCreatingSession", actions: ["tinycloud.kv/get", "tinycloud.kv/put"] }));
  await history.save(record("old", "old-share.md", { expiresAt: "2026-10-01T00:00:00.000Z" }));
  const reader: NodeStatusReader = (records, signal) => {
    const kind = params.get("reader") ?? "ok";
    if (kind === "hang") return new Promise(() => undefined);
    if (kind === "fail") return Promise.reject(new Error("offline"));
    void signal;
    return Promise.resolve(new Map(records.map((item) => [item.shareId, kind === "expired" && item.shareId === "html" ? { state: "expired" as const } : { state: "active" as const }])));
  };
  const options: SenderHomeOptions = { session, tinycloud, history, onNavigate: () => undefined, statusReader: reader };
  mountSenderHome(view, options);
}

function composer(): void {
  // The approval observer is registered above, for both screens.
  mountShareComposer(view, {
    origin: "https://share.tinycloud.xyz",
    openKeyAddress: ADDRESS,
    session,
    tinycloud,
    onBack: () => undefined,
    createShare: async (): Promise<ComposerShareResult> => {
      const create = params.get("create") ?? "ok";
      if (create === "hang") await trackWalletApproval(() => hold());
      if (create === "fail") throw fail("spaceNotReady", "space not ready");
      // "hang": the OpenKey approval stays open until the page approves it (`__qa.approve()`) or the sender cancels (the window closes).
      return { url: "https://share.example.invalid/viewer#tc1=opaque", cid: "cid-new", expiresAt: "2026-10-27T01:23:00.000Z" };
    },
  });
}

if (screen === "composer") composer(); else await library();
document.documentElement.dataset.ready = "yes";
