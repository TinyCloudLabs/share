/**
 * /courier inside TinyCloud One's frame (embed contract v1, child side).
 *
 * One hands this page a delegation of its own session; the page holds only an
 * in-memory session key (`persistSession: false`, no wallet, no OpenKey), applies
 * the delegation with `useDelegation` and reads the owner's courier mailbox
 * through the resulting `DelegatedAccess`. It is read-only: the store this
 * module builds refuses `createApproval` and `writeOrders`, and the screens
 * open the same page in a new tab for anything that writes.
 *
 * Nothing the mailbox holds is ever posted to the parent: only hello and
 * request (see one-embed.ts).
 */
import type { DelegatedAccess, PortableDelegation } from "@tinycloud/web-sdk";
import { COURIER_ROOT } from "./model.js";
import { startEmbedController, type EmbedController, type EmbedTheme, type EmbedWindow, type GrantMessage, type PermissionEntry } from "./one-embed.js";
import { COURIER_SPACE } from "./scope.js";
import type { CourierSession } from "./session.js";
import { createKvStore, StoreError, type CourierKv, type CourierStore } from "./store.js";

/** What the embedded view needs, and all it ever asks One for: kv get and list under the courier prefix of the owner's agents space. */
export const COURIER_EMBED_SCOPE: readonly PermissionEntry[] = [
  { service: "tinycloud.kv", space: COURIER_SPACE, path: COURIER_ROOT, actions: ["get", "list"] },
];

export interface EmbeddedEvents {
  /** The first usable grant: show the signed-in view. */
  onSession(session: CourierSession): void;
  /** A grant that answers a refused read arrived: load the mailbox again. */
  onRegranted(): void;
  /** Access ended (revoked, refused, or never granted): show the signed-out state. */
  onEnded(): void;
}

export interface EmbeddedCourier {
  start(events: EmbeddedEvents): void;
  /** Reads were refused (a 401): ask One once for exactly the courier scope, then end the session if refused again. */
  accessRefused(): void;
  /** Opens this same page, standalone, in a new tab. */
  openStandalone(): void;
  stop(): void;
}

/** The slice of the Web SDK this module uses; tests pass a fake. */
export interface EmbeddedSdk {
  readonly client: { readonly sessionDid: string; useDelegation(delegation: PortableDelegation): Promise<DelegatedAccess> };
  deserialize(serialized: string): PortableDelegation;
}

export interface EmbeddedOptions {
  /** Applies a theme to the page. Defaults to `<html data-theme>`. */
  onTheme?: (theme: EmbedTheme) => void;
  /** Builds the session-only SDK client. */
  loadSdk?: () => Promise<EmbeddedSdk>;
}

/** The owner's agents space id for a delegation, derived from the delegation itself. */
export function agentsSpaceOf(owner: { readonly ownerAddress: string; readonly chainId: number }): string {
  return `tinycloud:pkh:eip155:${String(owner.chainId)}:${owner.ownerAddress}:${COURIER_SPACE}`;
}

/** A store over the delegated kv that can only read. */
export function readOnlyStore(kv: CourierKv): CourierStore {
  const store = createKvStore(kv);
  return {
    list: store.list,
    readJson: store.readJson,
    readOrders: store.readOrders,
    createApproval: () => Promise.reject(new StoreError("denied")),
    writeOrders: () => Promise.reject(new StoreError("denied")),
  };
}

/** What a kv call returns while no delegation is held: the node's own 401 shape, which the store reads as "denied". */
const NO_DELEGATION = { ok: false, error: { code: "AUTH_UNAUTHORIZED", service: "kv", message: "no delegation", meta: { status: 401 } } } as const;

async function loadSdk(): Promise<EmbeddedSdk> {
  // On demand, as the OpenKey sign-in loads it: the standalone signed-out page never fetches the SDK.
  const { TinyCloudWeb, deserializeDelegation } = await import("@tinycloud/web-sdk");
  // A local-run node override: only the dev server defines it, so no build carries it. It pins the node and the registry to that one origin.
  const devNode = import.meta.env.COURIER_DEV_NODE;
  const client = typeof devNode === "string" && devNode !== ""
    ? await TinyCloudWeb.create({ persistSession: false, tinycloudHosts: [devNode], tinycloudRegistryUrl: devNode, autoDiscoverLocalNode: false } as Parameters<typeof TinyCloudWeb.create>[0])
    : await TinyCloudWeb.create({ persistSession: false });
  return { client, deserialize: deserializeDelegation };
}

/**
 * Returns null unless this is embedded mode under a One origin (the page then
 * runs its normal OpenKey sign-in and posts nothing).
 */
export function connectEmbedded(win: Window, options: EmbeddedOptions = {}): EmbeddedCourier | null {
  let events: EmbeddedEvents | undefined;
  let sdk: EmbeddedSdk | undefined;
  let current: DelegatedAccess | undefined;
  let session: CourierSession | undefined;
  let requested = false;
  let stopped = false;

  const applyTheme = options.onTheme ?? ((theme: EmbedTheme) => { win.document.documentElement.dataset["theme"] = theme; });

  const end = (): void => {
    current = undefined;
    session = undefined;
    requested = false;
    events?.onEnded();
  };

  // The store reads through whichever delegation is current, so a re-grant never repaints the page.
  const kv = {
    get: async (...args: Parameters<CourierKv["get"]>) => (current === undefined ? NO_DELEGATION : current.kv.get(...args)),
    list: async (...args: Parameters<CourierKv["list"]>) => (current === undefined ? NO_DELEGATION : current.kv.list(...args)),
    put: async (...args: Parameters<CourierKv["put"]>) => (current === undefined ? NO_DELEGATION : current.kv.put(...args)),
  } as unknown as CourierKv;

  const applyGrant = async (grant: GrantMessage): Promise<void> => {
    if (sdk === undefined) return;
    let chosen: DelegatedAccess | undefined;
    let ownerAddress = "";
    for (const entry of grant.grants) {
      if (typeof entry.delegation !== "string") continue;
      try {
        const delegation = sdk.deserialize(entry.delegation);
        // Only the owner's own agents space, named by the delegation itself.
        if (entry.spaceId !== agentsSpaceOf(delegation)) continue;
        const access = await sdk.client.useDelegation(delegation);
        if (access.spaceId !== entry.spaceId) continue;
        chosen = access;
        ownerAddress = delegation.ownerAddress;
      } catch {
        continue;
      }
    }
    if (stopped) return;
    if (chosen === undefined) {
      // A grant with no usable agents space: ask once for exactly the courier scope, then give up.
      if (requested) end();
      else { requested = true; controller?.request([...COURIER_EMBED_SCOPE]); }
      return;
    }
    const answeredRequest = requested;
    requested = false;
    current = chosen;
    if (session === undefined) {
      session = { address: ownerAddress, store: readOnlyStore(kv), dispose: async () => { current = undefined; }, signOut: async () => "share-only" };
      events?.onSession(session);
    } else if (answeredRequest) {
      // A refused read was answered with a new grant: load again. (A routine re-grant before expiry changes nothing on screen.)
      events?.onRegranted();
    }
  };

  const controller: EmbedController | null = startEmbedController({
    win: win as unknown as EmbedWindow,
    handlers: {
      onGrant: (grant) => { void applyGrant(grant); },
      onDenied: () => { end(); },
      onRevoke: () => { end(); },
      onTheme: applyTheme,
    },
  });
  if (controller === null) return null;

  return {
    start(next) {
      events = next;
      (options.loadSdk ?? loadSdk)().then((loaded) => {
        if (stopped) return;
        sdk = loaded;
        controller.hello(loaded.client.sessionDid);
      }, () => { if (!stopped) end(); });
    },
    accessRefused() {
      if (current === undefined) return;
      if (requested) { end(); return; }
      requested = true;
      controller.request([...COURIER_EMBED_SCOPE]);
    },
    openStandalone() { win.open(new URL(win.location.pathname, win.location.origin).href, "_blank", "noopener,noreferrer"); },
    stop() {
      stopped = true;
      controller.stop();
      current = undefined;
      session = undefined;
    },
  };
}
