import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
import { composeManifestRequest, authorizationVerdictOf, EXPIRY, verifyEip191MessageSignature, type ClientSession, type SignRequest, type SignResponse } from "@tinycloud/sdk-core";
import { TinyCloudWeb, type Manifest, type PermissionEntry } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";
import { defaultEncryptionNetworkForOwner, pathBoundSessionPermissions } from "@tinycloud/share-sdk";
import { checkLabel, SignInOptionError } from "./sign-in-label.js";
import { assertManifestInScope, ManifestRejectedError, MANIFEST_CHECK_ADDRESS, type ManifestScope } from "./manifest-policy.js";
import { trackWalletApproval } from "./wallet-approval.js";
import { OPENKEY_ORIGIN } from "./openkey-origin.js";
import { LIBRARY_SESSION_PREFIX, markOpenKeySignedInHere } from "./library-session.js";

export { SignInOptionError } from "./sign-in-label.js";

export interface OpenKeyShareSession {
  readonly address: string;
  readonly openkey: OpenKey;
  readonly auth: AuthResult;
}

export type ShareTinyCloud = TinyCloudWeb;

export const SHARE_APPLICATION_SPACE = "applications";
export const SHARE_APPLICATION_PREFIX = "xyz.tinycloud.share/";
export const FILES_FOR_YOU_SPACE = "files-for-you";
export const FILES_FOR_YOU_PREFIX = "v1/";
export const MAX_SHARE_FILE_BYTES = 100 * 1024 * 1024;

export async function authenticateWithOpenKey(onStatus: (message: string) => void, guardApproval: ApprovalGuard = (wait) => wait(), appName = DEFAULT_APP_NAME): Promise<OpenKeyShareSession> {
  const openkey = new OpenKey({ host: OPENKEY_ORIGIN, appName, mode: "iframe" });
  onStatus("Opening OpenKey…");
  let auth: AuthResult;
  try {
    auth = await guardApproval(() => openkey.connect(), { kind: "connect" });
  } catch (error) {
    // A cancelled or given-up connect leaves no window behind.
    openkey.disconnect();
    throw error;
  }
  onStatus("OpenKey connected.");
  return { address: auth.address, openkey, auth };
}

/**
 * The OpenKey session of an account the library session was saved for, without opening OpenKey: nothing is shown,
 * and the restored session needs no signature. A signature asked for later (a revoke, a fresh sign-in) opens OpenKey's
 * own window as usual and must still recover to `account.address`. Managed keys only: an external wallet signs
 * through `connect()`'s routing.
 */
export function reopenOpenKey(account: AuthResult, appName = DEFAULT_APP_NAME): OpenKeyShareSession {
  return { address: account.address, openkey: new OpenKey({ host: OPENKEY_ORIGIN, appName, mode: "iframe" }), auth: account };
}

/*
 * Every signature — the manifest-bearing sign-in, account bootstrap and
 * owned-space hosting — needs the sender's approval: OpenKey's own sign
 * widget for managed keys, the injected wallet for external ones. Share holds
 * no OpenKey credential, and accepts only a signature that recovers to the
 * signed-in account, whatever address the signer reports.
 * A later origin-bound OpenKey signing grant (TC-994 option a) can route the
 * non-sign-in purposes back to OpenKey's server-side Auto-Sign here.
 */
async function explicitOpenKeyApproval(session: OpenKeyShareSession, request: SignRequest): Promise<SignResponse> {
  const { signature } = await trackWalletApproval(() => session.openkey.signMessage({ message: request.message, keyId: session.auth.keyId }));
  return typeof signature === "string" && await verifyEip191MessageSignature(request.message, signature, session.address)
    ? { approved: true, signature }
    : { approved: false, reason: "OpenKey did not return a signature from the signed-in account" };
}

/*
 * The owner-policy path works only inside the authenticated sender's
 * applications space. Reads build the library picker; new encrypted share
 * objects are written below `xyz.tinycloud.share/shares/`. These grants never
 * delegate authority or content to the static Share host. The trailing slash
 * is a resource boundary, and `del` is deliberately absent.
 */
export function ownerSpacePermissions(): PermissionEntry[] {
  return [
    { service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: SHARE_APPLICATION_PREFIX, actions: ["get", "list", "metadata"], skipPrefix: true },
    { service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: `${SHARE_APPLICATION_PREFIX}shares/`, actions: ["put"], skipPrefix: true },
  ];
}

export function historyPermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.vault", space: SHARE_APPLICATION_SPACE, path: "sender-history/v2/records/", actions: ["put", "get", "list", "del"], skipPrefix: true }];
}

export function credentialSpacePermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: `${SHARE_APPLICATION_PREFIX}credentials/v1/`, actions: ["get", "put", "list"], skipPrefix: true }];
}

/** Private, recipient-owned copies created only by the post-render save action. */
export function filesForYouPermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.kv", space: FILES_FOR_YOU_SPACE, path: FILES_FOR_YOU_PREFIX, actions: ["get", "put", "list"], skipPrefix: true }];
}

/** Why an OpenKey approval did not produce a usable signature. */
export type WalletApprovalFailure = "cancelled" | "timeout" | "wrong-account";

type SignatureVerifier = (message: string, signature: string, address: string) => Promise<boolean>;

function approvalFailureOf(caught: unknown): WalletApprovalFailure | undefined {
  const code = typeof caught === "object" && caught !== null && "code" in caught ? caught.code : undefined;
  if (code === "USER_CANCELLED" || code === 4001) return "cancelled";
  if (code === "TIMEOUT") return "timeout";
  return undefined;
}

function hexToText(hex: string): string | undefined {
  const digits = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (digits.length === 0 || digits.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(digits)) return undefined;
  return new TextDecoder().decode(Uint8Array.from(digits.match(/.{2}/g)!, (pair) => Number.parseInt(pair, 16)));
}

/**
 * The OpenKey provider the Web SDK signs owner revocations with, plus the one
 * thing the SDK hides: how an approval failed. OpenKey rejects with a plain
 * `{ code: "USER_CANCELLED" | "TIMEOUT" }` object, and the SDK folds that into
 * "[object Object]". Every signature must also recover to the signed-in
 * account; one from any other account is refused here, before the SDK can
 * attach it to a request.
 */
export class ObservedOpenKeyProvider extends OpenKeyProvider {
  private failure: WalletApprovalFailure | undefined;
  /** Counts approvals asked for; an answer to an older one is not the current approval's. */
  private asked = 0;

  constructor(
    openkey: OpenKey,
    auth: AuthResult,
    private readonly signedInAddress: string,
    private readonly verify: SignatureVerifier = verifyEip191MessageSignature,
    private readonly guard?: ApprovalGuard,
  ) {
    super(openkey, auth);
  }

  override async request(args: { method: string; params?: any[] }): Promise<any> {
    if (args.method !== "personal_sign") return super.request(args);
    if (this.guard !== undefined) return this.guard(() => this.signObserved(args), { kind: "sign" });
    return this.signObserved(args);
  }

  private async signObserved(args: { method: string; params?: unknown[] }): Promise<unknown> {
    this.failure = undefined;
    const mine = ++this.asked;
    // Fail closed: a message that is not hex-encoded text cannot be checked against the signed-in account
    // afterwards, so OpenKey is never asked to sign it. The SDK always sends hex.
    const message = typeof args.params?.[0] === "string" ? hexToText(args.params[0]) : undefined;
    if (message === undefined) throw new Error("wallet-approval-unreadable-message");
    let signature: unknown;
    try {
      signature = await trackWalletApproval(() => super.request(args));
    } catch (caught) {
      if (mine === this.asked) this.failure = approvalFailureOf(caught);
      throw caught;
    }
    if (typeof signature !== "string" || !(await this.verify(message, signature, this.signedInAddress))) {
      if (mine === this.asked) this.failure = "wrong-account";
      throw new Error("wallet-approval-wrong-account");
    }
    return signature;
  }

  /** The failure of the most recent approval, once; undefined when it did not fail or failed for another reason. */
  takeFailure(): WalletApprovalFailure | undefined {
    const failure = this.failure;
    this.failure = undefined;
    return failure;
  }
}

const approvalObservers = new WeakMap<object, ObservedOpenKeyProvider>();

export function registerWalletApprovalObserver(tinycloud: ShareTinyCloud, provider: ObservedOpenKeyProvider): void {
  approvalObservers.set(tinycloud, provider);
}

export function takeWalletApprovalFailure(tinycloud: ShareTinyCloud): WalletApprovalFailure | undefined {
  return approvalObservers.get(tinycloud)?.takeFailure();
}

export function ownerEncryptionNetwork(address: string): string {
  // Network IDs use the storage-normalized EIP-155 account spelling at the
  // signed capability boundary; the SDK still canonicalizes the space DID.
  return `urn:tinycloud:encryption:did:pkh:eip155:1:${address.toLowerCase()}:default`;
}

/**
 * Wraps every wait on an OpenKey window (connect, each signature). A caller
 * that needs to know when an approval is open, or to give up on one, passes a
 * guard; the default runs the wait as is. A wait that ends in an error (a
 * cancel, a refusal, the guard giving up) closes the OpenKey flow it opened.
 */
export type ApprovalGuard = <T>(wait: () => Promise<T>, info?: ApprovalInfo) => Promise<T>;

/**
 * What a guarded wait is, for a caller that counts the person's approvals:
 * opening OpenKey (`connect`, no signature) or one signature (`sign`, with the
 * SDK's reason for it when it gives one). A guard that ignores it keeps working.
 */
export interface ApprovalInfo {
  readonly kind: "connect" | "sign";
  readonly purpose?: string | undefined;
}

/** The longest a session may last, and the default, apart from the sign-in session tier below. */
export const MAX_SESSION_MS = 60 * 60 * 1000;
/**
 * The SDK's sign-in session tier (`EXPIRY.SESSION_MS`, 30 days: OpenKey's own sign-in limit). Share's library
 * session lasts this long, saved on the device; it is the one value above the hour `expiry` accepts.
 */
export const SIGN_IN_SESSION_MS = EXPIRY.SESSION_MS;
const DEFAULT_APP_NAME = "TinyCloud Share";
const DEFAULT_SESSION_PREFIX = "tinycloud-share";
const REGISTRY_SYNC_WAIT_MS = 15_000;

export interface SignInWithManifestOptions extends ManifestScope {
  /** Explicit owner-approved library lease. Details: TC-2872 */
  readonly libraryRenewalAuthorization?: string;
  /**
   * What the signed-in session may do: a manifest, or a function of the signed-in
   * address for a manifest that names an account-specific resource (the share
   * manifest names the owner's encryption network). It is checked against the
   * scope below before OpenKey is opened (a function is checked once with a
   * placeholder address first, then again with the real one before anything is signed).
   */
  readonly manifest: Manifest | ((address: string) => Manifest);
  readonly config: SharePublicConfig;
  /** An OpenKey connection that already exists; omitted, OpenKey opens first. */
  readonly session?: OpenKeyShareSession;
  readonly onStatus?: (message: string) => void;
  /**
   * Owned spaces to host through the real SIWE flow once signed in, in order.
   * When account-registry permissions are enabled (the default), `account`
   * is hosted first for the SDK's registry/index setup.
   * Each must be in `allowedSpaces`.
   */
  readonly hostSpaces?: readonly string[];
  /** Include the SDK's account registry/index grants and host `account`. Default true. */
  readonly includeAccountRegistryPermissions?: boolean;
  /** Let the SDK create the manifest's primary space when absent. Default true. */
  readonly autoCreateSpace?: boolean;
  readonly guardApproval?: ApprovalGuard;
  /** Called with the client as soon as it exists, so a caller can read why an approval failed even if sign-in throws. */
  readonly onClient?: (tinycloud: ShareTinyCloud) => void;
  /**
   * Skips the scope check. For tests and Share's own tooling only: a caller
   * that passes a manifest from anywhere else must state its scope instead.
   * The SDK's own validation still runs.
   */
  readonly unsafeAllowBroadManifest?: boolean;
  /** The name OpenKey shows the person, and the sign-in statement. Used only when OpenKey is opened here. Default "TinyCloud Share". */
  readonly appName?: string;
  /** The SIWE domain, a host name. Default: the host of `config.shareOrigin`. */
  readonly domain?: string;
  /** Prefix of the SDK's session storage keys. Without `persistSession` this only names the SDK instance; with it, it is the boundary that keeps one caller's persisted session from another's. Default "tinycloud-share". */
  readonly sessionPrefix?: string;
  /**
   * Let the SDK persist the signed session (localStorage, under `sessionPrefix`) so a later sign-in
   * restores it while it is still valid and covers the manifest, with no new approval. Default false:
   * the session lives only in memory. Restore is bound to the connected account and to the prefix the
   * caller picks, and `dispose()` still signs out (clearing what was persisted).
   */
  readonly persistSession?: boolean;
  /** How long the session lasts, in milliseconds: a whole number from 1 to one hour (3 600 000), or exactly `SIGN_IN_SESSION_MS`. Default one hour. */
  readonly expiry?: number;
  /**
   * Waits, after sign-in and space hosting, for the SDK's background sync of the
   * account's own space registry, for at most `timeoutMs` (default 15 s). It
   * never rejects: the SDK already logs a failed sync as a warning. The SDK
   * exposes no public handle for the sync, so this reads its pending promise;
   * if the SDK stops keeping one, the wait ends at once.
   */
  readonly waitForAccountRegistrySync?: boolean | { readonly timeoutMs?: number };
}

export interface ManifestSignIn {
  readonly tinycloud: ShareTinyCloud;
  readonly session: OpenKeyShareSession;
  /** Space name to the id `ensureOwnedSpaceHosted` returned, for any requested hosting. */
  readonly spaces: Readonly<Record<string, string>>;
  /** Epoch ms the signed session ends at: the SIWE's Expiration Time, or the requested expiry when the message carries none. A restored session keeps its own remaining time. */
  readonly sessionExpiresAt: number;
  /** Closes the OpenKey connection this call opened without signing out: a persisted session stays usable by the next open. Safe to call more than once; never rejects. */
  detach(): Promise<void>;
  /** Signs the client out (clearing any persisted session) and, when this call opened the OpenKey connection, closes its windows and flows. Safe to call more than once; never rejects. */
  dispose(): Promise<void>;
}

const HOST_NAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/i;

function pendingRegistrySync(tinycloud: object): Promise<unknown> | undefined {
  if (!("pendingAccountRegistrySync" in tinycloud)) return undefined;
  const pending = tinycloud.pendingAccountRegistrySync;
  if (typeof pending !== "object" || pending === null || !("promise" in pending)) return undefined;
  return pending.promise instanceof Promise ? pending.promise : undefined;
}

async function settleAccountRegistrySync(tinycloud: ShareTinyCloud, timeoutMs: number): Promise<void> {
  const pending = pendingRegistrySync(tinycloud);
  if (pending === undefined) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((resolve) => { timer = setTimeout(resolve, timeoutMs); });
  try {
    await Promise.race([pending.then(() => undefined, () => undefined), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function checkOptions(options: SignInWithManifestOptions): void {
  const { expiry, domain, appName, sessionPrefix } = options;
  if (expiry !== undefined && expiry !== SIGN_IN_SESSION_MS && !(Number.isInteger(expiry) && expiry >= 1 && expiry <= MAX_SESSION_MS)) {
    throw new SignInOptionError("expiry", `a session lasts 1 to ${MAX_SESSION_MS} milliseconds, or exactly ${SIGN_IN_SESSION_MS}`);
  }
  if (domain !== undefined && (domain.length > 253 || !HOST_NAME.test(domain))) throw new SignInOptionError("domain", "the domain must be an ASCII host name");
  if (appName !== undefined) checkLabel("appName", appName);
  if (sessionPrefix !== undefined) {
    checkLabel("sessionPrefix", sessionPrefix);
    if (!/^[A-Za-z0-9._-]+$/.test(sessionPrefix)) throw new SignInOptionError("sessionPrefix", "letters, digits, dot, dash and underscore only");
  }
}

/** Freezes `value` and everything inside it. */
function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const inner of Object.values(value)) deepFreeze(inner);
  }
  return value;
}

function checkManifest(options: SignInWithManifestOptions, manifest: Manifest, address: string): void {
  if (options.unsafeAllowBroadManifest === true) return;
  assertManifestInScope(manifest, options, address);
  const allowed = options.allowedSpaces ?? [manifest.space ?? SHARE_APPLICATION_SPACE];
  for (const name of options.hostSpaces ?? []) {
    if (name !== "account" && !allowed.includes(name)) throw new ManifestRejectedError("space-not-allowed", `cannot host a space the manifest may not use: ${name}`);
  }
}

/**
 * The one sign-in: OpenKey, then a `TinyCloudWeb` session that holds `manifest`
 * plus the SDK's account-registry permissions by default (below), then the owned
 * spaces hosted. By default the session lives in memory only
 * (`persistSession: false`); nothing is written to storage. With
 * `persistSession: true` the SDK persists it under `sessionPrefix` and a later
 * `signIn()` restores it while it is still valid for the same account and
 * covers the manifest — a reload of that caller asks for no new approval.
 * Share's library and the viewer's "Save a
 * copy" sign in here, each with its own manifest and scope, and an app-install
 * flow does the same with an app's manifest.
 *
 * What the session can do is the manifest, which must sit inside the scope the
 * caller states (see `ManifestScope`; a manifest outside it is refused with a
 * `ManifestRejectedError` before OpenKey opens), AND what the SDK adds to every
 * sign-in so it can keep a new account's own space registry in sync:
 * get/put/list on `account/applications/` and `account/spaces/`, the bootstrap
 * flag, read/write/schema on the account database and delegation list. They
 * can be omitted with `includeAccountRegistryPermissions: false`; the SDK
 * skips registry sync without account SQL-read, and this helper skips account hosting.
 *
 * Every signature needs the person's approval in the OpenKey window and must
 * recover to the signed-in account (see `ObservedOpenKeyProvider`). A failed
 * or cancelled approval rejects and closes the OpenKey flow; the caller decides
 * what to say. Whatever ends the sign-in early also disposes the session.
 */
export async function signInWithManifest(options: SignInWithManifestOptions): Promise<ManifestSignIn> {
  const { config, hostSpaces = [], includeAccountRegistryPermissions = true, autoCreateSpace = true } = options;
  const onStatus = options.onStatus ?? (() => undefined);
  checkOptions(options);
  if (options.libraryRenewalAuthorization !== undefined &&
      (options.sessionPrefix !== LIBRARY_SESSION_PREFIX || options.persistSession !== true || options.manifest !== shareManifest)) {
    throw new Error("library-renewal-scope");
  }
  // The manifest that is checked is a frozen private copy, and that copy is what gets signed: nothing the caller holds can
  // change it during the OpenKey waits in between. A manifest given as an object is checked before OpenKey opens.
  const given = options.manifest;
  const freezeChecked = (candidate: Manifest, address: string): Manifest => {
    const copy = deepFreeze(structuredClone(candidate));
    checkManifest(options, copy, address);
    return copy;
  };
  const checked = typeof given === "function" ? undefined : freezeChecked(given, MANIFEST_CHECK_ADDRESS);
  // A function manifest needs the address: its shape is checked first with a placeholder, then the real one is checked and used.
  if (typeof given === "function") freezeChecked(given(MANIFEST_CHECK_ADDRESS), MANIFEST_CHECK_ADDRESS);
  const appName = options.appName ?? DEFAULT_APP_NAME;
  const opened = options.session === undefined;
  const session = options.session ?? await authenticateWithOpenKey(onStatus, options.guardApproval, appName);
  // From here on the connection is open. ANY throw (a function manifest, a refusal, a bad origin, an `onClient` that throws,
  // the SDK's constructor, the sign-in itself) ends it: a connection this call opened is closed, and so is a client that was made.
  // A connection the caller handed in is not this call's to close.
  let dispose: (() => Promise<void>) | undefined;
  try {
    const manifest = typeof given === "function" ? freezeChecked(given(session.address), session.address) : checked;
    if (manifest === undefined) throw new Error("sign-in-no-manifest");
    const guardApproval: ApprovalGuard = async (wait, info) => {
      try {
        return await (options.guardApproval ?? runUnguarded)(wait, info);
      } catch (error) {
        // A cancel, a refusal or the guard giving up: do not leave a window open that nothing is waiting on.
        closeOpenKeyFlows(session.openkey);
        throw error;
      }
    };
    const hermeticNodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true" ? window.location.origin : undefined;
    const provider = new ObservedOpenKeyProvider(session.openkey, session.auth, session.address, verifyEip191MessageSignature, guardApproval);
    const tinycloud = new TinyCloudWeb({
      provider,
      signStrategy: { type: "callback", handler: (request: SignRequest) => guardApproval(() => explicitOpenKeyApproval(session, request), { kind: "sign", purpose: request.purpose }) },
      ...(hermeticNodeHost === undefined ? {} : { tinycloudHosts: [hermeticNodeHost] }),
      // A new sender cannot resolve a signed location record before its first
      // session exists. Use the explicitly configured owner-node choice only
      // for that bootstrap; addressed recipients never receive this fallback.
      newUserHost: hermeticNodeHost === undefined ? config.senderBootstrapNodeOrigin : null,
      tinycloudRegistryUrl: hermeticNodeHost === undefined ? config.registryOrigin : null,
      autoDiscoverLocalNode: false,
      autoCreateSpace,
      autoBootstrapAccount: false,
      // Opting out also suppresses the SDK's registry sync and this helper's account hosting.
      includeAccountRegistryPermissions,
      domain: options.domain ?? new URL(config.shareOrigin).hostname,
      spacePrefix: manifest.space ?? SHARE_APPLICATION_SPACE,
      sessionStorageKeyPrefix: options.sessionPrefix ?? DEFAULT_SESSION_PREFIX,
      sessionExpirationMs: options.expiry ?? MAX_SESSION_MS,
      persistSession: options.persistSession === true,
      siweConfig: { statement: `Sign in to ${appName}.` },
      manifest,
      ui: false,
    });
    let disposing: Promise<void> | undefined;
    dispose = (): Promise<void> => {
      disposing ??= (async () => {
        if (opened) closeOpenKeyFlows(session.openkey);
        try { await tinycloud.signOut(); } catch { /* The SDK clears a saved session in its own `finally`; one in memory goes with the page. */ }
      })();
      return disposing;
    };
    registerWalletApprovalObserver(tinycloud, provider);
    options.onClient?.(tinycloud);
    onStatus("Connecting to your encrypted TinyCloud…");
    // The provider answers account calls only with this connection's address (for a reopened session, the saved
    // account's), so a fresh sign-in can only sign in as that owner. A saved session is looked up under that same
    // address: the SDK restores the record stored for it, checking its shape and expiry but not comparing the record's
    // own address field, and without asking the node. `restoredSessionRefused` below is what asks the node.
    let signedSession: ClientSession | undefined;
    try {
      if (options.libraryRenewalAuthorization !== undefined) {
        const restored = await tinycloud.restoreSessionWithRenewal(options.libraryRenewalAuthorization, session.address);
        if (restored.status !== "restored") throw new Error("library-renewal-restore");
        const permissions = composeManifestRequest([manifest], { includeAccountRegistryPermissions }).resources;
        if (!tinycloud.hasPermissions(permissions)) throw new Error("library-renewal-manifest");
        signedSession = restored.session;
      } else {
        signedSession = await tinycloud.signIn();
      }
    } catch (error) {
      // The SDK restored a saved session and then refused to use it (for example a manifest it cannot check against a
      // restored session): handled below like a session the node refuses. Any other failure is the sign-in's own.
      if (options.libraryRenewalAuthorization !== undefined || tinycloud.sessionRestoreStatus !== "restored") throw error;
    }
    if (signedSession === undefined || await restoredSessionRefused(tinycloud, includeAccountRegistryPermissions)) {
      if (options.libraryRenewalAuthorization !== undefined) throw new Error("library-renewal-refused");
      // A saved session that cannot be used: clear it and sign in afresh, as on a first visit.
      await tinycloud.signOut();
      signedSession = await tinycloud.signIn();
    }
    const sessionExpiresAt = options.libraryRenewalAuthorization === undefined
      ? signedSessionExpiry(signedSession.siwe) ?? Date.now() + (options.expiry ?? MAX_SESSION_MS)
      : (await tinycloud.getRenewalEffectiveExpiry(options.libraryRenewalAuthorization)) * 1000;
    const spaces: Record<string, string> = {};
    for (const name of new Set([...(includeAccountRegistryPermissions ? ["account"] : []), ...hostSpaces])) {
      spaces[name] = await tinycloud.ensureOwnedSpaceHosted(name);
    }
    if (options.waitForAccountRegistrySync !== undefined && options.waitForAccountRegistrySync !== false) {
      const wait = options.waitForAccountRegistrySync;
      await settleAccountRegistrySync(tinycloud, typeof wait === "object" ? wait.timeoutMs ?? REGISTRY_SYNC_WAIT_MS : REGISTRY_SYNC_WAIT_MS);
    }
    let detaching: Promise<void> | undefined;
    // Leaves the session where it is (in memory, and in storage when the caller persisted it):
    // only the OpenKey connection this call opened is closed. A later open restores the session.
    const detach = (): Promise<void> => {
      detaching ??= (async () => { if (opened) closeOpenKeyFlows(session.openkey); })();
      return detaching;
    };
    return { tinycloud, session, spaces, sessionExpiresAt, detach, dispose };
  } catch (error) {
    if (dispose !== undefined) await dispose();
    else if (opened) closeOpenKeyFlows(session.openkey);
    throw error;
  }
}

/** Epoch ms the signed SIWE ends at (`Expiration Time:`), or undefined when the message carries none or it cannot be read. */
function signedSessionExpiry(siwe: string | undefined): number | undefined {
  const value = siwe?.match(/^Expiration Time: (.+)$/m)?.[1];
  if (value === undefined) return undefined;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : undefined;
}

/**
 * True when `signIn()` restored a saved session that the node now refuses (HTTP 401: the owner revoked it, or the
 * node no longer knows it). The SDK restores a saved session locally without asking the node, so a refused one would
 * otherwise fail only at the first read, after space hosting had already asked for a signature. One read the
 * account-registry grants cover settles it; a network failure or any other answer is not a refusal and keeps the session.
 */
async function restoredSessionRefused(tinycloud: ShareTinyCloud, registryGrants: boolean): Promise<boolean> {
  const spaceId = tinycloud.spaceId;
  if (tinycloud.sessionRestoreStatus !== "restored" || !registryGrants || spaceId === undefined) return false;
  const read = await tinycloud.account.spaces.get(spaceId).catch((error: unknown) => ({ ok: false as const, error }));
  return !read.ok && authorizationVerdictOf(read.error) === "unauthenticated";
}

const runUnguarded: ApprovalGuard = (wait) => wait();

function closeOpenKeyFlows(openkey: OpenKey): void {
  try { openkey.disconnect(); } catch { /* Nothing was open. */ }
}

/** What Share's own library needs: the owner space, history, credentials and the private copies area, and the owner's decrypt grant. */
export function shareManifest(address: string): Manifest {
  return {
    manifest_version: 1,
    app_id: "xyz.tinycloud.share",
    name: "TinyCloud Share",
    description: "Create and reopen encrypted shares.",
    space: SHARE_APPLICATION_SPACE,
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    permissions: [
      ...ownerSpacePermissions(),
      ...historyPermissions(),
      ...credentialSpacePermissions(),
      ...filesForYouPermissions(),
      { service: "tinycloud.encryption", path: ownerEncryptionNetwork(address), actions: ["decrypt", "network.create"], skipPrefix: true },
      // Decrypt on the share/ prefix, built by the SDK: the node registers a share's policy only for an owner holding decrypt on the share's key.
      ...pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address }) }),
    ],
  };
}

/** The scope of `shareManifest`: where Share's library may read and write, and nothing else. */
export const SHARE_MANIFEST_SCOPE: ManifestScope = {
  allowedSpaces: [SHARE_APPLICATION_SPACE, FILES_FOR_YOU_SPACE],
  allowedServices: ["kv", "vault", "encryption"],
  allowedActions: ["get", "put", "list", "metadata", "del", "decrypt", "network.create"],
  allowedPathPrefixes: [
    { space: SHARE_APPLICATION_SPACE, prefix: SHARE_APPLICATION_PREFIX },
    { space: SHARE_APPLICATION_SPACE, prefix: "vault/sender-history/v2/records/" },
    { space: FILES_FOR_YOU_SPACE, prefix: FILES_FOR_YOU_PREFIX },
    { space: "encryption", prefix: "urn:tinycloud:encryption:did:pkh:eip155:1:{address}:default" },
    // A key under a network is spelled with the owner's checksummed address: exactly the share/ prefix the SDK's sign-in entry names.
    { space: "encryption", prefix: "urn:tinycloud:encryption:did:pkh:eip155:1:{checksumAddress}:default/share/" },
  ],
};

/** The app id of the viewer's Save session. Its own, so it never overwrites the library's registry record (`xyz.tinycloud.share`). */
export const SAVE_COPY_APP_ID = "xyz.tinycloud.share.copies";

/**
 * What the viewer's "Save a copy" asks the person to approve: get, put and
 * list under `files-for-you/v1/`. No share, history, credential or decrypt
 * grant is requested from a recipient. (The session also holds the SDK's
 * account-registry permissions; see `signInWithManifest`.) Only `put` is
 * needed to save; get and list are what the read-back in the joined gate uses.
 */
export function saveCopyManifest(): Manifest {
  return {
    manifest_version: 1,
    app_id: SAVE_COPY_APP_ID,
    name: "TinyCloud Share: saved copies",
    description: "Save a private copy of a file you opened.",
    space: SHARE_APPLICATION_SPACE,
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    permissions: filesForYouPermissions(),
  };
}

/** The scope of `saveCopyManifest`. */
export const SAVE_COPY_MANIFEST_SCOPE: ManifestScope = {
  allowedSpaces: [FILES_FOR_YOU_SPACE],
  allowedServices: ["kv"],
  allowedActions: ["get", "put", "list"],
  allowedPathPrefixes: [{ space: FILES_FOR_YOU_SPACE, prefix: FILES_FOR_YOU_PREFIX }],
};

export async function createTinyCloudClient(
  session: OpenKeyShareSession,
  config: SharePublicConfig,
  onStatus: (message: string) => void,
  libraryRenewalAuthorization?: string,
): Promise<ShareTinyCloud> {
  // Persisted under the library's own prefix for the SDK's sign-in session tier: a reload restores it, with no new
  // approval, until its signed expiry or until the sender signs out (which clears it). A revoked one is refused and
  // replaced by a fresh sign-in.
  // Every OpenKey approval that completes here needed OpenKey's sign-in in this tab, so Share's Sign out may end it.
  const guardApproval: ApprovalGuard = async (wait) => { const result = await wait(); markOpenKeySignedInHere(); return result; };
  const { tinycloud } = await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config, session, onStatus, guardApproval, ...(libraryRenewalAuthorization === undefined ? {} : { libraryRenewalAuthorization }), sessionPrefix: LIBRARY_SESSION_PREFIX, persistSession: true, expiry: SIGN_IN_SESSION_MS });
  onStatus("Your encrypted share library is ready.");
  return tinycloud;
}
