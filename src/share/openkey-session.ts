import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
import { verifyEip191MessageSignature, type SignRequest, type SignResponse } from "@tinycloud/sdk-core";
import { TinyCloudWeb, type Manifest, type PermissionEntry } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";
import { assertManifestInScope, ManifestRejectedError, MANIFEST_CHECK_ADDRESS, type ManifestScope } from "./manifest-policy.js";
import { trackWalletApproval } from "./wallet-approval.js";

export interface OpenKeyShareSession {
  readonly address: string;
  readonly openkey: OpenKey;
  readonly auth: AuthResult;
}

export type ShareTinyCloud = TinyCloudWeb;

const OPENKEY_ORIGIN = import.meta.env.VITE_OPENKEY_ORIGIN ?? "https://openkey.so";
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
    let signature: unknown;
    try {
      signature = await trackWalletApproval(() => super.request(args));
    } catch (caught) {
      if (mine === this.asked) this.failure = approvalFailureOf(caught);
      throw caught;
    }
    const message = typeof args.params?.[0] === "string" ? hexToText(args.params[0]) : undefined;
    if (message !== undefined && (typeof signature !== "string" || !(await this.verify(message, signature, this.signedInAddress)))) {
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

/** A sign-in option outside what the helper allows (an expiry over an hour, a domain that is not a host name). */
export class SignInOptionError extends Error {
  constructor(option: string, detail: string) {
    super(`sign-in-option-${option}: ${detail}`);
    this.name = "SignInOptionError";
  }
}

/** The longest a session may last. Also the default. */
export const MAX_SESSION_MS = 60 * 60 * 1000;
const DEFAULT_APP_NAME = "TinyCloud Share";
const DEFAULT_SESSION_PREFIX = "tinycloud-share";
const REGISTRY_SYNC_WAIT_MS = 15_000;

export interface SignInWithManifestOptions extends ManifestScope {
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
   * `account` is always hosted first: the Web SDK's manifest bootstrap reads
   * the canonical account space even when the manifest names another space.
   * Each must be in `allowedSpaces`.
   */
  readonly hostSpaces?: readonly string[];
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
  /** Prefix of the SDK's session storage keys. The session is never persisted, so this only names the SDK instance. Default "tinycloud-share". */
  readonly sessionPrefix?: string;
  /** How long the session lasts, in milliseconds: a whole number from 1 to one hour (3 600 000). Default one hour. */
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
  /** Space name to the id `ensureOwnedSpaceHosted` returned, for `account` and every `hostSpaces` entry. */
  readonly spaces: Readonly<Record<string, string>>;
  /** Clears the SDK's in-memory session and, when this call opened the OpenKey connection, closes its windows and flows. Safe to call more than once; never rejects. */
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

/** Longest app name, session prefix or domain label the helper accepts, in characters. */
const MAX_LABEL_CHARS = 64;
/**
 * Characters a name may not contain, whatever they look like: control, format (zero-width, joiners, soft hyphen, word
 * joiner, bidi controls, tag characters), surrogate, private-use and unassigned code points, every space and
 * separator other than a plain U+0020, the fillers that render as blanks (Hangul and Mongolian), variation selectors,
 * and the combining grapheme joiner.
 */
const INVISIBLE_OR_SPACE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}\u3164\uffa0\u115f\u1160\u17b4\u17b5\u180e\u034f\ufe00-\ufe0f\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/u;
/** Look-alikes of the characters that make a link, folded to the real ones before the link check (NFKC folds the full-width forms; these it leaves alone). */
const LINK_LOOKALIKES: ReadonlyArray<readonly [RegExp, string]> = [
  [/[\u2215\u2044\u29f8\u2571\u2afd]/g, "/"],
  [/[\u2216\u29f5\u29f9\ufe68]/g, "\\"],
  [/[\ua789\u2236\u0589\ufe13]/g, ":"],
  [/[\u3002\u0589\u06d4\u0701\u0702\u1803\u2e3c]/g, "."],
];
const SCHEME_TOKEN = /(?:^|\s)[a-z][a-z0-9+.-]*:(?!\s|$)/i;
const RISKY_SCHEME = /\b(?:javascript|vbscript|data|mailto|tel|sms|file|blob|ftp|https?|wss?)\s*:/i;
/** A dotted name whose last label is letters (`evil.com`, `a.b.example`); a version such as `1.2` or `v2.0.1` has no letter label. */
const HOST_LIKE = /[\p{L}\p{N}_-]+\.\p{L}{2,}(?![\p{L}\p{N}_-])/iu;
const PATH_LIKE = /[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)+\//iu;
const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const IPV6 = /\[[0-9a-f:.]+\]|(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{1,4}|::/i;

/** True when `value` reads as a link or an address, once look-alike slashes, colons, dots and full-width forms are folded to the real ones. */
function looksLikeLink(value: string): boolean {
  let folded = value.normalize("NFKC");
  for (const [pattern, replacement] of LINK_LOOKALIKES) folded = folded.replace(pattern, replacement);
  return SCHEME_TOKEN.test(folded) || RISKY_SCHEME.test(folded) || folded.includes("//") || folded.includes("\\") || folded.includes("@")
    || HOST_LIKE.test(folded) || PATH_LIKE.test(folded) || IPV4.test(folded) || IPV6.test(folded);
}

/**
 * A name that goes into the sign-in statement or OpenKey's window: one short printable line, written the one way, that
 * does not read as a link. Nothing is trimmed or collapsed: a name that needs it is refused.
 */
function checkLabel(option: string, value: string): void {
  if ([...value].length === 0 || [...value].length > MAX_LABEL_CHARS) throw new SignInOptionError(option, `1 to ${MAX_LABEL_CHARS} characters`);
  if (value.normalize("NFC") !== value) throw new SignInOptionError(option, "must be written in normalised (NFC) form");
  if (INVISIBLE_OR_SPACE.test(value.replaceAll(" ", ""))) throw new SignInOptionError(option, "no control, invisible, direction or special space characters");
  if (value.startsWith(" ") || value.endsWith(" ") || value.includes("  ")) throw new SignInOptionError(option, "no leading, trailing or repeated spaces");
  if (looksLikeLink(value)) throw new SignInOptionError(option, "must not look like a link or an address");
}

function checkOptions(options: SignInWithManifestOptions): void {
  const { expiry, domain, appName, sessionPrefix } = options;
  if (expiry !== undefined && !(Number.isInteger(expiry) && expiry >= 1 && expiry <= MAX_SESSION_MS)) {
    throw new SignInOptionError("expiry", `a session lasts 1 to ${MAX_SESSION_MS} milliseconds`);
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
 * plus the SDK's own account-registry permissions (below), then the owned
 * spaces hosted. The session lives in memory only (`persistSession: false`);
 * nothing is written to storage. Share's library and the viewer's "Save a
 * copy" sign in here, each with its own manifest and scope, and an app-install
 * flow does the same with an app's manifest.
 *
 * What the session can do is the manifest, which must sit inside the scope the
 * caller states (see `ManifestScope`; a manifest outside it is refused with a
 * `ManifestRejectedError` before OpenKey opens), AND what the SDK adds to every
 * sign-in so it can keep a new account's own space registry in sync:
 * get/put/list on `account/applications/` and `account/spaces/`, the bootstrap
 * flag, read/write/schema on the account database and delegation list. They
 * are not removable: without them the SDK's registry sync makes unauthorized
 * calls (401) and logs them. A narrower session waits on the SDK.
 *
 * Every signature needs the person's approval in the OpenKey window and must
 * recover to the signed-in account (see `ObservedOpenKeyProvider`). A failed
 * or cancelled approval rejects and closes the OpenKey flow; the caller decides
 * what to say. Whatever ends the sign-in early also disposes the session.
 */
export async function signInWithManifest(options: SignInWithManifestOptions): Promise<ManifestSignIn> {
  const { config, hostSpaces = [] } = options;
  const onStatus = options.onStatus ?? (() => undefined);
  checkOptions(options);
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
      tinycloudFallbackHosts: hermeticNodeHost === undefined ? [config.senderBootstrapNodeOrigin] : null,
      tinycloudRegistryUrl: hermeticNodeHost === undefined ? config.registryOrigin : null,
      autoDiscoverLocalNode: false,
      autoCreateSpace: true,
      autoBootstrapAccount: false,
      // The SDK keeps a new account's own space registry in sync during sign-in and needs these permissions for it
      // (see the helper's doc comment for what they are); without them it makes unauthorized calls (401) and logs them.
      includeAccountRegistryPermissions: true,
      domain: options.domain ?? new URL(config.shareOrigin).hostname,
      spacePrefix: manifest.space ?? SHARE_APPLICATION_SPACE,
      sessionStorageKeyPrefix: options.sessionPrefix ?? DEFAULT_SESSION_PREFIX,
      sessionExpirationMs: options.expiry ?? MAX_SESSION_MS,
      persistSession: false,
      siweConfig: { statement: `Sign in to ${appName}.` },
      manifest,
      notifications: { popups: false },
    });
    let disposing: Promise<void> | undefined;
    dispose = (): Promise<void> => {
      disposing ??= (async () => {
        if (opened) closeOpenKeyFlows(session.openkey);
        try { await tinycloud.signOut(); } catch { /* The session lives only in this tab; it is dropped with the page. */ }
      })();
      return disposing;
    };
    registerWalletApprovalObserver(tinycloud, provider);
    options.onClient?.(tinycloud);
    onStatus("Connecting to your encrypted TinyCloud…");
    await tinycloud.signIn();
    const spaces: Record<string, string> = {};
    for (const name of new Set(["account", ...hostSpaces])) {
      spaces[name] = await tinycloud.ensureOwnedSpaceHosted(name);
    }
    if (options.waitForAccountRegistrySync !== undefined && options.waitForAccountRegistrySync !== false) {
      const wait = options.waitForAccountRegistrySync;
      await settleAccountRegistrySync(tinycloud, typeof wait === "object" ? wait.timeoutMs ?? REGISTRY_SYNC_WAIT_MS : REGISTRY_SYNC_WAIT_MS);
    }
    return { tinycloud, session, spaces, dispose };
  } catch (error) {
    if (dispose !== undefined) await dispose();
    else if (opened) closeOpenKeyFlows(session.openkey);
    throw error;
  }
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
): Promise<ShareTinyCloud> {
  const { tinycloud } = await signInWithManifest({ manifest: shareManifest, ...SHARE_MANIFEST_SCOPE, config, session, onStatus });
  onStatus("Your encrypted share library is ready.");
  return tinycloud;
}
