import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
import { verifyEip191MessageSignature, type SignRequest, type SignResponse } from "@tinycloud/sdk-core";
import { TinyCloudWeb, type Manifest, type PermissionEntry } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";

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

export async function authenticateWithOpenKey(onStatus: (message: string) => void, guardApproval: ApprovalGuard = (wait) => wait()): Promise<OpenKeyShareSession> {
  const openkey = new OpenKey({ host: OPENKEY_ORIGIN, appName: "TinyCloud Share", mode: "iframe" });
  onStatus("Opening OpenKey…");
  const auth = await guardApproval(() => openkey.connect());
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
  const { signature } = await session.openkey.signMessage({ message: request.message, keyId: session.auth.keyId });
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
    if (this.guard !== undefined) return this.guard(() => this.signObserved(args));
    return this.signObserved(args);
  }

  private async signObserved(args: { method: string; params?: unknown[] }): Promise<unknown> {
    this.failure = undefined;
    const mine = ++this.asked;
    let signature: unknown;
    try {
      signature = await super.request(args);
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
 * guard; the default runs the wait as is.
 */
export type ApprovalGuard = <T>(wait: () => Promise<T>) => Promise<T>;

export interface SignInWithManifestOptions {
  /**
   * What the signed-in session may do. A function receives the signed-in
   * address, for manifests that name an account-specific resource (the share
   * manifest names the owner's encryption network).
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
   */
  readonly hostSpaces?: readonly string[];
  readonly guardApproval?: ApprovalGuard;
  /** Called with the client as soon as it exists, so a caller can read why an approval failed even if sign-in throws. */
  readonly onClient?: (tinycloud: ShareTinyCloud) => void;
}

export interface ManifestSignIn {
  readonly tinycloud: ShareTinyCloud;
  readonly session: OpenKeyShareSession;
  /** Space name to the id `ensureOwnedSpaceHosted` returned, for `account` and every `hostSpaces` entry. */
  readonly spaces: Readonly<Record<string, string>>;
}

/**
 * The one sign-in: OpenKey, then a `TinyCloudWeb` session that holds `manifest`
 * (plus the account-registry permissions the SDK needs for a new account's own
 * space registry), then the owned spaces hosted. The session lives in memory only
 * (`persistSession: false`); nothing is written to storage. Share's own
 * library and the viewer's "Save a copy" both sign in here, each with its own
 * manifest, and an app-install flow can do the same with an app's manifest.
 *
 * Every signature needs the person's approval in the OpenKey window and must
 * recover to the signed-in account (see `ObservedOpenKeyProvider`). A failed
 * or cancelled approval rejects; the caller decides what to say.
 */
export async function signInWithManifest(options: SignInWithManifestOptions): Promise<ManifestSignIn> {
  const { config, guardApproval, hostSpaces = [] } = options;
  const onStatus = options.onStatus ?? (() => undefined);
  const session = options.session ?? await authenticateWithOpenKey(onStatus, guardApproval);
  const manifest = typeof options.manifest === "function" ? options.manifest(session.address) : options.manifest;
  const hermeticNodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true" ? window.location.origin : undefined;
  const provider = new ObservedOpenKeyProvider(session.openkey, session.auth, session.address, verifyEip191MessageSignature, guardApproval);
  const tinycloud = new TinyCloudWeb({
    provider,
    signStrategy: { type: "callback", handler: (request: SignRequest) => (guardApproval ?? runUnguarded)(() => explicitOpenKeyApproval(session, request)) },
    ...(hermeticNodeHost === undefined ? {} : { tinycloudHosts: [hermeticNodeHost] }),
    // A new sender cannot resolve a signed location record before its first
    // session exists. Use the explicitly configured owner-node choice only
    // for that bootstrap; addressed recipients never receive this fallback.
    tinycloudFallbackHosts: hermeticNodeHost === undefined ? [config.senderBootstrapNodeOrigin] : null,
    tinycloudRegistryUrl: hermeticNodeHost === undefined ? config.registryOrigin : null,
    autoDiscoverLocalNode: false,
    autoCreateSpace: true,
    autoBootstrapAccount: false,
    // The SDK keeps a new account's own space registry in sync during sign-in; without these it makes unauthorized calls (401) and logs them.
    includeAccountRegistryPermissions: true,
    domain: new URL(config.shareOrigin).hostname,
    spacePrefix: manifest.space ?? SHARE_APPLICATION_SPACE,
    sessionStorageKeyPrefix: "tinycloud-share",
    sessionExpirationMs: 60 * 60 * 1000,
    persistSession: false,
    siweConfig: { statement: "Sign in to TinyCloud Share." },
    manifest,
    notifications: { popups: false },
  });
  registerWalletApprovalObserver(tinycloud, provider);
  options.onClient?.(tinycloud);
  onStatus("Connecting to your encrypted TinyCloud…");
  await tinycloud.signIn();
  const spaces: Record<string, string> = {};
  for (const name of new Set(["account", ...hostSpaces])) {
    spaces[name] = await tinycloud.ensureOwnedSpaceHosted(name);
  }
  return { tinycloud, session, spaces };
}

const runUnguarded: ApprovalGuard = (wait) => wait();

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

/**
 * What the viewer's "Save a copy" needs, and nothing else: read, write and
 * list under `files-for-you/v1/`. No share, history, credential or decrypt
 * grant is requested from a recipient.
 */
export function saveCopyManifest(): Manifest {
  return {
    manifest_version: 1,
    app_id: "xyz.tinycloud.share",
    name: "TinyCloud Share",
    description: "Save a private copy of a file you opened.",
    space: SHARE_APPLICATION_SPACE,
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    permissions: filesForYouPermissions(),
  };
}

export async function createTinyCloudClient(
  session: OpenKeyShareSession,
  config: SharePublicConfig,
  onStatus: (message: string) => void,
): Promise<ShareTinyCloud> {
  const { tinycloud } = await signInWithManifest({ manifest: shareManifest, config, session, onStatus });
  onStatus("Your encrypted share library is ready.");
  return tinycloud;
}
