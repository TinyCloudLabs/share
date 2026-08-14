import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
import { createOpenKeyCallbackSigningStrategy, type SignRequest, type SignResponse } from "@tinycloud/sdk-core";
import { TinyCloudWeb, type Manifest, type PermissionEntry } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import type { SenderPolicy } from "../email-share/sender.js";
import { fail } from "./sender-failure.js";

export interface OpenKeyShareSession {
  readonly address: string;
  readonly openkey: OpenKey;
  readonly auth: AuthResult;
}

export interface UploadCapability {
  readonly capabilityId?: string;
  readonly scope: SenderScope;
  readonly source: ContentSource;
  readonly policy: Pick<SenderPolicy, "policyCid" | "policyBytes" | "policyDigest">;
}

export type ShareTinyCloud = TinyCloudWeb;

interface NonceResponse {
  readonly nonce: string;
  readonly expiresAt: string;
}

const OPENKEY_ORIGIN = import.meta.env.VITE_OPENKEY_ORIGIN ?? "https://openkey.so";
export const SHARE_APPLICATION_SPACE = "applications";
export const SHARE_APPLICATION_PREFIX = "xyz.tinycloud.share/";
export const MAX_SHARE_FILE_BYTES = 100 * 1024 * 1024;

export async function authenticateWithOpenKey(onStatus: (message: string) => void): Promise<OpenKeyShareSession> {
  const openkey = new OpenKey({ host: OPENKEY_ORIGIN, appName: "TinyCloud Share", mode: "iframe" });
  onStatus("Opening OpenKey…");
  const auth = await openkey.connect();
  if (openkey.getSessionToken() === null) throw fail("signInService", "OpenKey did not provide a delegated signing session");
  onStatus("OpenKey connected.");
  return { address: auth.address, openkey, auth };
}

async function shareNonce(): Promise<NonceResponse> {
  const nonceResponse = await fetch("/api/share/auth/openkey/nonce", {
    credentials: "include",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  if (!nonceResponse.ok) throw fail("signInService", "share sign-in nonce endpoint rejected the request");
  const challenge = await nonceResponse.json() as NonceResponse;
  if (!/^[A-Za-z0-9]{32}$/.test(challenge.nonce) || !Number.isFinite(Date.parse(challenge.expiresAt))) throw fail("signInService", "share sign-in challenge is malformed");
  return challenge;
}

async function authenticateShareHost(message: string, signature: string): Promise<void> {
  const verified = await fetch("/api/share/auth/openkey", {
    method: "POST",
    credentials: "include",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ message, signature }),
  });
  // TC-335: this used to be rendered verbatim into the sign-in wall, banned
  // vocabulary and all. The kind is what the wall reads; the detail is for logs.
  if (!verified.ok) throw fail("account", "OpenKey account does not control an authorized sharing space");
}

function explicitOpenKeyApproval(session: OpenKeyShareSession, request: SignRequest): Promise<SignResponse> {
  return session.openkey.signMessage({ message: request.message, keyId: session.auth.keyId }).then((signed) => signed.address.toLowerCase() === session.address.toLowerCase()
    ? { approved: true, signature: signed.signature }
    : { approved: false, reason: "OpenKey signed with a different account" });
}

function openKeySigningStrategy(session: OpenKeyShareSession) {
  const signing = session.openkey.tinycloudSigningOptions();
  if (signing.token === null) throw fail("signInService", "OpenKey delegated signing session expired");
  // Embedded OpenKey sessions may arrive in Better Auth's signed-cookie form
  // (`token.signature`). Its delegated signer accepts the underlying bearer
  // token only; the suffix authenticates cookie transport and is not part of
  // the session token stored by Better Auth.
  const [token = ""] = signing.token.replace(/^Bearer\s+/i, "").split(".");
  if (!/^[A-Za-z0-9_-]+$/.test(token)) throw fail("signInService", "OpenKey delegated signing session is malformed");
  const automatic = createOpenKeyCallbackSigningStrategy({
    endpoint: signing.endpoint,
    token,
    keyId: session.auth.keyId,
    credentials: "omit",
  });
  return {
    ...automatic,
    // The manifest-bearing session is the one user decision. Bootstrap and
    // owned-space hosting use OpenKey's narrow server-side delegate policy.
    handler: (request: SignRequest): Promise<SignResponse> => request.purpose === "sign-in"
      ? explicitOpenKeyApproval(session, request)
      : automatic.handler(request),
  };
}

function writePermissions(capabilities: readonly UploadCapability[]): PermissionEntry[] {
  const seen = new Set<string>();
  const permissions: PermissionEntry[] = [];
  for (const candidate of capabilities) {
    if (candidate.source.kind !== "kv") continue;
    const key = `${candidate.source.space}\0${candidate.source.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // Manifest space names are resolved by the Web SDK into the authenticated
  // sender's owned `share` SpaceId. The policy source retains the native
  // fixture space and is still used at the signed capability boundary.
    permissions.push({ service: "tinycloud.kv", space: "share", path: candidate.source.path, actions: ["put"], skipPrefix: true });
  }
  return permissions;
}

/*
 * TC-344. The owner-policy path (`createOwnerPolicyShare`) is the only path
 * the shipped app takes for an addressed share. It works inside the sender's
 * enshrined `applications` space, bounded to the
 * `xyz.tinycloud.share/` namespace: it lists that namespace to build the
 * library picker, reads a picked object or folder, and writes the shared copy
 * under `xyz.tinycloud.share/shares/<shareId>/`.
 *
 * Until now the manifest's only KV grants came from `writePermissions`, i.e.
 * were derived from server-issued sender capabilities. No authenticated path
 * issues those any more — `docs/share-host-deployment.md` records that the
 * wallet-rooted capability-issuance path is not yet a supported shape, and
 * `GET /api/share/capabilities` consequently returns `[]` for every session.
 * So the session was built with no KV authority at all and every addressed
 * share failed the instant it touched storage.
 *
 * This wallet-rooted grant delegates nothing to the Share host and adds no
 * server-held material. Both halves are prefix grants: reads stay inside the
 * application's namespace and writes stay inside its `shares/` child. The
 * trailing slashes are significant because the resource matcher treats them
 * as byte-prefix boundaries. Sender-history writes are not affected:
 * they go through `tinycloud.vault`, which resolves to its own
 * `vault/sender-history/v2/records/` KV grant in `historyPermissions`.
 *
 * `del` is absent on purpose. Nothing here deletes, and this grant is the
 * sender's application namespace.
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
  return [{ service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: `${SHARE_APPLICATION_PREFIX}files-for-you/v1/`, actions: ["get", "put", "list"], skipPrefix: true }];
}

export function ownerEncryptionNetwork(address: string): string {
  // Network IDs use the storage-normalized EIP-155 account spelling at the
  // signed capability boundary; the SDK still canonicalizes the space DID.
  return `urn:tinycloud:encryption:did:pkh:eip155:1:${address.toLowerCase()}:default`;
}

export async function createTinyCloudClient(
  session: OpenKeyShareSession,
  config: SharePublicConfig,
  capabilities: readonly UploadCapability[],
  onStatus: (message: string) => void,
): Promise<ShareTinyCloud> {
  const manifest: Manifest = {
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
      ...writePermissions(capabilities),
      ...historyPermissions(),
      ...credentialSpacePermissions(),
      ...filesForYouPermissions(),
      { service: "tinycloud.encryption", path: ownerEncryptionNetwork(session.address), actions: ["decrypt", "network.create"], skipPrefix: true },
    ],
  };
  const nodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true" ? window.location.origin : config.nodeOrigin;
  const tinycloud = new TinyCloudWeb({
    provider: new OpenKeyProvider(session.openkey, session.auth),
    signStrategy: openKeySigningStrategy(session),
    tinycloudHosts: [nodeHost],
    tinycloudFallbackHosts: null,
    tinycloudRegistryUrl: null,
    autoDiscoverLocalNode: false,
    autoCreateSpace: true,
    autoBootstrapAccount: false,
    includeAccountRegistryPermissions: true,
    domain: new URL(config.shareOrigin).hostname,
    spacePrefix: SHARE_APPLICATION_SPACE,
    sessionStorageKeyPrefix: "tinycloud-share",
    sessionExpirationMs: 60 * 60 * 1000,
    persistSession: false,
    siweConfig: { statement: "Sign in to TinyCloud Share." },
    manifest,
    notifications: { popups: false },
  });
  onStatus("Connecting to your encrypted TinyCloud…");
  const challenge = await shareNonce();
  const signedSession = await tinycloud.signIn({ nonce: challenge.nonce });
  await authenticateShareHost(signedSession.siwe, signedSession.signature);
  // The Web SDK's manifest bootstrap reads the canonical account space even
  // when the application data space is named explicitly. Host that owned
  // account space through the real SIWE flow before the first manifest read.
  await tinycloud.ensureOwnedSpaceHosted("account");
  onStatus("Your encrypted share library is ready.");
  return tinycloud;
}

export async function createTinyCloudUploader(
  session: OpenKeyShareSession,
  config: SharePublicConfig,
  capabilities: readonly UploadCapability[],
  onStatus: (message: string) => void,
  existingTinyCloud?: ShareTinyCloud,
): Promise<(file: File, capability: UploadCapability, resourcePath?: string) => Promise<void>> {
  const permissions = writePermissions(capabilities);
  if (permissions.length === 0) throw fail("internal", "account has no uploadable sharing path");
  const tinycloud = existingTinyCloud ?? await createTinyCloudClient(session, config, capabilities, onStatus);

  return async (file, capability, resourcePath = capability.source.path) => {
    if (capability.source.kind !== "kv") throw fail("internal", "file upload requires a KV source");
    if (file.size === 0) throw fail("emptyFile", "uploaded document is empty");
    if (file.size > MAX_SHARE_FILE_BYTES) throw fail("fileTooLarge", "uploaded document exceeds 100 MB");
    const content = new Uint8Array(await file.arrayBuffer());
    if (content.byteLength > MAX_SHARE_FILE_BYTES) throw fail("fileTooLarge", "uploaded document bytes exceed 100 MB");
    const contentType = file.type.trim().length > 0 ? file.type : "application/octet-stream";
    if (resourcePath.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(resourcePath) || /[\\\u0000-\u001f\u007f]/.test(resourcePath) || resourcePath.split("/").some((segment) => segment.length === 0)) throw fail("internal", "upload target is not a canonical resource path");
    const sourcePrefix = capability.source.path.endsWith("/") ? capability.source.path : `${capability.source.path}/`;
    if (resourcePath !== capability.source.path && !resourcePath.startsWith(sourcePrefix)) throw fail("internal", "upload target is outside the authenticated writable path");
    const stored = await tinycloud.kvForSpace(capability.source.space).put(resourcePath, content, { contentType });
    if (!stored.ok) throw fail("upload", stored.error.message || "TinyCloud could not store this document.");
  };
}
