import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
import { createOpenKeyCallbackSigningStrategy, type SignRequest, type SignResponse } from "@tinycloud/sdk-core";
import { TinyCloudWeb, type Manifest, type PermissionEntry } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";
import { fail } from "./sender-failure.js";

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

export async function authenticateWithOpenKey(onStatus: (message: string) => void): Promise<OpenKeyShareSession> {
  const openkey = new OpenKey({ host: OPENKEY_ORIGIN, appName: "TinyCloud Share", mode: "iframe" });
  onStatus("Opening OpenKey…");
  const auth = await openkey.connect();
  if (openkey.getSessionToken() === null) throw fail("signInService", "OpenKey did not provide a delegated signing session");
  onStatus("OpenKey connected.");
  return { address: auth.address, openkey, auth };
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

export function ownerEncryptionNetwork(address: string): string {
  // Network IDs use the storage-normalized EIP-155 account spelling at the
  // signed capability boundary; the SDK still canonicalizes the space DID.
  return `urn:tinycloud:encryption:did:pkh:eip155:1:${address.toLowerCase()}:default`;
}

export async function createTinyCloudClient(
  session: OpenKeyShareSession,
  config: SharePublicConfig,
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
      ...historyPermissions(),
      ...credentialSpacePermissions(),
      ...filesForYouPermissions(),
      { service: "tinycloud.encryption", path: ownerEncryptionNetwork(session.address), actions: ["decrypt", "network.create"], skipPrefix: true },
    ],
  };
  const hermeticNodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true" ? window.location.origin : undefined;
  const tinycloud = new TinyCloudWeb({
    provider: new OpenKeyProvider(session.openkey, session.auth),
    signStrategy: openKeySigningStrategy(session),
    ...(hermeticNodeHost === undefined ? {} : { tinycloudHosts: [hermeticNodeHost] }),
    tinycloudFallbackHosts: null,
    tinycloudRegistryUrl: hermeticNodeHost === undefined ? config.registryOrigin : null,
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
  await tinycloud.signIn();
  // The Web SDK's manifest bootstrap reads the canonical account space even
  // when the application data space is named explicitly. Host that owned
  // account space through the real SIWE flow before the first manifest read.
  await tinycloud.ensureOwnedSpaceHosted("account");
  onStatus("Your encrypted share library is ready.");
  return tinycloud;
}
