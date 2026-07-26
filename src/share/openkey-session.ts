import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
import { TinyCloudWeb, type Manifest, type PermissionEntry } from "@tinycloud/web-sdk";
import type { SharePublicConfig } from "../email-share/config.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import type { SenderPolicy } from "../email-share/sender.js";

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
const SHARE_ORIGIN = import.meta.env.VITE_SHARE_ORIGIN ?? window.location.origin;
export const MAX_SHARE_FILE_BYTES = 100 * 1024 * 1024;

function authenticationMessage(address: string, nonce: string, issuedAt: string): string {
  return [
    `${new URL(SHARE_ORIGIN).host} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to TinyCloud Share.",
    "",
    `URI: ${SHARE_ORIGIN}`,
    "Version: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

export async function authenticateWithOpenKey(onStatus: (message: string) => void): Promise<OpenKeyShareSession> {
  const openkey = new OpenKey({ host: OPENKEY_ORIGIN, appName: "TinyCloud Share", mode: "iframe" });
  onStatus("Opening OpenKey…");
  const auth = await openkey.connect();
  onStatus("Confirm this sign-in with your passkey…");
  const nonceResponse = await fetch("/api/share/auth/openkey/nonce", {
    credentials: "include",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
  });
  if (!nonceResponse.ok) throw new Error("TinyCloud could not start the OpenKey sign-in.");
  const challenge = await nonceResponse.json() as NonceResponse;
  if (!/^[A-Za-z0-9_-]{32}$/.test(challenge.nonce) || !Number.isFinite(Date.parse(challenge.expiresAt))) throw new Error("TinyCloud returned an invalid sign-in challenge.");
  const issuedAt = new Date().toISOString();
  const message = authenticationMessage(auth.address, challenge.nonce, issuedAt);
  const signed = await openkey.signMessage({ message, keyId: auth.keyId });
  if (signed.address.toLowerCase() !== auth.address.toLowerCase()) throw new Error("OpenKey signed with a different account.");
  const verified = await fetch("/api/share/auth/openkey", {
    method: "POST",
    credentials: "include",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ address: auth.address, signature: signed.signature, message, nonce: challenge.nonce, issuedAt }),
  });
  if (!verified.ok) throw new Error("This OpenKey does not control an authorized TinyCloud sharing space.");
  onStatus("OpenKey verified.");
  return { address: auth.address, openkey, auth };
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

function historyPermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.vault", space: "share", path: "sender-history/v1/entries/", actions: ["put", "get", "list", "del"], skipPrefix: true }];
}

function ownerEncryptionNetwork(address: string): string {
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
    space: "share",
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    permissions: [
      ...writePermissions(capabilities),
      ...historyPermissions(),
      { service: "tinycloud.encryption", path: ownerEncryptionNetwork(session.address), actions: ["decrypt", "network.create"], skipPrefix: true },
    ],
  };
  const nodeHost = import.meta.env.VITE_SHARE_HERMETIC === "true" ? window.location.origin : config.nodeOrigin;
  const tinycloud = new TinyCloudWeb({
    provider: new OpenKeyProvider(session.openkey, session.auth),
    tinycloudHosts: [nodeHost],
    tinycloudFallbackHosts: null,
    tinycloudRegistryUrl: null,
    autoDiscoverLocalNode: false,
    autoCreateSpace: true,
    includeAccountRegistryPermissions: true,
    domain: new URL(config.shareOrigin).hostname,
    spacePrefix: "share",
    sessionStorageKeyPrefix: "tinycloud-share",
    manifest,
  });
  onStatus("Connecting your encrypted TinyCloud space…");
  await tinycloud.signIn();
  // The Web SDK's manifest bootstrap reads the canonical account space even
  // when the application data space is named explicitly. Host that owned
  // account space through the real SIWE flow before the first manifest read.
  await tinycloud.ensureOwnedSpaceHosted("account");
  // Rebuild the session after the owned account space is registered so the
  // manifest bootstrap cannot retain the intentional first-pass 404 result.
  await tinycloud.signOut();
  await tinycloud.signIn();
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
  if (permissions.length === 0) throw new Error("This account has no uploadable sharing path.");
  const tinycloud = existingTinyCloud ?? await createTinyCloudClient(session, config, capabilities, onStatus);

  return async (file, capability, resourcePath = capability.source.path) => {
    if (capability.source.kind !== "kv") throw new Error("File uploads require an authorized TinyCloud KV path.");
    if (file.size === 0) throw new Error("Choose a non-empty document.");
    if (file.size > MAX_SHARE_FILE_BYTES) throw new Error("Choose a document no larger than 100 MB.");
    const content = new Uint8Array(await file.arrayBuffer());
    if (content.byteLength > MAX_SHARE_FILE_BYTES) throw new Error("Choose a document no larger than 100 MB.");
    const contentType = file.type.trim().length > 0 ? file.type : "application/octet-stream";
    if (resourcePath.length === 0 || /(^|\/)(?:\.|\.\.)($|\/)/.test(resourcePath) || /[\\\u0000-\u001f\u007f]/.test(resourcePath) || resourcePath.split("/").some((segment) => segment.length === 0)) throw new Error("The upload target is not a canonical resource path.");
    const sourcePrefix = capability.source.path.endsWith("/") ? capability.source.path : `${capability.source.path}/`;
    if (resourcePath !== capability.source.path && !resourcePath.startsWith(sourcePrefix)) throw new Error("The upload target is outside the authenticated writable path.");
    const stored = await tinycloud.kvForSpace(capability.source.space).put(resourcePath, content, { contentType });
    if (!stored.ok) throw new Error(stored.error.message || "TinyCloud could not store this document.");
  };
}
