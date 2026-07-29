import { OpenKey, OpenKeyProvider, type AuthResult } from "@openkey/sdk";
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
  if (!nonceResponse.ok) throw fail("signInService", "share sign-in nonce endpoint rejected the request");
  const challenge = await nonceResponse.json() as NonceResponse;
  if (!/^[A-Za-z0-9_-]{32}$/.test(challenge.nonce) || !Number.isFinite(Date.parse(challenge.expiresAt))) throw fail("signInService", "share sign-in challenge is malformed");
  const issuedAt = new Date().toISOString();
  const message = authenticationMessage(auth.address, challenge.nonce, issuedAt);
  const signed = await openkey.signMessage({ message, keyId: auth.keyId });
  if (signed.address.toLowerCase() !== auth.address.toLowerCase()) throw fail("signIn", "OpenKey signed with a different account");
  const verified = await fetch("/api/share/auth/openkey", {
    method: "POST",
    credentials: "include",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ address: auth.address, signature: signed.signature, message, nonce: challenge.nonce, issuedAt }),
  });
  // TC-335: this used to be rendered verbatim into the sign-in wall, banned
  // vocabulary and all. The kind is what the wall reads; the detail is for logs.
  if (!verified.ok) throw fail("account", "OpenKey account does not control an authorized sharing space");
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

/*
 * TC-344. The owner-policy path (`createOwnerPolicyShare`) is the only path
 * the shipped app takes for an addressed share, and it works entirely inside
 * the sender's *own* space: it lists that space to build the library picker,
 * reads a picked object or folder, and writes the shared copy under
 * `shares/<shareId>/`.
 *
 * Until now the manifest's only KV grants came from `writePermissions`, i.e.
 * were derived from server-issued sender capabilities. No authenticated path
 * issues those any more — `docs/share-host-deployment.md` records that the
 * wallet-rooted capability-issuance path is not yet a supported shape, and
 * `GET /api/share/capabilities` consequently returns `[]` for every session.
 * So the session was built with no KV authority at all and every addressed
 * share failed the instant it touched storage.
 *
 * This grant is the sender's own wallet-rooted authority over the sender's
 * own space. It delegates nothing to the Share host and adds no server-held
 * material; the Share host never sees this session's capabilities.
 *
 * The path is deliberately "" (whole service on this space) and never "/":
 * the recap encoder joins "/" as `<space>/<service>//`, which the node's
 * byte-prefix resource matching can never extend.
 */
export function ownerSpacePermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.kv", space: "share", path: "", actions: ["get", "put", "list", "metadata"] }];
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
      ...ownerSpacePermissions(),
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
  onStatus("Connecting to your encrypted TinyCloud…");
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
