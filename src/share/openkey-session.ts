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
  readonly scope: SenderScope;
  readonly source: ContentSource;
  readonly policy: SenderPolicy;
}

interface NonceResponse {
  readonly nonce: string;
  readonly expiresAt: string;
}

const OPENKEY_ORIGIN = "https://openkey.so";
const MAX_FILE_BYTES = 1_048_576;

function authenticationMessage(address: string, nonce: string, issuedAt: string): string {
  return [
    `${window.location.host} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to TinyCloud Share.",
    "",
    `URI: ${window.location.origin}`,
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
    permissions.push({ service: "tinycloud.kv", space: candidate.source.space, path: candidate.source.path, actions: ["put"], skipPrefix: true });
  }
  return permissions;
}

export async function createTinyCloudUploader(
  session: OpenKeyShareSession,
  config: SharePublicConfig,
  capabilities: readonly UploadCapability[],
  onStatus: (message: string) => void,
): Promise<(file: File, capability: UploadCapability) => Promise<void>> {
  const permissions = writePermissions(capabilities);
  if (permissions.length === 0) throw new Error("This account has no uploadable sharing path.");
  const manifest: Manifest = {
    manifest_version: 1,
    app_id: "xyz.tinycloud.share",
    name: "TinyCloud Share",
    description: "Upload a document and create one exact, read-only share.",
    space: "share",
    prefix: "",
    defaults: false,
    includePublicSpace: false,
    permissions,
  };
  const tinycloud = new TinyCloudWeb({
    provider: new OpenKeyProvider(session.openkey, session.auth),
    tinycloudHosts: [config.nodeOrigin],
    tinycloudFallbackHosts: null,
    tinycloudRegistryUrl: null,
    autoDiscoverLocalNode: false,
    autoCreateSpace: true,
    spacePrefix: "share",
    sessionStorageKeyPrefix: "tinycloud-share",
    manifest,
  });
  onStatus("Connecting your encrypted TinyCloud space…");
  await tinycloud.signIn();
  onStatus("Your TinyCloud space is ready.");

  return async (file, capability) => {
    if (capability.source.kind !== "kv") throw new Error("File uploads require an authorized TinyCloud KV path.");
    if (file.size === 0) throw new Error("Choose a non-empty document.");
    if (file.size > MAX_FILE_BYTES) throw new Error("Choose a document smaller than 1 MB.");
    const content = await file.text();
    if (new TextEncoder().encode(content).length > MAX_FILE_BYTES) throw new Error("Choose a document smaller than 1 MB.");
    const stored = await tinycloud.kvForSpace(capability.source.space).put(capability.source.path, content, { contentType: "text/markdown; charset=utf-8" });
    if (!stored.ok) throw new Error(stored.error.message || "TinyCloud could not store this document.");
  };
}
