import { fromBase64Url } from "@tinycloud/share-envelope";
import type { CredentialTrust } from "./claim.js";
import type { TrustedNode } from "./protocol.js";

const CONFIG_VERSION = "tinycloud.share-email-claim/config-v1" as const;
const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const DID_WEB = /^did:web:[A-Za-z0-9.-]+$/;

/** Public deployment data. No private key, mailbox secret, token, or session is legal here. */
export interface SharePublicConfig {
  readonly version: typeof CONFIG_VERSION;
  readonly shareOrigin: string;
  readonly registryOrigin: string;
  readonly nodeOrigin: string;
  readonly credentialsOrigin: string;
  readonly nodeAudience: string;
  readonly issuerDid: string;
  readonly issuerVct: "opencredentials.email/v1";
  readonly nodeInvitationKid: string;
  readonly nodeInvitationPublicKey: string;
  readonly nodeKeyVersion: number;
  readonly issuerKeyVersion: number;
  readonly issuerPublicKey: string;
  readonly environment?: "production" | "test";
}

export interface SharePublicBinding {
  readonly shareId: string;
  readonly policyCid: string;
  readonly recipientEmail: string;
  readonly expiry: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: "amh_kv_001" | "amh_sql_001";
  readonly authorityMaterialDigest: string;
  readonly contentSource: Record<string, unknown>;
  readonly contentSourceDigest: string;
  readonly action: "tinycloud.kv/get" | "tinycloud.sql/read";
  readonly resource: string;
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("share config must be an object");
  const object = value as Record<string, unknown>;
  if (Object.keys(object).length !== keys.length || keys.some((key) => !Object.hasOwn(object, key))) throw new TypeError("share config has unknown or missing fields");
  return object;
}

function httpsOrigin(value: unknown, name: string): string {
  if (typeof value !== "string") throw new TypeError(`${name} is missing`);
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.origin !== value) throw new TypeError(`${name} must be a canonical HTTPS origin`);
  return value;
}

function publicKey(value: unknown, name: string): string {
  if (typeof value !== "string" || !B64_256.test(value) || fromBase64Url(value).length !== 32) throw new TypeError(`${name} must be a 32-byte base64url public key`);
  return value;
}

export function validateSharePublicConfig(value: unknown): SharePublicConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("share config must be an object");
  const raw = value as Record<string, unknown>;
  const object = exactObject(value, ["version", "shareOrigin", "registryOrigin", "nodeOrigin", "credentialsOrigin", "nodeAudience", "issuerDid", "issuerVct", "nodeInvitationKid", "nodeInvitationPublicKey", "nodeKeyVersion", "issuerKeyVersion", "issuerPublicKey", ...(Object.hasOwn(raw, "environment") ? ["environment"] : [])]);
  if (object.version !== CONFIG_VERSION || object.issuerVct !== "opencredentials.email/v1") throw new TypeError("unsupported share config version");
  const shareOrigin = httpsOrigin(object.shareOrigin, "shareOrigin");
  const registryOrigin = httpsOrigin(object.registryOrigin, "registryOrigin");
  const nodeOrigin = httpsOrigin(object.nodeOrigin, "nodeOrigin");
  const credentialsOrigin = httpsOrigin(object.credentialsOrigin, "credentialsOrigin");
  const environment = object.environment === undefined ? "production" : object.environment;
  if (environment !== "production" && environment !== "test") throw new TypeError("share config environment is invalid");
  if (typeof object.nodeKeyVersion !== "number" || !Number.isSafeInteger(object.nodeKeyVersion) || typeof object.issuerKeyVersion !== "number" || !Number.isSafeInteger(object.issuerKeyVersion)) throw new TypeError("share config key versions are invalid");
  if (typeof object.nodeAudience !== "string" || !DID_WEB.test(object.nodeAudience) || object.nodeAudience !== `did:web:${new URL(nodeOrigin).hostname}` || typeof object.issuerDid !== "string" || !/^did:web:[A-Za-z0-9.-]+$/.test(object.issuerDid) || typeof object.nodeInvitationKid !== "string" || !object.nodeInvitationKid.startsWith(`${object.nodeAudience}#`) || !Number.isSafeInteger(object.nodeKeyVersion) || object.nodeKeyVersion < 1 || !Number.isSafeInteger(object.issuerKeyVersion) || object.issuerKeyVersion < 1) throw new TypeError("share config trust binding is not enrolled");
  if (environment === "production" && [shareOrigin, registryOrigin, nodeOrigin, credentialsOrigin, object.nodeAudience, object.issuerDid].some((item) => /(?:node\.example|127\.0\.0\.1|localhost|fixture|test)/i.test(item))) throw new TypeError("production share config contains a placeholder or loopback trust value");
  return Object.freeze({
    version: CONFIG_VERSION,
    shareOrigin,
    registryOrigin,
    nodeOrigin,
    credentialsOrigin,
    nodeAudience: object.nodeAudience,
    issuerDid: object.issuerDid,
    issuerVct: "opencredentials.email/v1",
    nodeInvitationKid: object.nodeInvitationKid,
    nodeInvitationPublicKey: publicKey(object.nodeInvitationPublicKey, "nodeInvitationPublicKey"),
    nodeKeyVersion: object.nodeKeyVersion,
    issuerKeyVersion: object.issuerKeyVersion,
    issuerPublicKey: publicKey(object.issuerPublicKey, "issuerPublicKey"),
    ...(environment === "test" ? { environment: "test" as const } : {}),
  });
}

export function trustedNodeFromConfig(config: SharePublicConfig): TrustedNode {
  return Object.freeze({ targetOrigin: config.nodeOrigin, nodeAudience: config.nodeAudience, invitationKid: config.nodeInvitationKid, invitationPublicKey: fromBase64Url(config.nodeInvitationPublicKey), keyVersion: config.nodeKeyVersion, enabled: true });
}

export function credentialTrustFromConfig(config: SharePublicConfig): CredentialTrust {
  return Object.freeze({ issuerDid: config.issuerDid, vct: config.issuerVct, issuerPublicKey: fromBase64Url(config.issuerPublicKey) });
}

export async function loadSharePublicConfig(fetchFn: typeof fetch = globalThis.fetch.bind(globalThis), url = "/.well-known/tinycloud-share/config.json"): Promise<SharePublicConfig> {
  const parsed = new URL(url, globalThis.location?.origin ?? "https://share.tinycloud.xyz");
  if (parsed.origin !== (globalThis.location?.origin ?? parsed.origin)) throw new TypeError("share config must be same-origin");
  const response = await fetchFn(parsed, { credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (!response.ok) throw new Error(`share config unavailable (${response.status})`);
  return validateSharePublicConfig(await response.json());
}

export function validateSharePublicBinding(value: unknown): SharePublicBinding {
  const object = exactObject(value, ["shareId", "policyCid", "recipientEmail", "expiry", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "action", "resource"]);
  if (typeof object.shareId !== "string" || object.shareId.length === 0 || typeof object.policyCid !== "string" || !/^b[a-z2-7]{58}$/.test(object.policyCid) || typeof object.recipientEmail !== "string" || typeof object.expiry !== "string" || typeof object.delegationCid !== "string" || !/^b[a-z2-7]{58}$/.test(object.delegationCid) || (object.authorityMaterialHandle !== "amh_kv_001" && object.authorityMaterialHandle !== "amh_sql_001") || typeof object.authorityMaterialDigest !== "string" || !B64_256.test(object.authorityMaterialDigest) || typeof object.contentSource !== "object" || object.contentSource === null || Array.isArray(object.contentSource) || typeof object.contentSourceDigest !== "string" || !B64_256.test(object.contentSourceDigest) || (object.action !== "tinycloud.kv/get" && object.action !== "tinycloud.sql/read") || typeof object.resource !== "string") throw new TypeError("share binding is invalid");
  return object as unknown as SharePublicBinding;
}

export async function loadSharePublicBinding(shareCid: string, fetchFn: typeof fetch = globalThis.fetch.bind(globalThis)): Promise<SharePublicBinding> {
  if (!/^bafkrei[a-z2-7]{52}$/.test(shareCid)) throw new TypeError("share CID is invalid");
  const response = await fetchFn(`/.well-known/tinycloud-share/bindings/${shareCid}.json`, { credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (!response.ok) throw new Error(`share binding unavailable (${response.status})`);
  return validateSharePublicBinding(await response.json());
}
