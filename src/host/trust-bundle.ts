import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";

function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
function didKeyFromEd25519PublicKey(value: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes = [0xed, 0x01, ...value]; const digits = [0];
  for (const byte of bytes) { let carry = byte; for (let index = 0; index < digits.length; index++) { const next = digits[index]! * 256 + carry; digits[index] = next % 58; carry = Math.floor(next / 58); } while (carry > 0) { digits.push(carry % 58); carry = Math.floor(carry / 58); } }
  return `did:key:z${digits.reverse().map((digit) => alphabet[digit]!).join("")}`;
}

export interface ShareTrustBundle {
  readonly version: 1;
  readonly environment: "production" | "test";
  readonly public: {
    readonly shareOrigin: string;
    readonly registryOrigin: string;
    readonly nodeOrigin: string;
    readonly credentialsOrigin: string;
    readonly nodeAudience: string;
    readonly issuerDid: string;
    readonly issuerVct: "opencredentials.email/v1";
    readonly nodeInvitationKid: string;
    readonly nodeInvitationPublicKey: string;
    readonly issuerPublicKey: string;
  };
  readonly sender: {
    readonly senderDid: string;
    readonly senderPublicKey: string;
    readonly senderPrivateKey: string;
  };
}

const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const ORIGIN = /^https:\/\/[^/?#:@]+$/;
const DID_WEB = /^did:web:[A-Za-z0-9.-]+$/;

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const object = value as Record<string, unknown>;
  if (Object.keys(object).length !== keys.length || keys.some((key) => !Object.hasOwn(object, key))) throw new Error(`${label} has an invalid shape`);
  return object;
}

function b64(value: unknown, label: string): string {
  if (typeof value !== "string" || !B64_256.test(value) || fromBase64Url(value).length !== 32) throw new Error(`${label} must be a canonical 32-byte base64url key`);
  return value;
}

function origin(value: unknown, label: string): string {
  if (typeof value !== "string" || !ORIGIN.test(value) || new URL(value).origin !== value) throw new Error(`${label} must be a canonical HTTPS origin`);
  return value;
}

function rejectProductionPlaceholders(value: string): void {
  if (/(?:node\.example|127\.0\.0\.1|localhost|fixture|test|seed|placeholder)/i.test(value)) throw new Error("production trust bundle contains a placeholder or loopback value");
}

export function validateTrustBundle(value: unknown, allowTest = false): ShareTrustBundle {
  const root = exactObject(value, ["version", "environment", "public", "sender"], "trust bundle");
  if (root.version !== 1 || (root.environment !== "production" && root.environment !== "test") || (root.environment === "test" && !allowTest)) throw new Error("trust bundle environment is not permitted");
  const publicValue = exactObject(root.public, ["shareOrigin", "registryOrigin", "nodeOrigin", "credentialsOrigin", "nodeAudience", "issuerDid", "issuerVct", "nodeInvitationKid", "nodeInvitationPublicKey", "issuerPublicKey"], "trust bundle public");
  const senderValue = exactObject(root.sender, ["senderDid", "senderPublicKey", "senderPrivateKey"], "trust bundle sender");
  const publicConfig = {
    shareOrigin: origin(publicValue.shareOrigin, "shareOrigin"),
    registryOrigin: origin(publicValue.registryOrigin, "registryOrigin"),
    nodeOrigin: origin(publicValue.nodeOrigin, "nodeOrigin"),
    credentialsOrigin: origin(publicValue.credentialsOrigin, "credentialsOrigin"),
    nodeAudience: String(publicValue.nodeAudience),
    issuerDid: String(publicValue.issuerDid),
    issuerVct: publicValue.issuerVct as "opencredentials.email/v1",
    nodeInvitationKid: String(publicValue.nodeInvitationKid),
    nodeInvitationPublicKey: b64(publicValue.nodeInvitationPublicKey, "nodeInvitationPublicKey"),
    issuerPublicKey: b64(publicValue.issuerPublicKey, "issuerPublicKey"),
  };
  if (typeof publicConfig.nodeAudience !== "string" || !DID_WEB.test(publicConfig.nodeAudience) || typeof publicConfig.issuerDid !== "string" || !DID_WEB.test(publicConfig.issuerDid) || publicConfig.issuerVct !== "opencredentials.email/v1" || typeof publicConfig.nodeInvitationKid !== "string" || !publicConfig.nodeInvitationKid.startsWith(`${publicConfig.nodeAudience}#`)) throw new Error("trust bundle public trust binding is inconsistent");
  const senderPrivateKey = b64(senderValue.senderPrivateKey, "senderPrivateKey");
  const senderPublicKey = b64(senderValue.senderPublicKey, "senderPublicKey");
  const derivedPublicKey = toBase64Url(ed25519.getPublicKey(fromBase64Url(senderPrivateKey)));
  if (derivedPublicKey !== senderPublicKey || typeof senderValue.senderDid !== "string" || didKeyFromEd25519PublicKey(fromBase64Url(senderPublicKey)) !== senderValue.senderDid) throw new Error("trust bundle sender key binding is inconsistent");
  if (root.environment === "production") Object.values(publicConfig).forEach((item) => { if (typeof item === "string") rejectProductionPlaceholders(item); });
  return Object.freeze({ version: 1, environment: root.environment, public: Object.freeze(publicConfig), sender: Object.freeze({ senderDid: senderValue.senderDid, senderPublicKey, senderPrivateKey }) });
}

export function loadTrustBundle(env: NodeJS.ProcessEnv = process.env): ShareTrustBundle {
  const raw = env.SHARE_TRUST_BUNDLE ?? (env.SHARE_TRUST_BUNDLE_FILE === undefined ? undefined : readFileSync(env.SHARE_TRUST_BUNDLE_FILE, "utf8"));
  if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE is required");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error("SHARE_TRUST_BUNDLE is not valid JSON"); }
  return validateTrustBundle(value, env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true");
}
