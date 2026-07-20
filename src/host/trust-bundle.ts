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

/** The one public trust document mounted into every production composition. */
export interface ShareTrustBundle {
  readonly version: "tinycloud.share-email-trust-bundle/v1";
  readonly public: {
    readonly shareOrigin: string;
    readonly returnOrigin: string;
    readonly registryOrigin: string;
    readonly credentialsOrigin: string;
    readonly nodeOrigin: string;
    readonly nodeAudience: string;
    readonly nodeInvitationKid: string;
    readonly nodeInvitationPublicKey: string;
    readonly nodeKeyVersion: number;
    readonly nodeEnabled: true;
    readonly issuerDid: string;
    readonly issuerVct: "opencredentials.email/v1";
    readonly issuerKid: string;
    readonly issuerPublicKey: string;
    readonly issuerKeyVersion: number;
    readonly issuerEnabled: true;
  };
  readonly sender: {
    readonly senderDid: string;
    readonly senderPublicKey: string;
    /** Server-only secret loaded separately from the public trust document. */
    readonly senderPrivateKey: string;
  };
  readonly environment: "production" | "test";
}

const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const ORIGIN = /^https:\/\/[^/?#:@]+$/;
const DID_WEB = /^did:web:[A-Za-z0-9.-]+$/;
const TRUST_VERSION = "tinycloud.share-email-trust-bundle/v1" as const;

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

function senderSecret(env: NodeJS.ProcessEnv): string {
  const value = env.SHARE_SENDER_PRIVATE_KEY;
  if (value === undefined) throw new Error("SHARE_SENDER_PRIVATE_KEY is required outside the public trust bundle");
  return b64(value, "SHARE_SENDER_PRIVATE_KEY");
}

export function validateTrustBundle(value: unknown, allowTest = false, privateKey?: string): ShareTrustBundle {
  const root = exactObject(value, ["version", "shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "nodeOrigin", "nodeAudience", "nodeInvitationKid", "nodeInvitationPublicKey", "nodeKeyVersion", "nodeEnabled", "issuerDid", "issuerVct", "issuerKid", "issuerPublicKey", "issuerKeyVersion", "issuerEnabled"], "trust bundle");
  const environment = allowTest ? "test" : "production";
  if (root.version !== TRUST_VERSION) throw new Error("trust bundle version is unsupported");
  if (typeof root.nodeKeyVersion !== "number" || !Number.isSafeInteger(root.nodeKeyVersion) || typeof root.issuerKeyVersion !== "number" || !Number.isSafeInteger(root.issuerKeyVersion) || root.nodeEnabled !== true || root.issuerEnabled !== true || root.issuerVct !== "opencredentials.email/v1") throw new Error("trust bundle versions or enablement are invalid");
  const publicConfig = {
    shareOrigin: origin(root.shareOrigin, "shareOrigin"),
    returnOrigin: origin(root.returnOrigin, "returnOrigin"),
    registryOrigin: origin(root.registryOrigin, "registryOrigin"),
    credentialsOrigin: origin(root.credentialsOrigin, "credentialsOrigin"),
    nodeOrigin: origin(root.nodeOrigin, "nodeOrigin"),
    nodeAudience: String(root.nodeAudience),
    nodeInvitationKid: String(root.nodeInvitationKid),
    nodeInvitationPublicKey: b64(root.nodeInvitationPublicKey, "nodeInvitationPublicKey"),
    nodeKeyVersion: root.nodeKeyVersion,
    nodeEnabled: true,
    issuerDid: String(root.issuerDid),
    issuerVct: "opencredentials.email/v1",
    issuerKid: String(root.issuerKid),
    issuerPublicKey: b64(root.issuerPublicKey, "issuerPublicKey"),
    issuerKeyVersion: root.issuerKeyVersion,
    issuerEnabled: true,
  } as const;
  if (!DID_WEB.test(publicConfig.nodeAudience) || publicConfig.nodeAudience !== `did:web:${new URL(publicConfig.nodeOrigin).hostname}` || !publicConfig.nodeInvitationKid.startsWith(`${publicConfig.nodeAudience}#`) || publicConfig.nodeKeyVersion !== Number(publicConfig.nodeKeyVersion) || publicConfig.nodeKeyVersion < 1 || publicConfig.nodeEnabled !== true || !DID_WEB.test(publicConfig.issuerDid) || publicConfig.issuerVct !== "opencredentials.email/v1" || !publicConfig.issuerKid.startsWith(`${publicConfig.issuerDid}#`) || publicConfig.issuerKeyVersion !== Number(publicConfig.issuerKeyVersion) || publicConfig.issuerKeyVersion < 1 || publicConfig.issuerEnabled !== true) throw new Error("trust bundle public trust binding is inconsistent");
  if (environment === "production") Object.values(publicConfig).forEach((item) => { if (typeof item === "string") rejectProductionPlaceholders(item); });
  if (privateKey === undefined) return Object.freeze({ version: TRUST_VERSION, environment, public: Object.freeze(publicConfig), sender: Object.freeze({ senderDid: "", senderPublicKey: "", senderPrivateKey: "" }) });
  const senderPrivateKey = b64(privateKey, "senderPrivateKey");
  const senderPublicKey = toBase64Url(ed25519.getPublicKey(fromBase64Url(senderPrivateKey)));
  return Object.freeze({ version: TRUST_VERSION, environment, public: Object.freeze(publicConfig), sender: Object.freeze({ senderDid: didKeyFromEd25519PublicKey(fromBase64Url(senderPublicKey)), senderPublicKey, senderPrivateKey }) });
}

export function loadTrustBundle(env: NodeJS.ProcessEnv = process.env): ShareTrustBundle {
  if (env.SHARE_TRUST_BUNDLE !== undefined && env.SHARE_TRUST_BUNDLE_FILE !== undefined) throw new Error("configure exactly one Share trust bundle source");
  const raw = env.SHARE_TRUST_BUNDLE ?? (env.SHARE_TRUST_BUNDLE_FILE === undefined ? undefined : readFileSync(env.SHARE_TRUST_BUNDLE_FILE, "utf8"));
  if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE is required");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error("SHARE_TRUST_BUNDLE is not valid JSON"); }
  return validateTrustBundle(value, env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true", senderSecret(env));
}

export function securityHeadersForPath(bundle: ShareTrustBundle, pathname: string): Record<string, string> {
  const connect = ["'self'", bundle.public.nodeOrigin, bundle.public.credentialsOrigin, bundle.public.registryOrigin].join(" ");
  const common = { "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" };
  const isViewer = pathname === "/viewer.html" || pathname === "/viewer" || pathname === "/s/*" || /^\/s\/[a-z2-7]+$/.test(pathname);
  const isShare = pathname === "/share.html" || pathname === "/share";
  if (!isViewer && !isShare) return common;
  const csp = isViewer
    ? `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src ${connect}; font-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types share-viewer-html dompurify 'allow-duplicates'`
    : `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src ${connect}; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'`;
  return { ...common, "Content-Security-Policy": csp, "Content-Type": "text/html; charset=UTF-8" };
}

export function cloudflareHeaders(bundle: ShareTrustBundle): string {
  const render = (path: string): string => {
    const headers = securityHeadersForPath(bundle, path);
    return `${path}\n${Object.entries(headers).map(([name, value]) => `  ${name}: ${value}`).join("\n")}`;
  };
  return [render("/*"), render("/share"), render("/share.html"), render("/s/*"), render("/viewer.html"), "/mermaid-sandbox.html\n  Content-Security-Policy: frame-ancestors 'self'\n  X-Frame-Options: SAMEORIGIN\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  Cache-Control: no-store"].join("\n") + "\n";
}
