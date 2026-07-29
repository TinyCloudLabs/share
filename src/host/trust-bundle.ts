import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
export function didKeyFromEd25519PublicKey(value: Uint8Array): string {
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
    /**
     * The service that turns a Node-signed delivery authorization into an
     * email (`@tinycloud/share-email`, `POST /share/v2`).
     *
     * Separate from `credentialsOrigin` on purpose. The OpenCredentials
     * witness issues the claim credential; it has never exposed `/share/v2`
     * and answers 404 there, so the sender pointing at it could not deliver
     * anything (TC-379). These are two different services with two different
     * trust roles, and conflating them is what made addressed sharing look
     * like a signature problem for eleven days.
     */
    readonly emailOrigin: string;
    readonly nodeOrigin: string;
    readonly nodeAudience: string;
    readonly nodeInvitationKid: string;
    readonly nodeInvitationPublicKey: string;
    readonly nodeKeyVersion: number;
    readonly nodeEnabled: boolean;
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
const ORIGIN = /^https:\/\/[^/?#@]+$/;
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

function senderSecret(env: NodeJS.ProcessEnv): string | undefined {
  const value = env.SHARE_SENDER_PRIVATE_KEY;
  if (value === undefined) return undefined;
  if (env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true") return b64(value, "SHARE_SENDER_PRIVATE_KEY");
  throw new Error("SHARE_SENDER_PRIVATE_KEY is forbidden; authenticate through OpenKey");
}

export function validateTrustBundle(value: unknown, allowTest = false, privateKey?: string): ShareTrustBundle {
  const root = exactObject(value, ["version", "shareOrigin", "returnOrigin", "registryOrigin", "credentialsOrigin", "emailOrigin", "nodeOrigin", "nodeAudience", "nodeInvitationKid", "nodeInvitationPublicKey", "nodeKeyVersion", "nodeEnabled", "issuerDid", "issuerVct", "issuerKid", "issuerPublicKey", "issuerKeyVersion", "issuerEnabled"], "trust bundle");
  const environment = allowTest ? "test" : "production";
  if (root.version !== TRUST_VERSION) throw new Error("trust bundle version is unsupported");
  if (typeof root.nodeKeyVersion !== "number" || !Number.isSafeInteger(root.nodeKeyVersion) || typeof root.issuerKeyVersion !== "number" || !Number.isSafeInteger(root.issuerKeyVersion) || typeof root.nodeEnabled !== "boolean" || root.issuerEnabled !== true || root.issuerVct !== "opencredentials.email/v1") throw new Error("trust bundle versions or enablement are invalid");
  const publicConfig = {
    shareOrigin: origin(root.shareOrigin, "shareOrigin"),
    returnOrigin: origin(root.returnOrigin, "returnOrigin"),
    registryOrigin: origin(root.registryOrigin, "registryOrigin"),
    credentialsOrigin: origin(root.credentialsOrigin, "credentialsOrigin"),
    emailOrigin: origin(root.emailOrigin, "emailOrigin"),
    nodeOrigin: origin(root.nodeOrigin, "nodeOrigin"),
    nodeAudience: String(root.nodeAudience),
    nodeInvitationKid: String(root.nodeInvitationKid),
    nodeInvitationPublicKey: b64(root.nodeInvitationPublicKey, "nodeInvitationPublicKey"),
    nodeKeyVersion: root.nodeKeyVersion,
    nodeEnabled: root.nodeEnabled,
    issuerDid: String(root.issuerDid),
    issuerVct: "opencredentials.email/v1",
    issuerKid: String(root.issuerKid),
    issuerPublicKey: b64(root.issuerPublicKey, "issuerPublicKey"),
    issuerKeyVersion: root.issuerKeyVersion,
    issuerEnabled: true,
  } as const;
  if (!DID_WEB.test(publicConfig.nodeAudience) || publicConfig.nodeAudience !== `did:web:${new URL(publicConfig.nodeOrigin).hostname}` || !publicConfig.nodeInvitationKid.startsWith(`${publicConfig.nodeAudience}#`) || publicConfig.nodeKeyVersion !== Number(publicConfig.nodeKeyVersion) || publicConfig.nodeKeyVersion < 1 || !DID_WEB.test(publicConfig.issuerDid) || publicConfig.issuerVct !== "opencredentials.email/v1" || !publicConfig.issuerKid.startsWith(`${publicConfig.issuerDid}#`) || publicConfig.issuerKeyVersion !== Number(publicConfig.issuerKeyVersion) || publicConfig.issuerKeyVersion < 1 || publicConfig.issuerEnabled !== true) throw new Error("trust bundle public trust binding is inconsistent");
  if (environment === "production") Object.values(publicConfig).forEach((item) => { if (typeof item === "string") rejectProductionPlaceholders(item); });
  if (privateKey === undefined) return Object.freeze({ version: TRUST_VERSION, environment, public: Object.freeze(publicConfig), sender: Object.freeze({ senderDid: "", senderPublicKey: "", senderPrivateKey: "" }) });
  const senderPrivateKey = b64(privateKey, "senderPrivateKey");
  const senderPublicKey = toBase64Url(ed25519.getPublicKey(fromBase64Url(senderPrivateKey)));
  return Object.freeze({ version: TRUST_VERSION, environment, public: Object.freeze(publicConfig), sender: Object.freeze({ senderDid: didKeyFromEd25519PublicKey(fromBase64Url(senderPublicKey)), senderPublicKey, senderPrivateKey }) });
}

/**
 * The reviewed, non-secret production trust document that ships inside the
 * image.
 *
 * Every field of a `tinycloud.share-email-trust-bundle/v1` document is public:
 * five HTTPS origins, two `did:web` identifiers, two key ids, two *public*
 * Ed25519 keys, two key versions and two enablement booleans. Fifteen of the
 * seventeen are already republished verbatim to anyone who asks, at
 * `/.well-known/tinycloud-share/config.json`; the two that are not
 * (`returnOrigin`, `issuerKid`) are a canonical origin the node pins equal to
 * `shareOrigin` and a fragment of the published `issuerDid`. The one genuine
 * secret in this system — the sender signing key — is deliberately *not* in
 * this document: `senderSecret` rejects `SHARE_SENDER_PRIVATE_KEY` outright in
 * production, and sender authority is derived per request from an
 * authenticated OpenKey session.
 *
 * Sealing a document with no secrets in it bought no confidentiality and cost
 * the ability to change it: a Phala sealed environment can only be rewritten
 * wholesale, which would take the co-sealed Cloudflare Tunnel token with it.
 * Reviewing this file in a pull request is the stronger integrity control
 * anyway — a fetched URL or an unsealed environment variable is tamperable by
 * anyone who can influence a request or a deploy, whereas this value is
 * covered by branch protection and pinned into an immutable image digest.
 *
 * Resolved from the package root, the same assumption `production-server.ts`
 * already makes for `dist/`. Every supported composition runs from there
 * (`WORKDIR /app` in the image, Vite and Vitest from the repository root); any
 * other working directory fails closed with the path in the message.
 */
export const COMMITTED_TRUST_BUNDLE_PATH = resolve(process.cwd(), "config/trust-bundle.production.json");

/** Reads the committed document. Fails closed: never falls back to a default. */
function readCommittedTrustBundle(path: string): string {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new Error(`the committed Share trust bundle is missing or unreadable at ${path}`);
  }
  if (raw.trim().length === 0) throw new Error(`the committed Share trust bundle at ${path} is empty`);
  return raw;
}

export function loadTrustBundle(env: NodeJS.ProcessEnv = process.env, committedPath: string = COMMITTED_TRUST_BUNDLE_PATH): ShareTrustBundle {
  const source = env.SHARE_TRUST_BUNDLE_SOURCE;
  if (source !== undefined && source !== "committed" && source !== "environment") throw new Error('SHARE_TRUST_BUNDLE_SOURCE must be exactly "committed" or "environment"');
  // `committed` is a selector, not a fallback. An environment source alongside
  // it is an error rather than a silent winner: a stale sealed value quietly
  // overriding a reviewed file is precisely the failure this replaces.
  if (env.SHARE_TRUST_BUNDLE !== undefined && env.SHARE_TRUST_BUNDLE_FILE !== undefined) throw new Error("configure exactly one Share trust bundle source");
  if (source === "committed" && (env.SHARE_TRUST_BUNDLE !== undefined || env.SHARE_TRUST_BUNDLE_FILE !== undefined)) throw new Error("configure exactly one Share trust bundle source");
  const raw = source === "committed"
    ? readCommittedTrustBundle(committedPath)
    : env.SHARE_TRUST_BUNDLE ?? (env.SHARE_TRUST_BUNDLE_FILE === undefined ? undefined : readFileSync(env.SHARE_TRUST_BUNDLE_FILE, "utf8"));
  if (raw === undefined || raw.length === 0) throw new Error("SHARE_TRUST_BUNDLE is required");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error(source === "committed" ? "the committed Share trust bundle is not valid JSON" : "SHARE_TRUST_BUNDLE is not valid JSON"); }
  return validateTrustBundle(value, env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true", senderSecret(env));
}

export function securityHeadersForPath(bundle: ShareTrustBundle, pathname: string): Record<string, string> {
  const hermeticOpenKey = process.env.SHARE_HERMETIC_OPENKEY_ORIGIN;
  const openKeyFrame = hermeticOpenKey !== undefined && /^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(hermeticOpenKey) ? hermeticOpenKey : "https://openkey.so";
  const hermeticWallet = process.env.SHARE_HERMETIC_WALLET_ORIGIN;
  const walletConnect = hermeticWallet !== undefined && /^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(hermeticWallet) ? [hermeticWallet] : [];
  // `emailOrigin` belongs here for the same reason `registryOrigin` does: the
  // sender's `notify` fetches it directly from the page. Omit it and the send
  // dies as a CSP violation in the console, which the composer surfaces as the
  // same generic "We couldn't send that email" as every other failure.
  const connect = ["'self'", bundle.public.nodeOrigin, bundle.public.credentialsOrigin, bundle.public.emailOrigin, bundle.public.registryOrigin, ...(openKeyFrame.startsWith("http://127.0.0.1") ? [openKeyFrame] : []), ...walletConnect].join(" ");
  const common = { "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "Cache-Control": "no-store" };
  const isLanding = pathname === "/" || pathname === "/index.html" || pathname === "/how-it-works" || pathname === "/how-it-works/" || pathname === "/how-it-works.html";
  const isViewer = pathname === "/viewer.html" || pathname === "/viewer" || pathname === "/s/*" || /^\/s\/[a-z2-7]+$/.test(pathname);
  const isShare = pathname === "/share.html" || pathname === "/share";
  const isSandbox = pathname === "/mermaid-sandbox.html" || pathname === "/artifact-sandbox" || pathname === "/artifact-sandbox.html";
  if (isLanding) {
    return {
      ...common,
      "Content-Security-Policy": "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'",
      "Content-Type": "text/html; charset=UTF-8",
    };
  }
  if (isSandbox) {
    return {
      ...common,
      "Content-Security-Policy": "frame-ancestors 'self'",
      "X-Frame-Options": "SAMEORIGIN",
      "Content-Type": "text/html; charset=UTF-8",
    };
  }
  if (!isViewer && !isShare) return common;
  const csp = isViewer
    ? `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src ${connect}; font-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types share-viewer-html dompurify 'allow-duplicates'`
    : `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src ${connect}; img-src 'self' data:; font-src 'self'; frame-src 'self' ${openKeyFrame}; base-uri 'none'; form-action 'self'; object-src 'none'; frame-ancestors 'none'`;
  return { ...common, "Content-Security-Policy": csp, "Content-Type": "text/html; charset=UTF-8" };
}

export function cloudflareHeaders(bundle: ShareTrustBundle): string {
  const render = (path: string, headers: Record<string, string>): string =>
    `${path}\n${Object.entries(headers).map(([name, value]) => `  ${name}: ${value}`).join("\n")}`;
  const common = securityHeadersForPath(bundle, "/*");
  const { "Cache-Control": _cacheControl, ...nonCachingCommon } = common;
  return [
    render("/*", nonCachingCommon),
    render("/", securityHeadersForPath(bundle, "/")),
    render("/index.html", securityHeadersForPath(bundle, "/index.html")),
    render("/how-it-works", securityHeadersForPath(bundle, "/how-it-works")),
    render("/how-it-works.html", securityHeadersForPath(bundle, "/how-it-works.html")),
    render("/share", securityHeadersForPath(bundle, "/share")),
    render("/share.html", securityHeadersForPath(bundle, "/share.html")),
    render("/s/*", securityHeadersForPath(bundle, "/s/*")),
    render("/viewer", securityHeadersForPath(bundle, "/viewer")),
    render("/viewer.html", securityHeadersForPath(bundle, "/viewer.html")),
    render("/assets/*", { "Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff" }),
    render("/404.html", { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }),
    "/mermaid-sandbox.html\n  Content-Security-Policy: frame-ancestors 'self'\n  X-Frame-Options: SAMEORIGIN\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  Cache-Control: no-store",
    "/artifact-sandbox\n  Content-Security-Policy: frame-ancestors 'self'\n  X-Frame-Options: SAMEORIGIN\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  Cache-Control: no-store",
    "/artifact-sandbox.html\n  Content-Security-Policy: frame-ancestors 'self'\n  X-Frame-Options: SAMEORIGIN\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  Cache-Control: no-store",
  ].join("\n") + "\n";
}
