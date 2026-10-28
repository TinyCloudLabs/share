import { createCipheriv, createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { base64UrlEncode, cidForBytes, sha256, utf8 } from "../../src/bytes.ts";
import type { LinkType } from "../../src/config.ts";
import { jcs } from "../../src/jcs.ts";
import { DOMAIN_DELETE, DOMAIN_HEADER } from "../../src/service.ts";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  let out = "";
  while (n > 0n) {
    out = B58.charAt(Number(n % 58n)) + out;
    n /= 58n;
  }
  return out;
}

/** A random Ed25519 identity: a did:key and a signer. */
export interface Issuer {
  readonly did: string;
  signDigest(digest: Uint8Array): string;
}

export function makeIssuer(): Issuer {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, randomBytes(32)]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
  const did = "did:key:z" + base58(Buffer.concat([Buffer.from([0xed, 0x01]), publicKey]));
  return { did, signDigest: (digest) => base64UrlEncode(sign(null, digest, key)) };
}

export const AUDIENCE = "https://api.tinycloud.xyz";
export const CLIENT_IP = "198.51.100.23";

/**
 * The client-address header the Worker keys its per-address limits on. In-process tests and runs against a local
 * Worker send it. A Cloudflare hostname answers a client-sent `CF-Connecting-IP` with a 403 from its edge (the edge
 * sets that header itself), so a run against one passes `null` and nothing is sent.
 */
export function addressHeader(ip: string | null): Record<string, string> {
  return ip === null ? {} : { "CF-Connecting-IP": ip };
}

/** The address to send for a base URL: `CLIENT_IP` for localhost, 127.0.0.1 and [::1]; `null` (send none) for any other host. */
export function clientAddressFor(baseUrl: string): string | null {
  const host = new URL(baseUrl).hostname;
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]" ? CLIENT_IP : null;
}

/** `0x01 || nonce(12) || AES-256-GCM(plaintext) || tag(16)` with the share-envelope AAD, as js-sdk `aead.ts`. */
export function sealBody(plaintext: string, key: Uint8Array): Uint8Array {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from("tinycloud-share-envelope-v1", "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([Buffer.from([0x01]), nonce, ct, cipher.getAuthTag()]);
}

export function filler(length: number): Uint8Array {
  const bytes = new Uint8Array(length).fill(0x42);
  bytes[0] = 0x01;
  return bytes;
}

export interface CreateOptions {
  readonly type?: LinkType;
  readonly issuer: Issuer;
  readonly body?: Uint8Array;
  readonly nowMs: number;
  readonly lifeSeconds?: number;
  readonly headers?: Record<string, string>;
  /** The client address to send; `null` sends no address header. Default: `CLIENT_IP`. */
  readonly ip?: string | null;
}

const DEFAULT_LIFE: Record<LinkType, number> = { "openkey-login": 600, "openkey-approval-request": 3_600, courier: 86_400, share: 2_592_000 };

export async function signedCreate(options: CreateOptions): Promise<Request> {
  const type = options.type ?? "share";
  const body = options.body ?? filler(100);
  const issuedMs = options.nowMs;
  const header = {
    version: 1,
    type,
    issuer: options.issuer.did,
    audience: AUDIENCE,
    issuedAt: new Date(issuedMs).toISOString(),
    expiresAt: new Date(issuedMs + (options.lifeSeconds ?? DEFAULT_LIFE[type]) * 1000).toISOString(),
    size: body.length,
    bodyCid: await cidForBytes(body),
    nonce: base64UrlEncode(randomBytes(16)),
  };
  const digest = await sha256(utf8(DOMAIN_HEADER + jcs(header)));
  const request = { header, signature: { algorithm: "Ed25519", value: options.issuer.signDigest(digest) }, body: base64UrlEncode(body) };
  return new Request(`${AUDIENCE}/v1/links`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...addressHeader(options.ip === undefined ? CLIENT_IP : options.ip), ...options.headers },
    body: JSON.stringify(request),
  });
}

export async function signedDelete(options: { issuer: Issuer; id: string; nowMs: number; ip?: string | null; headers?: Record<string, string> }): Promise<Request> {
  const request = {
    version: 1,
    op: "delete",
    id: options.id,
    issuer: options.issuer.did,
    audience: AUDIENCE,
    issuedAt: new Date(options.nowMs).toISOString(),
    nonce: base64UrlEncode(randomBytes(16)),
  };
  const digest = await sha256(utf8(DOMAIN_DELETE + jcs(request)));
  const body = { request, signature: { algorithm: "Ed25519", value: options.issuer.signDigest(digest) } };
  return new Request(`${AUDIENCE}/v1/links/${options.id}/delete`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...addressHeader(options.ip === undefined ? CLIENT_IP : options.ip), ...options.headers },
    body: JSON.stringify(body),
  });
}

export function get(id: string, ip: string | null = CLIENT_IP, headers: Record<string, string> = {}): Request {
  return new Request(`${AUDIENCE}/v1/links/${id}`, { headers: { ...addressHeader(ip), ...headers } });
}

export function take(id: string, ip: string | null = CLIENT_IP, headers: Record<string, string> = {}): Request {
  return new Request(`${AUDIENCE}/v1/links/${id}/take`, { method: "POST", headers: { ...addressHeader(ip), ...headers } });
}
