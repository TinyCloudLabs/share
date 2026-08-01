import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { closeSync, constants, existsSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, statSync, unlinkSync, writeSync } from "node:fs";
import { open, stat, unlink } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519";
import { verifyMessage } from "viem";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { isAbsolute, relative, resolve } from "node:path";
import { canonicalize } from "@tinycloud/share-envelope";
import { loadTrustBundle, type ShareTrustBundle } from "./trust-bundle.js";
import { derivablePrincipal, derivedSenderIdentitySource, loadSenderRootSeed, staticSenderIdentitySource, type SenderIdentity, type SenderIdentitySource } from "./sender-identity.js";
import { assertSecurePath, secureReadSync, SECURE_APPEND, SECURE_CREATE, SECURE_READ } from "./secure-path.js";
import { resolveShareUpstreams, sanitizeUpstreamRequest, sanitizeUpstreamResponse } from "./upstream.js";

function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
const SIGNATURE_DOMAINS = { envelope: "xyz.tinycloud.share/envelope/v1\0", envelopeV2: "xyz.tinycloud.share/envelope/v2\0", inviteAuthorization: "xyz.tinycloud.share/invite-authorization/v1\0", delegationAuthoring: "xyz.tinycloud.share/delegation-authoring/v2\0" } as const;
const AGENT_CARD = { version: 1, cli: "npx -y @tinycloud/cli@latest", input: "stdin", inspectArgs: ["share", "inspect", "-", "--json"], receiveArgs: ["share", "receive", "-", "--output", "."], fragmentLocalOnly: true } as const;
type ContentSource = Record<string, unknown>;
function validateSource(value: ContentSource): ContentSource {
  if (value.kind === "kv") {
    if (Object.keys(value).sort().join(",") !== "action,kind,path,space" || typeof value.space !== "string" || typeof value.path !== "string" || value.action !== "tinycloud.kv/get" || value.path.length === 0 || /[\u0000-\u001f\u007f\\]/.test(value.path) || value.path.split("/").some((part) => part === "" || part === "." || part === "..")) throw new Error("source");
    return value;
  }
  if (value.kind !== "sql" || Object.keys(value).sort().join(",") !== "action,arguments,argumentsDigest,database,kind,path,space,statement" || typeof value.space !== "string" || typeof value.database !== "string" || typeof value.statement !== "string" || typeof value.path !== "string" || value.action !== "tinycloud.sql/read" || typeof value.argumentsDigest !== "string" || !B64_256.test(value.argumentsDigest) || typeof value.arguments !== "object" || value.arguments === null || Array.isArray(value.arguments) || value.path.length === 0 || /[\u0000-\u001f\u007f\\]/.test(value.path) || value.path.split("/").some((part) => part === "" || part === "." || part === "..")) throw new Error("source");
  return value;
}
function stable(value: unknown): string { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`; return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}`; }

function isCanonicalRecipientDid(value: string): boolean {
  if (value.length === 0 || value.length > 2048 || /[\u0000-\u0020\u007f]/.test(value)) return false;
  const parts = value.split(":");
  if (parts.length < 3 || parts[0] !== "did" || !/^[a-z0-9]+$/.test(parts[1] ?? "")) return false;
  const identifier = parts.slice(2);
  if (identifier.some((part) => part.length === 0)) return false;
  if (parts[1] === "web") {
    const host = identifier[0] ?? "";
    if (host.length > 253 || host.split(".").some((label) => !label || label.length > 63 || !/^[A-Za-z0-9-]+$/.test(label) || label.startsWith("-") || label.endsWith("-"))) return false;
    return identifier.slice(1).every((part) => /^[A-Za-z0-9._%-]+$/.test(part));
  }
  if (parts[1] === "pkh") return identifier.length >= 3 && identifier.every((part) => /^[A-Za-z0-9._%-]+$/.test(part));
  if (parts[1] === "key") {
    if (!/^z[1-9A-HJ-NP-Za-km-z]+$/.test(identifier.join(":"))) return false;
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const digits = identifier.join(":").slice(1).split("").map((char) => alphabet.indexOf(char));
    if (digits.some((digit) => digit < 0)) return false;
    const bytes = [0];
    for (const digit of digits) {
      let carry = digit;
      for (let index = bytes.length - 1; index >= 0; index -= 1) {
        const value = (bytes[index] ?? 0) * 58 + carry;
        bytes[index] = value & 0xff;
        carry = value >>> 8;
      }
      while (carry > 0) {
        bytes.unshift(carry & 0xff);
        carry >>>= 8;
      }
    }
    const leadingZeroes = identifier.join(":").slice(1).match(/^1*/)?.[0].length ?? 0;
    const decoded = [...new Array(leadingZeroes).fill(0), ...bytes].slice(bytes.length === 1 && bytes[0] === 0 ? leadingZeroes : 0);
    return decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01;
  }
  return false;
}

const MAX_BODY = 128 * 1024;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" };
const B64_128 = /^[A-Za-z0-9_-]{22}$/;
const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const OPENKEY_NONCE_TTL_MS = 5 * 60 * 1000;
const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1(?::\d+)?$/;
const HERMETIC_BROWSER_ORIGIN_PATTERN = /^http:\/\/127\.0\.0\.1:([0-9]+)$/;
const SEALED_BLOB_OVERHEAD_BYTES = 1 + 12 + 16;
const LINK_ONLY_BLOB_LIMIT = 100 * 1024 * 1024 + SEALED_BLOB_OVERHEAD_BYTES;
const LINK_ONLY_REGISTRY_PREFIX = "/api/share/link-only/registry";
const LINK_ONLY_RETENTION_LIMIT_MS = 8 * 24 * 60 * 60 * 1000;
const LINK_ONLY_UPLOAD_WINDOW_MS = 5 * 60 * 1000;
const LINK_ONLY_UPLOAD_LIMIT = 20;
const LINK_ONLY_AUTHORIZATION_TTL_MS = 60 * 1000;
const UPLOAD_ATTESTATION_HEADER = "x-tinycloud-upload-attestation";
const UPLOAD_RETENTION_HEADER = "x-tinycloud-retention";
const UPLOAD_ATTESTATION_DOMAIN = "xyz.tinycloud.share/upload-attestation/v1\0";
const MAX_UPLOAD_ATTESTATION_BYTES = 64 * 1024;
const MAX_UPLOAD_ATTESTATION_REPLAY = 8192;
const UPLOAD_ATTESTATION_CLOCK_SKEW_MS = 30 * 1000;
const UPLOAD_ATTESTATION_TTL_MS = 120 * 1000;
const MAX_RETENTION_BYTES = 1024;
const REGISTRY_AUTHORIZATION_DOMAIN =
  "xyz.tinycloud.share/registry-authorization/v1\0";
const REGISTRY_STORE_DOMAIN = "xyz.tinycloud.share/registry-store/v1\0";
export const PRODUCTION_BINDING_STORE_ROOT = "/var/lib/tinycloud/share";
export const DEFAULT_PRODUCTION_BINDING_STORE_PATH = `${PRODUCTION_BINDING_STORE_ROOT}/bindings.ndjson`;

class PayloadTooLargeError extends Error {}

export interface BindingStore {
  readonly writable: boolean;
  get(cid: string): Promise<Record<string, unknown> | undefined>;
  put(cid: string, binding: Record<string, unknown>): Promise<void>;
  reserveUpload?(principal: string, now: number, windowMs: number, limit: number): Promise<boolean>;
  consumeUploadAttestation?(jti: string, expiresAt: number, now: number, limit: number): Promise<boolean>;
}

export interface UploadBudgetStore {
  readonly writable: boolean;
  reserveUpload(principal: string, now: number, windowMs: number, limit: number): Promise<boolean>;
  consumeUploadAttestation?(jti: string, expiresAt: number, now: number, limit: number): Promise<boolean>;
}

async function secureRead(path: string): Promise<string> {
  assertSecurePath(path);
  const handle = await open(path, SECURE_READ);
  try { return await handle.readFile("utf8"); }
  finally { await handle.close(); }
}

/** Production bindings must live inside the persistent Share volume. */
export function validateProductionBindingStorePath(value: string, root = PRODUCTION_BINDING_STORE_ROOT): string {
  if (typeof root !== "string" || !isAbsolute(root) || root.includes("\0") || root.endsWith("/")) {
    throw new Error("binding store root must be an absolute mounted directory");
  }
  const rootSegments = root.split("/").slice(1);
  if (rootSegments.some((segment) => segment === "." || segment === ".." || segment === "")) {
    throw new Error("binding store root must be normalized and traversal-free");
  }
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0") || value.endsWith("/")) {
    throw new Error("binding store path must be an absolute path inside the persistent Share volume");
  }
  const segments = value.split("/");
  if (segments.slice(1).some((segment) => segment === "." || segment === ".." || segment === "")) {
    throw new Error("binding store path must be normalized and traversal-free");
  }
  const normalizedRoot = resolve(root);
  const normalized = resolve(value);
  const remainder = relative(normalizedRoot, normalized);
  if (remainder === "" || remainder.startsWith("..") || isAbsolute(remainder)) {
    throw new Error("binding store path must be a descendant of the configured persistent Share volume");
  }
  return normalized;
}

function scryptAsync(password: string, salt: Uint8Array, length: number, options: { readonly N: number; readonly r: number; readonly p: number; readonly maxmem: number }): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password, salt, length, options, (error, derived) => error === null ? resolve(derived as Buffer) : reject(error)));
}

interface JournalState {
  readonly bindings: Map<string, Record<string, unknown>>;
  readonly budgets: Map<string, { count: number; windowStartedAt: number }>;
  readonly uploadAttestations: Map<string, number>;
}

function parseJournal(text: string): JournalState {
  const bindings = new Map<string, Record<string, unknown>>();
  const budgets = new Map<string, { count: number; windowStartedAt: number }>();
  const uploadAttestations = new Map<string, number>();
  if (text.length === 0) throw new Error("binding journal is empty");
  const lines = text.split("\n");
  for (const [lineNumber, line] of lines.entries()) {
    if (lineNumber === lines.length - 1 && line === "") continue;
    let value: unknown;
    try { value = JSON.parse(line); } catch { throw new Error("binding journal is corrupt"); }
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("binding journal record is invalid");
    const record = value as Record<string, unknown>;
    if (record.op === "put") {
      if (typeof record.cid !== "string" || typeof record.binding !== "object" || record.binding === null || Array.isArray(record.binding)) throw new Error("binding journal record is invalid");
      const binding = record.binding as Record<string, unknown>;
      const previous = bindings.get(record.cid);
      if (previous !== undefined && stable(previous) !== stable(binding)) throw new Error("binding journal contains conflicting records");
      bindings.set(record.cid, binding);
      continue;
    }
    if (record.op === "upload-budget" && typeof record.principal === "string" && Number.isSafeInteger(record.count) && (record.count as number) >= 0 && Number.isSafeInteger(record.windowStartedAt) && (record.windowStartedAt as number) >= 0) {
      budgets.set(record.principal, { count: record.count as number, windowStartedAt: record.windowStartedAt as number });
      continue;
    }
    if (record.op === "upload-attestation" && typeof record.jti === "string" && Number.isSafeInteger(record.expiresAt) && (record.expiresAt as number) > 0) {
      uploadAttestations.set(record.jti, record.expiresAt as number);
      continue;
    }
    throw new Error("binding journal record is invalid");
  }
  return { bindings, budgets, uploadAttestations };
}

/**
 * A small append-only transactional store for the host's public binding
 * records.  Each mutation takes an OS-backed exclusive lock, appends one
 * fsynced record, and is replayed on startup.  It intentionally has no
 * "empty on error" path: a truncated journal, invalid JSON, or an I/O error
 * disables the capability instead of changing authorization state.
 */
export class TransactionalBindingStore implements BindingStore {
  private readonly lockPath: string;
  private readonly staleLockMs = 30_000;

  readonly writable: boolean;
  constructor(private readonly path: string) {
    this.lockPath = `${path}.lock`;
    this.writable = this.probe();
  }

  private probe(): boolean {
    const existed = existsSync(this.path);
    let storeDescriptor: number | undefined;
    let lockDescriptor: number | undefined;
    let createdStore = false;
    let createdLock = false;
    try {
      assertSecurePath(this.path);
      assertSecurePath(this.lockPath);
      if (existed) {
        parseJournal(secureReadSync(this.path));
        storeDescriptor = openSync(this.path, SECURE_APPEND, 0o600);
      } else {
        storeDescriptor = openSync(this.path, SECURE_CREATE, 0o600);
        createdStore = true;
      }
      fsyncSync(storeDescriptor);
      closeSync(storeDescriptor);
      storeDescriptor = undefined;
      lockDescriptor = openSync(this.lockPath, SECURE_CREATE, 0o600);
      createdLock = true;
      fsyncSync(lockDescriptor);
      closeSync(lockDescriptor);
      lockDescriptor = undefined;
      unlinkSync(this.lockPath);
      createdLock = false;
      if (createdStore) {
        unlinkSync(this.path);
        createdStore = false;
      }
      return true;
    } catch {
      if (storeDescriptor !== undefined) try { closeSync(storeDescriptor); } catch { /* best-effort probe cleanup */ }
      if (lockDescriptor !== undefined) try { closeSync(lockDescriptor); } catch { /* best-effort probe cleanup */ }
      if (createdLock) try { unlinkSync(this.lockPath); } catch { /* best-effort probe cleanup */ }
      if (createdStore) try { unlinkSync(this.path); } catch { /* best-effort probe cleanup */ }
      return false;
    }
  }

  private async readJournal(): Promise<JournalState> {
    let text: string;
    try { text = await secureRead(this.path); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { bindings: new Map(), budgets: new Map(), uploadAttestations: new Map() };
      throw error;
    }
    return parseJournal(text);
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    for (;;) {
      try {
        assertSecurePath(this.lockPath);
        const handle = await open(this.lockPath, SECURE_CREATE, 0o600);
        try { return await operation(); } finally { await handle.close(); await unlink(this.lockPath).catch(() => undefined); }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        try {
          assertSecurePath(this.lockPath, false);
          if (Date.now() - (await stat(this.lockPath)).mtimeMs > this.staleLockMs) await unlink(this.lockPath);
        }
        catch (statError) { if ((statError as NodeJS.ErrnoException).code !== "ENOENT") throw statError; }
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    }
  }

  async get(cid: string): Promise<Record<string, unknown> | undefined> { return (await this.readJournal()).bindings.get(cid); }

  async put(cid: string, binding: Record<string, unknown>): Promise<void> {
    if (!this.writable) throw new Error("binding store is not writable");
    await this.withLock(async () => {
      const state = await this.readJournal();
      const previous = state.bindings.get(cid);
      if (previous !== undefined) {
        if (stable(previous) !== stable(binding)) throw new Error("binding is immutable");
        return;
      }
      assertSecurePath(this.path);
      const handle = await open(this.path, SECURE_APPEND, 0o600);
      try {
        await handle.write(`${JSON.stringify({ op: "put", cid, binding })}\n`, undefined, "utf8");
        await handle.sync();
      } finally { await handle.close(); }
    });
  }

  async reserveUpload(principal: string, now: number, windowMs: number, limit: number): Promise<boolean> {
    if (!this.writable) throw new Error("upload budget store is not writable");
    return this.withLock(async () => {
      const state = await this.readJournal();
      const prior = state.budgets.get(principal);
      const budget = prior === undefined || now - prior.windowStartedAt >= windowMs
        ? { count: 0, windowStartedAt: now }
        : prior;
      if (budget.count >= limit) return false;
      const next = { count: budget.count + 1, windowStartedAt: budget.windowStartedAt };
      assertSecurePath(this.path);
      const handle = await open(this.path, SECURE_APPEND, 0o600);
      try {
        await handle.write(`${JSON.stringify({ op: "upload-budget", principal, ...next })}\n`, undefined, "utf8");
        await handle.sync();
      } finally { await handle.close(); }
      return true;
    });
  }

  async consumeUploadAttestation(jti: string, expiresAt: number, now: number, limit: number): Promise<boolean> {
    if (!this.writable) throw new Error("upload attestation store is not writable");
    return this.withLock(async () => {
      const state = await this.readJournal();
      for (const [value, expiry] of state.uploadAttestations) {
        if (expiry <= now) state.uploadAttestations.delete(value);
      }
      if (state.uploadAttestations.has(jti) || state.uploadAttestations.size >= limit) return false;
      assertSecurePath(this.path);
      const handle = await open(this.path, SECURE_APPEND, 0o600);
      try {
        await handle.write(`${JSON.stringify({ op: "upload-attestation", jti, expiresAt })}\n`, undefined, "utf8");
        await handle.sync();
      } finally { await handle.close(); }
      return true;
    });
  }
}

class MemoryBindingStore implements BindingStore {
  readonly writable = true;
  private readonly values = new Map<string, Record<string, unknown>>();
  private readonly budgets = new MemoryUploadBudgetStore();
  constructor(initial: Record<string, Record<string, unknown>> = {}) { Object.entries(initial).forEach(([key, value]) => this.values.set(key, value)); }
  async get(cid: string): Promise<Record<string, unknown> | undefined> { return this.values.get(cid); }
  async put(cid: string, binding: Record<string, unknown>): Promise<void> { this.values.set(cid, binding); }
  async reserveUpload(principal: string, now: number, windowMs: number, limit: number): Promise<boolean> { return this.budgets.reserveUpload(principal, now, windowMs, limit); }
  async consumeUploadAttestation(jti: string, expiresAt: number, now: number, limit: number): Promise<boolean> { return this.budgets.consumeUploadAttestation(jti, expiresAt, now, limit); }
}

class MemoryUploadBudgetStore implements UploadBudgetStore {
  readonly writable = true;
  private readonly values = new Map<string, { count: number; windowStartedAt: number }>();
  private readonly attestations = new Map<string, number>();
  async reserveUpload(principal: string, now: number, windowMs: number, limit: number): Promise<boolean> {
    const prior = this.values.get(principal);
    const budget = prior === undefined || now - prior.windowStartedAt >= windowMs ? { count: 0, windowStartedAt: now } : prior;
    if (budget.count >= limit) return false;
    budget.count += 1;
    this.values.set(principal, budget);
    return true;
  }
  async consumeUploadAttestation(jti: string, expiresAt: number, now: number, limit: number): Promise<boolean> {
    for (const [value, expiry] of this.attestations) if (expiry <= now) this.attestations.delete(value);
    if (this.attestations.has(jti) || this.attestations.size >= limit) return false;
    this.attestations.set(jti, expiresAt);
    return true;
  }
}

/**
 * Production replay and quota state lives in the registry Worker’s
 * UploadAuthorization Durable Object.  The Share process only holds the
 * private half of the dedicated registry-upload key and signs the exact
 * store operation; it never treats a local file as authorization state.
 */
export class RegistryUploadAuthorizationStore implements UploadBudgetStore {
  readonly writable = true;

  constructor(
    private readonly origin: string,
    private readonly privateKey: Uint8Array,
    private readonly fetchFn?: typeof fetch,
  ) {
    if (!/^https:\/\/[^/?#:@]+$/.test(origin) && !LOOPBACK_ORIGIN.test(origin)) throw new Error("registry authorization store origin is invalid");
    if (privateKey.byteLength !== 32) throw new Error("registry authorization store key is invalid");
  }

  private async request(body: Record<string, unknown>): Promise<boolean> {
    const signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`${REGISTRY_STORE_DOMAIN}${stable(body)}`), this.privateKey));
    try {
      const response = await (this.fetchFn ?? globalThis.fetch)(`${this.origin}/internal/upload-authorizations`, {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json", "x-tinycloud-registry-store-signature": signature },
        body: JSON.stringify(body),
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
      return response.status === 204;
    } catch {
      return false;
    }
  }

  async reserveUpload(principal: string, now: number, windowMs: number, limit: number): Promise<boolean> {
    return this.request({ key: principal, limit, now, operation: "reserve", windowMs });
  }

  async consumeUploadAttestation(jti: string, expiresAt: number, _now: number, _limit: number): Promise<boolean> {
    return this.request({ expiresAt, key: jti, operation: "consume" });
  }
}

export interface ShareHostOptions {
  readonly bundle: ShareTrustBundle;
  readonly capability?: { readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: Record<string, unknown> };
  readonly capabilities?: ReadonlyMap<string, { readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: Record<string, unknown> }>;
  readonly bindingStore?: BindingStore;
  readonly uploadBudgetStore?: UploadBudgetStore;
  readonly registryOrigin: string;
  /** Registry transport is bundle-derived, except inside the explicit hermetic resolver or SHARE_HERMETIC_REGISTRY_ORIGIN. */
  readonly registryTransportOrigin: string;
  /** Optional transport injection for hermetic tests; production uses the platform fetch. */
  readonly fetchFn?: typeof fetch;
  readonly authUsers?: readonly AuthUser[];
  readonly registryUploadPrivateKey?: Uint8Array;
  /** Resolves the per-principal sender signing identity; absent means the sender path cannot serve any session. */
  readonly senderIdentitySource?: SenderIdentitySource;
  readonly senderEnabled: boolean;
  readonly testMode: boolean;
  /** Explicit local production-shaped composition; never enabled by trust data. */
  readonly hermeticComposition?: boolean;
  /** The single dedicated local browser origin authorized outside hermeticComposition/testMode; never a wildcard. */
  readonly hermeticBrowserOrigin?: string;
}

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response { return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...headers } }); }
function generic(status = 400): Response { return response(status, { error: { code: "capability_unavailable" } }); }
function safeString(value: unknown, label: string): string { if (typeof value !== "string" || value.length === 0 || value.length > 4096) throw new Error(label); return value; }
function hash(value: string): string { return createHash("sha256").update(value).digest("base64url"); }
function hashBytes(value: Uint8Array): string { return createHash("sha256").update(value).digest("base64url"); }

interface UploadAttestation {
  readonly type: "TinyCloudShareUploadAttestation";
  readonly version: 1;
  readonly issuer: string;
  readonly kid: string;
  readonly ownerDid: string;
  readonly sessionDid: string;
  readonly shareOrigin: string;
  readonly encryptedBlobCid: string;
  readonly encryptedBlobSha256: string;
  readonly byteLength: number;
  readonly deleteAfter: string;
  readonly retention: unknown;
  readonly issuedAt: string;
  readonly authorityExpiresAt: string;
  readonly expiresAt: string;
  readonly jti: string;
  readonly signature: string;
}

const UPLOAD_ATTESTATION_KEYS = ["authorityExpiresAt", "byteLength", "deleteAfter", "encryptedBlobCid", "encryptedBlobSha256", "expiresAt", "issuedAt", "issuer", "jti", "kid", "ownerDid", "retention", "sessionDid", "shareOrigin", "signature", "type", "version"] as const;
const PRINCIPAL = /^did:[A-Za-z0-9][A-Za-z0-9.-]*:[^\s\u0000-\u001f\u007f]{1,1023}$/;

function strictBase64Url(value: unknown, bytes: number): value is string {
  const length = Math.ceil(bytes * 4 / 3);
  if (typeof value !== "string" || value.length !== length || !new RegExp(`^[A-Za-z0-9_-]{${length}}$`).test(value)) return false;
  const decoded = fromBase64Url(value);
  return decoded.byteLength === bytes && toBase64Url(decoded) === value;
}

function canonicalTimestamp(value: unknown, label: string): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) throw new Error(label);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) throw new Error(label);
  return time;
}

function exactAttestation(value: unknown): UploadAttestation {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("attestation shape");
  const object = value as Record<string, unknown>;
  if (Object.keys(object).sort().join(",") !== [...UPLOAD_ATTESTATION_KEYS].sort().join(",")) throw new Error("attestation shape");
  return object as unknown as UploadAttestation;
}

function uploadAttestationBytes(attestation: UploadAttestation): Uint8Array {
  const unsigned = Object.fromEntries(Object.entries(attestation).filter(([key]) => key !== "signature"));
  return new TextEncoder().encode(`${UPLOAD_ATTESTATION_DOMAIN}${canonicalize(unsigned)}`);
}

async function verifyUploadAttestation(
  request: Request,
  bytes: Uint8Array,
  bundle: ShareTrustBundle,
  now: number,
): Promise<UploadAttestation> {
  const encoded = request.headers.get(UPLOAD_ATTESTATION_HEADER);
  const retentionHeader = request.headers.get(UPLOAD_RETENTION_HEADER);
  if (encoded === null || Buffer.byteLength(encoded, "utf8") > MAX_UPLOAD_ATTESTATION_BYTES || retentionHeader === null || Buffer.byteLength(retentionHeader, "utf8") > MAX_RETENTION_BYTES) throw new Error("attestation missing");
  let attestation: UploadAttestation;
  let retention: unknown;
  try {
    attestation = exactAttestation(JSON.parse(encoded));
    retention = JSON.parse(retentionHeader);
  } catch { throw new Error("attestation malformed"); }
  if (retention !== "until-delete" || canonicalize(retention).length > MAX_RETENTION_BYTES || canonicalize(retention) !== retentionHeader) throw new Error("attestation retention");
  if (attestation.type !== "TinyCloudShareUploadAttestation" || attestation.version !== 1 || attestation.issuer !== bundle.public.nodeAudience || attestation.kid !== bundle.public.nodeInvitationKid || attestation.shareOrigin !== bundle.public.shareOrigin || attestation.retention === null || canonicalize(attestation.retention) !== retentionHeader || !PRINCIPAL.test(attestation.ownerDid) || !PRINCIPAL.test(attestation.sessionDid) || !strictBase64Url(attestation.signature, 64) || !strictBase64Url(attestation.encryptedBlobSha256, 32) || !strictBase64Url(attestation.jti, 16) || typeof attestation.encryptedBlobCid !== "string" || attestation.encryptedBlobCid.length > 200 || typeof attestation.byteLength !== "number" || !Number.isSafeInteger(attestation.byteLength) || attestation.byteLength < 0 || typeof attestation.deleteAfter !== "string" || typeof attestation.issuedAt !== "string" || typeof attestation.expiresAt !== "string") throw new Error("attestation fields");
  const issuedAt = canonicalTimestamp(attestation.issuedAt, "attestation issuedAt");
  const authorityExpiresAt = canonicalTimestamp(attestation.authorityExpiresAt, "attestation authorityExpiresAt");
  const expiresAt = canonicalTimestamp(attestation.expiresAt, "attestation expiresAt");
  const deleteAfter = canonicalTimestamp(attestation.deleteAfter, "attestation deleteAfter");
  if (issuedAt > now + UPLOAD_ATTESTATION_CLOCK_SKEW_MS || authorityExpiresAt <= now || expiresAt <= now || expiresAt > authorityExpiresAt || expiresAt > now + UPLOAD_ATTESTATION_TTL_MS || expiresAt <= issuedAt || expiresAt - issuedAt > UPLOAD_ATTESTATION_TTL_MS || deleteAfter <= now || deleteAfter > now + LINK_ONLY_RETENTION_LIMIT_MS || attestation.deleteAfter !== request.headers.get("x-delete-after")) throw new Error("attestation time");
  if (attestation.byteLength !== bytes.byteLength || attestation.byteLength > LINK_ONLY_BLOB_LIMIT) throw new Error("attestation length");
  const cid = CID.create(1, 0x55, await sha256.digest(bytes)).toString();
  if (attestation.encryptedBlobCid !== cid || attestation.encryptedBlobSha256 !== hashBytes(bytes)) throw new Error("attestation body binding");
  if (!ed25519.verify(fromBase64Url(attestation.signature), uploadAttestationBytes(attestation), fromBase64Url(bundle.public.nodeInvitationPublicKey))) throw new Error("attestation signature");
  return attestation;
}

function registryUploadAuthorization(
  privateKey: Uint8Array,
  body: Uint8Array,
  deleteAfter: string,
  sessionToken: string,
): string {
  const authorization = {
    action: "tinycloud.share/upload",
    audience: "https://registry.tinycloud.xyz",
    bodyDigest: hashBytes(body),
    contentLength: body.byteLength,
    deleteAfter,
    expiresAt: new Date(Date.now() + LINK_ONLY_AUTHORIZATION_TTL_MS).toISOString(),
    mode: "link-only",
    resource: "registry/blobs",
    sessionBinding: hash(sessionToken),
    type: "TinyCloudShareRegistryAuthorization",
    version: 1,
    jti: toBase64Url(randomBytes(16)),
  };
  const message = new TextEncoder().encode(
    `${REGISTRY_AUTHORIZATION_DOMAIN}${stable(authorization)}`,
  );
  return JSON.stringify({
    authorization,
    proof: {
      alg: "EdDSA",
      signature: toBase64Url(ed25519.sign(message, privateKey)),
    },
  });
}

function canonicalEmail(value: unknown): string {
  if (typeof value !== "string" || value.length < 3 || value.length > 254 || !/^[\x00-\x7f]*$/.test(value)) throw new Error("email");
  const at = value.indexOf("@");
  if (at <= 0 || at !== value.lastIndexOf("@")) throw new Error("email");
  const local = value.slice(0, at); const domain = value.slice(at + 1);
  const atext = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$/;
  if (Buffer.byteLength(local) > 64 || local.split(".").some((part) => !atext.test(part)) || Buffer.byteLength(domain) > 253 || domain.split(".").some((part) => part.length === 0 || part.length > 63 || part.startsWith("-") || part.endsWith("-") || !/^[A-Za-z0-9-]+$/.test(part))) throw new Error("email");
  return `${local}@${domain.toLowerCase()}`;
}

function exactExpiry(value: unknown, label: string): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) throw new Error(label);
  const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw new Error(label); return parsed;
}

function assertExpiry(scope: Record<string, unknown>, candidate: unknown): string {
  const value = typeof candidate === "string" ? candidate : (() => { throw new Error("expiry"); })();
  const time = exactExpiry(value, "expiry");
  for (const [key, comparison] of [["expiryMin", (actual: number, bound: number) => actual >= bound], ["expiryMax", (actual: number, bound: number) => actual <= bound], ["expiresAt", (actual: number, bound: number) => actual <= bound]] as const) {
    if (scope[key] !== undefined && !comparison(time, exactExpiry(scope[key], key))) throw new Error("expiry outside capability bounds");
  }
  return value;
}

const POLICY_KEYS = ["action", "authorityMaterialDigest", "contentSourceDigest", "delegationCid", "expiresAt", "policyAuthorityBytes", "policyAuthorityCid", "policyBytes", "policyDigest", "policyEnforcementBytes", "policyEnforcementCid", "policyCid", "recipientEmail", "resource", "source", "target"] as const;

function policyString(value: unknown, label: string, max = 128 * 1024): string {
  if (typeof value !== "string" || value.length === 0 || new TextEncoder().encode(value).length > max) throw new Error(label);
  return value;
}

function parsePolicy(value: unknown, scope: Record<string, unknown>, source: ContentSource): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("policy shape");
  const policy = value as Record<string, unknown>;
  if (Object.keys(policy).length !== POLICY_KEYS.length || POLICY_KEYS.some((key) => !Object.hasOwn(policy, key))) throw new Error("policy shape");
  const policySource = validateSource(policy.source as ContentSource);
  const target = policy.target;
  if (!sameJson(policySource, source) || policy.action !== source.action || policy.resource !== source.path || typeof target !== "object" || target === null || Array.isArray(target)) throw new Error("policy capability binding");
  const policyTarget = target as Record<string, unknown>;
  if (policyTarget.origin !== scope.targetOrigin || policyTarget.nodeAudience !== scope.nodeAudience || policyTarget.spaceId !== scope.spaceId) throw new Error("policy target binding");
  const recipientEmail = canonicalEmail(policy.recipientEmail);
  if (scope.recipientEmail !== undefined && recipientEmail !== canonicalEmail(scope.recipientEmail)) throw new Error("policy recipient binding");
  if (policy.delegationCid !== scope.delegationCid || policy.authorityMaterialDigest !== scope.authorityMaterialDigest) throw new Error("policy authority binding");
  assertExpiry(scope, policy.expiresAt);
  for (const key of ["action", "resource", "expiresAt", "policyCid", "policyDigest", "contentSourceDigest", "delegationCid", "authorityMaterialDigest", "policyAuthorityCid", "policyEnforcementCid"] as const) policyString(policy[key], `policy ${key}`);
  policyString(policy.policyBytes, "policy bytes");
  policyString(policy.policyAuthorityBytes, "policy authority bytes");
  policyString(policy.policyEnforcementBytes, "policy enforcement bytes");
  return { ...policy, source: policySource, recipientEmail };
}

/**
 * Parses one sender capability descriptor and binds it to the identity that is
 * allowed to sign with it.
 *
 * `identity` is the sender key of the *authenticated session* the descriptor is
 * being admitted for (or, in the explicit test-authority composition, the
 * trust-bundle sender key). `principal`, when supplied, is the verified session
 * principal: the descriptor's policy owner must be that exact principal, so a
 * session can never admit another wallet's authority.
 */
function parseCapabilityValue(value: Record<string, unknown>, bundle: ShareTrustBundle, identity: SenderIdentity, principal?: string): { scope: Record<string, unknown>; source: ContentSource; policy: Record<string, unknown> } {
  if (typeof value !== "object" || value === null || Array.isArray(value) || (Object.keys(value).length !== 3 && Object.keys(value).length !== 4) || !Object.hasOwn(value, "scope") || !Object.hasOwn(value, "source") || !Object.hasOwn(value, "policy") || typeof value.scope !== "object" || value.scope === null || typeof value.source !== "object" || value.source === null || (value.userId !== undefined && typeof value.userId !== "string")) throw new Error("capability shape");
  const scope = { ...(value.scope as Record<string, unknown>) };
  if (typeof value.userId === "string") scope.userId = value.userId;
  if (scope.senderDid !== identity.did || identity.publicKey.length === 0 || scope.targetOrigin !== bundle.public.nodeOrigin || scope.nodeAudience !== bundle.public.nodeAudience) throw new Error("capability trust binding");
  if (principal !== undefined && !capabilityOwnedByPrincipal({ scope }, principal)) throw new Error("capability holder binding");
  delete scope.senderPrivateKey;
  delete scope.privateKey;
  scope.shareOrigin = bundle.public.shareOrigin;
  scope.signingCapability = { capabilityId: toBase64Url(randomBytes(16)), publicKey: identity.publicKey };
  const trustedNode = scope.trustedNode as Record<string, unknown>;
  if (trustedNode === undefined || typeof trustedNode !== "object" || trustedNode.invitationPublicKey === undefined) throw new Error("capability enrollment");
  trustedNode.invitationPublicKey = typeof trustedNode.invitationPublicKey === "string" ? trustedNode.invitationPublicKey : toBase64Url(new Uint8Array(trustedNode.invitationPublicKey as number[]));
  if (trustedNode.invitationPublicKey !== bundle.public.nodeInvitationPublicKey || trustedNode.invitationKid !== bundle.public.nodeInvitationKid) throw new Error("capability enrollment does not match trust bundle");
  const source = validateSource(value.source as ContentSource);
  if (scope.recipientEmail !== undefined) scope.recipientEmail = canonicalEmail(scope.recipientEmail);
  for (const key of ["expiryMin", "expiryMax", "expiresAt", "expiryDefault"]) if (scope[key] !== undefined) exactExpiry(scope[key], key);
  const policy = parsePolicy(value.policy, scope, source);
  return { scope, source, policy };
}

function parseCapability(raw: string, bundle: ShareTrustBundle, identity: SenderIdentity): { scope: Record<string, unknown>; source: ContentSource; policy: Record<string, unknown> } {
  return parseCapabilityValue(JSON.parse(raw) as Record<string, unknown>, bundle, identity);
}

function browserSafeScope(value: Record<string, unknown>): Record<string, unknown> {
  const copy = structuredClone(value);
  const scrub = (item: unknown): void => {
    if (typeof item !== "object" || item === null) return;
    for (const [key, child] of Object.entries(item as Record<string, unknown>)) {
      if (/privatekey/i.test(key)) delete (item as Record<string, unknown>)[key];
      else scrub(child);
    }
  };
  scrub(copy);
  return copy as Record<string, unknown>;
}

interface AuthUser { readonly userId: string; readonly username: string; readonly passwordHash: string; }
/** A capability plus the identity authorized to sign with it; never serialized. */
interface CapabilityRecord { readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: Record<string, unknown>; readonly identity: SenderIdentity }
interface ShareSession { readonly userId: string; readonly expiresAt: number; readonly capabilities: Map<string, CapabilityRecord> }
/** Bounds the per-session authority a single wallet may enroll. */
const SESSION_CAPABILITY_LIMIT = 32;
/**
 * The signing idempotency cache is reachable in production now that the sender
 * path can boot, so it is bounded in both size and time: an entry only has to
 * outlive one client retry.
 */
const SIGNER_CACHE_LIMIT = 4096;
const SIGNER_CACHE_TTL_MS = 10 * 60 * 1000;
/**
 * Bounds concurrent sessions *per principal*, which is the only bound that is
 * safe here: a global cap would let a stranger's disposable-wallet churn evict
 * a live user's session, trading a memory bound for a forced logout. Total
 * session state remains bounded the same way it was before TC-348 — by who can
 * complete a SIWE ceremony — and expired entries are now actively swept.
 */
const SESSIONS_PER_PRINCIPAL = 8;

/**
 * Ownership is the *complete* normalized DID, chain id included: a session on
 * one EIP-155 chain must not select a capability owned on another.
 */
function normalizedOwnerDid(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const match = /^did:pkh:eip155:([1-9][0-9]*):(0x[0-9a-fA-F]{40})$/.exec(value);
  return match === null ? undefined : `did:pkh:eip155:${match[1]}:${match[2]!.toLowerCase()}`;
}

function capabilityOwnedByPrincipal(candidate: { readonly scope: Record<string, unknown> }, principal: string): boolean {
  const ownerDid = normalizedOwnerDid(principal);
  if (ownerDid !== undefined) {
    return normalizedOwnerDid(candidate.scope.policyOwnerDid) === ownerDid;
  }
  return typeof candidate.scope.userId === "string" && candidate.scope.userId === principal;
}

function samePrincipal(left: string, right: string): boolean {
  const normalizedLeft = normalizedOwnerDid(left);
  const normalizedRight = normalizedOwnerDid(right);
  return normalizedLeft !== undefined || normalizedRight !== undefined ? normalizedLeft === normalizedRight : left === right;
}

function openKeyMessage(origin: string, address: string, nonce: string, issuedAt: string): string {
  return [
    `${new URL(origin).host} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to TinyCloud Share.",
    "",
    `URI: ${origin}`,
    "Version: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join("\n");
}

function sessionCookie(request: Request): string | undefined { return cookie(request, "share_session"); }

/**
 * SHARE_HERMETIC_BROWSER_ORIGIN authorizes exactly one dedicated local
 * browser origin (never a wildcard loopback pattern); every other shape,
 * including IPv6, aliases, credentials, path/query/fragment, and
 * missing/zero/out-of-range ports, fails startup.
 */
function parseHermeticBrowserOrigin(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const invalid = (): never => { throw new Error("SHARE_HERMETIC_BROWSER_ORIGIN must be an exact http://127.0.0.1:<port> origin with no credentials, path, query, or fragment"); };
  const match = HERMETIC_BROWSER_ORIGIN_PATTERN.exec(value);
  if (match === null) return invalid();
  const portText = match[1]!;
  if (!/^[1-9][0-9]*$/.test(portText)) return invalid();
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return invalid();
  let parsed: URL;
  try { parsed = new URL(value); } catch { return invalid(); }
  if (parsed.origin !== value || parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") return invalid();
  return value;
}

/**
 * SHARE_HERMETIC_REGISTRY_ORIGIN authorizes exactly one dedicated local
 * registry transport origin (never a wildcard loopback pattern); every other
 * shape, including IPv6, aliases, credentials, path/query/fragment, and
 * missing/zero/leading-zero/out-of-range ports, fails startup. It overrides
 * only registryTransportOrigin: the public registryOrigin, trust bundle, and
 * every other upstream stay canonical.
 */
function parseHermeticRegistryOrigin(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const invalid = (): never => { throw new Error("SHARE_HERMETIC_REGISTRY_ORIGIN must be an exact http://127.0.0.1:<port> origin with no credentials, path, query, or fragment"); };
  const match = HERMETIC_BROWSER_ORIGIN_PATTERN.exec(value);
  if (match === null) return invalid();
  const portText = match[1]!;
  if (!/^[1-9][0-9]*$/.test(portText)) return invalid();
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return invalid();
  let parsed: URL;
  try { parsed = new URL(value); } catch { return invalid(); }
  if (parsed.origin !== value || parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") return invalid();
  return value;
}

function shareOriginAllowed(origin: string | null, options: ShareHostOptions): boolean {
  return origin === null || origin === options.bundle.public.shareOrigin || ((options.testMode || options.hermeticComposition === true) && LOOPBACK_ORIGIN.test(origin)) || (options.hermeticBrowserOrigin !== undefined && origin === options.hermeticBrowserOrigin);
}

function sessionValid(request: Request, options: ShareHostOptions, sessions: Map<string, ShareSession>): ShareSession | undefined {
  const origin = request.headers.get("origin");
  if (!shareOriginAllowed(origin, options)) return undefined;
  const value = sessionCookie(request);
  if (value === undefined) return options.testMode ? { userId: "fixture", expiresAt: Date.now() + 300_000, capabilities: new Map() } : undefined;
  const session = sessions.get(value);
  if (session === undefined || session.expiresAt <= Date.now()) { if (session !== undefined) sessions.delete(value); return undefined; }
  return session;
}

function cookie(request: Request, name: string): string | undefined {
  return request.headers.get("cookie")?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

function bodyBinding(value: Record<string, unknown>): Record<string, unknown> {
  if (typeof value.binding !== "object" || value.binding === null || Array.isArray(value.binding)) throw new Error("binding");
  return value.binding as Record<string, unknown>;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && timingSafeEqual(Buffer.from(left), Buffer.from(right)); }

function parsePasswordHash(value: string): { readonly cost: number; readonly blockSize: number; readonly parallelism: number; readonly salt: Uint8Array; readonly digest: Uint8Array } {
  const parts = value.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") throw new Error("authentication configuration is invalid");
  const [, cost = "", blockSize = "", parallelism = "", salt = "", digest = ""] = parts;
  if (!/^\d+$/.test(cost) || !/^\d+$/.test(blockSize) || !/^\d+$/.test(parallelism) || !/^[A-Za-z0-9_-]{16,128}$/.test(salt) || !/^[A-Za-z0-9_-]{43}$/.test(digest)) throw new Error("authentication configuration is invalid");
  return { cost: Number(cost), blockSize: Number(blockSize), parallelism: Number(parallelism), salt: fromBase64Url(salt), digest: fromBase64Url(digest) };
}

async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const hash = parsePasswordHash(encoded);
  const derived = new Uint8Array(await scryptAsync(password, hash.salt, hash.digest.length, { N: hash.cost, r: hash.blockSize, p: hash.parallelism, maxmem: 64 * 1024 * 1024 }) as Buffer);
  return constantTimeEqual(derived, hash.digest);
}

function sameJson(left: unknown, right: unknown): boolean { return stable(left) === stable(right); }

function sourceDigest(source: ContentSource): string { return createHash("sha256").update(stable(source), "utf8").digest("base64url"); }

function requiredScopeString(scope: Record<string, unknown>, key: string): string {
  const value = scope[key]; if (typeof value !== "string" || value.length === 0) throw new Error(`capability ${key} is missing`); return value;
}

function v2ResourceCovered(resource: Record<string, unknown>, source: ContentSource, scope: Record<string, unknown>): boolean {
  if ((resource.kind !== "exact" && resource.kind !== "prefix") || typeof resource.path !== "string") return false;
  const path = resource.path;
  if (path.length === 0 || /[\\\u0000-\u001f\u007f]/.test(path) || /%2f|%5c|%2e/i.test(path)) return false;
  const body = resource.kind === "prefix" && path.endsWith("/") ? path.slice(0, -1) : path;
  if (body.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")) return false;
  if (source.path === path || source.path === body) return true;
  const prefixes = Array.isArray(scope.prefixes) ? scope.prefixes.filter((value): value is string => typeof value === "string") : [];
  return prefixes.some((prefix) => {
    const normalized = prefix.endsWith("/") ? prefix : `${prefix}/`;
    return path === prefix || path.startsWith(normalized) || body === prefix || body.startsWith(normalized);
  });
}

function assertAddressedDelegationAuthoringSigningBinding(message: Record<string, unknown>, binding: Record<string, unknown>, scope: Record<string, unknown>, source: ContentSource): void {
  const keys = ["version", "nonce", "jti", "senderDid", "recipientMatcher", "targetOrigin", "nodeAudience", "shareCid", "shareId", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "actions", "resource", "expiresAt", "requestBodyDigest"];
  if (Object.keys(message).some((key) => !keys.includes(key)) || keys.some((key) => !Object.hasOwn(message, key)) || !sameJson(binding, message)) throw new Error("delegation authoring signing shape");
  if (message.version !== 2 || typeof message.nonce !== "string" || typeof message.jti !== "string" || !B64_256.test(message.nonce) || !B64_128.test(message.jti) || message.senderDid !== scope.senderDid || message.targetOrigin !== scope.targetOrigin || message.nodeAudience !== scope.nodeAudience || message.delegationCid !== scope.delegationCid || message.authorityMaterialHandle !== scope.authorityMaterialHandle || message.authorityMaterialDigest !== scope.authorityMaterialDigest || !sameJson(message.contentSource, source) || message.contentSourceDigest !== sourceDigest(source)) throw new Error("delegation authoring binding");
  const matcher = message.recipientMatcher;
  if (typeof matcher !== "object" || matcher === null || Array.isArray(matcher) || !["exactEmail", "emailDomain", "recipientDid"].includes((matcher as Record<string, unknown>).kind as string) || typeof (matcher as Record<string, unknown>).value !== "string") throw new Error("delegation authoring matcher");
  if ((matcher as Record<string, unknown>).kind === "recipientDid" && !isCanonicalRecipientDid((matcher as Record<string, unknown>).value as string)) throw new Error("delegation authoring matcher");
  const resource = message.resource;
  if (typeof resource !== "object" || resource === null || Array.isArray(resource)) throw new Error("delegation authoring resource");
  const resourceObject = resource as Record<string, unknown>;
  if ((resourceObject.kind !== "exact" && resourceObject.kind !== "prefix") || typeof resourceObject.value !== "string" || !v2ResourceCovered({ kind: resourceObject.kind, path: resourceObject.value }, source, scope)) throw new Error("delegation authoring resource");
  const actions = message.actions;
  if (!Array.isArray(actions) || actions.length === 0 || actions.length > 3 || actions.some((action) => typeof action !== "string")) throw new Error("delegation authoring actions");
  const allowedActions = Array.isArray(scope.actions) ? scope.actions.filter((value): value is string => typeof value === "string") : [];
  if (actions.some((action) => !allowedActions.includes(action) && !allowedActions.includes(action.replace("tinycloud.kv/", "")))) throw new Error("delegation authoring actions");
  assertExpiry(scope, message.expiresAt);
  const requestBody = { ...message };
  delete requestBody.requestBodyDigest;
  if (message.requestBodyDigest !== hash(stable(requestBody))) throw new Error("delegation authoring digest");
}

async function parseV2Policy(policyCid: string, policyBytes: string): Promise<Record<string, unknown>> {
  const bytes = fromBase64Url(policyBytes);
  if (toBase64Url(bytes) !== policyBytes) throw new Error("v2 policy encoding");
  if (CID.create(1, 0x55, await sha256.digest(bytes)).toString() !== policyCid) throw new Error("v2 policy CID mismatch");
  let value: unknown;
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); value = JSON.parse(text); } catch { throw new Error("v2 policy bytes"); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("v2 policy shape");
  const parsed = value as Record<string, unknown>;
  const keys = ["type", "version", "issuerDid", "recipientMatcher", "contentSource", "contentSourceDigest", "resource", "actions", "expiresAt"];
  const matcher = parsed.recipientMatcher as Record<string, unknown>;
  const resource = parsed.resource as Record<string, unknown>;
  const source = parsed.contentSource as Record<string, unknown>;
  if (Object.keys(parsed).some((key) => !keys.includes(key)) || keys.some((key) => !Object.hasOwn(parsed, key)) || stable(parsed) !== text || parsed.type !== "TinyCloudSharePolicy" || parsed.version !== 2 || typeof parsed.issuerDid !== "string" || typeof parsed.expiresAt !== "string" || typeof parsed.contentSource !== "object" || parsed.contentSource === null || Array.isArray(parsed.contentSource) || typeof parsed.resource !== "object" || parsed.resource === null || Array.isArray(parsed.resource) || !Array.isArray(parsed.actions) || parsed.actions.length === 0 || parsed.actions.length > 4 || parsed.actions.some((action) => action !== "tinycloud.kv/get" && action !== "tinycloud.kv/metadata" && action !== "tinycloud.kv/list" && action !== "tinycloud.kv/put") || typeof parsed.recipientMatcher !== "object" || parsed.recipientMatcher === null || Array.isArray(parsed.recipientMatcher) || typeof parsed.contentSourceDigest !== "string" || Object.keys(matcher).some((key) => key !== "kind" && key !== "value") || (matcher.kind !== "exactEmail" && matcher.kind !== "emailDomain" && matcher.kind !== "recipientDid") || typeof matcher.value !== "string" || (matcher.kind === "recipientDid" ? !isCanonicalRecipientDid(matcher.value) : false) || Object.keys(resource).some((key) => key !== "kind" && key !== "value") || (resource.kind !== "exact" && resource.kind !== "prefix") || typeof resource.value !== "string" || Object.keys(source).some((key) => key !== "kind" && key !== "space" && key !== "path" && key !== "action") || source.kind !== "kv" || typeof source.space !== "string" || typeof source.path !== "string" || (source.action !== "tinycloud.kv/get" && source.action !== "tinycloud.kv/list" && source.action !== "tinycloud.kv/put")) throw new Error("v2 policy shape");
  return parsed;
}

async function assertV2SigningBinding(message: Record<string, unknown>, binding: Record<string, unknown>, scope: Record<string, unknown>, source: ContentSource, policy: Record<string, unknown>): Promise<void> {
  const messageKeys = ["version", "shareId", "recipientMatcher", "deliveryEmail", "actions", "resource", "target", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "contentSource", "contentSourceDigest", "authorizationTarget", "display", "expiry", "encrypted", "metadata"];
  const bindingKeys = ["version", "shareId", "recipientMatcher", "deliveryEmail", "actions", "resource", "source", "contentSource", "contentSourceDigest", "policyCid", "policyDigest", "expiresAt", "targetOrigin", "nodeAudience", "spaceId", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest"];
  if (Object.keys(message).some((key) => !messageKeys.includes(key)) || Object.keys(binding).some((key) => !bindingKeys.includes(key))) throw new Error("v2 signing contains unsupported fields");
  if (message.version !== 2 || binding.version !== 2 || message.shareId !== binding.shareId || typeof message.shareId !== "string") throw new Error("v2 envelope binding");
  const recipient = message.recipientMatcher;
  if (typeof recipient !== "object" || recipient === null || Array.isArray(recipient)) throw new Error("v2 recipient matcher");
  const matcher = recipient as Record<string, unknown>;
  if ((matcher.kind !== "exactEmail" && matcher.kind !== "emailDomain" && matcher.kind !== "recipientDid" && matcher.kind !== "policyDigest" && matcher.kind !== "bearer") || (matcher.kind !== "bearer" && typeof matcher.value !== "string")) throw new Error("v2 recipient matcher");
  const matcherValue = matcher.value as string | undefined;
  if (matcher.kind === "exactEmail") canonicalEmail(matcherValue!);
  if (matcher.kind === "emailDomain" && !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/.test(matcherValue!)) throw new Error("v2 recipient domain");
  if (matcher.kind === "policyDigest" && !B64_256.test(matcherValue!)) throw new Error("v2 policy matcher");
  if (matcher.kind === "recipientDid" && !isCanonicalRecipientDid(matcherValue!)) throw new Error("v2 recipient DID");
  if (stable(matcher) !== stable(binding.recipientMatcher)) throw new Error("v2 recipient binding");
  const actions = message.actions;
  if (!Array.isArray(actions) || actions.length === 0 || actions.length > 3 || stable(actions) !== stable(["read", "list", "edit"].filter((action) => actions.includes(action)))) throw new Error("v2 actions");
  if (stable(actions) !== stable(binding.actions)) throw new Error("v2 action binding");
  const target = message.target;
  const targetObject = typeof target === "object" && target !== null && !Array.isArray(target) ? target as Record<string, unknown> : undefined;
  const resource = message.resource;
  if (targetObject === undefined || targetObject.origin !== scope.targetOrigin || targetObject.nodeAudience !== scope.nodeAudience || targetObject.spaceId !== scope.spaceId || typeof resource !== "object" || resource === null || Array.isArray(resource) || !v2ResourceCovered(resource as Record<string, unknown>, source, scope)) throw new Error("v2 target binding");
  if (stable(resource) !== stable(binding.resource) || stable(message.contentSource) !== stable(binding.contentSource) || stable(binding.contentSource) !== stable(source)) throw new Error("v2 resource binding");
  if (message.authorizationTarget === undefined || typeof message.authorizationTarget !== "object") throw new Error("v2 policy target");
  const targetPolicy = message.authorizationTarget as Record<string, unknown>;
  if (targetPolicy.kind !== "policy" || typeof targetPolicy.policyCid !== "string" || typeof targetPolicy.policyBytes !== "string") throw new Error("v2 policy target");
  const authoredPolicy = await parseV2Policy(targetPolicy.policyCid, targetPolicy.policyBytes);
  const matcherBound = matcher.kind === "policyDigest"
    ? matcher.value === hashBytes(fromBase64Url(targetPolicy.policyBytes)) && typeof authoredPolicy.recipientMatcher === "object"
    : sameJson(authoredPolicy.recipientMatcher, matcher);
  const policyResource = authoredPolicy.resource as Record<string, unknown>;
  const envelopeResource = resource as Record<string, unknown>;
  const expectedPolicyResource = { kind: envelopeResource.kind, value: typeof envelopeResource.path === "string" ? envelopeResource.path.replace(/\/$/, "") : "" };
  const expectedPolicyActions = [...new Set(actions.flatMap((action) => action === "read" ? ["tinycloud.kv/get", "tinycloud.kv/metadata"] : action === "list" ? ["tinycloud.kv/list"] : ["tinycloud.kv/put"]))].sort();
  if (authoredPolicy.issuerDid !== scope.senderDid || !sameJson(authoredPolicy.contentSource, source) || !sameJson(policyResource, expectedPolicyResource) || !sameJson(authoredPolicy.actions, expectedPolicyActions) || authoredPolicy.expiresAt !== message.expiry || authoredPolicy.contentSourceDigest !== sourceDigest(source) || !matcherBound) throw new Error("v2 policy signing binding mismatch");
  const allowedActions = Array.isArray(scope.actions) ? scope.actions.filter((value): value is string => typeof value === "string") : ["tinycloud.kv/get"];
  if (actions.includes("list") && !allowedActions.includes("tinycloud.kv/list") && !allowedActions.includes("list")) throw new Error("v2 list action exceeds capability");
  if (actions.includes("edit") && !allowedActions.includes("tinycloud.kv/put") && !allowedActions.includes("edit")) throw new Error("v2 edit action exceeds capability");
  void policy;
  if (message.delegationCid !== scope.delegationCid || message.authorityMaterialDigest !== scope.authorityMaterialDigest || binding.delegationCid !== scope.delegationCid || binding.authorityMaterialDigest !== scope.authorityMaterialDigest || binding.targetOrigin !== scope.targetOrigin || binding.nodeAudience !== scope.nodeAudience || binding.spaceId !== scope.spaceId) throw new Error("v2 authority binding");
  const expiry = assertExpiry(scope, message.expiry);
  if (binding.expiresAt !== expiry) throw new Error("v2 expiry binding");
  if (message.encrypted !== true && matcher.kind !== "policyDigest") throw new Error("unsafe plaintext v2 policy");
  const deliveryEmail = binding.deliveryEmail;
  if (message.encrypted !== true && (message.content !== undefined || message.deliveryEmail !== undefined || deliveryEmail !== undefined || (typeof message.display === "object" && message.display !== null && Object.keys(message.display).length !== 0) || (typeof message.metadata === "object" && message.metadata !== null && Object.keys(message.metadata).length !== 0))) throw new Error("unsafe plaintext v2 content");
  if (deliveryEmail !== undefined) {
    const email = canonicalEmail(deliveryEmail);
    if (matcher.kind === "exactEmail" && email !== matcher.value || matcher.kind === "emailDomain" && email.slice(email.lastIndexOf("@") + 1) !== matcher.value) throw new Error("v2 delivery binding");
    if (matcher.kind === "recipientDid") throw new Error("v2 delivery binding");
  }
}

async function assertV2InvitationAuthorizationSigningBinding(message: Record<string, unknown>, binding: Record<string, unknown>, scope: Record<string, unknown>, source: ContentSource, policy: Record<string, unknown>): Promise<void> {
  const keys = ["version", "jti", "reportAbuseToken", "senderDid", "shareCid", "shareId", "policyCid", "delegationCid", "authorityMaterialHandle", "authorityMaterialDigest", "recipientMatcher", "deliveryEmail", "shareUrl", "targetOrigin", "nodeAudience", "documentName", "senderTrust", "contentSource", "contentSourceDigest", "actions", "resource", "shareExpiresAt", "requestBodyDigest", "idempotencyKey"];
  if (Object.keys(message).some((key) => !keys.includes(key)) || keys.some((key) => !Object.hasOwn(message, key)) || !sameJson(binding, message)) throw new Error("v2 invitation signing shape");
  const requestedActions = message.actions as unknown[];
  if (message.version !== 2 || typeof message.jti !== "string" || typeof message.reportAbuseToken !== "string" || !B64_128.test(message.jti) || !B64_128.test(message.reportAbuseToken) || message.senderDid !== scope.senderDid || message.targetOrigin !== scope.targetOrigin || message.nodeAudience !== scope.nodeAudience || message.documentName !== scope.documentName || message.senderTrust !== scope.senderTrust || message.delegationCid !== scope.delegationCid || message.authorityMaterialHandle !== scope.authorityMaterialHandle || message.authorityMaterialDigest !== scope.authorityMaterialDigest || typeof message.policyCid !== "string" || typeof message.shareUrl !== "string" || new URL(message.shareUrl).origin !== scope.shareOrigin || !sameJson(message.contentSource, source) || message.contentSourceDigest !== sourceDigest(source) || typeof message.resource !== "string" || !v2ResourceCovered({ kind: "exact", path: message.resource }, source, scope) || !Array.isArray(requestedActions) || stable(requestedActions) !== stable(["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/put"].filter((action) => requestedActions.includes(action)))) throw new Error("v2 invitation binding");
  assertExpiry(scope, message.shareExpiresAt);
  void policy;
  const requestBody = { ...message };
  delete requestBody.requestBodyDigest;
  if (message.requestBodyDigest !== hash(stable(requestBody)) || typeof message.idempotencyKey !== "string" || message.idempotencyKey !== hash(stable({ shareUrl: message.shareUrl, recipientEmail: message.deliveryEmail }))) throw new Error("v2 invitation request digest");
}

async function assertSigningBinding(purpose: string, message: string, binding: Record<string, unknown>, scope: Record<string, unknown>, authorizedSource: ContentSource, authorizedPolicy: Record<string, unknown>): Promise<void> {
  const parsed = JSON.parse(message) as Record<string, unknown>;
  if (purpose === "inviteAuthorization" && parsed.version === 2) {
    await assertV2InvitationAuthorizationSigningBinding(parsed, binding, scope, authorizedSource, authorizedPolicy);
    return;
  }
  if (purpose === "envelope" && parsed.version === 2) {
    await assertV2SigningBinding(parsed, binding, scope, authorizedSource, authorizedPolicy);
    return;
  }
  const messageSource = parsed.contentSource as Record<string, unknown> | undefined;
  const authorizationTarget = parsed.authorizationTarget as Record<string, unknown> | undefined;
  const policy = purpose === "envelope" && typeof authorizationTarget?.policyBytes === "string"
    ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(authorizationTarget.policyBytes))) as Record<string, unknown>
    : undefined;
  const messageRecipient = canonicalEmail(parsed.recipientEmail ?? binding.recipientEmail);
  if (parsed.recipientEmail !== undefined && binding.recipientEmail !== undefined && canonicalEmail(binding.recipientEmail) !== messageRecipient) throw new Error("recipient binding mismatch");
  const recipientEmail = scope.recipientEmail === undefined ? messageRecipient : canonicalEmail(scope.recipientEmail);
  if (recipientEmail !== messageRecipient) throw new Error("recipient is outside authenticated capability");
  const expectedSourceDigest = sourceDigest(authorizedSource);
  const selectedExpiry = purpose === "envelope" ? parsed.expiry : parsed.shareExpiresAt;
  const expiresAt = assertExpiry(scope, selectedExpiry);
  const expected = { shareId: parsed.shareId, recipientEmail, ...(purpose === "envelope" ? { action: authorizedSource.action, resource: authorizedSource.path } : {}), expiresAt };
  if (Object.entries(expected).some(([key, value]) => !sameJson(binding[key], value))) throw new Error("signing binding mismatch");
  if (purpose === "envelope") {
    const target = parsed.target as Record<string, unknown>;
    if (parsed.delegation !== scope.delegation || target?.origin !== scope.targetOrigin || target.nodeAudience !== scope.nodeAudience || target.spaceId !== scope.spaceId || (target.resource as Record<string, unknown>)?.path !== authorizedSource.path || (target.resource as Record<string, unknown>)?.kind !== "exact") throw new Error("envelope signing binding mismatch");
    if (authorizationTarget?.kind !== "policy" || typeof authorizationTarget.policyBytes !== "string") throw new Error("envelope signing target mismatch");
    if (policy === undefined || authorizationTarget.policyCid !== authorizedPolicy.policyCid || authorizationTarget.policyBytes !== authorizedPolicy.policyBytes || policy.recipientEmail !== recipientEmail || policy.action !== authorizedSource.action || policy.resource !== authorizedSource.path || policy.expiresAt !== parsed.expiry || !sameJson(policy.contentSource, authorizedSource) || policy.contentSourceDigest !== expectedSourceDigest || policy.issuerDid !== scope.senderDid) throw new Error("policy signing binding mismatch");
    const expectedBinding = {
      ...expected,
      policyCid: authorizedPolicy.policyCid, policyDigest: authorizedPolicy.policyDigest,
      policyAuthorityCid: authorizedPolicy.policyAuthorityCid, policyAuthorityBytes: authorizedPolicy.policyAuthorityBytes,
      policyEnforcementCid: authorizedPolicy.policyEnforcementCid, policyEnforcementBytes: authorizedPolicy.policyEnforcementBytes,
      delegation: scope.delegation, targetOrigin: scope.targetOrigin, nodeAudience: scope.nodeAudience, returnOrigin: scope.shareOrigin,
    };
    if (!sameJson(binding, expectedBinding)) throw new Error("envelope signing binding mismatch");
  } else {
    const authorizationBody = { shareCid: parsed.shareCid, shareId: parsed.shareId, policyCid: parsed.policyCid, delegationCid: parsed.delegationCid, authorityMaterialHandle: parsed.authorityMaterialHandle, authorityMaterialDigest: parsed.authorityMaterialDigest, recipientEmail: parsed.recipientEmail, targetOrigin: parsed.targetOrigin, nodeAudience: parsed.nodeAudience, action: authorizedSource.action, resource: authorizedSource.path };
    const requestDigest = hash(stable(authorizationBody));
    if (parsed.jti === undefined || typeof parsed.jti !== "string" || !B64_128.test(parsed.jti) || parsed.reportAbuseToken === undefined || typeof parsed.reportAbuseToken !== "string" || !B64_128.test(parsed.reportAbuseToken) || parsed.shareCid === undefined || parsed.shareId === undefined || parsed.requestBodyDigest !== requestDigest) throw new Error("authorization request binding mismatch");
    const mismatches = Object.entries({ senderDid: [parsed.senderDid, scope.senderDid], targetOrigin: [parsed.targetOrigin, scope.targetOrigin], nodeAudience: [parsed.nodeAudience, scope.nodeAudience], delegationCid: [parsed.delegationCid, scope.delegationCid], authorityMaterialHandle: [parsed.authorityMaterialHandle, scope.authorityMaterialHandle], authorityMaterialDigest: [parsed.authorityMaterialDigest, scope.authorityMaterialDigest], documentName: [parsed.documentName, scope.documentName], senderTrust: [parsed.senderTrust, scope.senderTrust], recipientEmail: [parsed.recipientEmail, recipientEmail], policyCid: [parsed.policyCid, authorizedPolicy.policyCid], shareExpiresAt: [parsed.shareExpiresAt, authorizedPolicy.expiresAt], action: [messageSource?.action, authorizedSource.action], resource: [messageSource?.path, authorizedSource.path], contentSourceDigest: [parsed.contentSourceDigest, expectedSourceDigest], shareId: [parsed.shareId, binding.shareId] }).filter(([, values]) => values[0] !== values[1] || (values[0] !== undefined && typeof values[0] === "object" && !sameJson(values[0], values[1])));
    if (mismatches.length !== 0 || !sameJson(messageSource, authorizedSource) || parsed.recipientEmail !== recipientEmail || parsed.shareExpiresAt !== expiresAt) throw new Error("authorization signing binding mismatch");
    const expectedBinding = {
      ...parsed,
      expiresAt: parsed.shareExpiresAt,
      policyDigest: authorizedPolicy.policyDigest, policyAuthorityCid: authorizedPolicy.policyAuthorityCid, policyAuthorityBytes: authorizedPolicy.policyAuthorityBytes,
      policyEnforcementCid: authorizedPolicy.policyEnforcementCid, policyEnforcementBytes: authorizedPolicy.policyEnforcementBytes,
    };
    if (!sameJson(binding, expectedBinding)) throw new Error("authorization signing binding mismatch");
  }
}

async function assertPublishedBinding(binding: Record<string, unknown>, cid: string, scope: Record<string, unknown>, source: ContentSource, policy: Record<string, unknown>): Promise<void> {
  if (binding.version === 2) {
    if (binding.shareCid !== cid || typeof binding.policyCid !== "string" || !/^bafkrei[a-z2-7]{52}$/.test(binding.policyCid) || binding.contentSource === undefined || !sameJson(binding.contentSource, source) || binding.resource === undefined || !v2ResourceCovered(binding.resource as Record<string, unknown>, source, scope) || typeof binding.target !== "object" || binding.target === null || (binding.target as Record<string, unknown>).origin !== scope.targetOrigin || (binding.target as Record<string, unknown>).nodeAudience !== scope.nodeAudience || (binding.target as Record<string, unknown>).spaceId !== scope.spaceId || binding.delegationCid !== scope.delegationCid || binding.authorityMaterialDigest !== scope.authorityMaterialDigest) throw new Error("published v2 binding is outside the selected policy");
    const actions = binding.actions;
    if (!Array.isArray(actions) || actions.length === 0 || stable(actions) !== stable(["read", "list", "edit"].filter((action) => actions.includes(action)))) throw new Error("published v2 actions");
    return;
  }
  const expected: Record<string, unknown> = {
    policyCid: policy.policyCid,
    policyDigest: policy.policyDigest,
    policyBytes: policy.policyBytes,
    recipientEmail: policy.recipientEmail,
    expiry: policy.expiresAt,
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
    policyAuthorityCid: policy.policyAuthorityCid,
    policyAuthorityBytes: policy.policyAuthorityBytes,
    policyEnforcementCid: policy.policyEnforcementCid,
    policyEnforcementBytes: policy.policyEnforcementBytes,
    contentSource: source,
    contentSourceDigest: sourceDigest(source),
    action: source.action,
    resource: source.path,
    target: { origin: scope.targetOrigin, nodeAudience: scope.nodeAudience, spaceId: scope.spaceId },
    returnOrigin: scope.shareOrigin,
  };
  if (binding.shareCid !== cid || Object.entries(expected).some(([key, value]) => !sameJson(binding[key], value))) throw new Error("published binding is outside the selected exact policy");
}

export function createShareHostAdapter(options: ShareHostOptions): { handler(request: Request): Promise<Response>; publicConfig: Record<string, unknown>; readiness: Record<string, boolean> } {
  const signers = new Map<string, { signature: string; expiresAt: number }>();
  const sessions = new Map<string, ShareSession>();
  const openKeyNonces = new Map<string, number>();
  const uploadBudgetStore = options.uploadBudgetStore ?? (options.testMode ? new MemoryUploadBudgetStore() : undefined);
  const capability = options.capability;
  /**
   * Drops state whose lifetime has ended. Called before issuing a session, so
   * the cost of retaining state is paid by whoever creates it.
   */
  const sweep = (): void => {
    const now = Date.now();
    for (const [token, session] of sessions) if (session.expiresAt <= now) sessions.delete(token);
    for (const [key, entry] of signers) if (entry.expiresAt <= now) signers.delete(key);
    for (const [value, expiresAt] of openKeyNonces) if (expiresAt <= now) openKeyNonces.delete(value);
  };
  const consumeUploadAttestationJti = async (jti: string, expiresAt: number, now: number): Promise<boolean> => {
    const store = uploadBudgetStore ?? (options.testMode ? options.bindingStore : undefined);
    if (store?.writable !== true || store.consumeUploadAttestation === undefined) throw new Error("upload_attestation_store_unavailable");
    return store.consumeUploadAttestation(jti, expiresAt, now, MAX_UPLOAD_ATTESTATION_REPLAY);
  };
  const reserveUpload = async (principal: string, now: number): Promise<boolean> => {
    if (uploadBudgetStore?.writable !== true) throw new Error("upload_budget_unavailable");
    return uploadBudgetStore.reserveUpload(principal, now, LINK_ONLY_UPLOAD_WINDOW_MS, LINK_ONLY_UPLOAD_LIMIT);
  };
  const issueSession = (token: string, session: ShareSession): void => {
    sweep();
    // Map iteration is insertion order, so these drop the oldest first.
    const owned = [...sessions].filter(([, candidate]) => candidate.userId === session.userId).map(([value]) => value);
    while (owned.length >= SESSIONS_PER_PRINCIPAL) sessions.delete(owned.shift()!);
    sessions.set(token, session);
  };
  /**
   * Readiness is a property of the sender *path*, not of one pre-issued key.
   * `senderReady` answers "is this host configured to serve a sender operation
   * for an authenticated session": the flag is on, the trusted node is
   * enabled, a per-principal signing identity can be resolved, and bindings
   * are durably writable. Whether a given session has enrolled authority is a
   * per-request fact and is reported per request, not here — a session-scoped
   * capability could never flip a construction-time constant.
   */
  const senderReady = options.senderEnabled && options.bundle.public.nodeEnabled && options.senderIdentitySource !== undefined && options.bindingStore?.writable === true;
  const authReady = true;
  const publicConfig = { version: "tinycloud.share-email-claim/config-v1", shareOrigin: options.bundle.public.shareOrigin, registryOrigin: options.bundle.public.registryOrigin, nodeOrigin: options.bundle.public.nodeOrigin, credentialsOrigin: options.bundle.public.credentialsOrigin, emailOrigin: options.bundle.public.emailOrigin, nodeAudience: options.bundle.public.nodeAudience, enforcerDid: process.env.SHARE_NODE_ENFORCER_DID ?? options.bundle.public.nodeAudience, nodeEnabled: options.bundle.public.nodeEnabled, issuerDid: options.bundle.public.issuerDid, issuerVct: options.bundle.public.issuerVct, issuerEnabled: options.bundle.public.issuerEnabled, nodeInvitationKid: options.bundle.public.nodeInvitationKid, nodeInvitationPublicKey: options.bundle.public.nodeInvitationPublicKey, nodeKeyVersion: options.bundle.public.nodeKeyVersion, issuerKeyVersion: options.bundle.public.issuerKeyVersion, issuerPublicKey: options.bundle.public.issuerPublicKey, ...(options.testMode ? { environment: "test" } : {}) };
  /**
   * The signing identity for a session. Derived per verified principal, so a
   * session for one wallet can never sign under another wallet's identity.
   */
  const sessionIdentity = (session: ShareSession): SenderIdentity => {
    if (options.senderIdentitySource === undefined) throw new Error("sender_not_ready");
    return options.senderIdentitySource.forPrincipal(session.userId);
  };
  /**
   * Statically configured capabilities exist only in the explicit
   * test-authority composition. Their signing key is re-resolved and must
   * still match the public key frozen into the descriptor at parse time.
   */
  const staticRecord = (candidate: { readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: Record<string, unknown> }): CapabilityRecord | undefined => {
    if (options.senderIdentitySource === undefined) return undefined;
    const principal = typeof candidate.scope.policyOwnerDid === "string" ? candidate.scope.policyOwnerDid : typeof candidate.scope.userId === "string" ? candidate.scope.userId : undefined;
    if (principal === undefined) return undefined;
    let identity: SenderIdentity;
    try { identity = options.senderIdentitySource.forPrincipal(principal); } catch { return undefined; }
    if (identity.publicKey.length === 0 || identity.publicKey !== (candidate.scope.signingCapability as Record<string, unknown> | undefined)?.publicKey) return undefined;
    return { ...candidate, identity };
  };
  const sessionCandidates = (session: ShareSession): CapabilityRecord[] => [
    ...session.capabilities.values(),
    ...[...(options.capabilities?.values() ?? (capability === undefined ? [] : [capability]))].map(staticRecord).filter((record): record is CapabilityRecord => record !== undefined),
  ].filter((candidate) => capabilityOwnedByPrincipal(candidate, session.userId));
  const selectedCapability = (request: Request, session: ShareSession, requestedCapabilityId?: string): CapabilityRecord => {
    if (!senderReady) throw new Error("sender_not_ready");
    if (requestedCapabilityId === undefined && new URL(request.url).searchParams.has("capabilityId")) throw new Error("query capability selection is not supported");
    const requested = requestedCapabilityId ?? null;
    const candidates = sessionCandidates(session);
    if (requested !== null) {
      const selected = candidates.find((candidate) => (candidate.scope.signingCapability as Record<string, unknown> | undefined)?.capabilityId === requested);
      if (selected === undefined) throw new Error("capability is not authorized for this session");
      return selected;
    }
    const selected = candidates[0];
    if (selected === undefined) throw new Error("sender_capability_required");
    return selected;
  };
  const authUsers = options.authUsers ?? [];
  /**
   * Secure is omitted only for the exact configured local browser origin: the
   * authenticating request's own URL origin and its Origin header must both
   * equal it, so no other loopback or production request can downgrade the
   * cookie.
   */
  const isDedicatedLocalBrowserRequest = (request: Request): boolean => {
    if (options.hermeticBrowserOrigin === undefined) return false;
    if (request.headers.get("origin") !== options.hermeticBrowserOrigin) return false;
    return new URL(request.url).origin === options.hermeticBrowserOrigin;
  };
  const sessionCookieHeader = (token: string, maxAge: number, request: Request): string => `share_session=${token}; HttpOnly;${options.hermeticComposition === true || isDedicatedLocalBrowserRequest(request) ? "" : " Secure;"} SameSite=Lax; Path=/; Max-Age=${maxAge}; Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}`;
  async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if ((url.pathname === "/health/readiness" || url.pathname === "/api/health/readiness") && request.method === "GET") return response(200, { authReady, senderReady });
      if (url.pathname === "/.well-known/tinycloud-share/config.json" && request.method === "GET") return response(200, publicConfig);
      if (url.pathname === "/.well-known/tinycloud-share/agent.json" && request.method === "GET") return response(200, AGENT_CARD);
      if (url.pathname === "/api/share/auth/openkey/nonce" && request.method === "GET") {
        const requestOrigin = request.headers.get("origin");
        if (!shareOriginAllowed(requestOrigin, options)) return generic(403);
        const now = Date.now();
        // Bounded by TTL only. A hard cap here would be worse than the memory
        // it saves: evicting the oldest live challenge lets an unauthenticated
        // burst cancel a victim's pending sign-in before they submit it.
        for (const [value, expiresAt] of openKeyNonces) if (expiresAt <= now) openKeyNonces.delete(value);
        const nonce = toBase64Url(randomBytes(24));
        const expiresAt = now + OPENKEY_NONCE_TTL_MS;
        openKeyNonces.set(nonce, expiresAt);
        return response(200, { nonce, expiresAt: new Date(expiresAt).toISOString() });
      }
      if (url.pathname === "/api/share/auth/openkey" && request.method === "POST") {
        if (!shareOriginAllowed(request.headers.get("origin"), options)) return generic(403);
        const body = await boundedJson(request);
        if (Object.keys(body).sort().join(",") !== "address,issuedAt,message,nonce,signature") return generic(400);
        const address = safeString(body.address, "address");
        const signature = safeString(body.signature, "signature");
        const message = safeString(body.message, "message");
        const nonce = safeString(body.nonce, "nonce");
        const issuedAt = safeString(body.issuedAt, "issuedAt");
        const nonceExpiry = openKeyNonces.get(nonce);
        openKeyNonces.delete(nonce);
        const issuedTime = Date.parse(issuedAt);
        if (!EVM_ADDRESS.test(address) || !/^0x[0-9a-fA-F]{130}$/.test(signature) || !/^[A-Za-z0-9_-]{32}$/.test(nonce) || nonceExpiry === undefined || nonceExpiry <= Date.now() || !Number.isFinite(issuedTime) || Math.abs(Date.now() - issuedTime) > OPENKEY_NONCE_TTL_MS || message !== openKeyMessage(options.bundle.public.shareOrigin, address, nonce, issuedAt)) return generic(401);
        let valid = false;
        try { valid = await verifyMessage({ address: address as `0x${string}`, message, signature: signature as `0x${string}` }); } catch { valid = false; }
        if (!valid) return generic(401);
        const normalizedAddress = address.toLowerCase();
        const token = toBase64Url(randomBytes(32));
        // A valid OpenKey proof is an authentication ceremony, not a sender
        // capability lookup. Sender capabilities are checked only when a
        // sender operation selects one below.
        issueSession(token, { userId: `did:pkh:eip155:1:${normalizedAddress}`, expiresAt: Date.now() + 1_800_000, capabilities: new Map() });
        return response(200, { status: "authenticated", address: normalizedAddress }, { "set-cookie": sessionCookieHeader(token, 1_800, request) });
      }
      if (url.pathname === "/api/share/auth/login" && request.method === "POST") {
        if (!shareOriginAllowed(request.headers.get("origin"), options)) return generic(403);
        const body = await boundedJson(request);
        const username = safeString(body.username, "username"); const password = safeString(body.password, "password");
        const user = authUsers.find((candidate) => candidate.username === username);
        if (user === undefined || !(await verifyPassword(password, user.passwordHash))) return generic(401);
        const token = toBase64Url(randomBytes(32));
        issueSession(token, { userId: user.userId, expiresAt: Date.now() + 1_800_000, capabilities: new Map() });
        return response(200, { status: "authenticated" }, { "set-cookie": sessionCookieHeader(token, 1_800, request) });
      }
      if (url.pathname === "/api/share/auth/logout" && request.method === "POST") {
        const token = sessionCookie(request); if (token !== undefined) sessions.delete(token);
        return response(200, { status: "signed_out" }, { "set-cookie": "share_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" });
      }
      if (url.pathname === "/api/share/capability" && request.method === "GET") {
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const selected = selectedCapability(request, session);
        const scope = selected.scope as Record<string, unknown>;
        return response(200, { scope: browserSafeScope(scope), source: selected.source, policy: selected.policy });
      }
      if (url.pathname === "/api/share/capabilities" && request.method === "GET") {
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const candidates = sessionCandidates(session);
        return response(200, { capabilities: candidates.map((candidate) => ({ capabilityId: (candidate.scope.signingCapability as Record<string, unknown>).capabilityId, scope: browserSafeScope(candidate.scope), source: candidate.source, policy: candidate.policy })) });
      }
      /**
       * The wallet-rooted sender identity for this session. The holder mints
       * node authority material bound to this exact `senderDid`; the private
       * half never leaves the host.
       */
      if (url.pathname === "/api/share/sender-identity" && request.method === "GET") {
        if (!senderReady) return response(503, { error: { code: "sender_not_ready" } });
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const identity = sessionIdentity(session);
        return response(200, { alg: "Ed25519", senderDid: identity.did, senderPublicKey: identity.publicKey });
      }
      /**
       * Admits one wallet-rooted sender capability into the authenticated
       * session. The descriptor must already be bound to this session's sender
       * identity and to this session's verified principal as its policy owner;
       * both are re-derived here and never read from the request.
       */
      if (url.pathname === "/api/share/capabilities" && request.method === "POST") {
        if (!senderReady) return response(503, { error: { code: "sender_not_ready" } });
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        if (session.capabilities.size >= SESSION_CAPABILITY_LIMIT) return response(429, { error: { code: "sender_capability_limit" } });
        const body = await boundedJson(request);
        if (Object.keys(body).join(",") !== "capability" || typeof body.capability !== "object" || body.capability === null || Array.isArray(body.capability)) return generic(400);
        const identity = sessionIdentity(session);
        const parsed = parseCapabilityValue(body.capability as Record<string, unknown>, options.bundle, identity, session.userId);
        const capabilityId = (parsed.scope.signingCapability as Record<string, unknown>).capabilityId as string;
        session.capabilities.set(capabilityId, { ...parsed, identity });
        return response(201, { capabilityId, senderDid: identity.did, scope: browserSafeScope(parsed.scope), source: parsed.source, policy: parsed.policy });
      }
      if (url.pathname === `${LINK_ONLY_REGISTRY_PREFIX}/public-key` && request.method === "GET") {
        if (options.registryUploadPrivateKey === undefined) return response(503, { error: { code: "registry_upload_not_ready" } });
        return response(200, {
          alg: "Ed25519",
          publicKey: toBase64Url(ed25519.getPublicKey(options.registryUploadPrivateKey)),
        });
      }
      if (url.pathname === "/api/share/sign" && request.method === "POST") {
        if (!senderReady) return response(503, { error: { code: "sender_not_ready" } });
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const body = await boundedJson(request);
        const capabilityId = safeString(body.capabilityId, "capabilityId");
        const selected = selectedCapability(request, session, capabilityId);
        const signer = (selected.scope.signingCapability as Record<string, unknown>);
        if (capabilityId !== signer.capabilityId || !["envelope", "inviteAuthorization", "delegationAuthoring"].includes(body.purpose as string)) return generic(403);
        const message = safeString(body.message, "message");
        const binding = bodyBinding(body);
        if (body.purpose === "delegationAuthoring") {
          const parsed = JSON.parse(message) as Record<string, unknown>;
          assertAddressedDelegationAuthoringSigningBinding(parsed, binding, selected.scope as Record<string, unknown>, selected.source);
        } else {
          await assertSigningBinding(body.purpose as string, message, binding, selected.scope as Record<string, unknown>, selected.source, selected.policy);
        }
        const expected = stable({ purpose: body.purpose, message, binding });
        const idempotency = request.headers.get("idempotency-key");
        if (idempotency === null || !B64_128.test(idempotency)) return generic(400);
        // Bound to the selected capability's own signing identity, so a cached
        // signature can never be replayed across sessions or sender keys.
        const key = hash(`${selected.identity.did}:${capabilityId}:${idempotency}:${expected}`);
        const cached = signers.get(key);
        let signature = cached === undefined || cached.expiresAt <= Date.now() ? undefined : cached.signature;
        if (signature === undefined) {
          const parsedMessage = body.purpose === "envelope" ? JSON.parse(message) as Record<string, unknown> : undefined;
          const domain = new TextEncoder().encode(body.purpose === "delegationAuthoring" ? SIGNATURE_DOMAINS.delegationAuthoring : body.purpose === "envelope" && parsedMessage?.version === 2 ? SIGNATURE_DOMAINS.envelopeV2 : SIGNATURE_DOMAINS[body.purpose === "envelope" ? "envelope" : "inviteAuthorization"]);
          const bytes = new TextEncoder().encode(message);
          const preimage = new Uint8Array(domain.length + bytes.length); preimage.set(domain); preimage.set(bytes, domain.length);
          signature = toBase64Url(ed25519.sign(preimage, selected.identity.privateKey));
          if (signers.size >= SIGNER_CACHE_LIMIT) {
            const now = Date.now();
            for (const [candidate, entry] of signers) if (entry.expiresAt <= now) signers.delete(candidate);
            while (signers.size >= SIGNER_CACHE_LIMIT) signers.delete(signers.keys().next().value as string);
          }
          signers.set(key, { signature, expiresAt: Date.now() + SIGNER_CACHE_TTL_MS });
        }
        return response(200, { signerDid: selected.identity.did, signature });
      }
      if (url.pathname === "/api/share/bindings" && request.method === "POST") {
        if (!senderReady) return response(503, { error: { code: "sender_not_ready" } });
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const body = await boundedJson(request); const cid = safeString(body.shareCid, "shareCid"); const capabilityId = safeString(body.capabilityId, "capabilityId");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid) || typeof body.binding !== "object" || body.binding === null) return generic(400);
        const { shareCid: bindingShareCid, capabilityId: _capabilityId, ...binding } = body.binding as Record<string, unknown>;
        const selected = selectedCapability(request, session, capabilityId);
        await assertPublishedBinding({ ...binding, shareCid: bindingShareCid }, cid, selected.scope as Record<string, unknown>, selected.source, selected.policy);
        const publicBinding = {
          ...(binding.version === 2 ? { version: 2 } : {}),
          shareId: binding.shareId,
          policyCid: binding.policyCid,
          expiry: binding.expiry,
          contentSourceDigest: binding.contentSourceDigest,
          actionDigest: hash(stable(binding.version === 2 ? binding.actions : binding.action)),
          resourceDigest: hash(stable(binding.resource)),
        };
        await options.bindingStore!.put(cid, publicBinding); return response(201, { status: "stored" });
      }
      if (url.pathname.startsWith("/.well-known/tinycloud-share/bindings/") && request.method === "GET") {
        const cid = url.pathname.slice("/.well-known/tinycloud-share/bindings/".length).replace(/\.json$/, "");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid)) return generic(400);
        const binding = await options.bindingStore?.get(cid); return binding === undefined ? generic(404) : response(200, binding);
      }
      if (url.pathname.startsWith(`${LINK_ONLY_REGISTRY_PREFIX}/`) || url.pathname === LINK_ONLY_REGISTRY_PREFIX) {
        if (url.pathname !== `${LINK_ONLY_REGISTRY_PREFIX}/blobs`) return undefinedResponse();
        if (request.method !== "POST") return response(405, { error: { code: "method_not_allowed" } }, { allow: "POST" });
        if (options.registryUploadPrivateKey === undefined) return response(503, { error: { code: "registry_upload_not_ready" } });
        const attestationHeader = request.headers.get(UPLOAD_ATTESTATION_HEADER);
        if (attestationHeader !== null && attestationHeader.length > MAX_UPLOAD_ATTESTATION_BYTES) return response(413, { error: { code: "upload_attestation_too_large" } });
        const now = Date.now();
        const deleteAfterHeader = request.headers.get("x-delete-after") ?? "";
        const deleteAfter = Date.parse(deleteAfterHeader);
        if (!Number.isFinite(deleteAfter) || deleteAfter <= now || deleteAfter > now + LINK_ONLY_RETENTION_LIMIT_MS) {
          return response(400, { error: { code: "upload_retention_invalid" } });
        }
        if (attestationHeader !== null) {
          if (!shareOriginAllowed(request.headers.get("origin"), options)) return response(401, { error: { code: "authentication_required" } });
          const bytes = await boundedUpload(request, LINK_ONLY_BLOB_LIMIT);
          const attestation = await verifyUploadAttestation(request, bytes, options.bundle, now);
          const sessionToken = sessionCookie(request);
          if (sessionToken !== undefined) {
            const session = sessionValid(request, options, sessions);
            if (session === undefined || !samePrincipal(session.userId, attestation.ownerDid)) return response(401, { error: { code: "authentication_required" } });
          }
          if (!(await consumeUploadAttestationJti(attestation.jti, Date.parse(attestation.expiresAt), now))) return response(401, { error: { code: "upload_attestation_replayed" } });
          if (!(await reserveUpload(attestation.ownerDid, now))) return response(429, { error: { code: "upload_rate_limited" } });
          const registryResponse = await proxyRegistry(
            request,
            options.registryOrigin,
            options.registryTransportOrigin,
            LINK_ONLY_REGISTRY_PREFIX,
            LINK_ONLY_BLOB_LIMIT,
            (body) => registryUploadAuthorization(options.registryUploadPrivateKey!, body, deleteAfterHeader, `${attestation.ownerDid}:${attestation.sessionDid}`),
            bytes,
            options.fetchFn,
          );
          if (registryResponse.status === 401 || registryResponse.status === 403) return response(502, { error: { code: "registry_upload_rejected" } });
          return registryResponse;
        }
        const session = sessionValid(request, options, sessions); if (session === undefined) return response(401, { error: { code: "authentication_required" } });
        if (((request.headers?.get("content-type") ?? "").split(";", 1)[0]?.trim().toLowerCase() ?? "") !== "application/vnd.ipld.raw") return response(400, { error: { code: "upload_content_type_invalid" } });
        const bytes = await boundedUpload(request, LINK_ONLY_BLOB_LIMIT);
        // The registry authorization binds to the session token, but the durable
        // budget is keyed by the verified principal: signing out and back in
        // must not reset the allowance or accrue a fresh accounting entry.
        const uploadKey = sessionCookie(request) ?? session.userId;
        if (!(await reserveUpload(session.userId, now))) return response(429, { error: { code: "upload_rate_limited" } });
        const registryResponse = await proxyRegistry(
          request,
          options.registryOrigin,
          options.registryTransportOrigin,
          LINK_ONLY_REGISTRY_PREFIX,
          LINK_ONLY_BLOB_LIMIT,
          (bytes) => registryUploadAuthorization(options.registryUploadPrivateKey!, bytes, deleteAfterHeader, uploadKey),
          bytes,
          options.fetchFn,
        );
        if (registryResponse.status === 401 || registryResponse.status === 403) {
          return response(502, { error: { code: "registry_upload_rejected" } });
        }
        return registryResponse;
      }
      if ((url.pathname.startsWith("/registry/") || url.pathname === "/registry") && request.method === "POST") {
        return response(401, { error: { code: "authentication_required" } });
      }
      if (url.pathname.startsWith("/registry/") || url.pathname === "/registry") return await proxyRegistry(request, options.registryOrigin, options.registryTransportOrigin, "/registry", MAX_BODY, undefined, undefined, options.fetchFn);
      return undefinedResponse();
    } catch (error) {
      if (error instanceof PayloadTooLargeError) return response(413, { error: { code: "upload_too_large" } });
      if (error instanceof Error && error.message === "sender_not_ready") return response(503, { error: { code: "sender_not_ready" } });
      if (error instanceof Error && error.message === "upload_budget_unavailable") return response(503, { error: { code: "upload_budget_unavailable" } });
      if (error instanceof Error && error.message === "upload_attestation_store_unavailable") return response(503, { error: { code: "upload_attestation_store_unavailable" } });
      // The sender path is ready but this session has enrolled no wallet-rooted
      // authority yet: a per-session fact, deliberately distinct from readiness.
      if (error instanceof Error && error.message === "sender_capability_required") return response(409, { error: { code: "sender_capability_required" } });
      return generic(400);
    }
  }
  return { handler, publicConfig, readiness: { authReady, senderReady } };
}

async function boundedJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? "0"); if (length > MAX_BODY) throw new Error("body too large");
  const bytes = new Uint8Array(await request.arrayBuffer()); if (bytes.length > MAX_BODY) throw new Error("body too large");
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("body shape"); return value as Record<string, unknown>;
}

async function proxyRegistry(
  request: Request,
  origin: string,
  transportOrigin = origin,
  routePrefix = "/registry",
  maxBody = MAX_BODY,
  authorize?: (body: Uint8Array) => string,
  bodyOverride?: Uint8Array,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<Response> {
  const requestUrl = new URL(request.url);
  const suffix = requestUrl.pathname.slice(routePrefix.length) || "/";
  const policyPath = `/registry${suffix}`;
  const base = new URL(transportOrigin); const target = new URL(suffix, base); target.search = requestUrl.search;
  const bytes = bodyOverride ?? new Uint8Array(await request.arrayBuffer());
  if (bytes.length > maxBody) throw new PayloadTooLargeError("upload too large");
  const headers = sanitizeUpstreamRequest(policyPath, request.method, request.headers, bytes.length, origin);
  if (authorize !== undefined) {
    headers.set("x-tinycloud-authorization", authorize(bytes));
  }
  headers.delete(UPLOAD_ATTESTATION_HEADER);
  headers.delete(UPLOAD_RETENTION_HEADER);
  const result = await fetchFn(target, { method: request.method, headers, ...(bytes.length === 0 ? {} : { body: bytes.buffer as ArrayBuffer }), redirect: "error" });
  return sanitizeUpstreamResponse(policyPath, request.method, result);
}

async function boundedUpload(request: Request, maxBytes: number): Promise<Uint8Array> {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(length) || length < 0 || length > maxBytes) throw new PayloadTooLargeError("upload too large");
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > maxBytes) throw new PayloadTooLargeError("upload too large");
  return bytes;
}

function undefinedResponse(): Response { return new Response(null, { status: 404, headers: JSON_HEADERS }); }

export function senderEnabledFromEnv(env: NodeJS.ProcessEnv): boolean {
  const value = env.SHARE_SENDER_ENABLED;
  if (value === undefined || value === "false") return false;
  if (value === "true") return true;
  throw new Error("SHARE_SENDER_ENABLED must be exactly true or false");
}

function parseRegistryUploadPrivateKey(value: string): Uint8Array {
  if (!B64_256.test(value)) throw new Error("registry upload private key is invalid");
  const key = fromBase64Url(value);
  if (key.byteLength !== 32 || toBase64Url(key) !== value) {
    throw new Error("registry upload private key is invalid");
  }
  return key;
}

function loadRegistryUploadPrivateKey(
  env: NodeJS.ProcessEnv,
  environment: ShareTrustBundle["environment"],
): Uint8Array | undefined {
  const path = env.SHARE_REGISTRY_UPLOAD_KEY_PATH;
  const inline = env.SHARE_REGISTRY_UPLOAD_PRIVATE_KEY;
  if (path !== undefined && inline !== undefined) {
    throw new Error("configure exactly one registry upload key source");
  }
  if (inline !== undefined) {
    if (environment !== "test") {
      throw new Error("inline registry upload keys are test-only");
    }
    return parseRegistryUploadPrivateKey(inline);
  }
  if (path === undefined) return undefined;
  if (!path.startsWith("/") || path.includes("\u0000")) {
    throw new Error("registry upload key path must be absolute");
  }
  const readExisting = (): Uint8Array =>
    parseRegistryUploadPrivateKey(readFileSync(path, "utf8").trim());
  try {
    return readExisting();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const generated = randomBytes(32);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, "wx", 0o600);
    writeSync(descriptor, toBase64Url(generated), undefined, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    return new Uint8Array(generated);
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* best-effort close */ }
    }
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return readExisting();
    throw error;
  }
}

export function createShareHostFromEnv(env: NodeJS.ProcessEnv = process.env, overrides: Pick<ShareHostOptions, "fetchFn"> = {}): ReturnType<typeof createShareHostAdapter> {
  const senderEnabled = senderEnabledFromEnv(env);
  if (senderEnabled && env.SHARE_TRUST_BUNDLE_ALLOW_TEST !== "true" && (env.SHARE_SENDER_PRIVATE_KEY !== undefined || env.SHARE_SENDER_CAPABILITY_JSON !== undefined || env.SHARE_SENDER_CAPABILITIES_JSON !== undefined)) throw new Error("static sender authority variables are forbidden; authenticate through OpenKey");
  const bundle = loadTrustBundle(senderEnabled ? env : { ...env, SHARE_SENDER_PRIVATE_KEY: undefined });
  if (senderEnabled && !bundle.public.nodeEnabled) throw new Error("sender requires an enabled trusted node");
  const testAuthority = env.SHARE_TRUST_BUNDLE_ALLOW_TEST === "true";
  // TC-348: sender authority is issued per authenticated OpenKey session at
  // runtime, so there is deliberately no boot-time capability requirement. The
  // previous guard demanded capability material that the guard above forbids,
  // which made SHARE_SENDER_ENABLED=true unbootable in every production shape.
  const capabilityRaw = testAuthority && senderEnabled ? env.SHARE_SENDER_CAPABILITY_JSON : undefined;
  const capabilityListRaw = testAuthority && senderEnabled ? env.SHARE_SENDER_CAPABILITIES_JSON : undefined;
  if (testAuthority && senderEnabled && capabilityRaw !== undefined && capabilityListRaw !== undefined) throw new Error("configure exactly one sender capability source");
  if (testAuthority && senderEnabled && capabilityRaw === undefined && capabilityListRaw === undefined) throw new Error("sender capability material is required when SHARE_SENDER_ENABLED=true");
  const capabilityValues = capabilityRaw === undefined && capabilityListRaw === undefined ? [] : capabilityListRaw === undefined ? [capabilityRaw] : JSON.parse(capabilityListRaw) as unknown[];
  if (!Array.isArray(capabilityValues) || (testAuthority && senderEnabled && capabilityValues.length === 0) || capabilityValues.some((value) => typeof value !== "string")) throw new Error("sender capability input is invalid");
  const bootIdentity: SenderIdentity = { did: bundle.sender.senderDid, publicKey: bundle.sender.senderPublicKey, privateKey: bundle.sender.senderPrivateKey.length > 0 ? fromBase64Url(bundle.sender.senderPrivateKey) : new Uint8Array(0) };
  const parsedCapabilities = capabilityValues.map((value) => parseCapability(value as string, bundle, bootIdentity));
  const capability = parsedCapabilities[0];
  const capabilities = new Map(parsedCapabilities.map((value, index) => [String(index), value]));
  const initialBindings = !senderEnabled || env.SHARE_TEST_BINDINGS_JSON === undefined ? {} : JSON.parse(env.SHARE_TEST_BINDINGS_JSON) as Record<string, Record<string, unknown>>;
  const hermeticComposition = env.SHARE_HERMETIC_COMPOSITION === "true";
  const bindingRoot = env.SHARE_BINDING_STORE_ROOT ?? PRODUCTION_BINDING_STORE_ROOT;
  if (bundle.environment === "production" && !hermeticComposition && bindingRoot !== PRODUCTION_BINDING_STORE_ROOT) throw new Error("production binding store root is fixed to the named Share volume");
  const bindingPath = env.SHARE_BINDING_STORE_PATH ?? (bundle.environment === "production" ? DEFAULT_PRODUCTION_BINDING_STORE_PATH : undefined);
  if (senderEnabled && bundle.environment === "production") {
    validateProductionBindingStorePath(bindingPath!, bindingRoot);
    try {
      assertSecurePath(bindingPath!);
      if (!statSync(resolve(bindingRoot)).isDirectory()) throw new Error("not a directory");
    } catch {
      throw new Error("binding store root must be an existing mounted directory");
    }
  }
  const bindingStore = !senderEnabled ? undefined : bindingPath === undefined ? new MemoryBindingStore(initialBindings) : new TransactionalBindingStore(bindingPath);
  if (senderEnabled && bindingStore === undefined) throw new Error("durable binding store is required when SHARE_SENDER_ENABLED=true");
  if (senderEnabled && bindingStore?.writable !== true) throw new Error("binding store is not writable");
  /**
   * The sender signing identity source, resolved only once the rest of the
   * composition is valid so a broken deployment never mints key material. In
   * production the trust bundle carries no sender secret, so identities are
   * derived per authenticated principal from a seed created once inside the
   * persistent Share volume; only the explicit test-authority composition can
   * supply a bundle sender key.
   */
  const senderIdentitySource = !senderEnabled
    ? undefined
    : bundle.sender.senderPrivateKey.length > 0
      ? staticSenderIdentitySource(bundle.sender.senderPrivateKey)
      : derivedSenderIdentitySource(loadSenderRootSeed(env, bundle.environment, { root: bindingRoot, reserved: [bindingPath, env.SHARE_REGISTRY_UPLOAD_KEY_PATH].filter((value): value is string => value !== undefined) }));
  const registryOrigin = bundle.public.registryOrigin;
  if (!/^https:\/\/[^/?#:@]+$/.test(registryOrigin)) throw new Error("trust-bundle registryOrigin must be a canonical HTTPS origin");
  const registryTransportOrigin = parseHermeticRegistryOrigin(env.SHARE_HERMETIC_REGISTRY_ORIGIN) ?? resolveShareUpstreams(bundle, env).registry;
  const registryUploadPrivateKey = loadRegistryUploadPrivateKey(env, bundle.environment);
  const storeOrigin = env.SHARE_UPLOAD_AUTHORIZATION_ORIGIN ?? (hermeticComposition ? registryTransportOrigin : registryOrigin);
  if (bundle.environment === "production" && !hermeticComposition && storeOrigin !== registryOrigin) throw new Error("production upload authorization store must use the trusted registry origin");
  const uploadBudgetStore = registryUploadPrivateKey === undefined
    ? undefined
    : bundle.environment === "production"
      ? new RegistryUploadAuthorizationStore(storeOrigin, registryUploadPrivateKey)
      : env.SHARE_UPLOAD_BUDGET_STORE_PATH === undefined
        ? new MemoryUploadBudgetStore()
        : new TransactionalBindingStore(env.SHARE_UPLOAD_BUDGET_STORE_PATH);
  if (registryUploadPrivateKey !== undefined && bundle.environment === "production" && uploadBudgetStore?.writable !== true) throw new Error("durable upload authorization store is required");
  const authUsersRaw = env.SHARE_AUTH_USERS_JSON;
  let authUsers: AuthUser[] = [];
  if (authUsersRaw !== undefined) {
    const value = JSON.parse(authUsersRaw) as unknown;
    if (!Array.isArray(value)) throw new Error("SHARE_AUTH_USERS_JSON is invalid");
    authUsers = value.map((candidate) => {
      if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) throw new Error("SHARE_AUTH_USERS_JSON is invalid");
      const user = candidate as Record<string, unknown>;
      if (typeof user.userId !== "string" || typeof user.username !== "string" || typeof user.passwordHash !== "string") throw new Error("SHARE_AUTH_USERS_JSON is invalid");
      // Anything the host will authenticate must also be able to derive a
      // sender identity, so this fails at startup rather than at request time.
      if (!derivablePrincipal(user.userId)) throw new Error("SHARE_AUTH_USERS_JSON userId cannot derive a sender identity");
      parsePasswordHash(user.passwordHash);
      return { userId: user.userId, username: user.username, passwordHash: user.passwordHash };
    });
  }
  const hermeticBrowserOrigin = parseHermeticBrowserOrigin(env.SHARE_HERMETIC_BROWSER_ORIGIN);
  return createShareHostAdapter({ bundle, ...(capability === undefined ? {} : { capability }), ...(parsedCapabilities.length > 1 ? { capabilities } : {}), ...(bindingStore === undefined ? {} : { bindingStore }), ...(uploadBudgetStore === undefined ? {} : { uploadBudgetStore }), ...(registryUploadPrivateKey === undefined ? {} : { registryUploadPrivateKey }), ...(senderIdentitySource === undefined ? {} : { senderIdentitySource }), registryOrigin, registryTransportOrigin, authUsers, senderEnabled, testMode: bundle.environment === "test", hermeticComposition, ...(hermeticBrowserOrigin === undefined ? {} : { hermeticBrowserOrigin }), ...(overrides.fetchFn === undefined ? {} : { fetchFn: overrides.fetchFn }) });
}
