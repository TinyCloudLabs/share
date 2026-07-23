import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { open, readFile, rm, stat, unlink } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519";
import { verifyMessage } from "viem";
import { loadTrustBundle, type ShareTrustBundle } from "./trust-bundle.js";
import { resolveShareUpstreams, sanitizeUpstreamRequest, sanitizeUpstreamResponse } from "./upstream.js";

function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
const SIGNATURE_DOMAINS = { envelope: "xyz.tinycloud.share/envelope/v1\0", inviteAuthorization: "xyz.tinycloud.share/invite-authorization/v1\0" } as const;
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

const MAX_BODY = 128 * 1024;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" };
const B64_128 = /^[A-Za-z0-9_-]{22}$/;
const B64_256 = /^[A-Za-z0-9_-]{43}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const OPENKEY_NONCE_TTL_MS = 5 * 60 * 1000;

export interface BindingStore {
  get(cid: string): Promise<Record<string, unknown> | undefined>;
  put(cid: string, binding: Record<string, unknown>): Promise<void>;
}

function scryptAsync(password: string, salt: Uint8Array, length: number, options: { readonly N: number; readonly r: number; readonly p: number; readonly maxmem: number }): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password, salt, length, options, (error, derived) => error === null ? resolve(derived as Buffer) : reject(error)));
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

  constructor(private readonly path: string) { this.lockPath = `${path}.lock`; }

  private async readJournal(): Promise<Map<string, Record<string, unknown>>> {
    let text: string;
    try { text = await readFile(this.path, "utf8"); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
      throw error;
    }
    const records = new Map<string, Record<string, unknown>>();
    if (text.length === 0) throw new Error("binding journal is empty");
    for (const [lineNumber, line] of text.split("\n").entries()) {
      if (lineNumber === text.split("\n").length - 1 && line === "") continue;
      let value: unknown;
      try { value = JSON.parse(line); } catch { throw new Error("binding journal is corrupt"); }
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("binding journal record is invalid");
      const record = value as Record<string, unknown>;
      if (record.op !== "put" || typeof record.cid !== "string" || typeof record.binding !== "object" || record.binding === null || Array.isArray(record.binding)) throw new Error("binding journal record is invalid");
      const binding = record.binding as Record<string, unknown>;
      const previous = records.get(record.cid);
      if (previous !== undefined && stable(previous) !== stable(binding)) throw new Error("binding journal contains conflicting records");
      records.set(record.cid, binding);
    }
    return records;
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    for (;;) {
      try {
        const handle = await open(this.lockPath, "wx", 0o600);
        try { return await operation(); } finally { await handle.close(); await unlink(this.lockPath).catch(() => undefined); }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        try { if (Date.now() - (await stat(this.lockPath)).mtimeMs > this.staleLockMs) await rm(this.lockPath, { recursive: true }); }
        catch (statError) { if ((statError as NodeJS.ErrnoException).code !== "ENOENT") throw statError; }
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    }
  }

  async get(cid: string): Promise<Record<string, unknown> | undefined> { return (await this.readJournal()).get(cid); }

  async put(cid: string, binding: Record<string, unknown>): Promise<void> {
    await this.withLock(async () => {
      const records = await this.readJournal();
      const previous = records.get(cid);
      if (previous !== undefined) {
        if (stable(previous) !== stable(binding)) throw new Error("binding is immutable");
        return;
      }
      const handle = await open(this.path, "a", 0o600);
      try {
        await handle.write(`${JSON.stringify({ op: "put", cid, binding })}\n`, undefined, "utf8");
        await handle.sync();
      } finally { await handle.close(); }
    });
  }
}

class MemoryBindingStore implements BindingStore {
  private readonly values = new Map<string, Record<string, unknown>>();
  constructor(initial: Record<string, Record<string, unknown>> = {}) { Object.entries(initial).forEach(([key, value]) => this.values.set(key, value)); }
  async get(cid: string): Promise<Record<string, unknown> | undefined> { return this.values.get(cid); }
  async put(cid: string, binding: Record<string, unknown>): Promise<void> { this.values.set(cid, binding); }
}

export interface ShareHostOptions {
  readonly bundle: ShareTrustBundle;
  readonly capability?: { readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: Record<string, unknown> };
  readonly capabilities?: ReadonlyMap<string, { readonly scope: Record<string, unknown>; readonly source: ContentSource; readonly policy: Record<string, unknown> }>;
  readonly bindingStore?: BindingStore;
  readonly registryOrigin: string;
  /** Registry transport is bundle-derived, except inside the explicit hermetic resolver. */
  readonly registryTransportOrigin: string;
  readonly authUsers?: readonly AuthUser[];
  readonly testMode: boolean;
}

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response { return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...headers } }); }
function generic(status = 400): Response { return response(status, { error: { code: "capability_unavailable" } }); }
function safeString(value: unknown, label: string): string { if (typeof value !== "string" || value.length === 0 || value.length > 4096) throw new Error(label); return value; }
function hash(value: string): string { return createHash("sha256").update(value).digest("base64url"); }

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

function parseCapability(raw: string, bundle: ShareTrustBundle): { scope: Record<string, unknown>; source: ContentSource; policy: Record<string, unknown> } {
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (typeof value !== "object" || value === null || (Object.keys(value).length !== 3 && Object.keys(value).length !== 4) || !Object.hasOwn(value, "scope") || !Object.hasOwn(value, "source") || !Object.hasOwn(value, "policy") || typeof value.scope !== "object" || value.scope === null || typeof value.source !== "object" || value.source === null || (value.userId !== undefined && typeof value.userId !== "string")) throw new Error("capability shape");
  const scope = { ...(value.scope as Record<string, unknown>) };
  if (typeof value.userId === "string") scope.userId = value.userId;
  if (scope.senderDid !== bundle.sender.senderDid || scope.targetOrigin !== bundle.public.nodeOrigin || scope.nodeAudience !== bundle.public.nodeAudience) throw new Error("capability trust binding");
  delete scope.senderPrivateKey;
  delete scope.privateKey;
  scope.shareOrigin = bundle.public.shareOrigin;
  scope.signingCapability = { capabilityId: toBase64Url(randomBytes(16)), publicKey: bundle.sender.senderPublicKey };
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
interface ShareSession { readonly userId: string; readonly expiresAt: number; }

function openKeyAddressFromOwnerDid(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const match = /^did:pkh:eip155:[1-9][0-9]*:(0x[0-9a-fA-F]{40})$/.exec(value);
  return match?.[1]?.toLowerCase();
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

function sessionValid(request: Request, options: ShareHostOptions, sessions: Map<string, ShareSession>): ShareSession | undefined {
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== options.bundle.public.shareOrigin) return undefined;
  const value = sessionCookie(request);
  if (value === undefined) return options.testMode ? { userId: "fixture", expiresAt: Date.now() + 300_000 } : undefined;
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

function assertSigningBinding(purpose: string, message: string, binding: Record<string, unknown>, scope: Record<string, unknown>, authorizedSource: ContentSource, authorizedPolicy: Record<string, unknown>): void {
  const parsed = JSON.parse(message) as Record<string, unknown>;
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

function assertPublishedBinding(binding: Record<string, unknown>, cid: string, scope: Record<string, unknown>, source: ContentSource, policy: Record<string, unknown>): void {
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
  const signers = new Map<string, string>();
  const sessions = new Map<string, ShareSession>();
  const openKeyNonces = new Map<string, number>();
  const capability = options.capability;
  const senderReady = capability !== undefined && options.bundle.sender.senderPrivateKey.length > 0 && options.bindingStore !== undefined;
  const authReady = true;
  const publicConfig = { version: "tinycloud.share-email-claim/config-v1", shareOrigin: options.bundle.public.shareOrigin, registryOrigin: options.bundle.public.registryOrigin, nodeOrigin: options.bundle.public.nodeOrigin, credentialsOrigin: options.bundle.public.credentialsOrigin, nodeAudience: options.bundle.public.nodeAudience, issuerDid: options.bundle.public.issuerDid, issuerVct: options.bundle.public.issuerVct, nodeInvitationKid: options.bundle.public.nodeInvitationKid, nodeInvitationPublicKey: options.bundle.public.nodeInvitationPublicKey, nodeKeyVersion: options.bundle.public.nodeKeyVersion, issuerKeyVersion: options.bundle.public.issuerKeyVersion, issuerPublicKey: options.bundle.public.issuerPublicKey, ...(options.testMode ? { environment: "test" } : {}) };
  const selectedCapability = (request: Request, session: ShareSession, requestedCapabilityId?: string): { scope: Record<string, unknown>; source: ContentSource; policy: Record<string, unknown> } => {
    if (!senderReady || capability === undefined) throw new Error("sender_not_ready");
    if (requestedCapabilityId === undefined && new URL(request.url).searchParams.has("capabilityId")) throw new Error("query capability selection is not supported");
    const requested = requestedCapabilityId ?? null;
    const candidates = [...(options.capabilities?.values() ?? (capability === undefined ? [] : [capability]))].filter((candidate) => candidate.scope.userId === undefined || candidate.scope.userId === session.userId || options.testMode);
    if (requested !== null) {
      const selected = candidates.find((candidate) => (candidate.scope.signingCapability as Record<string, unknown> | undefined)?.capabilityId === requested);
      if (selected === undefined) throw new Error("capability is not authorized for this session");
      return selected;
    }
    const selected = candidates[0];
    if (selected === undefined) throw new Error("capability is unavailable");
    return selected;
  };
  const authUsers = options.authUsers ?? [];
  const sessionCookieHeader = (token: string, maxAge: number): string => `share_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}; Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}`;
  async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if ((url.pathname === "/health/readiness" || url.pathname === "/api/health/readiness") && request.method === "GET") return response(200, { authReady, senderReady });
      if (url.pathname === "/.well-known/tinycloud-share/config.json" && request.method === "GET") return response(200, publicConfig);
      if (url.pathname === "/api/share/auth/openkey/nonce" && request.method === "GET") {
        const requestOrigin = request.headers.get("origin");
        if (requestOrigin !== null && requestOrigin !== options.bundle.public.shareOrigin) return generic(403);
        const now = Date.now();
        for (const [value, expiresAt] of openKeyNonces) if (expiresAt <= now) openKeyNonces.delete(value);
        const nonce = toBase64Url(randomBytes(24));
        const expiresAt = now + OPENKEY_NONCE_TTL_MS;
        openKeyNonces.set(nonce, expiresAt);
        return response(200, { nonce, expiresAt: new Date(expiresAt).toISOString() });
      }
      if (url.pathname === "/api/share/auth/openkey" && request.method === "POST") {
        if (request.headers.get("origin") !== options.bundle.public.shareOrigin) return generic(403);
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
        const valid = await verifyMessage({ address: address as `0x${string}`, message, signature: signature as `0x${string}` });
        if (!valid) return generic(401);
        const normalizedAddress = address.toLowerCase();
        const token = toBase64Url(randomBytes(32));
        // A valid OpenKey proof is an authentication ceremony, not a sender
        // capability lookup. Sender capabilities are checked only when a
        // sender operation selects one below.
        sessions.set(token, { userId: `did:pkh:eip155:1:${normalizedAddress}`, expiresAt: Date.now() + 1_800_000 });
        return response(200, { status: "authenticated", address: normalizedAddress }, { "set-cookie": sessionCookieHeader(token, 1_800) });
      }
      if (url.pathname === "/api/share/auth/login" && request.method === "POST") {
        if (!options.testMode && request.headers.get("origin") !== options.bundle.public.shareOrigin) return generic(403);
        const body = await boundedJson(request);
        const username = safeString(body.username, "username"); const password = safeString(body.password, "password");
        const user = authUsers.find((candidate) => candidate.username === username);
        if (user === undefined || !(await verifyPassword(password, user.passwordHash))) return generic(401);
        const token = toBase64Url(randomBytes(32)); sessions.set(token, { userId: user.userId, expiresAt: Date.now() + 1_800_000 });
        return response(200, { status: "authenticated" }, { "set-cookie": sessionCookieHeader(token, 1_800) });
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
    const candidates = [...(options.capabilities?.values() ?? (capability === undefined ? [] : [capability]))].filter((candidate) => candidate.scope.userId === undefined || candidate.scope.userId === session.userId || (typeof candidate.scope.policyOwnerDid === "string" && openKeyAddressFromOwnerDid(candidate.scope.policyOwnerDid) === session.userId.slice(session.userId.lastIndexOf(":") + 1)) || options.testMode);
        return response(200, { capabilities: candidates.map((candidate) => ({ capabilityId: (candidate.scope.signingCapability as Record<string, unknown>).capabilityId, scope: browserSafeScope(candidate.scope), source: candidate.source, policy: candidate.policy })) });
      }
      if (url.pathname === "/api/share/sign" && request.method === "POST") {
        if (!senderReady) return response(503, { error: { code: "sender_not_ready" } });
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const body = await boundedJson(request);
        const capabilityId = safeString(body.capabilityId, "capabilityId");
        const selected = selectedCapability(request, session, capabilityId);
        const signer = (selected.scope.signingCapability as Record<string, unknown>);
        if (capabilityId !== signer.capabilityId || (body.purpose !== "envelope" && body.purpose !== "inviteAuthorization")) return generic(403);
        const message = safeString(body.message, "message");
        const binding = bodyBinding(body);
        assertSigningBinding(body.purpose, message, binding, selected.scope as Record<string, unknown>, selected.source, selected.policy);
        const expected = stable({ purpose: body.purpose, message, binding });
        const idempotency = request.headers.get("idempotency-key");
        if (idempotency === null || !B64_128.test(idempotency)) return generic(400);
        const key = hash(`${capabilityId}:${idempotency}:${expected}`);
        let signature = signers.get(key);
        if (signature === undefined) {
          const domain = new TextEncoder().encode(SIGNATURE_DOMAINS[body.purpose === "envelope" ? "envelope" : "inviteAuthorization"]);
          const bytes = new TextEncoder().encode(message);
          const preimage = new Uint8Array(domain.length + bytes.length); preimage.set(domain); preimage.set(bytes, domain.length);
          signature = toBase64Url(ed25519.sign(preimage, fromBase64Url(options.bundle.sender.senderPrivateKey)));
          signers.set(key, signature);
        }
        return response(200, { signerDid: options.bundle.sender.senderDid, signature });
      }
      if (url.pathname === "/api/share/bindings" && request.method === "POST") {
        if (!senderReady) return response(503, { error: { code: "sender_not_ready" } });
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const body = await boundedJson(request); const cid = safeString(body.shareCid, "shareCid"); const capabilityId = safeString(body.capabilityId, "capabilityId");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid) || typeof body.binding !== "object" || body.binding === null) return generic(400);
        const { shareCid: bindingShareCid, capabilityId: _capabilityId, ...binding } = body.binding as Record<string, unknown>;
        const selected = selectedCapability(request, session, capabilityId);
        assertPublishedBinding({ ...binding, shareCid: bindingShareCid }, cid, selected.scope as Record<string, unknown>, selected.source, selected.policy);
        const publicBinding = {
          shareId: binding.shareId, policyCid: binding.policyCid, recipientEmail: binding.recipientEmail, expiry: binding.expiry,
          delegationCid: binding.delegationCid, authorityMaterialHandle: binding.authorityMaterialHandle, authorityMaterialDigest: binding.authorityMaterialDigest,
          contentSource: binding.contentSource, contentSourceDigest: binding.contentSourceDigest, action: binding.action, resource: binding.resource,
        };
        await options.bindingStore!.put(cid, publicBinding); return response(201, { status: "stored" });
      }
      if (url.pathname.startsWith("/.well-known/tinycloud-share/bindings/") && request.method === "GET") {
        const cid = url.pathname.slice("/.well-known/tinycloud-share/bindings/".length).replace(/\.json$/, "");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid)) return generic(400);
        const binding = await options.bindingStore?.get(cid); return binding === undefined ? generic(404) : response(200, binding);
      }
      if (url.pathname.startsWith("/registry/") || url.pathname === "/registry") return proxyRegistry(request, options.registryOrigin, options.registryTransportOrigin);
      return undefinedResponse();
    } catch (error) { if (error instanceof Error && error.message === "sender_not_ready") return response(503, { error: { code: "sender_not_ready" } }); return generic(400); }
  }
  return { handler, publicConfig, readiness: { authReady, senderReady } };
}

async function boundedJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? "0"); if (length > MAX_BODY) throw new Error("body too large");
  const bytes = new Uint8Array(await request.arrayBuffer()); if (bytes.length > MAX_BODY) throw new Error("body too large");
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("body shape"); return value as Record<string, unknown>;
}

async function proxyRegistry(request: Request, origin: string, transportOrigin = origin): Promise<Response> {
  const requestUrl = new URL(request.url); const base = new URL(transportOrigin); const target = new URL(requestUrl.pathname.slice("/registry".length) || "/", base); target.search = requestUrl.search;
  const bytes = new Uint8Array(await request.arrayBuffer());
  const headers = sanitizeUpstreamRequest(requestUrl.pathname, request.method, request.headers, bytes.length, origin);
  const result = await fetch(target, { method: request.method, headers, ...(bytes.length === 0 ? {} : { body: bytes.buffer as ArrayBuffer }), redirect: "error" });
  return sanitizeUpstreamResponse(requestUrl.pathname, request.method, result);
}

function undefinedResponse(): Response { return new Response(null, { status: 404, headers: JSON_HEADERS }); }

export function createShareHostFromEnv(env: NodeJS.ProcessEnv = process.env): ReturnType<typeof createShareHostAdapter> {
  const bundle = loadTrustBundle(env);
  const capabilityRaw = env.SHARE_SENDER_CAPABILITY_JSON;
  const capabilityListRaw = env.SHARE_SENDER_CAPABILITIES_JSON;
  const capabilityValues = capabilityRaw === undefined && capabilityListRaw === undefined ? [] : capabilityListRaw === undefined ? [capabilityRaw] : JSON.parse(capabilityListRaw) as unknown[];
  if (!Array.isArray(capabilityValues) || capabilityValues.some((value) => typeof value !== "string")) throw new Error("SHARE_SENDER_CAPABILITIES_JSON is invalid");
  const parsedCapabilities = bundle.sender.senderPrivateKey.length === 0 ? [] : capabilityValues.map((value) => parseCapability(value as string, bundle));
  if (bundle.environment === "production" && parsedCapabilities.some((value) => typeof value.scope.userId !== "string")) throw new Error("production capabilities require authenticated user bindings");
  const capability = parsedCapabilities[0];
  const capabilities = new Map(parsedCapabilities.map((value, index) => [String(index), value]));
  const initialBindings = env.SHARE_TEST_BINDINGS_JSON === undefined ? {} : JSON.parse(env.SHARE_TEST_BINDINGS_JSON) as Record<string, Record<string, unknown>>;
  const bindingStore = env.SHARE_BINDING_STORE_PATH === undefined ? (bundle.environment === "test" ? new MemoryBindingStore(initialBindings) : undefined) : new TransactionalBindingStore(env.SHARE_BINDING_STORE_PATH);
  const registryOrigin = bundle.public.registryOrigin;
  if (!/^https:\/\/[^/?#:@]+$/.test(registryOrigin)) throw new Error("trust-bundle registryOrigin must be a canonical HTTPS origin");
  const registryTransportOrigin = resolveShareUpstreams(bundle, env).registry;
  const authUsersRaw = env.SHARE_AUTH_USERS_JSON;
  let authUsers: AuthUser[] = [];
  if (authUsersRaw !== undefined) {
    const value = JSON.parse(authUsersRaw) as unknown;
    if (!Array.isArray(value)) throw new Error("SHARE_AUTH_USERS_JSON is invalid");
    authUsers = value.map((candidate) => {
      if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) throw new Error("SHARE_AUTH_USERS_JSON is invalid");
      const user = candidate as Record<string, unknown>;
      if (typeof user.userId !== "string" || typeof user.username !== "string" || typeof user.passwordHash !== "string") throw new Error("SHARE_AUTH_USERS_JSON is invalid");
      parsePasswordHash(user.passwordHash);
      return { userId: user.userId, username: user.username, passwordHash: user.passwordHash };
    });
  }
  return createShareHostAdapter({ bundle, ...(capability === undefined ? {} : { capability }), ...(parsedCapabilities.length > 1 ? { capabilities } : {}), ...(bindingStore === undefined ? {} : { bindingStore }), registryOrigin, registryTransportOrigin, authUsers, testMode: bundle.environment === "test" });
}
