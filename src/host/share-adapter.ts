import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { open, readFile, rm, stat, unlink } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519";
import { loadTrustBundle, type ShareTrustBundle } from "./trust-bundle.js";

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
  readonly capability: { readonly scope: Record<string, unknown>; readonly source: ContentSource };
  readonly capabilities?: ReadonlyMap<string, { readonly scope: Record<string, unknown>; readonly source: ContentSource }>;
  readonly bindingStore: BindingStore;
  readonly registryOrigin: string;
  readonly authUsers?: readonly AuthUser[];
  readonly testMode: boolean;
}

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response { return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...headers } }); }
function generic(status = 400): Response { return response(status, { error: { code: "capability_unavailable" } }); }
function safeString(value: unknown, label: string): string { if (typeof value !== "string" || value.length === 0 || value.length > 4096) throw new Error(label); return value; }
function hash(value: string): string { return createHash("sha256").update(value).digest("base64url"); }

function parseCapability(raw: string, bundle: ShareTrustBundle): { scope: Record<string, unknown>; source: ContentSource } {
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (typeof value !== "object" || value === null || (Object.keys(value).length !== 2 && Object.keys(value).length !== 3) || typeof value.scope !== "object" || value.scope === null || typeof value.source !== "object" || value.source === null || (value.userId !== undefined && typeof value.userId !== "string")) throw new Error("capability shape");
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
  if (scope.recipientEmail !== undefined && typeof scope.recipientEmail !== "string") throw new Error("capability recipient binding");
  return { scope, source };
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

function assertSigningBinding(purpose: string, message: string, binding: Record<string, unknown>, scope: Record<string, unknown>, authorizedSource: ContentSource): void {
  const parsed = JSON.parse(message) as Record<string, unknown>;
  const messageSource = parsed.contentSource as Record<string, unknown> | undefined;
  const authorizationTarget = parsed.authorizationTarget as Record<string, unknown> | undefined;
  const policy = purpose === "envelope" && typeof authorizationTarget?.policyBytes === "string"
    ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(authorizationTarget.policyBytes))) as Record<string, unknown>
    : undefined;
  const recipientEmail = requiredScopeString(scope, "recipientEmail");
  const expectedSourceDigest = sourceDigest(authorizedSource);
  const expected = { shareId: parsed.shareId, recipientEmail, action: authorizedSource.action, resource: authorizedSource.path, expiresAt: purpose === "envelope" ? parsed.expiry : parsed.shareExpiresAt };
  if (!sameJson(binding, expected)) throw new Error("signing binding mismatch");
  if (purpose === "envelope") {
    const target = parsed.target as Record<string, unknown>;
    if (parsed.delegation !== scope.delegation || target?.origin !== scope.targetOrigin || target.nodeAudience !== scope.nodeAudience || target.spaceId !== scope.spaceId || (target.resource as Record<string, unknown>)?.path !== authorizedSource.path || (target.resource as Record<string, unknown>)?.kind !== "exact") throw new Error("envelope signing binding mismatch");
    if (authorizationTarget?.kind !== "policy" || typeof authorizationTarget.policyBytes !== "string") throw new Error("envelope signing target mismatch");
    if (policy?.recipientEmail !== recipientEmail || policy?.action !== authorizedSource.action || policy?.resource !== authorizedSource.path || policy?.expiresAt !== parsed.expiry || !sameJson(policy.contentSource, authorizedSource) || policy.contentSourceDigest !== expectedSourceDigest || policy.issuerDid !== scope.senderDid) throw new Error("policy signing binding mismatch");
  } else if (parsed.senderDid !== scope.senderDid || parsed.targetOrigin !== scope.targetOrigin || parsed.nodeAudience !== scope.nodeAudience || parsed.returnOrigin !== scope.shareOrigin || parsed.delegationCid !== scope.delegationCid || parsed.authorityMaterialHandle !== scope.authorityMaterialHandle || parsed.authorityMaterialDigest !== scope.authorityMaterialDigest || parsed.documentName !== scope.documentName || parsed.senderTrust !== scope.senderTrust || parsed.recipientEmail !== recipientEmail || parsed.action !== authorizedSource.action || parsed.resource !== authorizedSource.path || !sameJson(messageSource, authorizedSource) || parsed.contentSourceDigest !== expectedSourceDigest || parsed.shareExpiresAt !== scope.expiresAt) throw new Error("authorization signing binding mismatch");
}

export function createShareHostAdapter(options: ShareHostOptions): { handler(request: Request): Promise<Response>; publicConfig: Record<string, unknown> } {
  const signers = new Map<string, string>();
  const sessions = new Map<string, ShareSession>();
  const capability = options.capability;
  const publicConfig = { version: "tinycloud.share-email-claim/config-v1", shareOrigin: options.bundle.public.shareOrigin, registryOrigin: options.bundle.public.registryOrigin, nodeOrigin: options.bundle.public.nodeOrigin, credentialsOrigin: options.bundle.public.credentialsOrigin, nodeAudience: options.bundle.public.nodeAudience, issuerDid: options.bundle.public.issuerDid, issuerVct: options.bundle.public.issuerVct, nodeInvitationKid: options.bundle.public.nodeInvitationKid, nodeInvitationPublicKey: options.bundle.public.nodeInvitationPublicKey, nodeKeyVersion: options.bundle.public.nodeKeyVersion, issuerKeyVersion: options.bundle.public.issuerKeyVersion, issuerPublicKey: options.bundle.public.issuerPublicKey, ...(options.testMode ? { environment: "test" } : {}) };
  const selectedCapability = (request: Request, session: ShareSession): { scope: Record<string, unknown>; source: ContentSource } => {
    const requested = new URL(request.url).searchParams.get("capabilityId");
    const candidates = [...(options.capabilities?.values() ?? [capability])].filter((candidate) => candidate.scope.userId === undefined || candidate.scope.userId === session.userId || options.testMode);
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
      if (url.pathname === "/.well-known/tinycloud-share/config.json" && request.method === "GET") return response(200, publicConfig);
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
        return response(200, { scope: browserSafeScope(scope), source: selected.source });
      }
      if (url.pathname === "/api/share/capabilities" && request.method === "GET") {
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const candidates = [...(options.capabilities?.values() ?? [capability])].filter((candidate) => candidate.scope.userId === undefined || candidate.scope.userId === session.userId || options.testMode);
        return response(200, { capabilities: candidates.map((candidate) => ({ capabilityId: (candidate.scope.signingCapability as Record<string, unknown>).capabilityId, scope: browserSafeScope(candidate.scope), source: candidate.source })) });
      }
      if (url.pathname === "/api/share/sign" && request.method === "POST") {
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const body = await boundedJson(request);
        const capabilityId = safeString(body.capabilityId, "capabilityId");
        const selected = selectedCapability(request, session);
        const signer = (selected.scope.signingCapability as Record<string, unknown>);
        if (capabilityId !== signer.capabilityId || (body.purpose !== "envelope" && body.purpose !== "inviteAuthorization")) return generic(403);
        const message = safeString(body.message, "message");
        const binding = bodyBinding(body);
        assertSigningBinding(body.purpose, message, binding, selected.scope as Record<string, unknown>, selected.source);
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
        const session = sessionValid(request, options, sessions); if (session === undefined) return generic(401);
        const body = await boundedJson(request); const cid = safeString(body.shareCid, "shareCid");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid) || typeof body.binding !== "object" || body.binding === null) return generic(400);
        const { shareCid: _shareCid, ...binding } = body.binding as Record<string, unknown>;
        const selected = selectedCapability(request, session);
        if (binding.recipientEmail !== selected.scope.recipientEmail || binding.contentSourceDigest !== sourceDigest(selected.source) || binding.action !== selected.source.action || binding.resource !== selected.source.path) return generic(403);
        await options.bindingStore.put(cid, binding); return response(201, { status: "stored" });
      }
      if (url.pathname.startsWith("/.well-known/tinycloud-share/bindings/") && request.method === "GET") {
        const cid = url.pathname.slice("/.well-known/tinycloud-share/bindings/".length).replace(/\.json$/, "");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid)) return generic(400);
        const binding = await options.bindingStore.get(cid); return binding === undefined ? generic(404) : response(200, binding);
      }
      if (url.pathname.startsWith("/registry/") || url.pathname === "/registry") return proxyRegistry(request, options.registryOrigin);
      return undefinedResponse();
    } catch { return generic(400); }
  }
  return { handler, publicConfig };
}

async function boundedJson(request: Request): Promise<Record<string, unknown>> {
  const length = Number(request.headers.get("content-length") ?? "0"); if (length > MAX_BODY) throw new Error("body too large");
  const bytes = new Uint8Array(await request.arrayBuffer()); if (bytes.length > MAX_BODY) throw new Error("body too large");
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("body shape"); return value as Record<string, unknown>;
}

async function proxyRegistry(request: Request, origin: string): Promise<Response> {
  const requestUrl = new URL(request.url); const base = new URL(origin); const target = new URL(requestUrl.pathname.slice("/registry".length) || "/", base); target.search = requestUrl.search;
  const headers = new Headers(); ["accept", "content-type", "if-none-match", "x-delete-after"].forEach((name) => { const value = request.headers.get(name); if (value !== null) headers.set(name, value); });
  const result = await fetch(target, { method: request.method, headers, ...(request.method === "GET" ? {} : { body: await request.arrayBuffer() }), redirect: "error" });
  return new Response(result.body, { status: result.status, headers: result.headers });
}

function undefinedResponse(): Response { return new Response(null, { status: 404, headers: JSON_HEADERS }); }

export function createShareHostFromEnv(env: NodeJS.ProcessEnv = process.env): ReturnType<typeof createShareHostAdapter> {
  const bundle = loadTrustBundle(env);
  const capabilityRaw = env.SHARE_SENDER_CAPABILITY_JSON;
  const capabilityListRaw = env.SHARE_SENDER_CAPABILITIES_JSON;
  if (capabilityRaw === undefined && capabilityListRaw === undefined) throw new Error("SHARE_SENDER_CAPABILITY_JSON is required");
  const capabilityValues = capabilityListRaw === undefined ? [capabilityRaw] : JSON.parse(capabilityListRaw) as unknown[];
  if (!Array.isArray(capabilityValues) || capabilityValues.length === 0 || capabilityValues.some((value) => typeof value !== "string")) throw new Error("SHARE_SENDER_CAPABILITIES_JSON is invalid");
  const parsedCapabilities = capabilityValues.map((value) => parseCapability(value as string, bundle));
  if (bundle.environment === "production" && parsedCapabilities.some((value) => typeof value.scope.userId !== "string" || typeof value.scope.recipientEmail !== "string")) throw new Error("production capabilities require authenticated user and recipient bindings");
  const capability = parsedCapabilities[0]!;
  const capabilities = new Map(parsedCapabilities.map((value, index) => [String(index), value]));
  const initialBindings = env.SHARE_TEST_BINDINGS_JSON === undefined ? {} : JSON.parse(env.SHARE_TEST_BINDINGS_JSON) as Record<string, Record<string, unknown>>;
  const bindingStore = env.SHARE_BINDING_STORE_PATH === undefined ? (bundle.environment === "test" ? new MemoryBindingStore(initialBindings) : (() => { throw new Error("SHARE_BINDING_STORE_PATH is required in production"); })()) : new TransactionalBindingStore(env.SHARE_BINDING_STORE_PATH);
  const registryOrigin = bundle.environment === "production" ? bundle.public.registryOrigin : (env.SHARE_REGISTRY_ORIGIN ?? bundle.public.registryOrigin);
  if (!/^https:\/\/[^/?#:@]+$/.test(registryOrigin)) throw new Error("SHARE_REGISTRY_ORIGIN must be a canonical HTTPS origin");
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
  if (bundle.environment === "production" && authUsers.length === 0) throw new Error("SHARE_AUTH_USERS_JSON is required for the authenticated Share host");
  return createShareHostAdapter({ bundle, capability, ...(parsedCapabilities.length > 1 ? { capabilities } : {}), bindingStore, registryOrigin, authUsers, testMode: bundle.environment === "test" });
}
