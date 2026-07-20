import { createHash, randomBytes } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519";
import { loadTrustBundle, type ShareTrustBundle } from "./trust-bundle.js";

function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
const SIGNATURE_DOMAINS = { envelope: "xyz.tinycloud.share/envelope/v1\0", inviteAuthorization: "xyz.tinycloud.share/invite-authorization/v1\0" } as const;
type ContentSource = Record<string, unknown>;
function validateSource(value: ContentSource): ContentSource { if (value.kind !== "kv" && value.kind !== "sql" || typeof value.space !== "string" || typeof value.path !== "string" || typeof value.action !== "string") throw new Error("source"); return value; }
function stable(value: unknown): string { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`; return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}`; }

const MAX_BODY = 128 * 1024;
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" };
const B64_128 = /^[A-Za-z0-9_-]{22}$/;
const B64_256 = /^[A-Za-z0-9_-]{43}$/;

export interface BindingStore {
  get(cid: string): Promise<Record<string, unknown> | undefined>;
  put(cid: string, binding: Record<string, unknown>): Promise<void>;
}

export class FileBindingStore implements BindingStore {
  constructor(private readonly path: string) {}
  private async read(): Promise<Record<string, Record<string, unknown>>> { try { return JSON.parse(await readFile(this.path, "utf8")) as Record<string, Record<string, unknown>>; } catch { return {}; } }
  async get(cid: string): Promise<Record<string, unknown> | undefined> { return (await this.read())[cid]; }
  async put(cid: string, binding: Record<string, unknown>): Promise<void> { const value = await this.read(); value[cid] = binding; const temporary = `${this.path}.${process.pid}.tmp`; await writeFile(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600 }); await rename(temporary, this.path); }
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
  readonly sessionSecret: string;
  readonly testMode: boolean;
}

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response { return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...headers } }); }
function generic(status = 400): Response { return response(status, { error: { code: "capability_unavailable" } }); }
function safeString(value: unknown, label: string): string { if (typeof value !== "string" || value.length === 0 || value.length > 4096) throw new Error(label); return value; }
function hash(value: string): string { return createHash("sha256").update(value).digest("base64url"); }

function parseCapability(raw: string, bundle: ShareTrustBundle): { scope: Record<string, unknown>; source: ContentSource } {
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (Object.keys(value).length !== 2 || typeof value.scope !== "object" || value.scope === null || typeof value.source !== "object" || value.source === null) throw new Error("capability shape");
  const scope = { ...(value.scope as Record<string, unknown>) };
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
  return { scope, source };
}

function sessionValid(request: Request, options: ShareHostOptions): boolean {
  const origin = request.headers.get("origin");
  if (origin !== options.bundle.public.shareOrigin) return false;
  const cookie = request.headers.get("cookie") ?? "";
  return cookie.split(";").some((part) => part.trim() === `share_session=${options.sessionSecret}`) || (options.testMode && request.url.includes("127.0.0.1"));
}

function cookie(request: Request, name: string): string | undefined {
  return request.headers.get("cookie")?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

function bodyBinding(value: Record<string, unknown>): Record<string, unknown> {
  if (typeof value.binding !== "object" || value.binding === null || Array.isArray(value.binding)) throw new Error("binding");
  return value.binding as Record<string, unknown>;
}

function assertSigningBinding(purpose: string, message: string, binding: Record<string, unknown>, scope: Record<string, unknown>): void {
  const parsed = JSON.parse(message) as Record<string, unknown>;
  const source = parsed.contentSource as Record<string, unknown> | undefined;
  const expected = ["shareId", "recipientEmail", "action", "resource", "expiresAt"];
  if (Object.keys(binding).length !== expected.length || expected.some((key) => binding[key] !== (key === "expiresAt" ? (parsed.expiresAt ?? parsed.expiry ?? parsed.shareExpiresAt) : key === "action" ? (parsed.action ?? source?.action) : key === "resource" ? (parsed.resource ?? source?.path) : parsed[key]))) throw new Error("signing binding mismatch");
  if (purpose === "envelope") {
    const target = parsed.target as Record<string, unknown>;
    if (target?.origin !== scope.targetOrigin || target.nodeAudience !== scope.nodeAudience || (target.resource as Record<string, unknown>)?.path !== binding.resource) throw new Error("envelope signing binding mismatch");
    const authorizationTarget = parsed.authorizationTarget as Record<string, unknown>;
    if (authorizationTarget?.kind !== "policy" || typeof authorizationTarget.policyBytes !== "string") throw new Error("envelope signing target mismatch");
    const policy = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(authorizationTarget.policyBytes))) as Record<string, unknown>;
    if (policy.recipientEmail !== binding.recipientEmail || policy.action !== binding.action || policy.resource !== binding.resource || policy.expiresAt !== binding.expiresAt) throw new Error("policy signing binding mismatch");
  } else if (parsed.senderDid !== scope.senderDid || parsed.targetOrigin !== scope.targetOrigin || parsed.nodeAudience !== scope.nodeAudience || parsed.contentSourceDigest === undefined) throw new Error("authorization signing binding mismatch");
}

export function createShareHostAdapter(options: ShareHostOptions): { handler(request: Request): Promise<Response>; publicConfig: Record<string, unknown> } {
  const signers = new Map<string, string>();
  const capability = options.capability;
  const publicConfig = { version: "tinycloud.share-email-claim/config-v1", ...options.bundle.public, ...(options.testMode ? { environment: "test" } : {}) };
  const selectedCapability = (request: Request): { scope: Record<string, unknown>; source: ContentSource } => options.capabilities?.get(cookie(request, "share_case") ?? "0") ?? capability;
  async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/.well-known/tinycloud-share/config.json" && request.method === "GET") return response(200, publicConfig);
      if (url.pathname === "/api/share/capability" && request.method === "GET") {
        if (!sessionValid(request, options)) return generic(503);
        const selected = selectedCapability(request);
        const scope = selected.scope as Record<string, unknown>;
        return response(200, { scope, source: capability.source }, { "set-cookie": `share_session=${options.sessionSecret}; HttpOnly; SameSite=Strict; Path=/; Max-Age=300` });
      }
      if (url.pathname === "/api/share/sign" && request.method === "POST") {
        if (!sessionValid(request, options)) return generic(503);
        const body = await boundedJson(request);
        const capabilityId = safeString(body.capabilityId, "capabilityId");
        const selected = selectedCapability(request);
        const signer = (selected.scope.signingCapability as Record<string, unknown>);
        if (capabilityId !== signer.capabilityId || (body.purpose !== "envelope" && body.purpose !== "inviteAuthorization")) return generic(403);
        const message = safeString(body.message, "message");
        const binding = bodyBinding(body);
        assertSigningBinding(body.purpose, message, binding, selected.scope as Record<string, unknown>);
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
        if (!sessionValid(request, options)) return generic(503);
        const body = await boundedJson(request); const cid = safeString(body.shareCid, "shareCid");
        if (!/^bafkrei[a-z2-7]{52}$/.test(cid) || typeof body.binding !== "object" || body.binding === null) return generic(400);
        await options.bindingStore.put(cid, body.binding as Record<string, unknown>); return response(201, { status: "stored" });
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
  const capability = parsedCapabilities[0]!;
  const capabilities = new Map(parsedCapabilities.map((value, index) => [String(index), value]));
  const initialBindings = env.SHARE_TEST_BINDINGS_JSON === undefined ? {} : JSON.parse(env.SHARE_TEST_BINDINGS_JSON) as Record<string, Record<string, unknown>>;
  const bindingStore = env.SHARE_BINDING_STORE_PATH === undefined ? (bundle.environment === "test" ? new MemoryBindingStore(initialBindings) : (() => { throw new Error("SHARE_BINDING_STORE_PATH is required in production"); })()) : new FileBindingStore(env.SHARE_BINDING_STORE_PATH);
  const registryOrigin = env.SHARE_REGISTRY_ORIGIN ?? bundle.public.registryOrigin;
  if (!/^https:\/\/[^/?#:@]+$/.test(registryOrigin) && bundle.environment === "production") throw new Error("SHARE_REGISTRY_ORIGIN must be a canonical HTTPS origin");
  return createShareHostAdapter({ bundle, capability, ...(parsedCapabilities.length > 1 ? { capabilities } : {}), bindingStore, registryOrigin, sessionSecret: env.SHARE_SESSION_SECRET ?? (bundle.environment === "test" ? "fixture-session" : (() => { throw new Error("SHARE_SESSION_SECRET is required"); })()), testMode: bundle.environment === "test" });
}
