import { createHash } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";
import { CID } from "multiformats/cid";
import { sha256 } from "multiformats/hashes/sha2";
import { canonicalize, toBase64Url } from "@tinycloud/share-envelope";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createShareHostFromEnv } from "../src/host/share-adapter.js";
import worker, { UploadAuthorization, type DurableObjectState, type DurableObjectStorage, type RegistryEnv } from "../packages/registry/src/worker.js";

const SHARE_ORIGIN = "https://share.tinycloud.xyz";
const NODE_AUDIENCE = "did:web:node.tinycloud.xyz";
const NODE_KID = `${NODE_AUDIENCE}#invitation-key-1`;
const NODE_SEED = new Uint8Array(32).fill(3);
const NODE_PUBLIC = ed25519.getPublicKey(NODE_SEED);
const OWNER = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
const SESSION = "did:key:z6MktwupD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7";
const RETENTION = "until-delete";

function bundle(): Record<string, unknown> {
  return {
    version: "tinycloud.share-email-trust-bundle/v1",
    shareOrigin: SHARE_ORIGIN,
    returnOrigin: SHARE_ORIGIN,
    registryOrigin: "https://registry.tinycloud.xyz",
    credentialsOrigin: "https://witness.credentials.org",
    emailOrigin: "https://email.tinycloud.xyz",
    nodeOrigin: "https://node.tinycloud.xyz",
    nodeAudience: NODE_AUDIENCE,
    nodeInvitationKid: NODE_KID,
    nodeInvitationPublicKey: toBase64Url(NODE_PUBLIC),
    nodeKeyVersion: 1,
    nodeEnabled: true,
    issuerDid: "did:web:issuer.credentials.org",
    issuerVct: "opencredentials.email/v1",
    issuerKid: "did:web:issuer.credentials.org#email-signing-key-1",
    issuerPublicKey: toBase64Url(new Uint8Array(32).fill(4)),
    issuerKeyVersion: 1,
    issuerEnabled: true,
  };
}

function timestamp(delta: number): string { return new Date(Date.now() + delta).toISOString(); }
function digest(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("base64url"); }

async function attestation(bytes: Uint8Array, overrides: Record<string, unknown> = {}, signatureSeed = NODE_SEED): Promise<Record<string, unknown>> {
  const unsigned = {
    type: "TinyCloudShareUploadAttestation",
    version: 1,
    issuer: NODE_AUDIENCE,
    kid: NODE_KID,
    ownerDid: OWNER,
    sessionDid: SESSION,
    shareOrigin: SHARE_ORIGIN,
    encryptedBlobCid: CID.create(1, 0x55, await sha256.digest(bytes)).toString(),
    encryptedBlobSha256: digest(bytes),
    byteLength: bytes.byteLength,
    deleteAfter: timestamp(7 * 24 * 60 * 60 * 1000),
    retention: RETENTION,
    issuedAt: timestamp(-1000),
    authorityExpiresAt: timestamp(120 * 1000),
    expiresAt: timestamp(60 * 1000),
    jti: toBase64Url(new Uint8Array(16).fill(Math.floor(Math.random() * 255))),
    ...overrides,
  };
  const signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/upload-attestation/v1\0${canonicalize(unsigned)}`), signatureSeed));
  return { ...unsigned, signature };
}

async function setup() {
  const root = await mkdtemp(`${tmpdir()}/share-upload-attestation-`);
  const keyPath = `${root}/registry-upload.key`;
  const budgetPath = `${root}/upload-budget.ndjson`;
  const host = () => createShareHostFromEnv({
    SHARE_TRUST_BUNDLE: JSON.stringify(bundle()),
    SHARE_TRUST_BUNDLE_ALLOW_TEST: "true",
    SHARE_REGISTRY_UPLOAD_KEY_PATH: keyPath,
    SHARE_UPLOAD_BUDGET_STORE_PATH: budgetPath,
  });
  return { root, host };
}

function shippedRegistryNamespace(): NonNullable<RegistryEnv["UPLOAD_AUTHORIZATION"]> {
  const values = new Map<string, Map<string, unknown>>();
  const locks = new Map<string, Promise<void>>();
  return {
    getByName(name) {
      const stored = values.get(name) ?? new Map<string, unknown>();
      values.set(name, stored);
      const storage: DurableObjectStorage = {
        get: async <T>(key: string) => stored.get(key) as T | undefined,
        put: async <T>(key: string, value: T) => { stored.set(key, value); },
      };
      const state: DurableObjectState = {
        storage,
        blockConcurrencyWhile: async <T>(callback: () => Promise<T>) => {
          const prior = locks.get(name) ?? Promise.resolve();
          let release!: () => void;
          const current = new Promise<void>((resolve) => { release = resolve; });
          const queued = prior.then(() => current);
          locks.set(name, queued);
          await prior;
          try { return await callback(); } finally { release(); if (locks.get(name) === queued) locks.delete(name); }
        },
      };
      const durableObject = new UploadAuthorization(state);
      return { fetch: (input, init) => durableObject.fetch(new Request(input, init)) };
    },
  };
}

async function shippedRegistrySetup(root: string): Promise<{ host: ReturnType<typeof createShareHostFromEnv>; origin: string; fetchFn: typeof fetch; dispose: () => Promise<void> }> {
  const key = new Uint8Array(32).fill(19);
  const keyPath = `${root}/registry-upload.key`;
  await writeFile(keyPath, toBase64Url(key), { mode: 0o600 });
  const namespace = shippedRegistryNamespace();
  const registry: RegistryEnv = {
    REGISTRY: (() => {
      const objects = new Map<string, Uint8Array>();
      return {
        get: async (keyName: string) => { const value = objects.get(keyName); return value === undefined ? null : { arrayBuffer: async () => value.slice().buffer }; },
        put: async (keyName: string, value: ArrayBuffer | Uint8Array) => { objects.set(keyName, value instanceof Uint8Array ? value.slice() : new Uint8Array(value.slice(0))); },
      };
    })(),
    REGISTRY_AUTH_PUBLIC_KEY: toBase64Url(ed25519.getPublicKey(key)),
    REGISTRY_LINK_UPLOAD_PUBLIC_KEY: toBase64Url(ed25519.getPublicKey(key)),
    UPLOAD_AUTHORIZATION: namespace,
  } as RegistryEnv;
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
      const requestInit: RequestInit = {
        method: incoming.method ?? "GET",
        headers: Object.entries(incoming.headers).flatMap(([name, value]) => value === undefined ? [] : [[name, Array.isArray(value) ? value.join(", ") : value]]),
      };
      if (incoming.method !== "GET" && incoming.method !== "HEAD") requestInit.body = Buffer.concat(chunks);
      const request = new Request(`http://127.0.0.1:${(server.address() as { port: number }).port}${incoming.url ?? "/"}`, requestInit);
      const response = await worker.fetch(request, registry);
      outgoing.statusCode = response.status;
      response.headers.forEach((value, name) => outgoing.setHeader(name, value));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.statusCode = 503;
      outgoing.end();
    }
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = (server.address() as { port: number }).port;
  const loopbackFetch: typeof fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    const headers = new Headers(init.headers);
    const body = init.body === undefined ? undefined : Buffer.from(await new Response(init.body as BodyInit).arrayBuffer());
    return await new Promise<Response>((resolve, reject) => {
      const outgoing = httpRequest({ hostname: url.hostname, port: Number(url.port), path: `${url.pathname}${url.search}`, method: init.method ?? "GET", headers: Object.fromEntries(headers.entries()) }, (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
        incoming.on("end", () => resolve(new Response(Buffer.concat(chunks), { status: incoming.statusCode ?? 503, headers: incoming.headers as Record<string, string> })));
      });
      outgoing.on("error", reject);
      if (body !== undefined) outgoing.end(body); else outgoing.end();
    });
  };
  const host = createShareHostFromEnv({
    SHARE_TRUST_BUNDLE: JSON.stringify(bundle()),
    SHARE_HERMETIC_COMPOSITION: "true",
    SHARE_HERMETIC_REGISTRY_ORIGIN: `http://127.0.0.1:${port}`,
    SHARE_REGISTRY_UPLOAD_KEY_PATH: keyPath,
  }, { fetchFn: loopbackFetch });
  const origin = `http://127.0.0.1:${port}`;
  return { host, origin, fetchFn: loopbackFetch, dispose: async () => { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); await rm(root, { recursive: true, force: true }); } };
}

function request(body: Uint8Array, signed: Record<string, unknown> | null, extra: Record<string, string> = {}): Request {
  const headers: Record<string, string> = {
    origin: SHARE_ORIGIN,
    "content-type": "application/vnd.ipld.raw",
    "if-none-match": "*",
    "x-delete-after": String(signed?.deleteAfter ?? timestamp(7 * 24 * 60 * 60 * 1000)),
    "x-tinycloud-retention": JSON.stringify(RETENTION),
    ...extra,
  };
  if (signed !== null) headers["x-tinycloud-upload-attestation"] = JSON.stringify(signed);
  return new Request(`${SHARE_ORIGIN}/api/share/link-only/registry/blobs`, { method: "POST", headers, body: body.slice().buffer as ArrayBuffer });
}

describe("owner-bound upload attestations", () => {
  afterEach(() => vi.restoreAllMocks());

  it("verifies, consumes, and strips one valid attestation before registry authorization", async () => {
    const fixture = await setup();
    try {
      vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ cid: "bafkrei" + "a".repeat(52), deleteAfter: timestamp(7 * 24 * 60 * 60 * 1000) }), { status: 201, headers: { "content-type": "application/json" } }));
      const bytes = new Uint8Array([1, 2, 3]);
      const host = fixture.host();
      const signed = await attestation(bytes);
      signed.deleteAfter = request(bytes, signed).headers.get("x-delete-after")!;
      signed.signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/upload-attestation/v1\0${canonicalize(Object.fromEntries(Object.entries(signed).filter(([key]) => key !== "signature")))}`), NODE_SEED));
      const response = await host.handler(request(bytes, signed));
      expect(response.status).toBe(201);
      const [, init] = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
      const forwarded = new Headers(init.headers);
      expect(forwarded.get("x-tinycloud-upload-attestation")).toBeNull();
      expect(forwarded.get("x-tinycloud-retention")).toBeNull();
      expect(forwarded.get("cookie")).toBeNull();
      expect(forwarded.get("x-tinycloud-authorization")).toContain("TinyCloudShareRegistryAuthorization");
      expect((await host.handler(request(bytes, signed))).status).toBe(401);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });

  it("rejects unknown kid, bad proof, field mismatches, time violations, and malformed bounds", async () => {
    const fixture = await setup();
    try {
      const bytes = new Uint8Array([4, 5, 6]);
      const fields: Array<[string, Record<string, unknown>]> = [
        ["unknown kid", { kid: `${NODE_AUDIENCE}#unknown` }],
        ["issuer", { issuer: "did:web:other.tinycloud.xyz" }],
        ["owner", { ownerDid: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222" }],
        ["session", { sessionDid: "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7" }],
        ["origin", { shareOrigin: "https://other.tinycloud.xyz" }],
        ["cid", { encryptedBlobCid: "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }],
        ["sha256", { encryptedBlobSha256: toBase64Url(new Uint8Array(32).fill(9)) }],
        ["byte length", { byteLength: 4 }],
        ["delete after", { deleteAfter: timestamp(6 * 24 * 60 * 60 * 1000) }],
        ["retention", { retention: "different" }],
        ["unknown field", { unexpected: true }],
        ["bad proof", {}],
      ];
      for (const [name, overrides] of fields) {
        const signed = await attestation(bytes);
        Object.assign(signed, overrides);
        if (name === "bad proof") signed.signature = toBase64Url(ed25519.sign(new TextEncoder().encode("wrong"), NODE_SEED));
        const response = await fixture.host().handler(request(bytes, signed));
        expect(response.status, name).toBe(400);
      }
      for (const [name, overrides] of [["future", { issuedAt: timestamp(31 * 1000) }], ["expired", { expiresAt: timestamp(-1000) }], ["overlong", { expiresAt: timestamp(121 * 1000) }]] as const) {
        const signed = await attestation(bytes, overrides);
        expect((await fixture.host().handler(request(bytes, signed))).status, name).toBe(400);
      }
      const malformed = request(bytes, null, { "x-tinycloud-upload-attestation": "{" });
      expect((await fixture.host().handler(malformed)).status).toBe(400);
      expect((await fixture.host().handler(request(bytes, null, { "x-tinycloud-upload-attestation": "x".repeat(64 * 1024 + 1) }))).status).toBe(413);
      const stripped = request(bytes, null);
      stripped.headers.set("origin", "https://wrong.example");
      const strippedResponse = await fixture.host().handler(stripped);
      expect(strippedResponse.status).toBe(401);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });

  it("enforces the durable budget after restart and across concurrent instances", async () => {
    const fixture = await setup();
    try {
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({ cid: "bafkrei" + "b".repeat(52), deleteAfter: timestamp(7 * 24 * 60 * 60 * 1000) }), { status: 201, headers: { "content-type": "application/json" } }));
      const first = fixture.host();
      const second = fixture.host();
      const body = new Uint8Array([7, 8, 9]);
      const make = async (value: number, host: ReturnType<typeof fixture.host>) => {
        const signed = await attestation(body, { jti: toBase64Url(new Uint8Array(16).fill(value)) });
        signed.deleteAfter = request(body, signed).headers.get("x-delete-after")!;
        signed.signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/upload-attestation/v1\0${canonicalize(Object.fromEntries(Object.entries(signed).filter(([key]) => key !== "signature")))}`), NODE_SEED));
        return host.handler(request(body, signed));
      };
      expect((await make(1, first)).status).toBe(201);
      const restarted = fixture.host();
      const responses = await Promise.all(Array.from({ length: 20 }, (_, index) => make(index + 2, index % 2 === 0 ? restarted : second)));
      expect(responses.filter((value) => value.status === 201)).toHaveLength(19);
      expect(responses.filter((value) => value.status === 429)).toHaveLength(1);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  }, 15_000);

  it("consumes the same attestation jti durably across restart and horizontal concurrency", async () => {
    const fixture = await setup();
    try {
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({ cid: "bafkrei" + "c".repeat(52), deleteAfter: timestamp(7 * 24 * 60 * 60 * 1000) }), { status: 201, headers: { "content-type": "application/json" } }));
      const body = new Uint8Array([4, 5, 6]);
      const jti = toBase64Url(new Uint8Array(16).fill(77));
      const signed = await attestation(body, { jti });
      signed.deleteAfter = request(body, signed).headers.get("x-delete-after")!;
      signed.signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/upload-attestation/v1\0${canonicalize(Object.fromEntries(Object.entries(signed).filter(([key]) => key !== "signature")))}`), NODE_SEED));
      const first = fixture.host();
      const second = fixture.host();
      const results = await Promise.all([first.handler(request(body, signed)), second.handler(request(body, signed))]);
      expect(results.filter((value) => value.status === 201)).toHaveLength(1);
      expect(results.filter((value) => value.status === 401)).toHaveLength(1);
      const restarted = fixture.host();
      expect((await restarted.handler(request(body, signed))).status).toBe(401);
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  });

  it("uses the shipped Worker and UploadAuthorization Durable Object across host restarts", async () => {
    const root = await mkdtemp(`${tmpdir()}/share-upload-worker-store-`);
    const fixture = await shippedRegistrySetup(root);
    try {
      const body = new Uint8Array([11, 12, 13]);
      const make = async (host: ReturnType<typeof createShareHostFromEnv>, value: number) => {
        const signed = await attestation(body, { jti: toBase64Url(new Uint8Array(16).fill(value)) });
        signed.deleteAfter = request(body, signed).headers.get("x-delete-after")!;
        signed.signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/upload-attestation/v1\0${canonicalize(Object.fromEntries(Object.entries(signed).filter(([key]) => key !== "signature")))}`), NODE_SEED));
        return host.handler(request(body, signed));
      };
      const first = fixture.host;
      const second = createShareHostFromEnv({
        SHARE_TRUST_BUNDLE: JSON.stringify(bundle()),
        SHARE_HERMETIC_COMPOSITION: "true",
        SHARE_HERMETIC_REGISTRY_ORIGIN: fixture.origin,
        SHARE_REGISTRY_UPLOAD_KEY_PATH: `${root}/registry-upload.key`,
      }, { fetchFn: fixture.fetchFn });
      const responses = await Promise.all(Array.from({ length: 21 }, (_, index) => make(index % 2 === 0 ? first : second, index + 1)));
      expect(responses.filter((response) => response.status >= 200 && response.status < 300)).toHaveLength(20);
      expect(responses.filter((response) => response.status === 429)).toHaveLength(1);
      const jti = toBase64Url(new Uint8Array(16).fill(88));
      const signed = await attestation(body, { jti, ownerDid: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222" });
      signed.deleteAfter = request(body, signed).headers.get("x-delete-after")!;
      signed.signature = toBase64Url(ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/upload-attestation/v1\0${canonicalize(Object.fromEntries(Object.entries(signed).filter(([key]) => key !== "signature")))}`), NODE_SEED));
      const replay = await Promise.all([first.handler(request(body, signed)), second.handler(request(body, signed))]);
      expect(replay.filter((response) => response.status >= 200 && response.status < 300)).toHaveLength(1);
      expect(replay.filter((response) => response.status === 401)).toHaveLength(1);
      const restarted = createShareHostFromEnv({
        SHARE_TRUST_BUNDLE: JSON.stringify(bundle()),
        SHARE_HERMETIC_COMPOSITION: "true",
        SHARE_HERMETIC_REGISTRY_ORIGIN: fixture.origin,
        SHARE_REGISTRY_UPLOAD_KEY_PATH: `${root}/registry-upload.key`,
      }, { fetchFn: fixture.fetchFn });
      expect((await restarted.handler(request(body, signed))).status).toBe(401);
    } finally { await fixture.dispose(); }
  }, 15_000);
});
