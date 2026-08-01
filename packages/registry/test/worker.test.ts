import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import { computeCid } from "@tinycloud/share-envelope";
import {
  DELETE_AFTER_HEADER,
  IF_NONE_MATCH_HEADER,
  RAW_BLOCK_CONTENT_TYPE,
} from "../src/client.js";
import worker, { UploadAuthorization, type DurableObjectState, type DurableObjectStorage, type RegistryEnv } from "../src/worker.js";

const DOMAIN = "xyz.tinycloud.share/registry-authorization/v1\0";
const STORE_DOMAIN = "xyz.tinycloud.share/registry-store/v1\0";
const ORIGIN = "https://registry.tinycloud.xyz";
const privateKey = new Uint8Array(32).fill(7);
const publicKey = ed25519.getPublicKey(privateKey);

function b64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function stableShallow(value: Record<string, unknown>): string {
  return JSON.stringify(
    Object.keys(value)
      .sort()
      .reduce<Record<string, unknown>>((result, key) => {
        result[key] = value[key];
        return result;
      }, {}),
  );
}

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => `${JSON.stringify(key)}:${stable((value as Record<string, unknown>)[key])}`).join(",")}}`;
}

function storeRequest(body: Record<string, unknown>, key = privateKey): Request {
  const signature = b64(ed25519.sign(new TextEncoder().encode(`${STORE_DOMAIN}${stable(body)}`), key));
  return new Request(`${ORIGIN}/internal/upload-authorizations`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-tinycloud-registry-store-signature": signature },
    body: JSON.stringify(body),
  });
}

function authorization(
  bytes: Uint8Array,
  deleteAfter: string,
  overrides: Record<string, unknown> = {},
): string {
  const body = {
    action: "tinycloud.share/upload",
    audience: ORIGIN,
    bodyDigest: createHash("sha256").update(bytes).digest("base64url"),
    contentLength: bytes.byteLength,
    deleteAfter,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    jti: b64(new Uint8Array(16).fill(5)),
    mode: "link-only",
    resource: "registry/blobs",
    sessionBinding: b64(new Uint8Array(32).fill(4)),
    type: "TinyCloudShareRegistryAuthorization",
    version: 1,
    ...overrides,
  };
  const message = new TextEncoder().encode(`${DOMAIN}${stableShallow(body)}`);
  return JSON.stringify({
    authorization: body,
    proof: {
      alg: "EdDSA",
      signature: b64(ed25519.sign(message, privateKey)),
    },
  });
}

function legacyAuthorization(): string {
  const body = {
    action: "tinycloud.share/upload",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    resource: "registry/blobs",
    type: "TinyCloudShareInviteAuthorization",
    version: 1,
  };
  const message = new TextEncoder().encode(`${DOMAIN}${stableShallow(body)}`);
  return JSON.stringify({
    authorization: body,
    proof: {
      alg: "EdDSA",
      signature: b64(ed25519.sign(message, privateKey)),
    },
  });
}

function bucket(): RegistryEnv["REGISTRY"] {
  const values = new Map<string, { bytes: Uint8Array; customMetadata?: Record<string, string> }>();
  return {
    get: async (key) => {
      const value = values.get(key);
      return value === undefined
        ? null
        : { arrayBuffer: async () => value.bytes.slice().buffer, ...(value.customMetadata ? { customMetadata: value.customMetadata } : {}) };
    },
    put: async (key, value, options) => {
      const metadata = options as { customMetadata?: Record<string, string> } | undefined;
      values.set(
        key,
        {
          bytes: value instanceof Uint8Array ? value.slice() : new Uint8Array(value.slice(0)),
          ...(metadata?.customMetadata ? { customMetadata: metadata.customMetadata } : {}),
        },
      );
    },
    delete: async (keys) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) values.delete(key);
    },
  };
}

function uploadAuthorizationNamespace(): NonNullable<RegistryEnv["UPLOAD_AUTHORIZATION"]> {
  const values = new Map<string, Map<string, unknown>>();
  const locks = new Map<string, Promise<void>>();
  return {
    getByName(name) {
      const value = values.get(name) ?? new Map<string, unknown>();
      values.set(name, value);
      const storage: DurableObjectStorage = {
        get: async <T>(key: string) => value.get(key) as T | undefined,
        put: async <T>(key: string, next: T) => { value.set(key, next); },
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
      return {
        fetch: (input, init) => durableObject.fetch(new Request(input, init)),
      };
    },
  };
}

function env(uploadAuthorization = uploadAuthorizationNamespace()): RegistryEnv {
  return {
    REGISTRY: bucket(),
    REGISTRY_LINK_UPLOAD_PUBLIC_KEY: b64(publicKey),
    UPLOAD_AUTHORIZATION: uploadAuthorization,
    MAX_BLOB_BYTES: "65536",
  };
}

function request(
  bytes: Uint8Array,
  deleteAfter: string,
  auth = authorization(bytes, deleteAfter),
): Request {
  return new Request(`${ORIGIN}/blobs`, {
    method: "POST",
    headers: {
      origin: ORIGIN,
      "content-type": RAW_BLOCK_CONTENT_TYPE,
      [IF_NONE_MATCH_HEADER]: "*",
      [DELETE_AFTER_HEADER]: deleteAfter,
      "x-tinycloud-authorization": auth,
    },
    body: bytes.slice().buffer as ArrayBuffer,
  });
}

describe("production link-only registry authorization", () => {
  it("denies missing, tampered, wrong-audience, expired, and replayed authorizations", async () => {
    const bytes = new Uint8Array([2, 4, 6]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const missing = request(bytes, deleteAfter);
    missing.headers.delete("x-tinycloud-authorization");
    expect((await worker.fetch(missing, env())).status).toBe(401);

    const signed = authorization(bytes, deleteAfter);
    const tampered = JSON.parse(signed) as { proof: { signature: string } };
    tampered.proof.signature = `${tampered.proof.signature[0] === "A" ? "B" : "A"}${tampered.proof.signature.slice(1)}`;
    expect((await worker.fetch(request(bytes, deleteAfter, JSON.stringify(tampered)), env())).status).toBe(401);

    expect((await worker.fetch(request(bytes, deleteAfter, authorization(bytes, deleteAfter, { audience: "https://wrong.example" })), env())).status).toBe(401);
    expect((await worker.fetch(request(bytes, deleteAfter, authorization(bytes, deleteAfter, { expiresAt: new Date(Date.now() - 1_000).toISOString() })), env())).status).toBe(401);

    const replayEnv = env();
    expect((await worker.fetch(request(bytes, deleteAfter, signed), replayEnv)).status).toBe(201);
    expect((await worker.fetch(request(bytes, deleteAfter, signed), replayEnv)).status).toBe(401);
  });

  it("fails closed without the durable single-use primitive", async () => {
    const bytes = new Uint8Array([2, 4, 6]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const unavailable = env();
    delete unavailable.UPLOAD_AUTHORIZATION;
    expect((await worker.fetch(request(bytes, deleteAfter), unavailable)).status).toBe(401);
    expect((await worker.fetch(storeRequest({ expiresAt: Date.now() + 60_000, key: "jti", operation: "consume" }), unavailable)).status).toBe(503);
  });

  it("uses the exported Durable Object for atomic replay state across fresh instances", async () => {
    const values = new Map<string, unknown>();
    const storage: DurableObjectStorage = {
      get: async <T>(key: string) => values.get(key) as T | undefined,
      put: async <T>(key: string, value: T) => { values.set(key, value); },
    };
    let queue = Promise.resolve();
    const state: DurableObjectState = {
      storage,
      blockConcurrencyWhile: async <T>(callback: () => Promise<T>) => {
        const result = queue.then(callback);
        queue = result.then(() => undefined, () => undefined);
        return result;
      },
    };
    const [first, second] = await Promise.all([
      new UploadAuthorization(state).fetch(new Request("https://upload-authorization/consume", { method: "POST" })),
      new UploadAuthorization(state).fetch(new Request("https://upload-authorization/consume", { method: "POST" })),
    ]);
    expect([first.status, second.status].sort((a, b) => a - b)).toEqual([204, 409]);
    expect((await new UploadAuthorization(state).fetch(new Request("https://upload-authorization/consume", { method: "POST" }))).status).toBe(409);
  });

  it("enforces the twenty-reservation boundary through the Worker binding across instances", async () => {
    const sharedAuthorization = uploadAuthorizationNamespace();
    const first = env(sharedAuthorization);
    const second = env(sharedAuthorization);
    const body = { key: "principal", limit: 20, now: Date.now(), operation: "reserve", windowMs: 86_400_000 };
    const responses = await Promise.all(Array.from({ length: 21 }, (_, index) => worker.fetch(storeRequest({ ...body, key: body.key }), index % 2 === 0 ? first : second)));
    expect(responses.filter((response) => response.status === 204)).toHaveLength(20);
    expect(responses.filter((response) => response.status === 503)).toHaveLength(1);
  });

  it("accepts exactly one concurrent request across independent Worker instances for one JTI", async () => {
    const bytes = new Uint8Array([7, 7, 7]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const sharedBucket = bucket();
    const sharedAuthorization = uploadAuthorizationNamespace();
    const first = env(sharedAuthorization);
    const second = env(sharedAuthorization);
    first.REGISTRY = sharedBucket;
    second.REGISTRY = sharedBucket;
    const [left, right] = await Promise.all([
      worker.fetch(request(bytes, deleteAfter), first),
      worker.fetch(request(bytes, deleteAfter), second),
    ]);
    expect([left.status, right.status].sort((a, b) => a - b)).toEqual([201, 401]);
  });

  it("accepts a short-lived session-bound authorization for exactly the uploaded ciphertext", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const response = await worker.fetch(request(bytes, deleteAfter), env());
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      cid: await computeCid(bytes),
      deleteAfter,
    });
  });

  it("rejects body, retention, session, expiry, and key substitutions", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const signed = authorization(bytes, deleteAfter);
    const changedBody = await worker.fetch(
      request(new Uint8Array([1, 2, 3, 5]), deleteAfter, signed),
      env(),
    );
    expect(changedBody.status).toBe(401);

    const changedRetention = await worker.fetch(
      request(
        bytes,
        new Date(Date.now() + 30_000).toISOString(),
        signed,
      ),
      env(),
    );
    expect(changedRetention.status).toBe(401);

    for (const overrides of [
      { sessionBinding: "invalid" },
      { expiresAt: new Date(Date.now() - 1_000).toISOString() },
      { expiresAt: new Date(Date.now() + 10 * 60_000).toISOString() },
      { mode: "email" },
      { resource: "registry/anything" },
    ]) {
      const response = await worker.fetch(
        request(bytes, deleteAfter, authorization(bytes, deleteAfter, overrides)),
        env(),
      );
      expect(response.status).toBe(401);
    }

    const wrongKey = env();
    wrongKey.REGISTRY_LINK_UPLOAD_PUBLIC_KEY = b64(
      ed25519.getPublicKey(new Uint8Array(32).fill(8)),
    );
    expect(
      (await worker.fetch(request(bytes, deleteAfter), wrongKey)).status,
    ).toBe(401);
  });

  it("rejects link-only uploads without the dedicated key and never accepts the browser origin on that path", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const missing = env();
    delete missing.REGISTRY_LINK_UPLOAD_PUBLIC_KEY;
    expect(
      (await worker.fetch(request(bytes, deleteAfter), missing)).status,
    ).toBe(401);

    const browserRequest = request(bytes, deleteAfter);
    browserRequest.headers.set("origin", "https://share.tinycloud.xyz");
    expect(
      (await worker.fetch(browserRequest, env())).status,
    ).toBe(401);
  });

  it("preserves the existing Node authorization path without accepting link-only proofs there", async () => {
    const bytes = new Uint8Array([9, 8, 7]);
    const deleteAfter = new Date(Date.now() + 60_000).toISOString();
    const existingEnv = env();
    existingEnv.REGISTRY_AUTH_PUBLIC_KEY = b64(publicKey);
    const existingRequest = request(bytes, deleteAfter, legacyAuthorization());
    existingRequest.headers.set("origin", "https://share.tinycloud.xyz");
    expect(
      (await worker.fetch(existingRequest, existingEnv)).status,
    ).toBe(201);

    const linkProofOnExistingPath = request(bytes, deleteAfter);
    linkProofOnExistingPath.headers.set(
      "origin",
      "https://share.tinycloud.xyz",
    );
    expect(
      (await worker.fetch(linkProofOnExistingPath, existingEnv)).status,
    ).toBe(401);
  });

  it("persists the retention boundary and denies reads after expiry", async () => {
    const bytes = new Uint8Array([6, 7, 8]);
    const deleteAfter = new Date(Date.now() + 1_000).toISOString();
    const registry = bucket();
    const productionEnv = { ...env(), REGISTRY: registry };
    const uploaded = await worker.fetch(request(bytes, deleteAfter), productionEnv);
    expect(uploaded.status).toBe(201);
    const cid = await computeCid(bytes);
    const live = await worker.fetch(new Request(`${ORIGIN}/blobs/${cid}`), productionEnv);
    expect(live.status).toBe(200);
    expect(Number(live.headers.get("cache-control")?.match(/max-age=(\d+)/)?.[1])).toBeLessThanOrEqual(1);

    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const expired = await worker.fetch(new Request(`${ORIGIN}/blobs/${cid}`), productionEnv);
    expect(expired.status).toBe(410);
    expect(await worker.fetch(new Request(`${ORIGIN}/blobs/${cid}`), productionEnv)).toHaveProperty("status", 404);
  });

  it("rejects an unauthenticated oversized request before reading its body", async () => {
    let read = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(128)); controller.close(); },
      pull() { read = true; },
    });
    const response = await worker.fetch(new Request(`${ORIGIN}/blobs`, {
      method: "POST",
      headers: { origin: ORIGIN, [IF_NONE_MATCH_HEADER]: "*", "content-length": "999999" },
      body,
      // undici requires duplex for a streaming request body.
      duplex: "half",
    } as RequestInit), env());
    expect(response.status).toBe(401);
    expect(read).toBe(false);
  });
});
