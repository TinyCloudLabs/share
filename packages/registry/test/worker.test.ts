import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import { computeCid } from "@tinycloud/share-envelope";
import {
  DELETE_AFTER_HEADER,
  IF_NONE_MATCH_HEADER,
  RAW_BLOCK_CONTENT_TYPE,
} from "../src/client.js";
import worker, { type RegistryEnv } from "../src/worker.js";

const DOMAIN = "xyz.tinycloud.share/registry-authorization/v1\0";
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

function env(): RegistryEnv {
  return {
    REGISTRY: bucket(),
    REGISTRY_LINK_UPLOAD_PUBLIC_KEY: b64(publicKey),
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
    tampered.proof.signature = `${tampered.proof.signature.slice(0, -1)}${tampered.proof.signature.endsWith("A") ? "B" : "A"}`;
    expect((await worker.fetch(request(bytes, deleteAfter, JSON.stringify(tampered)), env())).status).toBe(401);

    expect((await worker.fetch(request(bytes, deleteAfter, authorization(bytes, deleteAfter, { audience: "https://wrong.example" })), env())).status).toBe(401);
    expect((await worker.fetch(request(bytes, deleteAfter, authorization(bytes, deleteAfter, { expiresAt: new Date(Date.now() - 1_000).toISOString() })), env())).status).toBe(401);

    const replayEnv = env();
    expect((await worker.fetch(request(bytes, deleteAfter, signed), replayEnv)).status).toBe(201);
    expect((await worker.fetch(request(bytes, deleteAfter, signed), replayEnv)).status).toBe(401);
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
