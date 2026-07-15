import { ed25519 } from "@noble/curves/ed25519";
import {
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  nativeVerifiedRecipientBundleV2Schema,
  open,
  parseShareUrl,
  recipientDidEnvelopeV2Schema,
  recipientDidEnvelopeV2SigningBytes,
  toBase64Url,
  type RecipientDidEnvelopeV2,
} from "@tinycloud/share-envelope";
import { fetchBlob } from "@tinycloud/share-registry";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { beforeEach, describe, expect, it } from "vitest";

import {
  createRecipientDidShare,
  type RecipientDidEnvelopeRequest,
  type RecipientDidSenderAdapter,
} from "../src/recipient-did.js";
import { main } from "../src/cli.js";
import vector from "../../envelope/test/vectors/recipient-did-v2.json";

const REGISTRY_BASE = "http://registry.local";
const NOW = Date.parse("2029-01-01T00:00:00.000Z");
const fixture = recipientDidEnvelopeV2Schema.parse(vector.envelope);
const native = nativeVerifiedRecipientBundleV2Schema.parse(vector.nativeVerified);
let registry: DevRegistry;
let events: string[];

function handlerFetch(target: DevRegistry): typeof fetch {
  return async (input, init) => {
    events.push("registry");
    const requestInit = init?.body === undefined || init.body === null
      ? init
      : ({ ...init, duplex: "half" } as RequestInit);
    return target.handler(new Request(input, requestInit));
  };
}

function signRequest(request: RecipientDidEnvelopeRequest): RecipientDidEnvelopeV2 {
  const seed = fromBase64Url(vector.currentSdkFixture.sessionJwkD);
  const signerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(seed));
  const payload = {
    version: 2 as const,
    shareId: request.shareId,
    delegation: fixture.delegation,
    authorizationTarget: { kind: "recipientDid" as const, did: request.recipientDid },
    target: {
      ...request.target,
      actions: [...request.target.actions],
    },
    display: request.display,
    expiry: request.expiry,
    signature: { signerDid, algorithm: "Ed25519" as const },
  };
  return {
    ...payload,
    signature: {
      ...payload.signature,
      value: toBase64Url(ed25519.sign(recipientDidEnvelopeV2SigningBytes(payload), seed)),
    },
  };
}

function adapter(overrides: Partial<RecipientDidSenderAdapter> = {}): RecipientDidSenderAdapter {
  return {
    createAndSignEnvelope: async (request) => {
      events.push("sign");
      return signRequest(request);
    },
    verifyDelegationBundle: async (_bundle, now) => {
      events.push("native");
      const envelope = lastEnvelope;
      if (envelope === undefined) throw new Error("test envelope missing");
      return {
        ...native,
        recipientDid: envelope.authorizationTarget.did,
        scope: {
          spaceId: envelope.target.spaceId,
          resource: envelope.target.resource,
          actions: envelope.target.actions,
        },
        expiry: envelope.expiry,
        ...(now.getTime() > Date.parse(envelope.expiry) ? { notBefore: envelope.expiry } : {}),
      };
    },
    putExact: async () => { events.push("tinycloud-put"); },
    ...overrides,
  };
}

let lastEnvelope: RecipientDidEnvelopeV2 | undefined;

function options(overrides: Record<string, unknown> = {}) {
  const baseAdapter = adapter();
  return {
    content: new TextEncoder().encode("# Addressed file"),
    filename: "report.md",
    recipientDid: fixture.authorizationTarget.did,
    origin: fixture.target.origin,
    nodeAudience: fixture.target.nodeAudience,
    spaceId: fixture.target.spaceId,
    registryBaseUrl: REGISTRY_BASE,
    allowedOrigins: [fixture.target.origin],
    now: () => NOW,
    expiresAt: new Date("2096-10-02T07:06:40.000Z"),
    fetchFn: handlerFetch(registry),
    adapter: {
      ...baseAdapter,
      createAndSignEnvelope: async (request: RecipientDidEnvelopeRequest) => {
        events.push("sign");
        lastEnvelope = signRequest(request);
        return lastEnvelope;
      },
    },
    ...overrides,
  };
}

beforeEach(() => {
  registry = createDevRegistry();
  events = [];
  lastEnvelope = undefined;
});

describe("createRecipientDidShare", () => {
  it("verifies, copies to TinyCloud, and stores only the encrypted envelope", async () => {
    const captured: Uint8Array[] = [];
    const result = await createRecipientDidShare(options({
      onKeyBuffer: (key: Uint8Array) => { captured.push(key); },
    }));
    expect(events).toEqual(["sign", "native", "tinycloud-put", "registry"]);
    expect(registry.store.size).toBe(1);
    expect(captured).toHaveLength(1);
    expect(captured[0]?.every((byte) => byte === 0)).toBe(true);

    const { ciphertextCid, key32 } = parseShareUrl(result.url);
    const blob = await fetchBlob(REGISTRY_BASE, ciphertextCid, { fetchFn: handlerFetch(registry) });
    const decoded = recipientDidEnvelopeV2Schema.parse(
      JSON.parse(new TextDecoder().decode(await open(blob, key32))),
    );
    expect(decoded).toEqual(result.envelope);
    expect(decoded.target.resource.path).toBe(`shares/${result.shareId}/report.md`);
    expect(decoded.target.actions).toEqual(["tinycloud.kv/get"]);
    expect("content" in decoded).toBe(false);
  });

  it("normalizes a millisecond expiry once for the grant, envelope, and registry", async () => {
    let requestedExpiry: string | undefined;
    let requestedRegistryRetention: string | null = null;
    const baseAdapter = adapter();
    const result = await createRecipientDidShare(options({
      expiresAt: new Date("2096-10-02T07:06:40.987Z"),
      fetchFn: async (input: string | URL | Request, init?: RequestInit) => {
        requestedRegistryRetention = new Headers(init?.headers).get(
          "x-delete-after",
        );
        return handlerFetch(registry)(input, init);
      },
      adapter: {
        ...baseAdapter,
        createAndSignEnvelope: async (request: RecipientDidEnvelopeRequest) => {
          events.push("sign");
          requestedExpiry = request.expiry;
          lastEnvelope = signRequest(request);
          return lastEnvelope;
        },
      },
    }));

    expect(requestedExpiry).toBe("2096-10-02T07:06:40.000Z");
    expect(result.expiry).toBe(requestedExpiry);
    expect(result.envelope.expiry).toBe(requestedExpiry);
    expect(requestedRegistryRetention).toBe(requestedExpiry);
    expect(Date.parse(result.registryDeleteAfter)).toBeLessThanOrEqual(
      Date.parse(requestedExpiry!),
    );
  });

  it("fails before SDK, TinyCloud, or registry activity for invalid routing or identity", async () => {
    await expect(createRecipientDidShare(options({
      recipientDid: fixture.authorizationTarget.did.toUpperCase(),
    }))).rejects.toThrow(/canonical/);
    await expect(createRecipientDidShare(options({
      nodeAudience: "did:web:other.example",
    }))).rejects.toThrow(/exactly match/);
    await expect(createRecipientDidShare(options({
      allowedOrigins: [],
    }))).rejects.toThrow(/allowlist/);
    expect(events).toEqual([]);
    expect(registry.store.size).toBe(0);
  });

  it("does not copy or publish when the fixed-purpose SDK returns different signed fields", async () => {
    const mismatching = adapter({
      createAndSignEnvelope: async (request) => {
        events.push("sign");
        lastEnvelope = signRequest({ ...request, shareId: "different-share" });
        return lastEnvelope;
      },
    });
    await expect(createRecipientDidShare(options({ adapter: mismatching })))
      .rejects.toThrow(/differs/);
    expect(events).toEqual(["sign"]);
    expect(registry.store.size).toBe(0);
  });

  it("publishes no registry link when the TinyCloud copy fails", async () => {
    const failing = adapter({
      createAndSignEnvelope: async (request) => {
        events.push("sign");
        lastEnvelope = signRequest(request);
        return lastEnvelope;
      },
      putExact: async () => {
        events.push("tinycloud-put");
        throw new Error("node unavailable");
      },
    });
    await expect(createRecipientDidShare(options({ adapter: failing })))
      .rejects.toThrow(/node unavailable/);
    expect(events).toEqual(["sign", "native", "tinycloud-put"]);
    expect(registry.store.size).toBe(0);
  });
});

describe("recipient-DID CLI boundary", () => {
  it("parses --recipient-did and fails closed when the SDK lane is not linked", async () => {
    const errors: string[] = [];
    const original = process.stderr.write;
    process.stderr.write = ((chunk: string | Uint8Array) => {
      errors.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    try {
      const code = await main([
        "create",
        "../../README.md",
        "--recipient-did", fixture.authorizationTarget.did,
        "--origin", fixture.target.origin,
        "--node-audience", fixture.target.nodeAudience,
        "--space", fixture.target.spaceId,
      ]);
      expect(code).toBe(1);
      expect(errors.join("")).toContain("fixed-purpose TinyCloud SDK adapter");
    } finally {
      process.stderr.write = original;
    }
  });
});
