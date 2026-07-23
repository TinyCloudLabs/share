/**
 * createBearerShare: round-trip against the in-process dev registry, checked
 * with the SAME primitives the viewer uses (parseShareUrl → fetchBlob →
 * open → schema → checkBearerDelegation → content fetch/decrypt), so the
 * create side is proven to emit exactly what the verify side consumes.
 */
import { Buffer } from "node:buffer";

import {
  checkBearerDelegation,
  open,
  parseShareUrl,
  shareEnvelopeSchema,
  verifyEnvelope,
  fromBase64Url,
} from "@tinycloud/share-envelope";
import { fetchBlob } from "@tinycloud/share-registry";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { beforeEach, describe, expect, it } from "vitest";

import { MAX_CONTENT_BYTES, createBearerShare } from "../src/create.js";
import { parseDuration } from "../src/duration.js";

const REGISTRY_BASE = "http://registry.local";
const MARKDOWN = "# Hello\n\nA *bearer* share.\n";

let registry: DevRegistry;
let fetchFn: typeof fetch;

/** In-process fetch adapter over the dev-registry handler (no port). */
function handlerFetch(target: DevRegistry): typeof fetch {
  return async (input, init) => {
    const withDuplex =
      init?.body === undefined || init.body === null
        ? init
        : ({ ...init, duplex: "half" } as RequestInit);
    return target.handler(new Request(input, withDuplex));
  };
}

beforeEach(() => {
  registry = createDevRegistry();
  fetchFn = handlerFetch(registry);
});

function create(overrides: Record<string, unknown> = {}) {
  return createBearerShare({
    content: new TextEncoder().encode(MARKDOWN),
    filename: "hello.md",
    registryBaseUrl: REGISTRY_BASE,
    senderName: "Adam",
    fetchFn,
    ...overrides,
  });
}

describe("createBearerShare", () => {
  it("produces a link whose envelope round-trips the full viewer verify path", async () => {
    const result = await create();

    // The link parses with the strict share-URL codec.
    const { ciphertextCid, key32 } = parseShareUrl(result.url);
    expect(ciphertextCid).toBe(result.envelopeCid);

    // Envelope blob: fetch (CID re-verified) → decrypt → strict schema.
    const blob = await fetchBlob(REGISTRY_BASE, ciphertextCid, { fetchFn });
    const plaintext = await open(blob, key32);
    const envelope = shareEnvelopeSchema.parse(
      JSON.parse(new TextDecoder().decode(plaintext)),
    );
    expect(envelope).toEqual(result.envelope);

    // Signature verifies; bearer binding check accepts the minted delegation.
    await expect(
      verifyEnvelope(envelope, { expectedSignerDid: envelope.signature.signerDid }),
    ).resolves.toBe(true);
    expect(checkBearerDelegation(envelope).ok).toBe(true);

    // Signed shape: bearer target, exact path under shares/<shareId>/.
    expect(envelope.authorizationTarget.kind).toBe("bearerKey");
    expect(envelope.target.resource).toEqual({
      kind: "exact",
      path: `shares/${result.shareId}/hello.md`,
    });
    expect(envelope.display).toEqual({ senderName: "Adam", filename: "hello.md" });

    // Content blob: pointer is signed; fetch by CID → decrypt with the
    // carried key → the original markdown.
    expect(envelope.content).toBeDefined();
    expect(envelope.content?.cid).toBe(result.contentCid);
    const contentBlob = await fetchBlob(REGISTRY_BASE, result.contentCid, { fetchFn });
    const contentBytes = await open(contentBlob, fromBase64Url(envelope.content!.key));
    expect(new TextDecoder().decode(contentBytes)).toBe(MARKDOWN);
  });

  it("defaults expiry to 30 days from now and stores retention on BOTH blobs", async () => {
    const now = Date.parse("2026-07-13T12:00:00.000Z");
    const result = await create({ now: () => now });
    expect(result.expiry).toBe("2026-08-12T12:00:00.000Z");
    for (const cid of [result.envelopeCid, result.contentCid]) {
      const record = registry.store.get(cid);
      expect(record).toBeDefined();
      // The dev registry clamps to ITS OWN Date.now()+30d horizon; retention
      // must exist and never exceed the requested expiry.
      expect(record!.deleteAfter).toBeLessThanOrEqual(Date.parse(result.expiry));
    }
  });

  it("uses a fresh session key, share id, and fragment key per share", async () => {
    const a = await create();
    const b = await create();
    expect(a.shareId).not.toBe(b.shareId);
    expect(a.url).not.toBe(b.url);
    expect(a.envelopeCid).not.toBe(b.envelopeCid);
    const jwkA = a.envelope.authorizationTarget;
    const jwkB = b.envelope.authorizationTarget;
    if (jwkA.kind !== "bearerKey" || jwkB.kind !== "bearerKey") {
      throw new Error("expected bearer targets");
    }
    expect(jwkA.sessionJwk.x).not.toBe(jwkB.sessionJwk.x);
  });

  it("rejects past/invalid expiry before uploading anything", async () => {
    await expect(
      create({ expiresAt: new Date(Date.now() - 1000) }),
    ).rejects.toThrow(/future/);
    await expect(create({ expiresAt: new Date(Number.NaN) })).rejects.toThrow(
      /future/,
    );
    expect(registry.store.size).toBe(0);
  });

  it("rejects oversized and empty content before uploading anything", async () => {
    await expect(
      create({ content: new Uint8Array(MAX_CONTENT_BYTES + 1) }),
    ).rejects.toThrow(/at most/);
    await expect(create({ content: new Uint8Array(0) })).rejects.toThrow(/empty/);
    expect(registry.store.size).toBe(0);
  });

  it("rejects unsafe filenames and non-canonical origins", async () => {
    for (const filename of ["", ".", "..", "a/b.md", "a\\b.md"]) {
      await expect(create({ filename })).rejects.toThrow(/path segment/);
    }
    await expect(create({ origin: "http://plain.example" })).rejects.toThrow(
      /canonical https origin/,
    );
    expect(registry.store.size).toBe(0);
  });

  it("omits senderName from display when not provided", async () => {
    const result = await create({ senderName: undefined });
    expect(result.envelope.display).toEqual({ filename: "hello.md" });
  });

  it("delegation exp (seconds) always covers the envelope expiry (ms) — no sub-second dead window", async () => {
    // expiry with a sub-second component: flooring would make the delegation
    // die BEFORE the envelope; the create must ceil instead.
    const expiresAt = new Date(Date.parse("2099-01-01T00:00:00.500Z"));
    const result = await create({ expiresAt });
    const payloadSegment = result.envelope.delegation.split(".")[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadSegment, "base64url").toString("utf8"),
    ) as { exp: number };
    expect(payload.exp * 1000).toBeGreaterThanOrEqual(Date.parse(result.expiry));
    // and the binding check agrees at the very last live instant
    expect(
      checkBearerDelegation(result.envelope, {
        now: () => Date.parse(result.expiry) - 1,
      }).ok,
    ).toBe(true);
  });

  describe("key hygiene (every buffer zeroed on EVERY exit path)", () => {
    function captureKeys() {
      const buffers: Uint8Array[] = [];
      let liveAtCapture = 0;
      const onKeyBuffer = (key: Uint8Array): void => {
        buffers.push(key);
        if (key.some((byte) => byte !== 0)) liveAtCapture += 1;
      };
      const expectAllZeroed = (expectedCount: number): void => {
        expect(buffers).toHaveLength(expectedCount);
        expect(liveAtCapture).toBe(expectedCount); // they really held keys once
        for (const buffer of buffers) {
          expect(Array.from(buffer).every((byte) => byte === 0)).toBe(true);
        }
      };
      return { onKeyBuffer, expectAllZeroed };
    }

    it("zeroes session/sender/content/envelope keys on success", async () => {
      const { onKeyBuffer, expectAllZeroed } = captureKeys();
      await create({ onKeyBuffer });
      expectAllZeroed(4);
    });

    it("zeroes all generated keys when the upload throws (finding: success-only zeroing)", async () => {
      const failingFetch: typeof fetch = async () => {
        throw new Error("registry unreachable");
      };
      const { onKeyBuffer, expectAllZeroed } = captureKeys();
      await expect(
        create({ fetchFn: failingFetch, onKeyBuffer }),
      ).rejects.toThrow(/registry unreachable/);
      expectAllZeroed(4); // all four buffers existed by upload time — all zeroed
    });

    it("zeroes all keys when the SECOND upload (envelope put) throws", async () => {
      let calls = 0;
      const failSecondPut: typeof fetch = async (input, init) => {
        calls += 1;
        if (calls >= 2) throw new Error("second put down");
        return fetchFn(input, init);
      };
      const { onKeyBuffer, expectAllZeroed } = captureKeys();
      await expect(
        create({ fetchFn: failSecondPut, onKeyBuffer }),
      ).rejects.toThrow(/second put down/);
      expectAllZeroed(4);
    });
  });
});

describe("parseDuration", () => {
  it("parses s/m/h/d", () => {
    expect(parseDuration("10s")).toBe(10_000);
    expect(parseDuration("45m")).toBe(2_700_000);
    expect(parseDuration("12h")).toBe(43_200_000);
    expect(parseDuration("30d")).toBe(2_592_000_000);
  });

  it("fails closed on anything else", () => {
    for (const bad of ["", "30", "d", "1w", "1h30m", "-1d", "1.5h", " 1d"]) {
      expect(() => parseDuration(bad)).toThrow(/invalid duration/);
    }
  });
});
