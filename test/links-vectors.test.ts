// @vitest-environment node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { buildFullLink, parseLink } from "../src/short-links/codec.js";
import { verifyStrict } from "../src/short-links/ed25519.js";
import { LinkReadError, resolveLink } from "../src/short-links/resolve.js";
import { checkRecord } from "../src/short-links/record.js";
import { chooseLink } from "../src/short-links/publish.js";
import { createMockLinksApi } from "./fixtures/links-mock-api.js";

const FIXTURE = "test/fixtures/links-api-vectors.json";
/**
 * SHA-256 of the shared vector file (contract Appendix B). The copy is byte-identical to the
 * canonical one in tinycloud-dev `docs/specs/`; a change there changes this pin.
 */
const VECTORS_SHA256 = "4b7c95e9bd0e5a489ab17c0b28bd334f06f2c17dd8ac982eedee04df2fab6bdd";
const bytes = readFileSync(FIXTURE);
const vectors = JSON.parse(bytes.toString("utf8"));
const NOW = Date.parse(vectors.meta.now);
const AUDIENCE: string = vectors.meta.audience;
const TRUSTED: readonly string[] = vectors.meta.trustedOrigins;
const hex = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text, "hex"));

describe("shared vector file", () => {
  it("is the pinned copy", () => {
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(VECTORS_SHA256);
  });
});

describe("ed25519Strict vectors", () => {
  for (const vector of vectors.ed25519Strict) {
    it(vector.name, () => {
      expect(verifyStrict(hex(vector.publicKeyHex), hex(vector.messageHex), hex(vector.signatureHex))).toBe(vector.expect.valid);
    });
  }
});

describe("links vectors (grammar)", () => {
  for (const vector of vectors.links) {
    it(vector.name, () => {
      const parsed = parseLink(vector.href, TRUSTED);
      expect(parsed.ok).toBe(vector.expect.valid ?? true);
      if (parsed.ok) {
        const { link } = parsed;
        if (vector.expect.form !== undefined) expect(link.form).toBe(vector.expect.form);
        if (link.form === "short") {
          expect(link.pathType).toBe(vector.expect.pathType);
          expect(link.id).toBe(vector.expect.id);
          expect(link.key).toBe(vector.expect.k);
          expect(link.cid).toBe(vector.expect.c);
        } else {
          expect(link.key).toBe(vector.expect.k ?? link.key);
          if (vector.expect.recordJcs !== undefined) {
            expect(buildFullLink({ origin: link.origin, key: link.key, record: link.record })).toBe(vector.href);
          }
        }
      } else {
        expect(parsed.reason).toBe(vector.expect.reason);
      }
    });
  }
});

describe("records vectors (reader checks)", () => {
  for (const vector of vectors.records) {
    it(vector.name, async () => {
      const record = { header: vector.record.header, ...(vector.record.signature === undefined ? {} : { signature: vector.record.signature }), body: fromBase64Url(vector.record.body) };
      const result = await checkRecord(record, { now: Date.parse(vector.now), key: fromBase64Url(vector.contentKeyB64u) });
      if (vector.expect.status === 200) expect("refusal" in result).toBe(false);
      else expect("refusal" in result ? result.refusal : undefined).toBe(vector.expect.reason);
    });
  }
});

describe("resolve vectors (the whole viewer reader)", () => {
  for (const vector of vectors.resolve) {
    it(vector.name, async () => {
      const api = createMockLinksApi({ now: () => Date.parse(vector.now), audience: AUDIENCE, corsOrigins: ["https://share.tinycloud.xyz"] });
      const parsed = parseLink(vector.link, TRUSTED);
      if (parsed.ok && parsed.link.form === "short" && vector.serverRecord !== null) {
        // Serve the vector's record as the service would.
        const sr = vector.serverRecord;
        api.state.records.set(parsed.link.id, { type: sr.header.type, issuer: sr.header.issuer, expiresAt: sr.header.expiresAt, headerJcs: JSON.stringify(sr.header), ...(sr.signature === undefined ? {} : { signature: sr.signature }), body: fromBase64Url(sr.body) });
      }
      const outcome = await resolveLink(vector.link, { trustedOrigins: ["https://share.tinycloud.xyz"], apiOrigin: AUDIENCE, fetchFn: api.fetchFor(AUDIENCE), now: () => Date.parse(vector.now) }).then(
        (value) => ({ ok: true as const, type: value.type }),
        (error: unknown) => ({ ok: false as const, error }),
      );
      if (vector.expect.status === 200) {
        // The Share viewer opens shares and invitations only; a login link is valid but not viewable here.
        if (vector.expect.type === "openkey-login") expect(outcome.ok).toBe(false);
        else expect(outcome).toEqual({ ok: true, type: vector.expect.type });
      } else {
        expect(outcome.ok).toBe(false);
        if (!outcome.ok) {
          expect(outcome.error).toBeInstanceOf(LinkReadError);
          expect((outcome.error as LinkReadError).kind).toBe("not-found");
          // The service answers an expired record with the uniform 404, so the reader sees "gone" where the vector names the expiry check.
          const expected = vector.expect.reason === "expired" ? "gone" : vector.expect.reason;
          expect((outcome.error as LinkReadError).reason).toBe(expected);
        }
      }
    });
  }
});

describe("linkChoice vectors (the 30-day rule)", () => {
  for (const vector of vectors.linkChoice) {
    it(`lifetime ${vector.shareLifetimeSeconds} s`, () => {
      const choice = chooseLink(vector.shareLifetimeSeconds);
      expect(choice.form).toBe(vector.expect.form);
      expect(choice.warning).toBe(vector.expect.warning);
    });
  }
});

describe("mock links API runs the service vectors", () => {
  const apiKeys = vectors.apiKeys.map((entry: { stored: { keyId: string; service: string; allowedTypes: string[]; secretSha256: string } }) => entry.stored);
  const bearerOf = (authorization: string | undefined): string | undefined =>
    authorization === undefined ? undefined : authorization.replace("<bearer from apiKeys[0]>", vectors.apiKeys[0].bearer);

  const fresh = (state: Record<string, unknown>) => {
    const api = createMockLinksApi({ now: () => NOW, audience: AUDIENCE, corsOrigins: vectors.constants.corsPostOrigins, apiKeys });
    for (const entry of (state["seenNonces"] as string[] | undefined) ?? []) api.state.seenNonces.add(entry);
    for (const issuer of (state["blocked"] as string[] | undefined) ?? []) api.state.blockedIssuers.add(issuer);
    api.state.issuerRateLimited = state["issuerRateLimited"] === true;
    api.state.capacityFull = state["capacityFull"] === true;
    api.state.addressBlocked = state["addressBlocked"] === true;
    api.state.addressRateLimited = state["addressRateLimited"] === true;
    api.state.addressLiveFull = state["addressLiveFull"] === true;
    for (const [id, stored] of Object.entries((state["records"] as Record<string, { issuer: string; expiresAt: string }> | undefined) ?? {})) {
      api.state.records.set(id, { type: stored.issuer.startsWith("service:") ? "openkey-login" : "share", ...stored });
    }
    return api;
  };

  for (const vector of vectors.create) {
    it(`create: ${vector.name}`, async () => {
      const api = fresh(vector.state);
      let body: string;
      if (vector.bodySynthesized !== undefined) {
        const synthesized = new Uint8Array(vector.bodySynthesized.length).fill(vector.bodySynthesized.fillByte);
        synthesized[0] = vector.bodySynthesized.firstByte;
        body = JSON.stringify({ ...vector.request, body: toBase64Url(synthesized) });
      } else {
        body = JSON.stringify(vector.request);
      }
      const headers: Record<string, string> = { "content-type": vector.state.contentType ?? "application/json" };
      if (vector.state.origin !== undefined) headers["origin"] = vector.state.origin;
      const authorization = bearerOf(vector.authorization);
      if (authorization !== undefined) headers["authorization"] = authorization;
      const response = await api.handle({ method: "POST", path: "/v1/links", headers, body });
      expect(response.status).toBe(vector.expect.status);
      if (vector.expect.error !== undefined) expect(await response.json()).toEqual({ error: vector.expect.error });
    });
  }

  for (const vector of vectors.delete) {
    it(`delete: ${vector.name}`, async () => {
      const api = fresh(vector.state);
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (vector.state.origin !== undefined) headers["origin"] = vector.state.origin;
      const authorization = bearerOf(vector.authorization);
      if (authorization !== undefined) headers["authorization"] = authorization;
      const response = await api.handle({ method: "POST", path: `/v1/links/${vector.urlId}/delete`, headers, body: JSON.stringify(vector.request) });
      expect(response.status).toBe(vector.expect.status);
      if (vector.expect.error !== undefined) expect(await response.json()).toEqual({ error: vector.expect.error });
    });
  }

  for (const vector of vectors.read) {
    it(`read: ${vector.type}, ${vector.sequence.join(", ")}`, async () => {
      const api = fresh({});
      const id = "lqdw5iopqq2tkkvjj6gbbi5vbv";
      api.state.records.set(id, { type: vector.type, issuer: "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S", expiresAt: "2026-10-24T13:00:00.000Z", headerJcs: "{}", body: new Uint8Array(40) });
      const statuses: number[] = [];
      for (const step of vector.sequence as string[]) {
        const response = await api.handle({ method: step === "GET" ? "GET" : "POST", path: step === "GET" ? `/v1/links/${id}` : `/v1/links/${id}/take`, headers: {} });
        statuses.push(response.status);
      }
      expect(statuses).toEqual(vector.expect);
    });
  }
});
