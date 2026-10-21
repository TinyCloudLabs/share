import { describe, expect, it } from "vitest";
import { base64UrlEncode } from "../src/encoding";
import { MAX_CIPHERTEXT_BYTES, MAX_TTL_MS, MIN_TTL_MS, parseCreateBody } from "../src/validate";

const NOW = Date.UTC(2026, 0, 1, 0, 0, 0);

function body(ciphertext: string, expiresAt: string): string {
  return JSON.stringify({ ciphertext, expiresAt });
}

const ciphertext = base64UrlEncode(new Uint8Array(64).fill(1));
const inTtl = (ms: number) => new Date(NOW + ms).toISOString();

describe("parseCreateBody", () => {
  it("accepts a well-formed body and returns the decoded bytes", () => {
    const parsed = parseCreateBody(body(ciphertext, inTtl(MIN_TTL_MS + 60_000)), NOW);
    expect(parsed?.bytes.length).toBe(64);
    expect(parsed?.expiresAtMs).toBe(NOW + MIN_TTL_MS + 60_000);
  });

  it("rejects a TTL under the minimum", () => {
    expect(parseCreateBody(body(ciphertext, inTtl(MIN_TTL_MS - 1000)), NOW)).toBeNull();
  });

  it("rejects a TTL over the maximum", () => {
    expect(parseCreateBody(body(ciphertext, inTtl(MAX_TTL_MS + 1000)), NOW)).toBeNull();
  });

  it("rejects an expiresAt that is not canonical UTC with milliseconds", () => {
    const withoutMs = new Date(NOW + MIN_TTL_MS + 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
    expect(parseCreateBody(body(ciphertext, withoutMs), NOW)).toBeNull();
    const withOffset = "2026-06-01T00:00:00.000+00:00";
    expect(parseCreateBody(body(ciphertext, withOffset), NOW)).toBeNull();
  });

  it("rejects empty ciphertext", () => {
    expect(parseCreateBody(body("", inTtl(MIN_TTL_MS + 60_000)), NOW)).toBeNull();
  });

  it("accepts exactly the decoded byte cap and rejects one byte over", () => {
    const atCap = base64UrlEncode(new Uint8Array(MAX_CIPHERTEXT_BYTES).fill(2));
    const overCap = base64UrlEncode(new Uint8Array(MAX_CIPHERTEXT_BYTES + 1).fill(2));
    const expiresAt = inTtl(MIN_TTL_MS + 60_000);
    expect(parseCreateBody(body(atCap, expiresAt), NOW)?.bytes.length).toBe(MAX_CIPHERTEXT_BYTES);
    expect(parseCreateBody(body(overCap, expiresAt), NOW)).toBeNull();
  });

  it("rejects non-object JSON and malformed JSON", () => {
    expect(parseCreateBody("[]", NOW)).toBeNull();
    expect(parseCreateBody("null", NOW)).toBeNull();
    expect(parseCreateBody("{not json", NOW)).toBeNull();
  });

  it("rejects a body with a non-string ciphertext", () => {
    expect(parseCreateBody(JSON.stringify({ ciphertext: 5, expiresAt: inTtl(MIN_TTL_MS + 60_000) }), NOW)).toBeNull();
  });
});
