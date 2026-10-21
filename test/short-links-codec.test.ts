import { describe, expect, it } from "vitest";
import vectorsJson from "./fixtures/shortlink-vectors.json";
import { parseInlineSharePayload, rebuildInlineFromShort, splitInlineToShort } from "../src/short-links/codec-local.js";

interface Vector {
  readonly inline: string;
  readonly id: string;
  readonly ciphertextB64Url: string;
  readonly cid: string;
  readonly k: string;
  readonly short: string;
}

const vectors = vectorsJson as readonly Vector[];

describe("short-link codec vectors", () => {
  it.each(vectors)("splits the inline link for $id into the shared short link", (vector) => {
    expect(splitInlineToShort(vector.inline, vector.id)).toBe(vector.short);
  });

  it.each(vectors)("rebuilds the inline payload for $id from the short link", (vector) => {
    expect(rebuildInlineFromShort(vector.short, vector.ciphertextB64Url)).toEqual({
      v: 2,
      c: vector.ciphertextB64Url,
      cid: vector.cid,
      k: vector.k,
    });
  });

  it.each(vectors)("reads the sealed bytes and CID from the inline link for $id", (vector) => {
    expect(parseInlineSharePayload(vector.inline)).toEqual({
      v: 2,
      c: vector.ciphertextB64Url,
      cid: vector.cid,
      k: vector.k,
    });
  });

  it("rejects a malformed short-link id", () => {
    const vector = vectors[0]!;
    expect(() => splitInlineToShort(vector.inline, "not-a-valid-id")).toThrow("short link id is malformed");
  });

  it("rejects an inline link without a v=2 payload", () => {
    expect(() => parseInlineSharePayload("https://share.tinycloud.xyz/s/inline#v=3&k=x")).toThrow("no v=2 payload");
  });
});
