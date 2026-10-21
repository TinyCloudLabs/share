import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { base32Lower, base64UrlDecode, base64UrlEncode, cidForBytes, newShareId } from "../src/encoding";

interface Vector {
  id: string;
  ciphertextB64Url: string;
  cid: string;
}

const VECTORS: Vector[] = JSON.parse(
  readFileSync(`${process.env.HOME}/scratch/artifacts/ship/shortlink-vectors.json`, "utf8"),
);

describe("base32Lower", () => {
  it("matches the RFC 4648 vector for foobar, lowercase and unpadded", () => {
    expect(base32Lower(new TextEncoder().encode("foobar"))).toBe("mzxw6ytboi");
  });
});

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = Uint8Array.from([0, 255, 254, 63, 62, 1, 2, 3]);
    expect(base64UrlDecode(base64UrlEncode(bytes))).toEqual(bytes);
  });

  it("rejects characters outside the unpadded base64url alphabet", () => {
    expect(base64UrlDecode("ab+c")).toBeNull();
    expect(base64UrlDecode("ab/c")).toBeNull();
    expect(base64UrlDecode("abc=")).toBeNull();
  });

  it("rejects lengths that no encoder output can have", () => {
    expect(base64UrlDecode("abcde")).toBeNull();
  });

  it("rejects non-canonical trailing bits", () => {
    // "AA" decodes to one zero byte; "AB" carries stray bits in the final character.
    expect(base64UrlDecode("AA")).toEqual(Uint8Array.of(0));
    expect(base64UrlDecode("AB")).toBeNull();
  });
});

describe("cidForBytes against the shared vector file", () => {
  it("reproduces every vector CID from its ciphertext", async () => {
    expect(VECTORS.length).toBeGreaterThan(0);
    for (const vector of VECTORS) {
      const bytes = base64UrlDecode(vector.ciphertextB64Url);
      expect(bytes).not.toBeNull();
      expect(await cidForBytes(bytes as Uint8Array)).toBe(vector.cid);
    }
  });
});

describe("newShareId", () => {
  it("is 26 lowercase base32 characters", () => {
    expect(newShareId()).toMatch(/^[a-z2-7]{26}$/);
  });
});
