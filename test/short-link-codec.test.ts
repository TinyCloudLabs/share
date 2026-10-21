import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { computeCid, encodeSealedInlineShareUrl, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { parseShortLink, splitInlineToShort } from "../src/short-links/codec.js";

interface Vector {
  readonly inline: string;
  readonly id: string;
  readonly ciphertextB64Url: string;
  readonly cid: string;
  readonly k: string;
  readonly short: string;
}

const raw = JSON.parse(readFileSync("test/fixtures/shortlink-vectors.json", "utf8")) as Record<string, Vector>;
const vectors: readonly Vector[] = Object.keys(raw).sort().map((key) => raw[key] as Vector);
const first = vectors[0] as Vector;
const { id, k, cid } = first;
const ORIGIN = "https://share.tinycloud.xyz";
const INLINE = `${ORIGIN}/s/inline`;

/** A v2 inline link whose payload is exactly the given JSON text. */
function inlineWithPayload(json: string): string {
  return `${INLINE}#v=2&p=${toBase64Url(new TextEncoder().encode(json))}`;
}

/** The inline link rebuilt from a short link and the sealed bytes it names. */
async function rebuildInlineFromShort(vector: Vector, shortHref: string): Promise<string> {
  const parts = parseShortLink(shortHref);
  if (parts === undefined) throw new Error("fixture short link did not parse");
  return encodeSealedInlineShareUrl({
    origin: ORIGIN,
    ciphertext: fromBase64Url(vector.ciphertextB64Url),
    key32: fromBase64Url(parts.key),
  });
}

describe("shared short-link vectors", () => {
  it.each(vectors)("parses $id to its id, key and cid", (v) => {
    expect(parseShortLink(v.short)).toEqual({ id: v.id, key: v.k, cid: v.cid });
  });

  it.each(vectors)("$id: the recorded cid matches the sealed bytes", async (v) => {
    expect(await computeCid(fromBase64Url(v.ciphertextB64Url))).toBe(v.cid);
  });

  it.each(vectors)("$id: splitInlineToShort turns the inline link into the short link", (v) => {
    expect(splitInlineToShort(v.inline, v.id)).toBe(v.short);
  });

  it.each(vectors)("$id: the short link from splitting rebuilds the inline link", async (v) => {
    const shortHref = splitInlineToShort(v.inline, v.id);
    expect(shortHref).toBeDefined();
    expect(await rebuildInlineFromShort(v, shortHref ?? "")).toBe(v.inline);
  });
});

describe("parseShortLink", () => {
  it("accepts an uppercase id and returns it lowercase", () => {
    expect(parseShortLink(`${ORIGIN}/s/${id.toUpperCase()}#v=3&k=${k}&c=${cid}`)).toEqual({ id, key: k, cid });
  });

  it.each([
    ["id one character short", `${ORIGIN}/s/${id.slice(1)}#v=3&k=${k}&c=${cid}`],
    ["id one character long", `${ORIGIN}/s/${id}a#v=3&k=${k}&c=${cid}`],
    ["id contains digit 1, outside base32", `${ORIGIN}/s/1${id.slice(1)}#v=3&k=${k}&c=${cid}`],
    ["key one character short", `${ORIGIN}/s/${id}#v=3&k=${k.slice(1)}&c=${cid}`],
    ["key one character long", `${ORIGIN}/s/${id}#v=3&k=${k}A&c=${cid}`],
    ["key contains +, outside base64url", `${ORIGIN}/s/${id}#v=3&k=+${k.slice(1)}&c=${cid}`],
    ["cid one character short", `${ORIGIN}/s/${id}#v=3&k=${k}&c=${cid.slice(1)}`],
    ["cid uppercase", `${ORIGIN}/s/${id}#v=3&k=${k}&c=${cid.toUpperCase()}`],
    ["cid with a non-raw codec prefix", `${ORIGIN}/s/${id}#v=3&k=${k}&c=bafybei${cid.slice(7)}`],
    ["extra fragment parameter", `${ORIGIN}/s/${id}#v=3&k=${k}&c=${cid}&x=1`],
    ["fragment parameters reordered", `${ORIGIN}/s/${id}#v=3&c=${cid}&k=${k}`],
    ["query string present", `${ORIGIN}/s/${id}?x=1#v=3&k=${k}&c=${cid}`],
    ["trailing slash on path", `${ORIGIN}/s/${id}/#v=3&k=${k}&c=${cid}`],
    ["v=3 without k", `${ORIGIN}/s/${id}#v=3&c=${cid}`],
    ["v=3 without c", `${ORIGIN}/s/${id}#v=3&k=${k}`],
    ["v=2 inline form", first.inline],
    ["native bearer form", `${ORIGIN}/viewer#tc1=tc1%3Aopaque`],
    ["not a URL", "not a link"],
  ])("rejects %s", (_label, href) => {
    expect(parseShortLink(href)).toBeUndefined();
  });
});

describe("splitInlineToShort", () => {
  const good = { c: first.ciphertextB64Url, cid, k, v: 2 };

  it("accepts an uppercase id and returns it lowercase", () => {
    expect(splitInlineToShort(first.inline, id.toUpperCase())).toBe(first.short);
  });

  it("keeps the origin of the inline link", () => {
    const other = inlineWithPayload(JSON.stringify(good)).replace(ORIGIN, "https://example.test");
    expect(splitInlineToShort(other, id)).toBe(`https://example.test/s/${id}#v=3&k=${k}&c=${cid}`);
  });

  it.each([
    ["a v3 short link", () => first.short],
    ["a native bearer link", () => `${ORIGIN}/viewer#tc1=tc1%3Aopaque`],
    ["not a URL", () => "not a link"],
    ["an http origin", () => first.inline.replace("https://", "http://")],
    ["a query string", () => first.inline.replace("/s/inline#", "/s/inline?x=1#")],
    ["padded payload", () => `${first.inline}=`],
    ["payload with a character outside base64url", () => `${first.inline}!`],
    ["payload of length 4n+1, which cannot be base64", () => `${INLINE}#v=2&p=abcde`],
    ["payload with a missing key field", () => inlineWithPayload(JSON.stringify({ c: good.c, cid, v: 2 }))],
    ["payload with the key fields out of JCS order", () => inlineWithPayload(JSON.stringify({ cid, c: good.c, k, v: 2 }))],
    ["payload with an extra field", () => inlineWithPayload(JSON.stringify({ ...good, x: 1 }))],
    ["payload with version 1", () => inlineWithPayload(JSON.stringify({ ...good, v: 1 }))],
    ["payload with a short key", () => inlineWithPayload(JSON.stringify({ ...good, k: k.slice(1) }))],
    ["payload with an uppercase cid", () => inlineWithPayload(JSON.stringify({ ...good, cid: cid.toUpperCase() }))],
    ["payload that is not JSON", () => `${INLINE}#v=2&p=${toBase64Url(new TextEncoder().encode("not json"))}`],
  ])("rejects %s", (_label, build) => {
    expect(splitInlineToShort(build(), id)).toBeUndefined();
  });

  it.each([
    ["an id one character short", id.slice(1)],
    ["an id containing 1, outside base32", `1${id.slice(1)}`],
    ["an empty id", ""],
  ])("rejects %s as the id", (_label, badId) => {
    expect(splitInlineToShort(first.inline, badId)).toBeUndefined();
  });
});
