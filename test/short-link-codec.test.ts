import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { computeCid, fromBase64Url } from "@tinycloud/share-envelope";
import { parseShortLink } from "../src/short-links/codec.js";

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

describe("shared short-link vectors", () => {
  it.each(vectors)("parses $id to its id, key and cid", (v) => {
    expect(parseShortLink(v.short)).toEqual({ id: v.id, key: v.k, cid: v.cid });
  });

  it.each(vectors)("$id: the recorded cid matches the sealed bytes", async (v) => {
    expect(await computeCid(fromBase64Url(v.ciphertextB64Url))).toBe(v.cid);
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
