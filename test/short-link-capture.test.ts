import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { captureAndScrubLaunch } from "../src/email-share/url.js";

interface Vector {
  readonly inline: string;
  readonly id: string;
  readonly k: string;
  readonly cid: string;
  readonly short: string;
}

const raw = JSON.parse(readFileSync("test/fixtures/shortlink-vectors.json", "utf8")) as Record<string, Vector>;
const first = raw["0"] as Vector;

function capture(href: string): { readonly result: ReturnType<typeof captureAndScrubLaunch>; readonly replaceState: ReturnType<typeof vi.fn> } {
  const replaceState = vi.fn();
  const result = captureAndScrubLaunch(new URL(href) as unknown as Location, { replaceState } as unknown as History);
  return { result, replaceState };
}

describe("short link capture", () => {
  it("captures a short link with its key and cid, and scrubs the fragment first", () => {
    const { result, replaceState } = capture(first.short);
    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/viewer");
    expect(result).toEqual({
      shareHref: first.short,
      kind: "short",
      shortLink: { id: first.id, key: first.k, cid: first.cid },
    });
  });

  it("scrubs a non-short link without capturing it as short", () => {
    const { result, replaceState } = capture(`${first.short}&x=1`);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/viewer");
    expect(result).toBeUndefined();
  });

  it("still captures the v2 inline form as addressed, without short-link parts", () => {
    const { result } = capture(first.inline);
    expect(result).toMatchObject({ kind: "addressed" });
    expect(result).not.toHaveProperty("shortLink");
  });

  it("still captures the native bearer form as bearer", () => {
    const { result } = capture("https://share.tinycloud.xyz/viewer#tc1=tc1%3Aopaque");
    expect(result).toMatchObject({ kind: "bearer" });
  });
});
