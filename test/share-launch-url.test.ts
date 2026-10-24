import { describe, expect, it, vi } from "vitest";
import { captureAndScrubLaunch } from "../src/email-share/url.js";

function capture(value: string): { readonly result: ReturnType<typeof captureAndScrubLaunch>; readonly replaceState: ReturnType<typeof vi.fn> } {
  const replaceState = vi.fn();
  const result = captureAndScrubLaunch(new URL(value) as unknown as Location, { replaceState } as unknown as History);
  return { result, replaceState };
}

describe("native share launch cutover", () => {
  it("captures and scrubs the secret native bearer fragment", () => {
    const href = "https://share.tinycloud.xyz/viewer#tc1=tc1%3Aopaque";
    const { result, replaceState } = capture(href);
    expect(result).toEqual({ shareHref: href, kind: "bearer" });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/viewer");
  });

  it("captures and scrubs a v=4 link for the link reader, without looking inside it", () => {
    const href = "https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=key&c=cid";
    const { result, replaceState } = capture(href);
    expect(result).toEqual({ shareHref: href, kind: "link" });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/viewer");
  });

  it("captures the invitation path the same way, and passes a removed version to the reader to refuse", () => {
    expect(capture("https://share.tinycloud.xyz/c/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=key&c=cid").result).toMatchObject({ kind: "link" });
    expect(capture("https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=3&k=key&c=cid").result).toMatchObject({ kind: "link" });
  });

  it("passes a link whose fragment is past the bound on without it", () => {
    const { result } = capture(`https://share.tinycloud.xyz/s/full#v=4&k=key&r=${"A".repeat(700_001)}`);
    expect(result).toEqual({ shareHref: "https://share.tinycloud.xyz/s/full", kind: "link" });
  });

  it.each([
    "https://share.tinycloud.xyz/s/bafkreiold#k=secret",
    "https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv?x=1#v=4&k=key&c=cid",
    "https://share.tinycloud.xyz/l/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=key&c=cid",
    "https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv",
    "https://share.tinycloud.xyz/viewer#tc2=old_encrypted_policy",
    "https://share.tinycloud.xyz/viewer?tc2=plaintext_policy",
    "https://share.tinycloud.xyz/viewer?tc2=public#k=secret",
    "https://share.tinycloud.xyz/viewer?tc2=public&other=value",
  ])("rejects a pre-cutover or mixed link: %s", (href) => {
    expect(capture(href).result).toBeUndefined();
  });
});
