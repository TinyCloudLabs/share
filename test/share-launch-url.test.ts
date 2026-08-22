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
    expect(result).toEqual({ shareHref: href });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/viewer");
  });

  it("captures and scrubs the public addressed invitation query", () => {
    const href = "https://share.tinycloud.xyz/viewer?tc2=canonical_public_policy";
    const { result, replaceState } = capture(href);
    expect(result).toEqual({ shareHref: href });
    expect(replaceState).toHaveBeenCalledWith(null, "", "/viewer");
  });

  it.each([
    "https://share.tinycloud.xyz/s/bafkreiold#k=secret",
    "https://share.tinycloud.xyz/viewer#tc2=old_encrypted_policy",
    "https://share.tinycloud.xyz/viewer?tc2=public#k=secret",
    "https://share.tinycloud.xyz/viewer?tc2=public&other=value",
  ])("rejects a pre-cutover or mixed link: %s", (href) => {
    expect(capture(href).result).toBeUndefined();
  });
});
