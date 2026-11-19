import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// TC-2923: a Courier session whose TinyCloud host is node.tinycloud.xyz (the default
// sender bootstrap) or tee.node.tinycloud.xyz (pinned key-release calls) must not be
// blocked by the page's CSP, in the <meta> policy, in both header rules and in the docs.
const page = readFileSync("courier/index.html", "utf8");
const headers = readFileSync("public/_headers", "utf8");
const docs = readFileSync("docs/courier-view.md", "utf8");

const meta = /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(page)?.[1] ?? "";
const headerPolicy = (route: string): string => {
  const block = headers.split(/\n\n+/).find((section) => section.startsWith(`${route}\n`)) ?? "";
  return block.split("\n").find((line) => line.trim().startsWith("Content-Security-Policy:"))?.trim().slice("Content-Security-Policy:".length).trim() ?? "";
};

/** CSP3 host-source match for a request URL, for the exact-origin sources these policies use. */
function connectAllows(policy: string, url: string): boolean {
  const target = new URL(url);
  const sources = (policy.split(/;\s*/).find((part) => part.startsWith("connect-src ")) ?? "").split(/\s+/).slice(1);
  return sources.some((source) => {
    if (source.startsWith("'") || source.includes("*")) return false;
    try { return new URL(source).origin === target.origin; } catch { return false; }
  });
}

const policies: Array<[string, string]> = [["meta", meta], ["/courier header", headerPolicy("/courier")], ["/courier/ header", headerPolicy("/courier/")]];

describe("Courier CSP and the node origins", () => {
  it.each(policies)("%s admits requests to node.* and tee.* and nothing broader", (_name, policy) => {
    expect(policy).not.toBe("");
    for (const origin of ["https://node.tinycloud.xyz", "https://tee.node.tinycloud.xyz"]) {
      for (const path of ["/info", "/delegate", "/invoke", "/policy/v3/status/x"]) expect(connectAllows(policy, `${origin}${path}`)).toBe(true);
    }
    expect(connectAllows(policy, "http://node.tinycloud.xyz/invoke")).toBe(false);
    expect(connectAllows(policy, "https://other.node.tinycloud.xyz/invoke")).toBe(false);
    expect(connectAllows(policy, "https://tinycloud.xyz/invoke")).toBe(false);
    expect(connectAllows(policy, "https://example.com/invoke")).toBe(false);
  });

  it("documents both node origins in the policy sentence", () => {
    const line = docs.split("\n").find((text) => text.includes("connect-src 'self'")) ?? "";
    expect(line).toContain("https://node.tinycloud.xyz");
    expect(line).toContain("https://tee.node.tinycloud.xyz");
  });

  it("admits whichever sender bootstrap origin the shipped config names", () => {
    const config = JSON.parse(readFileSync("public/.well-known/tinycloud-share/config.json", "utf8")) as { senderBootstrapNodeOrigin: string };
    for (const [, policy] of policies) expect(connectAllows(policy, `${config.senderBootstrapNodeOrigin}/info`)).toBe(true);
  });
});
