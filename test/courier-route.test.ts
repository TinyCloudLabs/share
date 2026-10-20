import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const page = readFileSync("courier/index.html", "utf8");
const headers = readFileSync("public/_headers", "utf8");
const metaPolicy = /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(page)?.[1] ?? "";

function headerPolicy(route: string): string | undefined {
  const block = headers.split(/\n\n+/).find((section) => section.startsWith(`${route}\n`));
  return block?.split("\n").find((line) => line.trim().startsWith("Content-Security-Policy:"))?.trim().slice("Content-Security-Policy:".length).trim();
}

const directive = (policy: string, name: string): string[] => (policy.split(/;\s*/).find((part) => part.startsWith(`${name} `)) ?? "").split(/\s+/).slice(1);

describe("the /courier route", () => {
  it("is a rewrite to the directory index with no self-rewrite to a .html file", () => {
    const redirects = readFileSync("public/_redirects", "utf8");
    expect(redirects).toContain("/courier /courier/ 200");
    expect(redirects).not.toMatch(/^\S+\s+\/\S*\.html\s+200/m);
  });

  it("serves the same policy in the page and in the header, the header adding only frame-ancestors", () => {
    expect(metaPolicy).not.toBe("");
    for (const route of ["/courier", "/courier/"]) {
      expect(headerPolicy(route)).toBe(`${metaPolicy}; frame-ancestors 'none'`);
      // the site-wide policy is detached, so only this one is sent
      expect(headers.split(/\n\n+/).find((section) => section.startsWith(`${route}\n`))).toContain("! Content-Security-Policy");
    }
  });

  it("is at least as strict as the viewer's policy and names exact hosts", () => {
    expect(directive(metaPolicy, "default-src")).toEqual(["'none'"]);
    expect(directive(metaPolicy, "script-src")).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(directive(metaPolicy, "form-action")).toEqual(["'none'"]);
    expect(directive(metaPolicy, "base-uri")).toEqual(["'none'"]);
    expect(directive(metaPolicy, "object-src")).toEqual(["'none'"]);
    expect(directive(metaPolicy, "require-trusted-types-for")).toEqual(["'script'"]);
    expect(directive(metaPolicy, "trusted-types")).toEqual(["share-viewer-html", "dompurify", "'allow-duplicates'"]);
    expect(directive(metaPolicy, "frame-src")).toEqual(["'self'", "https://openkey.so"]);
    const connect = directive(metaPolicy, "connect-src");
    expect(connect).toEqual(["'self'", "https://tee.node.tinycloud.xyz", "https://registry.tinycloud.xyz", "https://openkey.so"]);
    for (const source of connect) expect(source).not.toMatch(/^https:$|\*/);
    expect(directive(metaPolicy, "script-src")).not.toContain("'unsafe-eval'");
    expect(directive(metaPolicy, "script-src")).not.toContain("'unsafe-inline'");
  });
});
