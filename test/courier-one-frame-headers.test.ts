import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";
import { ONE_DEV_ORIGIN, ONE_PREVIEW_ORIGIN, ONE_PRODUCTION_ORIGIN, buildKindOf, frameAncestorsFor, oneOriginsFor, renderCourierFrameHeaders } from "../src/courier/one-origins.js";

const template = readFileSync("public/_headers", "utf8");
const page = readFileSync("courier/index.html", "utf8");
const metaPolicy = /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(page)?.[1] ?? "";
const FRAMED = ["/courier", "/courier/", "/courier/*"];
const policyFor = (source: string, path: string): string => productionHeadersForPath(parseProductionHeaders(source), path)["content-security-policy"] ?? "";
const directive = (policy: string, name: string): string[] => (policy.split(/;\s*/).find((part) => part.startsWith(`${name} `)) ?? "").split(/\s+/).slice(1);

describe("TinyCloud One framing of /courier", () => {
  it("production /courier, /courier/ and /courier/* allow exactly https://tinycloud.one, and nothing else changes in the policy", () => {
    expect(metaPolicy).not.toBe("");
    for (const route of FRAMED) {
      expect(policyFor(template, route), route).toBe(`${metaPolicy}; frame-ancestors https://tinycloud.one`);
      expect(productionHeadersForPath(parseProductionHeaders(template), route)["x-frame-options"], route).toBeUndefined();
    }
    // Paths below /courier/ get the same policy.
    expect(policyFor(template, "/courier/anything")).toBe(`${metaPolicy}; frame-ancestors https://tinycloud.one`);
  });

  it("names no wildcard, pages.dev or localhost origin in a production header", () => {
    for (const route of FRAMED) {
      const ancestors = directive(policyFor(template, route), "frame-ancestors");
      expect(ancestors).toEqual([ONE_PRODUCTION_ORIGIN]);
      for (const source of ancestors) expect(source).not.toMatch(/\*|pages\.dev|localhost/);
    }
  });

  it("keeps the rest of the /courier policy (frame-src, connect-src, trusted types) as it was", () => {
    const policy = policyFor(template, "/courier");
    expect(directive(policy, "frame-src")).toEqual(["'self'", "https://openkey.so"]);
    expect(directive(policy, "connect-src")).toEqual(["'self'", "https://node.tinycloud.xyz", "https://tee.node.tinycloud.xyz", "https://registry.tinycloud.xyz", "https://openkey.so"]);
    expect(directive(policy, "require-trusted-types-for")).toEqual(["'script'"]);
    expect(directive(policy, "trusted-types")).toEqual(["share-viewer-html", "dompurify", "'allow-duplicates'"]);
  });

  it("a preview build adds only the exact tinychat alias to the three framed routes, and leaves every other line alone", () => {
    const preview = renderCourierFrameHeaders(template, "preview");
    for (const route of FRAMED) {
      expect(directive(policyFor(preview, route), "frame-ancestors"), route).toEqual([ONE_PRODUCTION_ORIGIN, ONE_PREVIEW_ORIGIN]);
    }
    const before = template.split("\n");
    const after = preview.split("\n");
    expect(after.length).toBe(before.length);
    const changed = before.flatMap((line, at) => (line === after[at] ? [] : [at]));
    expect(changed).toHaveLength(FRAMED.length);
    for (const at of changed) expect(before[at]).toMatch(/^\s+Content-Security-Policy: .*frame-ancestors https:\/\/tinycloud\.one$/);
    // Rendering the production kind is the identity.
    expect(renderCourierFrameHeaders(template, "production")).toBe(template);
  });

  it("is production unless the signal is exactly 'preview'; dev adds nothing to a header", () => {
    for (const oneBuild of [undefined, "", "Preview", "true", "production", "preview ", "dev", 1]) {
      expect(buildKindOf({ oneBuild })).toBe("production");
    }
    expect(buildKindOf({ oneBuild: "preview" })).toBe("preview");
    expect(buildKindOf({ dev: true, oneBuild: "preview" })).toBe("dev");
    expect(frameAncestorsFor("dev")).toEqual([ONE_PRODUCTION_ORIGIN]);
    expect(oneOriginsFor("dev")).toEqual([ONE_PRODUCTION_ORIGIN, ONE_DEV_ORIGIN]);
    expect(oneOriginsFor("production")).toEqual(["https://tinycloud.one"]);
  });

  it("every other route's frame policy is unchanged", () => {
    const rules = parseProductionHeaders(template);
    // The site-wide policy refuses framing: the landing page, the share viewer and /c/* viewer routes, /how-it-works, and look-alike paths.
    for (const path of ["/", "/s/abc", "/c/abc", "/viewer", "/share", "/apps", "/apps/run", "/how-it-works", "/courier-x", "/couriers/", "/x/courier"]) {
      const headers = productionHeadersForPath(rules, path);
      expect(directive(headers["content-security-policy"] ?? "", "frame-ancestors"), path).toEqual(["'none'"]);
      expect(headers["x-frame-options"], path).toBeUndefined();
    }
    // The sandbox documents stay framable by this origin only.
    for (const path of ["/jsx-sandbox", "/jsx-sandbox.html", "/artifact-sandbox", "/mermaid-sandbox.html"]) {
      const headers = productionHeadersForPath(rules, path);
      expect(directive(headers["content-security-policy"] ?? "", "frame-ancestors"), path).toEqual(["'self'"]);
      expect(headers["x-frame-options"], path).toBe("SAMEORIGIN");
    }
    // Only the three framed routes name One anywhere.
    const named = rules.filter((rule) => Object.values(rule.headers).some((value) => value.includes("tinycloud.one"))).map((rule) => rule.pattern);
    expect(named).toEqual(FRAMED);
  });
});
