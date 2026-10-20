import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { parseProductionHeaders, productionHeadersForPath } from "./e2e-prod/production-headers.mjs";

/** `directive -> sources`, from a policy string. */
function parsePolicy(policy: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of policy.split(";").map((chunk) => chunk.trim()).filter(Boolean)) {
    const [name = "", ...sources] = part.split(/\s+/);
    directives.set(name, sources);
  }
  return directives;
}

const html = readFileSync("apps/index.html", "utf8");
const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1];
const header = productionHeadersForPath(parseProductionHeaders(readFileSync("public/_headers", "utf8")), "/apps/")["content-security-policy"];

describe("the /apps/ page's CSP", () => {
  it("has a meta policy and the site-wide header applies to it as well", () => {
    expect(meta).toBeTypeOf("string");
    expect(header).toBeTypeOf("string");
  });

  it("agrees with the header on every directive the two share, and is never looser on the others", () => {
    const page = parsePolicy(meta ?? "");
    const site = parsePolicy(header ?? "");
    // Identical where both speak: the browser enforces both, so a looser meta would hide in the header and a drift would go unseen.
    for (const name of ["default-src", "script-src", "style-src", "connect-src", "img-src", "font-src", "base-uri", "object-src", "require-trusted-types-for"]) {
      expect(page.get(name), name).toEqual(site.get(name));
    }
    // Where the page is narrower than the site, every source it names is one the site allows (or it says 'none').
    for (const name of ["frame-src", "form-action"]) {
      const own = page.get(name) ?? [];
      expect(own.length, name).toBeGreaterThan(0);
      for (const source of own) expect(source === "'none'" || (site.get(name) ?? []).includes(source), `${name} ${source}`).toBe(true);
    }
  });

  it("allows no inline or eval script, and keeps Trusted Types required, in the meta policy itself", () => {
    const page = parsePolicy(meta ?? "");
    const scripts = page.get("script-src") ?? [];
    expect(scripts).not.toContain("'unsafe-inline'");
    expect(scripts).not.toContain("'unsafe-eval'");
    expect(scripts).not.toContain("https:");
    expect(page.get("require-trusted-types-for")).toEqual(["'script'"]);
    expect(page.get("default-src")).toEqual(["'none'"]);
    expect(page.get("object-src")).toEqual(["'none'"]);
    expect(page.get("base-uri")).toEqual(["'none'"]);
    // The only frame the page may open is OpenKey.
    expect(page.get("frame-src")).toEqual(["https://openkey.so"]);
  });
});
