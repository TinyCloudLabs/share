import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { withUserContentOrigin } from "../src/artifact/user-content/headers.ts";

const page = readFileSync("apps/run/index.html", "utf8");
const metaPolicy = /<meta http-equiv="Content-Security-Policy" content="([^"]*)">/.exec(page)?.[1] ?? "";
const directives = (policy: string): Record<string, string[]> => Object.fromEntries(policy.split("; ").map((directive) => { const [name, ...values] = directive.split(" "); return [name ?? "", values]; }));
const headerPolicy = /^\/\*\n(?:.*\n)*?\s+Content-Security-Policy: (.*)$/m.exec(readFileSync("public/_headers", "utf8"))?.[1] ?? "";

describe("the runner page's policy", () => {
  it("lets the page frame only itself and OpenKey, talk to nodes over https, and run only its own scripts", () => {
    const policy = directives(metaPolicy);
    expect(policy["default-src"]).toEqual(["'none'"]);
    expect(policy["script-src"]).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(policy["frame-src"]).toEqual(["'self'", "https://openkey.so"]);
    expect(policy["connect-src"]).toEqual(["'self'", "https:"]);
    expect(policy["object-src"]).toEqual(["'none'"]);
    expect(policy["base-uri"]).toEqual(["'none'"]);
    expect(policy["form-action"]).toEqual(["'none'"]);
    expect(policy["require-trusted-types-for"]).toEqual(["'script'"]);
    expect(policy["script-src"]).not.toContain("'unsafe-eval'");
    expect(policy["script-src"]).not.toContain("'unsafe-inline'");
  });

  it("agrees with the site-wide header on what it frames and where it connects", () => {
    const header = directives(headerPolicy);
    const meta = directives(metaPolicy);
    for (const name of ["frame-src", "connect-src", "script-src", "object-src", "base-uri", "frame-ancestors"]) {
      if (name === "frame-ancestors") expect(header[name]).toEqual(["'none'"]);
      else expect(meta[name], name).toEqual(header[name]);
    }
  });

  it("loads one module script and has no inline script", () => {
    expect([...page.matchAll(/<script\b[^>]*>/g)].map((match) => match[0])).toEqual(['<script type="module" src="/src/apps/run-main.ts">']);
    expect(page).not.toMatch(/\son\w+=/i);
  });

  it("names the user-content origin in frame-src and connect-src when the build has one, and nothing else changes", () => {
    const origin = "https://usercontent.tinycloud.xyz";
    const changed = directives(withUserContentOrigin(metaPolicy, origin));
    expect(changed["frame-src"]).toEqual(["'self'", origin, "https://openkey.so"]);
    expect(changed["connect-src"]).toEqual(["'self'", origin, "https:"]);
    expect({ ...changed, "frame-src": undefined, "connect-src": undefined }).toEqual({ ...directives(metaPolicy), "frame-src": undefined, "connect-src": undefined });
  });
});
