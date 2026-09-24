import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { validateSharePublicConfig } from "../src/email-share/config.js";

const current = {
  version: "tinycloud.share/config-v2",
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://witness.credentials.org",
  accountlessReceiverEnabled: true,
} as const;

describe("Share public routing config", () => {
  it("rewrites public sender and receiver routes to directory indexes", () => {
    const redirects = readFileSync("public/_redirects", "utf8");
    expect(redirects).toContain("/share /share/ 200");
    expect(redirects).toContain("/viewer /viewer/ 200");
    expect(redirects).toContain("/s/* /viewer/ 200");
    expect(redirects).not.toMatch(/^\/(?:share|viewer)\s+\/[^\s]*\.html\s+200/m);
  });

  it("self-provenances the joined browser artifact against the installed npm betas", () => {
    const gate = readFileSync("test/e2e-prod/joined-gate.mjs", "utf8");
    for (const field of ["shareCommit", "shareTree", "bundleSha256", "publishedPackages", "integrity"]) expect(gate).toContain(field);
  });

  it("contains only a sender bootstrap choice, never a recipient trust anchor or invitation key", () => {
    expect(validateSharePublicConfig(current)).toEqual(current);
    for (const stale of ["nodeOrigin", "nodeAudience", "enforcerDid", "nodeInvitationPublicKey"]) {
      expect(() => validateSharePublicConfig({ ...current, [stale]: "retired" })).toThrow("unknown or missing fields");
    }
  });

  it("rejects a loopback or placeholder sender bootstrap node in production", () => {
    expect(() => validateSharePublicConfig({ ...current, senderBootstrapNodeOrigin: "http://127.0.0.1:8788" })).toThrow();
    expect(() => validateSharePublicConfig({ ...current, senderBootstrapNodeOrigin: "https://node.example" })).toThrow("placeholder or loopback");
  });

  it("lets the browser contact any HTTPS owner node while application trust stays registry-bound", () => {
    const headers = readFileSync("public/_headers", "utf8");
    const documents = ["share/index.html", "viewer/index.html"].map((path) => readFileSync(path, "utf8"));
    for (const policy of [headers, ...documents]) {
      expect(policy).toContain("connect-src 'self' https:;");
      expect(policy).not.toContain("https://tee.node.tinycloud.xyz");
      expect(policy).not.toContain("http://127.0.0.1:");
    }
  });

  it("advertises only the sealed addressed-link form in browser-visible protocol copy", () => {
    const viewer = readFileSync("viewer/index.html", "utf8");
    const product = readFileSync("PRODUCT.md", "utf8");
    for (const copy of [viewer, product]) {
      expect(copy).toContain("/s/inline#v=2");
      expect(copy).not.toContain("/viewer?tc2");
      expect(copy).not.toContain("policy-v3-tc2");
    }
  });
});
