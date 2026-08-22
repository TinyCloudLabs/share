import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { validateSharePublicConfig } from "../src/email-share/config.js";

const current = {
  version: "tinycloud.share/config-v2",
  shareOrigin: "https://share.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://witness.credentials.org",
  emailOrigin: "https://api.share.tinycloud.xyz",
  accountlessReceiverEnabled: true,
} as const;

describe("Share public routing config", () => {
  it("contains no deployment-wide owner Node or invitation key", () => {
    expect(validateSharePublicConfig(current)).toEqual(current);
    for (const stale of ["nodeOrigin", "nodeAudience", "enforcerDid", "nodeInvitationPublicKey"]) {
      expect(() => validateSharePublicConfig({ ...current, [stale]: "retired" })).toThrow("unknown or missing fields");
    }
  });

  it("lets the browser contact any HTTPS owner node while application trust stays registry-bound", () => {
    const headers = readFileSync("public/_headers", "utf8");
    const documents = ["share.html", "viewer.html"].map((path) => readFileSync(path, "utf8"));
    for (const policy of [headers, ...documents]) {
      expect(policy).toContain("connect-src 'self' https:;");
      expect(policy).not.toContain("https://tee.node.tinycloud.xyz");
      expect(policy).not.toContain("http://127.0.0.1:");
    }
  });
});
