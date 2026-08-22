import { describe, expect, it } from "vitest";
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
});
