import { describe, expect, it } from "vitest";
import { createEmailDomainCredentialRequirement, credentialRequirementDigest } from "@tinycloud/sdk-core";
import {
  EMAIL_CREDENTIAL_DESCRIPTOR,
  EMAIL_DOMAIN_CREDENTIAL_DESCRIPTOR,
  canonicalDigest,
  emailDomainCredentialPolicyProjection,
  emailDomainCredentialRequirement,
} from "../src/credentials/email.js";

describe("pinned OpenCredentials contracts", () => {
  it("keeps the exact-email descriptor digest that live policies commit to", () => {
    expect(canonicalDigest(EMAIL_CREDENTIAL_DESCRIPTOR)).toBe("1tg-qphmKBVtNwzVg9xyz-xxqt_xtMXAsQyXw46m8S0");
  });

  it("pins the email-domain descriptor the issuer serves", () => {
    expect(canonicalDigest(EMAIL_DOMAIN_CREDENTIAL_DESCRIPTOR)).toBe("33X5mAkZZgApdD3xh_T-3KS5moop0J2Nloi2nqWsdWY");
    expect(EMAIL_DOMAIN_CREDENTIAL_DESCRIPTOR.claims.map((claim) => claim.name)).toEqual(["email", "emailDomain"]);
  });

  it("commits the same domain requirement digest the receiving SDK recomputes", async () => {
    const sender = emailDomainCredentialRequirement("@TinyCloud.XYZ");
    const receiver = createEmailDomainCredentialRequirement({ domain: "tinycloud.xyz", profile: sender.profile, credentialType: sender.credentialType });
    expect(sender.claims).toEqual({ emailDomain: "tinycloud.xyz" });
    const projection = emailDomainCredentialPolicyProjection(sender);
    expect(projection.requirementDigest).toBe(await credentialRequirementDigest(receiver));
    expect(projection.descriptorDigest).toBe("33X5mAkZZgApdD3xh_T-3KS5moop0J2Nloi2nqWsdWY");
    for (const invalid of ["tinycloud", "bücher.de", "tinyclоud.xyz", "tinycloud.xyz.", "10.0.0.1"]) {
      expect(() => emailDomainCredentialRequirement(invalid), invalid).toThrow();
    }
  });
});
