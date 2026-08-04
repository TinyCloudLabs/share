import { describe, expect, it, vi } from "vitest";
import { canonicalize, toBase64Url, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";
import {
  EMAIL_CREDENTIAL_DESCRIPTOR,
  CredentialReceiverError,
  credentialRequirementFromVerifiedShare,
  mountCredentialReceiver,
  runCredentialReceiver,
  validateCredentialProjectionFromVerifiedShare,
  type ActiveCredentialClient,
  type CredentialEnsureResultLike,
  type VerifiedCredentialShare,
} from "../src/viewer/credential-receiver.js";

const holderDid = "did:key:z6MkholderSession";
const ownerDid = "did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678";

async function digest(value: unknown): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(value)))));
}

async function shareFixture(email = "Reader@Example.COM"): Promise<VerifiedCredentialShare> {
  const requirement = {
    type: "TinyCloudCredentialRequirement",
    version: 1,
    profile: { id: "tinycloud.email-proof/v1", version: 1 },
    credentialType: { id: "opencredentials.email/v1", version: 1 },
    claims: { email: email.toLowerCase() },
    maxAgeSeconds: 3600,
  } as const;
  const policy = {
    schema: "xyz.tinycloud.policy/policy/v2",
    credentialRequirement: {
      type: "TinyCloudPolicyCredentialRequirement",
      version: 1,
      requirementDigest: await digest(requirement),
      descriptorDigest: await digest(EMAIL_CREDENTIAL_DESCRIPTOR),
      issuerDid: EMAIL_CREDENTIAL_DESCRIPTOR.issuer.did,
      issuerKid: EMAIL_CREDENTIAL_DESCRIPTOR.issuer.kid,
      profile: requirement.profile,
      credentialType: requirement.credentialType,
    },
  };
  return {
    envelope: {
      version: 3,
      recipientMatcher: { kind: "exactEmail", value: email },
      actions: ["read"],
      resource: { kind: "exact", path: "docs/report.md" },
      target: { origin: "https://node.example", nodeAudience: "did:web:enforcer.example", spaceId: "owner-space" },
      policy,
      policyCid: "bafkreipolicy",
      policyRoot: { cid: "policy-root", authorization: "policy-root-authorization", role: "policy-authority" },
      enforcementRoot: { cid: "enforcement-root", authorization: "enforcement-root-authorization", role: "policy-enforcement" },
      contentSource: { kvResource: "owner-space/kv/docs/report.md", selector: "exact", encryptionNetwork: "urn:tinycloud:encryption:fixture" },
      encryptionNetwork: "urn:tinycloud:encryption:fixture",
      attestedEnforcerBinding: { nodeAudience: "did:web:node.example" },
      metadata: { mediaType: "text/plain" },
    } as unknown as ShareEnvelopeV3,
    policy,
    shareCid: "bafkreicredentialshare",
  };
}

async function receiverFixture(status: "reused" | "acquired") {
  const share = await shareFixture();
  const projection = share.policy.credentialRequirement as Record<string, unknown>;
  const credential = {
    holderDid,
    subjectDid: holderDid,
    credentialDigest: "credential-digest",
    descriptorDigest: projection.descriptorDigest as string,
    issuerDid: projection.issuerDid as string,
    issuerKid: projection.issuerKid as string,
    profile: projection.profile as { readonly id: string; readonly version: 1 },
    credentialType: projection.credentialType as { readonly id: string; readonly version: 1 },
    claims: { email: "reader@example.com" },
    credential: "verified-sd-jwt",
  };
  const record = {
    ownerDid,
    recordId: "record-1",
    holderDid,
    requirementDigest: projection.requirementDigest as string,
    descriptorDigest: projection.descriptorDigest as string,
    issuerDid: projection.issuerDid as string,
    issuerKid: projection.issuerKid as string,
    profile: projection.profile as { readonly id: string; readonly version: 1 },
    credentialType: projection.credentialType as { readonly id: string; readonly version: 1 },
    credentialDigest: credential.credentialDigest,
    claims: credential.claims,
  };
  const ensured: CredentialEnsureResultLike = {
    status,
    credential,
    record,
    ...(status === "acquired" ? { receipt: { ownerDid, recordId: record.recordId } } : {}),
  };
  const ensure = vi.fn(async (_requirement: unknown, options: { readonly onProgress: (event: { readonly state: "checking" | "saving" }) => void }) => {
    options.onProgress({ state: "checking" });
    if (status === "acquired") options.onProgress({ state: "saving" });
    return ensured;
  });
  const find = vi.fn(async () => record);
  const order: string[] = [];
  const admitPolicy = vi.fn(async () => {
    order.push("admitPolicy");
    return {
      session: { cid: "delegation-cid", authorization: "compact-authorization", aud: holderDid },
      installed: { cid: "delegation-cid", audience: holderDid },
    };
  });
  const encrypted = new TextEncoder().encode(canonicalize({ type: "fixture-encrypted-envelope" }));
  const get = vi.fn(async () => {
    order.push("get");
    return { ok: true as const, data: { data: encrypted, headers: {} } };
  });
  const decryptEnvelope = vi.fn(async () => {
    order.push("decrypt");
    return { ok: true as const, data: new TextEncoder().encode("opened") };
  });
  const signSessionBytes = vi.fn(async () => new Uint8Array([1, 2, 3]));
  const client = {
    sessionDid: `${holderDid}#${holderDid.slice("did:key:".length)}`,
    credentialHolderDid: holderDid,
    credentialHolderKid: `${holderDid}#${holderDid.slice("did:key:".length)}`,
    session: () => ({}),
    signSessionBytes,
    credentials: { ensure, find, admitPolicy },
    kvForSpace: vi.fn(() => ({ get })),
    encryption: { decryptEnvelope },
  } as unknown as ActiveCredentialClient;
  return { share, client, ensure, find, admitPolicy, get, decryptEnvelope, signSessionBytes, record, ensured, order };
}

describe("TC-465 credential-gated receiver", () => {
  it("returns error announcements to polite progress on retry", async () => {
    const share = await shareFixture();
    const operation = Object.freeze({ type: "TinyCloudInterruptedShareRead" as const, version: 1 as const, shareCid: share.shareCid, envelope: share.envelope });
    const root = document.createElement("div");
    mountCredentialReceiver(root, {
      share,
      operation,
      connect: async () => { throw new Error("offline"); },
      openerOrigin: "https://share.tinycloud.xyz",
      onComplete: () => undefined,
    });
    const button = root.querySelector("button");
    const status = root.querySelector("[role]");
    expect(button).toBeInstanceOf(HTMLButtonElement);
    expect(status?.getAttribute("role")).toBe("status");
    expect(status?.getAttribute("aria-live")).toBe("polite");

    button!.click();
    await vi.waitFor(() => expect(status?.getAttribute("role")).toBe("alert"));
    expect(status?.getAttribute("aria-live")).toBe("assertive");
    button!.click();

    expect(status?.getAttribute("role")).toBe("status");
    expect(status?.getAttribute("aria-live")).toBe("polite");
    expect(status?.textContent).toBe("Checking your TinyCloud for this credential…");
  });

  it("derives the request-local exact-email requirement only from the verified envelope and checks its signed projection", async () => {
    const share = await shareFixture();
    const requirement = credentialRequirementFromVerifiedShare(share);
    expect(requirement).toEqual({
      type: "TinyCloudCredentialRequirement",
      version: 1,
      profile: { id: "tinycloud.email-proof/v1", version: 1 },
      credentialType: { id: "opencredentials.email/v1", version: 1 },
      claims: { email: "reader@example.com" },
      maxAgeSeconds: 3600,
    });
    await expect(validateCredentialProjectionFromVerifiedShare(share, requirement)).resolves.toMatchObject({
      requirementDigest: await digest(requirement),
      descriptorDigest: await digest(EMAIL_CREDENTIAL_DESCRIPTOR),
      issuerDid: EMAIL_CREDENTIAL_DESCRIPTOR.issuer.did,
      issuerKid: EMAIL_CREDENTIAL_DESCRIPTOR.issuer.kid,
    });
    const frozenRequirement = credentialRequirementFromVerifiedShare(await shareFixture("Alice@Example.TEST"));
    expect(await digest(frozenRequirement)).toBe("e3awkBcMp_Ff0YBZXI2XUPYyKmkE_HjeAXI7tz6Brgo");
    expect(await digest(EMAIL_CREDENTIAL_DESCRIPTOR)).toBe("1tg-qphmKBVtNwzVg9xyz-xxqt_xtMXAsQyXw46m8S0");

    await expect(validateCredentialProjectionFromVerifiedShare({ ...share, policy: { ...share.policy, credentialRequirement: { ...(share.policy.credentialRequirement as object), issuerKid: "did:web:attacker.example#key" } } }, requirement))
      .rejects.toMatchObject({ code: "UNSUPPORTED_REQUIREMENT" });
  });

  it("reuses a durable credential in the active TinyCloud and resumes through ordinary delegation and invocation", async () => {
    const fixture = await receiverFixture("reused");
    const operation = Object.freeze({ type: "TinyCloudInterruptedShareRead" as const, version: 1 as const, shareCid: fixture.share.shareCid, envelope: fixture.share.envelope });
    const states: string[] = [];

    const content = await runCredentialReceiver({ share: fixture.share, operation, connect: async () => fixture.client, openerOrigin: "https://share.tinycloud.xyz", onState: (state) => states.push(state) });

    expect(new TextDecoder().decode(content.bytes)).toBe("opened");
    expect(fixture.ensure).toHaveBeenCalledOnce();
    expect(fixture.ensure.mock.calls[0]![1]).toMatchObject({ descriptor: EMAIL_CREDENTIAL_DESCRIPTOR, interaction: "popup", openerOrigin: "https://share.tinycloud.xyz" });
    expect(fixture.find).toHaveBeenCalledOnce();
    expect(fixture.admitPolicy).toHaveBeenCalledWith(expect.objectContaining({ ensured: fixture.ensured, requirement: expect.objectContaining({ claims: { email: "reader@example.com" } }), requestedCapabilities: [
      { kind: "kv", resource: "owner-space/kv/docs/report.md", selector: "exact", actions: ["tinycloud.kv/get"] },
      { kind: "encryption", resource: "urn:tinycloud:encryption:fixture", action: "tinycloud.encryption/decrypt" },
    ] }));
    expect(fixture.order).toEqual(["admitPolicy", "get", "decrypt"]);
    expect(states).toEqual(["checking-existing", "authorizing-access", "opening-content", "success"]);
    expect(fixture.client.kvForSpace).toHaveBeenCalledWith("owner-space");
    expect(fixture.get).toHaveBeenCalledWith("docs/report.md", expect.objectContaining({ binary: true }));
    expect(fixture.decryptEnvelope).toHaveBeenCalledWith(expect.anything(), { proofs: ["delegation-cid"] }, { targetNode: "did:web:node.example" });
  });

  it("acquires and durably reads back a missing credential before resuming the exact interrupted operation", async () => {
    const fixture = await receiverFixture("acquired");
    const operation = Object.freeze({ type: "TinyCloudInterruptedShareRead" as const, version: 1 as const, shareCid: fixture.share.shareCid, envelope: fixture.share.envelope });
    const states: string[] = [];

    await runCredentialReceiver({ share: fixture.share, operation, connect: async () => fixture.client, openerOrigin: "https://share.tinycloud.xyz", onState: (state) => states.push(state) });

    expect(fixture.order).toEqual(["admitPolicy", "get", "decrypt"]);
    expect(states).toContain("saving");
    expect(fixture.find).toHaveBeenCalledOnce();
  });

  it("does not admit an acquired credential without its authenticated storage receipt", async () => {
    const fixture = await receiverFixture("acquired");
    const operation = Object.freeze({ type: "TinyCloudInterruptedShareRead" as const, version: 1 as const, shareCid: fixture.share.shareCid, envelope: fixture.share.envelope });
    const { receipt: _receipt, ...withoutReceipt } = fixture.ensured;
    fixture.ensure.mockResolvedValueOnce(withoutReceipt);

    await expect(runCredentialReceiver({ share: fixture.share, operation, connect: async () => fixture.client, openerOrigin: "https://share.tinycloud.xyz" }))
      .rejects.toEqual(expect.objectContaining<Partial<CredentialReceiverError>>({ code: "CREDENTIAL_NOT_DURABLE" }));
    expect(fixture.admitPolicy).not.toHaveBeenCalled();
  });
});
