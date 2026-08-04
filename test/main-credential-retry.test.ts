import { beforeEach, describe, expect, it, vi } from "vitest";
import { canonicalize, toBase64Url, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";
import { EMAIL_CREDENTIAL_DESCRIPTOR } from "../src/credentials/email.js";

const state = vi.hoisted(() => ({
  authenticate: vi.fn(),
  createClient: vi.fn(),
  presented: [] as unknown[],
}));

vi.mock("../src/email-share/url.js", () => ({
  captureAndScrubLaunch: () => ({ shareHref: "https://share.tinycloud.xyz/s/test" }),
}));

vi.mock("../src/email-share/view.js", () => ({
  appendRecipientForgetAction: () => undefined,
  renderRecipientInvalid: () => undefined,
  renderRecipientLoading: () => undefined,
  renderRecipientState: () => undefined,
}));

vi.mock("../src/email-share/claim.js", () => ({
  createHolder: async () => ({}),
  createClaimController: () => ({ state: { state: "idle" }, subscribe: () => undefined }),
}));

vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({
    nodeOrigin: "https://node.example",
    nodeAudience: "did:web:node.example",
    enforcerDid: "did:web:node.example",
    nodeInvitationKid: "did:web:node.example#key-1",
    nodeInvitationPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  }),
  trustedNodeFromConfig: () => ({ did: "did:web:node.example" }),
}));

vi.mock("../src/viewer/resolve.js", () => ({
  createBrowserAddressedAuthorization: () => undefined,
  resolveShare: async () => state.resolved,
}));

vi.mock("../src/viewer/present.js", () => ({
  presentShare: async (_root: HTMLElement, result: unknown) => { state.presented.push(result); },
}));

vi.mock("@tinycloud/share-sdk", () => ({ createRegisteredPolicyAuthority: () => ({}) }));

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: (...args: unknown[]) => state.authenticate(...args),
  createTinyCloudClient: (...args: unknown[]) => state.createClient(...args),
}));

async function digest(value: unknown): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(value)))));
}

async function resolvedShare() {
  const requirement = {
    type: "TinyCloudCredentialRequirement",
    version: 1,
    profile: { id: "tinycloud.email-proof/v1", version: 1 },
    credentialType: { id: "opencredentials.email/v1", version: 1 },
    claims: { email: "reader@example.com" },
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
  const envelope = {
    version: 3,
    recipientMatcher: { kind: "exactEmail", value: "reader@example.com" },
    actions: ["read"],
    resource: { kind: "exact", path: "docs/report.md" },
    target: { origin: "https://node.example", nodeAudience: "did:web:node.example", spaceId: "owner-space" },
    policy,
    policyCid: "bafkreipolicy",
    policyRoot: { cid: "policy-root", authorization: "policy-root-authorization", role: "policy-authority" },
    enforcementRoot: { cid: "enforcement-root", authorization: "enforcement-root-authorization", role: "policy-enforcement" },
    contentSource: { kvResource: "owner-space/kv/docs/report.md", selector: "exact", encryptionNetwork: "urn:tinycloud:encryption:fixture" },
    encryptionNetwork: "urn:tinycloud:encryption:fixture",
    attestedEnforcerBinding: { nodeAudience: "did:web:node.example" },
    metadata: { mediaType: "text/plain" },
  } as unknown as ShareEnvelopeV3;
  return { state: "policy-v2-claim-required" as const, envelope, policy, shareCid: "bafkreicredentialshare" };
}

async function client() {
  const holderDid = "did:key:z6MkholderSession";
  const resolved = await resolvedShare();
  const projection = resolved.policy.credentialRequirement;
  const record = {
    ownerDid: "did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678",
    recordId: "record-1",
    holderDid,
    requirementDigest: projection.requirementDigest,
    descriptorDigest: projection.descriptorDigest,
    issuerDid: projection.issuerDid,
    issuerKid: projection.issuerKid,
    profile: projection.profile,
    credentialType: projection.credentialType,
    credentialDigest: "credential-digest",
    claims: { email: "reader@example.com" },
  };
  const encrypted = new TextEncoder().encode(canonicalize({ type: "fixture-encrypted-envelope" }));
  return {
    sessionDid: `${holderDid}#${holderDid.slice("did:key:".length)}`,
    credentialHolderDid: holderDid,
    credentialHolderKid: `${holderDid}#${holderDid.slice("did:key:".length)}`,
    session: () => ({}),
    signSessionBytes: async () => new Uint8Array([1, 2, 3]),
    credentials: {
      ensure: async () => ({ status: "acquired" as const, credential: { ...record, subjectDid: holderDid, credential: "verified-sd-jwt" }, record, receipt: { ownerDid: record.ownerDid, recordId: record.recordId } }),
      find: async () => record,
      admitPolicy: async () => ({ session: { cid: "delegation-cid", authorization: "compact-authorization", aud: holderDid }, installed: { cid: "delegation-cid", audience: holderDid } }),
    },
    kvForSpace: () => ({ get: async () => ({ ok: true as const, data: { data: encrypted, headers: {} } }) }),
    encryption: { decryptEnvelope: async () => ({ ok: true as const, data: new TextEncoder().encode("opened") }) },
  };
}

beforeEach(async () => {
  vi.resetModules();
  document.body.innerHTML = '<div id="viewer"></div>';
  window.history.replaceState(null, "", "/viewer.html#secret");
  state.authenticate.mockReset();
  state.createClient.mockReset();
  state.presented.length = 0;
  state.resolved = await resolvedShare();
});

describe("TC-465 recipient connection recovery", () => {
  it("retries OpenKey through the real main.ts receiver after a failed connection", async () => {
    const successfulClient = await client();
    state.authenticate.mockRejectedValueOnce(new Error("popup closed")).mockResolvedValueOnce({});
    state.createClient.mockResolvedValue(successfulClient);

    await import("../src/main.js");
    const root = document.getElementById("viewer")!;
    await vi.waitFor(() => expect(root.querySelector("button")?.textContent).toBe("Confirm email"));

    root.querySelector<HTMLButtonElement>("button")!.click();
    await vi.waitFor(() => expect(root.querySelector("[role=alert]")?.textContent).toContain("couldn't verify"));
    expect(state.authenticate).toHaveBeenCalledTimes(1);

    const retry = root.querySelector<HTMLButtonElement>("button")!;
    expect(retry.disabled).toBe(false);
    retry.click();
    await vi.waitFor(() => expect(state.presented).toHaveLength(1));
    expect(state.authenticate).toHaveBeenCalledTimes(2);
    expect(state.createClient).toHaveBeenCalledTimes(1);
    expect(state.presented[0]).toMatchObject({ state: "ok", access: "policy" });
    expect(new TextDecoder().decode((state.presented[0] as { contentBytes: Uint8Array }).contentBytes)).toBe("opened");
  });
});
