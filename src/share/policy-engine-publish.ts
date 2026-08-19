/**
 * TC-500 sender leg: publish the exact-recipient policy to the standalone
 * Policy Engine.
 *
 * Before this, the only policy the sender registered went to TinyCloud Node's
 * `/share/v3/policies`, which is a Share-shaped route on a service that should
 * only enforce generic capabilities — and which does not exist on Node `main`
 * at all. The engine that actually decides never saw a policy, so the
 * accountless receiver had nothing to present against.
 *
 * The sender now registers three owner-signed objects with the engine through
 * its own generic registration contract:
 *
 * | Object | Why the engine needs it |
 * | --- | --- |
 * | `OperationalKeyAuthorization` | the owner authorising *this* engine's grant-issuer key |
 * | `PolicyEngineRecord` | the owner naming this engine's endpoint, audience, and grant issuer |
 * | `Policy` | one exact recipient, one exact resource, read-only |
 *
 * The first two are per-owner-and-engine and are re-presented on every publish
 * because registration is idempotent for content-addressed objects; the policy
 * is per share.
 *
 * Nothing Share-specific reaches the engine. The objects are the frozen
 * TinyCloud signed-object profile, and the transport is the SDK's own
 * origin-pinned one — so a publish cannot egress anywhere but the configured
 * engine, and cannot touch a `/share/*` path.
 */
import {
  publishSignedPolicyObjects,
  type PolicyAccessTransport,
} from "@tinycloud/sdk-core/policy-access";
import {
  createAndSignOperationalKeyAuthorization,
  createAndSignPolicy,
  createAndSignPolicyEngineRecord,
  ED25519_JCS_SIGNATURE_SUITE,
  type SignedObjectSigner,
} from "@tinycloud/sdk-core/policy";

/** The engine's own verifier id for a W3C VC / SD-JWT credential. */
const CREDENTIAL_VERIFIER = "w3c.vc/credential/v1" as const;
/** The single evidence atom an accountless recipient satisfies. */
export const RECIPIENT_EMAIL_REQUIREMENT_ID = "recipient-email" as const;

export interface SharePolicyEngineTarget {
  readonly endpoint: string;
  readonly audience: string;
  readonly grantIssuerDid: string;
}

export interface PublishSharePolicyInput {
  readonly engine: SharePolicyEngineTarget;
  /** The owner's session DID. It signs, and it is the policy owner. */
  readonly ownerDid: string;
  readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;
  /** Exact recipient address, already canonicalized by the composer. */
  readonly recipientEmail: string;
  /** Exact TinyCloud KV resource holding the ciphertext. */
  readonly kvResource: string;
  /** Space-scoped capability slice the grant may never exceed. */
  readonly capabilitySpace: string;
  readonly resourcePath: string;
  readonly shareId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly transport: PolicyAccessTransport;
  /** Establish the owner-signed generic issuance parent before publication. */
  readonly prepareParent?: (input: {
    readonly policyId: string;
    readonly capability: ReturnType<typeof readOnlyCeiling>[number];
  }) => Promise<void>;
}

export interface PublishSharePolicyResult {
  readonly policyId: string;
  readonly requirementId: typeof RECIPIENT_EMAIL_REQUIREMENT_ID;
}

function domainOf(email: string): string {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) {
    throw new TypeError("an exact-email share requires an addressable recipient");
  }
  return email.slice(at + 1);
}

/**
 * The read-only ceiling. Exactly one action on exactly one resource: the engine
 * enforces containment against this, so anything wider here is authority the
 * recipient could actually use.
 */
function readOnlyCeiling(input: PublishSharePolicyInput) {
  return [
    {
      service: "tinycloud.kv",
      space: input.capabilitySpace,
      path: input.resourcePath,
      actions: ["tinycloud.kv/get"],
    },
  ];
}

export async function publishSharePolicyToEngine(
  input: PublishSharePolicyInput,
): Promise<PublishSharePolicyResult> {
  const signer: SignedObjectSigner = {
    suite: ED25519_JCS_SIGNATURE_SUITE,
    signerDid: input.ownerDid,
    signDigest: (digest) => input.sign(digest),
  };

  // The engine only honours a PolicyEngineRecord if the same owner separately
  // authorised the named grant-issuer key. Both artifacts expire with the
  // share, so a stale authority cannot outlive what it was published for.
  const grantIssuerAuthorization = await createAndSignOperationalKeyAuthorization(
    {
      schema: "xyz.tinycloud.auth/key-authorization/v0",
      ownerDid: input.ownerDid,
      keyDid: input.engine.grantIssuerDid,
      roles: ["grant-issuer"],
      notBefore: input.createdAt,
      expiresAt: input.expiresAt,
    },
    signer,
  );

  const engineRecord = await createAndSignPolicyEngineRecord(
    {
      schema: "xyz.tinycloud.policy/engine-record/v0",
      ownerDid: input.ownerDid,
      endpoint: input.engine.endpoint,
      audience: input.engine.audience,
      supportedPolicyVersions: ["v0"],
      supportedEvidenceVerifiers: [CREDENTIAL_VERIFIER],
      grantIssuerDid: input.engine.grantIssuerDid,
      expiresAt: input.expiresAt,
    },
    signer,
  );

  // `when` carries exactly one evidence atom and pins no subject: the recipient
  // is an ephemeral browser key that does not exist yet at publish time, and
  // the engine's accountless binding requires the evidence atom to be present
  // rather than falling back to subject-only matching.
  const policy = await createAndSignPolicy(
    {
      schema: "xyz.tinycloud.policy/policy/v0",
      ownerDid: input.ownerDid,
      signingKeyDid: input.ownerDid,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      resource: {
        resourceType: "tinycloud-share",
        resourceId: input.shareId,
        permissionsCeiling: readOnlyCeiling(input),
      },
      when: {
        evidence: {
          requirementId: RECIPIENT_EMAIL_REQUIREMENT_ID,
          verifier: CREDENTIAL_VERIFIER,
          requirements: {
            type: "opencredentials.email/v1",
            // The domain gate stays mandatory in the engine; the exact address
            // is what makes this share addressed to one person.
            emailDomains: [domainOf(input.recipientEmail)],
            emails: [input.recipientEmail],
          },
        },
      },
      grant: {
        output: "portable-delegation",
        maxTtlSeconds: 300,
        delegationMode: "terminal",
        revocation: "refresh_only",
      },
      disclosure: { denial: "code" },
      audit: { issuance: "security" },
    },
    signer,
  );

  await input.prepareParent?.({
    policyId: policy.policyId,
    capability: readOnlyCeiling(input)[0]!,
  });

  const { registeredPolicyIds } = await publishSignedPolicyObjects({
    endpoint: input.engine.endpoint,
    signedObjects: [grantIssuerAuthorization, engineRecord, policy],
    transport: input.transport,
  });
  if (!registeredPolicyIds.includes(policy.policyId)) {
    throw new Error("the policy engine did not report the published policy");
  }
  return { policyId: policy.policyId, requirementId: RECIPIENT_EMAIL_REQUIREMENT_ID };
}
