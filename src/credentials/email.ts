import { canonicalize, toBase64Url, type PolicyCredentialRequirementV1 } from "@tinycloud/share-envelope";
import { sha256 } from "@noble/hashes/sha256";

export const EMAIL_CREDENTIAL_DESCRIPTOR = Object.freeze({
  type: "tinycloud.credentials/descriptor/v1",
  contractVersion: 1,
  protocol: "tinycloud.credentials/acquisition/v1",
  profile: "tinycloud.email-proof/v1",
  profileVersion: 1,
  display: {
    title: "Email address",
    description: "Prove control of your mailbox",
    consent: "Prove control of your mailbox",
    securityTextLocked: true,
  },
  accessibility: {
    progressLabel: "Credential acquisition progress",
    errorLiveRegion: "assertive",
  },
  theme: {
    tokenVersion: "tinycloud.credentials/tokens/v1",
    allowed: ["accentColor", "fontFamily", "borderRadius"],
  },
  issuer: {
    did: "did:web:issuer.credentials.org",
    origin: "https://witness.credentials.org",
    kid: "did:web:issuer.credentials.org#controller",
  },
  interaction: {
    origin: "https://credentials.org",
    pathTemplate: "/credentials/acquire/{requestId}",
  },
  format: {
    id: "vc+sd-jwt",
    vct: "opencredentials.email/v1",
  },
  claims: [{ name: "email", matching: "normalized_exact", selectiveDisclosure: true }],
  subjectRelationship: "holder_is_subject",
  inputs: [{
    id: "email",
    label: "Email address",
    schema: { type: "string", format: "email", minLength: 3, maxLength: 320 },
    prefill: "privacy_hint_only",
    autocomplete: "off",
  }],
  steps: [
    { type: "collect_input", version: 1 },
    { type: "mailbox_otp", version: 1 },
    { type: "holder_signature", version: 1 },
  ],
  holderBinding: {
    required: true,
    alg: "EdDSA",
    domain: "tinycloud.credentials/holder-binding/v1",
    version: 1,
  },
  endpoints: {
    request: "request",
    state: "state",
    challenge: "challenge",
    proof: "proof",
    holderBinding: "holder_binding",
    holderSignature: "holder_signature",
    issue: "issue",
    result: "result",
  },
  lifecycle: {
    requestTtlSeconds: 600,
    challengeTtlSeconds: 300,
    maxProofAttempts: 5,
    challengeConsumption: "atomic_once",
    retry: "bounded",
  },
  status: { type: "none", freshnessSeconds: 300 },
  revocation: { supported: false },
  presentation: {
    stateVersion: "tinycloud.credentials/ux-states/v1",
    states: ["collecting", "challenging", "proving", "signing", "issuing", "verifying", "saving", "success", "recovery"],
  },
} as const);

export interface EmailCredentialRequirement {
  readonly type: "TinyCloudCredentialRequirement";
  readonly version: 1;
  readonly profile: { readonly id: "tinycloud.email-proof/v1"; readonly version: 1 };
  readonly credentialType: { readonly id: "opencredentials.email/v1"; readonly version: 1 };
  readonly claims: { readonly email: string };
  readonly maxAgeSeconds: 3600;
}

export function canonicalEmail(value: string): string {
  if (!/^[\x21-\x3f\x41-\x7e]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(value)) {
    throw new TypeError("unsupported exact-email credential requirement");
  }
  return value.toLowerCase();
}

export function emailCredentialRequirement(email: string): EmailCredentialRequirement {
  return Object.freeze({
    type: "TinyCloudCredentialRequirement",
    version: 1,
    profile: { id: "tinycloud.email-proof/v1", version: 1 },
    credentialType: { id: "opencredentials.email/v1", version: 1 },
    claims: { email: canonicalEmail(email) },
    maxAgeSeconds: 3600,
  } as const);
}

export function canonicalDigest(value: unknown): string {
  return toBase64Url(sha256(new TextEncoder().encode(canonicalize(value))));
}

export function emailCredentialPolicyProjection(requirement: EmailCredentialRequirement): PolicyCredentialRequirementV1 {
  return Object.freeze({
    type: "TinyCloudPolicyCredentialRequirement",
    version: 1,
    requirementDigest: canonicalDigest(requirement),
    descriptorDigest: canonicalDigest(EMAIL_CREDENTIAL_DESCRIPTOR),
    issuerDid: EMAIL_CREDENTIAL_DESCRIPTOR.issuer.did,
    issuerKid: EMAIL_CREDENTIAL_DESCRIPTOR.issuer.kid,
    profile: requirement.profile,
    credentialType: requirement.credentialType,
  });
}
