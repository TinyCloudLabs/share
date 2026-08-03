import { canonicalize, toBase64Url, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";

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
}

/**
 * This value may only be constructed from `resolveShare`'s verified result.
 * Query parameters, popup messages, and display/prefill strings are
 * intentionally absent from the type.
 */
export interface VerifiedCredentialShare {
  readonly envelope: ShareEnvelopeV3;
  readonly policy: Record<string, unknown>;
  readonly shareCid: string;
}

export type CredentialReceiverState =
  | "checking-existing"
  | "opening-verification"
  | "proving"
  | "waiting-for-approval"
  | "verifying"
  | "saving"
  | "authorizing-access"
  | "opening-content"
  | "success";

export interface CredentialProgressLike {
  readonly state: "checking" | "collecting" | "challenging" | "proving" | "signing" | "issuing" | "verifying" | "saving" | "success" | "recovery";
}

export interface VerifiedCredentialLike {
  readonly holderDid: string;
  readonly subjectDid: string;
  readonly credentialDigest: string;
  readonly descriptorDigest: string;
  readonly issuerDid: string;
  readonly issuerKid: string;
  readonly profile: { readonly id: string; readonly version: 1 };
  readonly credentialType: { readonly id: string; readonly version: 1 };
  readonly claims: Readonly<Record<string, string>>;
  readonly credential: string;
}

export interface StoredCredentialLike {
  readonly ownerDid: string;
  readonly recordId: string;
  readonly holderDid: string;
  readonly requirementDigest: string;
  readonly descriptorDigest: string;
  readonly issuerDid: string;
  readonly issuerKid: string;
  readonly profile: { readonly id: string; readonly version: 1 };
  readonly credentialType: { readonly id: string; readonly version: 1 };
  readonly credentialDigest: string;
  readonly claims: Readonly<Record<string, string>>;
}

export interface CredentialStorageReceiptLike {
  readonly ownerDid: string;
  readonly recordId: string;
}

export interface CredentialEnsureResultLike {
  readonly status: "reused" | "acquired";
  readonly credential: VerifiedCredentialLike;
  readonly record: StoredCredentialLike;
  readonly receipt?: CredentialStorageReceiptLike;
}

export interface ActiveCredentialClient {
  readonly sessionDid: string;
  session(): unknown;
  signSessionBytes(bytes: Uint8Array): Promise<Uint8Array>;
  readonly credentials: {
    ensure(requirement: EmailCredentialRequirement, options: {
      readonly descriptor: typeof EMAIL_CREDENTIAL_DESCRIPTOR;
      readonly interaction: "popup";
      readonly openerOrigin: string;
      readonly signal?: AbortSignal;
      readonly onProgress: (progress: CredentialProgressLike) => void;
    }): Promise<CredentialEnsureResultLike>;
    find(requirement: EmailCredentialRequirement, options: {
      readonly descriptor: typeof EMAIL_CREDENTIAL_DESCRIPTOR;
      readonly signal?: AbortSignal;
    }): Promise<StoredCredentialLike | undefined>;
  };
}

export interface OrdinaryPolicyDelegation {
  readonly type: "TinyCloudOrdinaryPolicyDelegation";
  readonly version: 1;
  readonly cid: string;
  readonly authorization: string;
  readonly audienceDid: string;
}

export interface OrdinaryDelegationImportReceipt {
  readonly type: "TinyCloudOrdinaryDelegationImportReceipt";
  readonly version: 1;
  readonly cid: string;
  readonly imported: true;
}

export interface CredentialAuthorizedContent {
  readonly type: "TinyCloudCredentialAuthorizedContent";
  readonly version: 1;
  readonly delegationCid: string;
  readonly invocationCid: string;
  readonly bytes: Uint8Array;
  readonly mediaType: string;
}

export interface CredentialPolicyAdmissionAdapter<Operation> {
  admit(input: {
    readonly share: VerifiedCredentialShare;
    readonly requirement: EmailCredentialRequirement;
    readonly credential: VerifiedCredentialLike;
    readonly holderDid: string;
    readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;
    readonly signal?: AbortSignal;
  }): Promise<OrdinaryPolicyDelegation>;
  importDelegation(input: {
    readonly delegation: OrdinaryPolicyDelegation;
    readonly signal?: AbortSignal;
  }): Promise<OrdinaryDelegationImportReceipt>;
  invoke(input: {
    readonly delegation: OrdinaryPolicyDelegation;
    readonly operation: Operation;
    readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;
    readonly signal?: AbortSignal;
  }): Promise<CredentialAuthorizedContent>;
}

export type CredentialReceiverErrorCode =
  | "UNSUPPORTED_REQUIREMENT"
  | "ACTIVE_SESSION_REQUIRED"
  | "CREDENTIAL_NOT_DURABLE"
  | "POLICY_ADMISSION_UNAVAILABLE"
  | "POLICY_ADMISSION_FAILED"
  | "DELEGATION_IMPORT_FAILED"
  | "INVOCATION_FAILED";

export class CredentialReceiverError extends Error {
  readonly name = "CredentialReceiverError";
  constructor(readonly code: CredentialReceiverErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
  }
}

function receiverError(code: CredentialReceiverErrorCode, message: string, cause: unknown): CredentialReceiverError {
  return cause instanceof CredentialReceiverError ? cause : new CredentialReceiverError(code, message, { cause });
}

function canonicalEmail(value: string): string {
  if (!/^[\x21-\x3f\x41-\x7e]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(value)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified share does not contain a supported exact-email requirement");
  }
  return value.toLowerCase();
}

export function credentialRequirementFromVerifiedShare(share: VerifiedCredentialShare): EmailCredentialRequirement {
  if (share.envelope.version !== 3 || share.envelope.recipientMatcher.kind !== "exactEmail") {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified share does not contain a supported credential requirement");
  }
  if (canonicalize(share.policy) !== canonicalize(share.envelope.policy)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified policy does not match the signed share envelope");
  }
  return Object.freeze({
    type: "TinyCloudCredentialRequirement",
    version: 1,
    profile: { id: "tinycloud.email-proof/v1", version: 1 },
    credentialType: { id: "opencredentials.email/v1", version: 1 },
    claims: { email: canonicalEmail(share.envelope.recipientMatcher.value) },
  } as const);
}

async function canonicalDigest(value: unknown): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(value)))));
}

interface SignedCredentialRequirementProjection {
  readonly type: "TinyCloudPolicyCredentialRequirement";
  readonly version: 1;
  readonly requirementDigest: string;
  readonly descriptorDigest: string;
  readonly issuerDid: string;
  readonly issuerKid: string;
  readonly profile: { readonly id: string; readonly version: 1 };
  readonly credentialType: { readonly id: string; readonly version: 1 };
}

export async function validateCredentialProjectionFromVerifiedShare(
  share: VerifiedCredentialShare,
  requirement: EmailCredentialRequirement,
): Promise<SignedCredentialRequirementProjection> {
  const raw = share.policy.credentialRequirement;
  if (share.policy.schema !== "xyz.tinycloud.policy/policy/v2" || raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified policy does not contain a supported credential projection");
  }
  const value = raw as Record<string, unknown>;
  const profile = value.profile;
  const credentialType = value.credentialType;
  const exactKeys = ["credentialType", "descriptorDigest", "issuerDid", "issuerKid", "profile", "requirementDigest", "type", "version"];
  if (Object.keys(value).sort().join("\0") !== exactKeys.sort().join("\0")
    || value.type !== "TinyCloudPolicyCredentialRequirement" || value.version !== 1
    || typeof value.requirementDigest !== "string" || typeof value.descriptorDigest !== "string"
    || value.issuerDid !== EMAIL_CREDENTIAL_DESCRIPTOR.issuer.did || value.issuerKid !== EMAIL_CREDENTIAL_DESCRIPTOR.issuer.kid
    || profile === null || typeof profile !== "object" || Array.isArray(profile) || Object.keys(profile).sort().join("\0") !== "id\0version" || (profile as Record<string, unknown>).id !== requirement.profile.id || (profile as Record<string, unknown>).version !== 1
    || credentialType === null || typeof credentialType !== "object" || Array.isArray(credentialType) || Object.keys(credentialType).sort().join("\0") !== "id\0version" || (credentialType as Record<string, unknown>).id !== requirement.credentialType.id || (credentialType as Record<string, unknown>).version !== 1
    || value.requirementDigest !== await canonicalDigest(requirement)
    || value.descriptorDigest !== await canonicalDigest(EMAIL_CREDENTIAL_DESCRIPTOR)) {
    throw new CredentialReceiverError("UNSUPPORTED_REQUIREMENT", "The verified policy credential projection does not match the requested credential");
  }
  return value as unknown as SignedCredentialRequirementProjection;
}

export function mapCredentialProgress(progress: CredentialProgressLike): CredentialReceiverState | undefined {
  switch (progress.state) {
    case "checking": return "checking-existing";
    case "collecting":
    case "challenging": return "opening-verification";
    case "proving": return "proving";
    case "signing": return "waiting-for-approval";
    case "issuing":
    case "verifying": return "verifying";
    case "saving": return "saving";
    case "success": return undefined;
    case "recovery": return "opening-verification";
  }
}

function assertDurableCredential(result: CredentialEnsureResultLike, readback: StoredCredentialLike | undefined, holderDid: string, email: string, projection: SignedCredentialRequirementProjection): void {
  const credential = result.credential;
  const record = result.record;
  if (credential.holderDid !== holderDid || credential.subjectDid !== holderDid || record.holderDid !== holderDid
    || credential.claims.email !== email || record.claims.email !== email
    || credential.descriptorDigest !== projection.descriptorDigest || record.descriptorDigest !== projection.descriptorDigest || record.requirementDigest !== projection.requirementDigest
    || credential.issuerDid !== projection.issuerDid || record.issuerDid !== projection.issuerDid || credential.issuerKid !== projection.issuerKid || record.issuerKid !== projection.issuerKid
    || credential.profile.id !== projection.profile.id || record.profile.id !== projection.profile.id || credential.profile.version !== 1 || record.profile.version !== 1
    || credential.credentialType.id !== projection.credentialType.id || record.credentialType.id !== projection.credentialType.id || credential.credentialType.version !== 1 || record.credentialType.version !== 1
    || credential.credentialDigest.length === 0 || record.credentialDigest !== credential.credentialDigest
    || readback === undefined || readback.recordId !== record.recordId || readback.ownerDid !== record.ownerDid
    || readback.holderDid !== holderDid || readback.credentialDigest !== credential.credentialDigest) {
    throw new CredentialReceiverError("CREDENTIAL_NOT_DURABLE", "The acquired credential was not verified in the active TinyCloud");
  }
  if (result.status === "acquired" && (result.receipt === undefined || result.receipt.recordId !== record.recordId || result.receipt.ownerDid !== record.ownerDid)) {
    throw new CredentialReceiverError("CREDENTIAL_NOT_DURABLE", "The acquired credential has no authenticated storage receipt");
  }
}

function assertDelegation(value: OrdinaryPolicyDelegation, holderDid: string): void {
  if (value.type !== "TinyCloudOrdinaryPolicyDelegation" || value.version !== 1 || value.cid.length === 0 || value.authorization.length === 0 || value.audienceDid !== holderDid) {
    throw new CredentialReceiverError("POLICY_ADMISSION_FAILED", "Policy admission did not return ordinary recipient authority");
  }
}

export async function runCredentialReceiver<Operation>(input: {
  readonly share: VerifiedCredentialShare;
  readonly operation: Operation;
  readonly connect: () => Promise<ActiveCredentialClient>;
  readonly admission: CredentialPolicyAdmissionAdapter<Operation>;
  readonly openerOrigin: string;
  readonly signal?: AbortSignal;
  readonly onState?: (state: CredentialReceiverState) => void;
}): Promise<CredentialAuthorizedContent> {
  const requirement = credentialRequirementFromVerifiedShare(input.share);
  const projection = await validateCredentialProjectionFromVerifiedShare(input.share, requirement);
  const client = await input.connect();
  if (client.session() === undefined || !/^did:key:z6Mk[^#]+$/.test(client.sessionDid)) {
    throw new CredentialReceiverError("ACTIVE_SESSION_REQUIRED", "Credential acquisition requires the active TinyCloud/OpenKey session");
  }
  const ensured = await client.credentials.ensure(requirement, {
    descriptor: EMAIL_CREDENTIAL_DESCRIPTOR,
    interaction: "popup",
    openerOrigin: input.openerOrigin,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    onProgress: (progress) => {
      const state = mapCredentialProgress(progress);
      if (state !== undefined) input.onState?.(state);
    },
  });
  // Popup completion is deliberately not consumed here. `ensure` retrieves
  // and verifies the result through its authenticated channel; Share then
  // proves durable storage by reading the active credentials space again.
  const readback = await client.credentials.find(requirement, {
    descriptor: EMAIL_CREDENTIAL_DESCRIPTOR,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  assertDurableCredential(ensured, readback, client.sessionDid, requirement.claims.email, projection);

  input.onState?.("authorizing-access");
  let delegation: OrdinaryPolicyDelegation;
  try {
    delegation = await input.admission.admit({ share: input.share, requirement, credential: ensured.credential, holderDid: client.sessionDid, sign: (bytes) => client.signSessionBytes(bytes), ...(input.signal === undefined ? {} : { signal: input.signal }) });
    assertDelegation(delegation, client.sessionDid);
  } catch (cause) {
    throw receiverError("POLICY_ADMISSION_FAILED", "The verified credential did not authorize this share", cause);
  }
  try {
    const receipt = await input.admission.importDelegation({ delegation, ...(input.signal === undefined ? {} : { signal: input.signal }) });
    if (receipt.type !== "TinyCloudOrdinaryDelegationImportReceipt" || receipt.version !== 1 || receipt.imported !== true || receipt.cid !== delegation.cid) {
      throw new Error("ordinary delegation import receipt mismatch");
    }
  } catch (cause) {
    throw receiverError("DELEGATION_IMPORT_FAILED", "TinyCloud could not import the ordinary share delegation", cause);
  }

  input.onState?.("opening-content");
  let content: CredentialAuthorizedContent;
  try {
    // The exact interrupted operation object is passed through unchanged.
    content = await input.admission.invoke({ delegation, operation: input.operation, sign: (bytes) => client.signSessionBytes(bytes), ...(input.signal === undefined ? {} : { signal: input.signal }) });
    if (content.type !== "TinyCloudCredentialAuthorizedContent" || content.version !== 1 || content.delegationCid !== delegation.cid || content.invocationCid.length === 0 || !ArrayBuffer.isView(content.bytes) || content.bytes.BYTES_PER_ELEMENT !== 1 || content.mediaType.length === 0) {
      throw new Error("ordinary invocation response mismatch");
    }
  } catch (cause) {
    throw receiverError("INVOCATION_FAILED", "TinyCloud could not resume the shared operation", cause);
  }
  input.onState?.("success");
  return content;
}

export function unavailableCredentialPolicyAdmission<Operation>(): CredentialPolicyAdmissionAdapter<Operation> {
  const unavailable = (): never => {
    throw new CredentialReceiverError("POLICY_ADMISSION_UNAVAILABLE", "Credential policy admission is not available on this TinyCloud node");
  };
  return {
    admit: async () => unavailable(),
    importDelegation: async () => unavailable(),
    invoke: async () => unavailable(),
  };
}

const STATE_COPY: Record<CredentialReceiverState, string> = {
  "checking-existing": "Checking your TinyCloud for this credential…",
  "opening-verification": "Opening email verification…",
  proving: "Confirm your email with the code you received…",
  "waiting-for-approval": "Approve the email binding with your OpenKey…",
  verifying: "Verifying your credential…",
  saving: "Saving the verified credential to your TinyCloud…",
  "authorizing-access": "Email verified. Authorizing this share…",
  "opening-content": "Access granted. Opening the share…",
  success: "Email verified. This credential is now in your TinyCloud.",
};

function element<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, value?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

export function mountCredentialReceiver<Operation>(root: HTMLElement, input: {
  readonly share: VerifiedCredentialShare;
  readonly operation: Operation;
  readonly connect: () => Promise<ActiveCredentialClient>;
  readonly admission: CredentialPolicyAdmissionAdapter<Operation>;
  readonly openerOrigin: string;
  readonly onComplete: (content: CredentialAuthorizedContent) => Promise<void> | void;
}): void {
  const doc = root.ownerDocument;
  const main = element(doc, "main", "viewer-state viewer-claim");
  const status = element(doc, "p", "viewer-state-detail", "Your verified email credential stays in your TinyCloud and can be reused without repeating this flow.");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const button = element(doc, "button", "viewer-primary-action", "Confirm email") as HTMLButtonElement;
  button.type = "button";
  main.append(
    element(doc, "h1", "viewer-state-title", "Confirm your email to open this"),
    element(doc, "p", "viewer-state-detail", `This share requires ${credentialRequirementFromVerifiedShare(input.share).claims.email}.`),
    status,
    button,
  );
  root.replaceChildren(main);
  root.setAttribute("tabindex", "-1");
  root.focus();

  button.addEventListener("click", () => {
    button.disabled = true;
    status.textContent = STATE_COPY["checking-existing"];
    void runCredentialReceiver({
      share: input.share,
      operation: input.operation,
      connect: input.connect,
      admission: input.admission,
      openerOrigin: input.openerOrigin,
      onState: (state) => { status.textContent = STATE_COPY[state]; },
    }).then(input.onComplete).catch((error: unknown) => {
      console.debug("tinycloud share: credential receiver failed", error);
      button.disabled = false;
      status.setAttribute("role", "alert");
      status.textContent = error instanceof CredentialReceiverError && error.code === "POLICY_ADMISSION_UNAVAILABLE"
        ? "Email verified and saved. This TinyCloud node is not ready to authorize this share yet."
        : "We couldn't verify and save this email credential. Try again or ask the sender for a new link.";
    });
  });
}
