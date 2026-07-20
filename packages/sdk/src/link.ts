import {
  canonicalEmail,
  canonicalDigest,
  createInvitationDraft,
  validateSource,
  type ContentSource,
  type InvitationDraft,
  type SenderScope,
  type ShareAction,
} from "../../../src/email-share/protocol.js";
import {
  canonicalize,
  isCanonicalHttpsOrigin,
  isCanonicalPathSegment,
  parseShareUrl,
  shareEnvelopeSchema,
  targetSchema,
  didKeyFromEd25519PublicKey,
} from "@tinycloud/share-envelope";

declare const generatedShareLinkBrand: unique symbol;

export interface ShareLinkTarget {
  readonly origin: string;
  readonly nodeAudience: string;
  readonly spaceId: string;
}

/** The policy bindings that must remain identical through authorization and delivery. */
export interface ShareLinkPolicy {
  readonly recipientEmail: string;
  readonly source: ContentSource;
  readonly action: ShareAction;
  readonly resource: string;
  readonly expiresAt: string;
  readonly target: ShareLinkTarget;
}

/** Safe, non-secret provenance retained for the later authorization/delivery lane. */
export interface GeneratedShareLinkProvenance extends ShareLinkPolicy {
  readonly shareOrigin: string;
  readonly shareId: string;
  readonly shareCid: string;
  readonly policyCid: string;
  readonly contentSourceDigest: string;
  readonly senderDid: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: SenderScope["authorityMaterialHandle"];
  readonly authorityMaterialDigest: string;
}

/**
 * An opaque result of link generation. The only secret-bearing value is the
 * fragment in shareUrl; sender signing material and claim secrets are never
 * properties of this artifact.
 */
export interface GeneratedShareLink {
  readonly [generatedShareLinkBrand]: true;
  readonly shareUrl: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly recipientEmail: string;
  readonly source: ContentSource;
  readonly action: ShareAction;
  readonly resource: string;
  readonly expiresAt: string;
  readonly target: ShareLinkTarget;
  readonly provenance: GeneratedShareLinkProvenance;
}

export type ShareArtifact = GeneratedShareLink;

export interface ShareLinkAdapters {
  /** Uploads only the sealed envelope blob; this is the sole generation I/O. */
  readonly uploadEnvelope: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void>;
  readonly publishBinding?: (binding: Record<string, unknown>) => Promise<void>;
}

export interface CreateShareLinkInput {
  /** Exact RFC 5322 addr-spec; the domain is canonicalized, local-part bytes are preserved. */
  readonly email: string;
  readonly source: ContentSource;
  readonly scope: SenderScope;
  readonly shareId: string;
  readonly expiresAt: string;
  /** Optional explicit policy contract, checked against every generated binding. */
  readonly policy?: ShareLinkPolicy;
  /** Optional explicit target contract, checked against the authenticated scope. */
  readonly target?: ShareLinkTarget;
  readonly adapters: ShareLinkAdapters;
  readonly now?: string;
}

const drafts = new WeakMap<object, InvitationDraft>();
const provenances = new WeakMap<object, GeneratedShareLinkProvenance>();

function freezeValue<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value as Record<string, unknown>)) freezeValue(child);
  return Object.freeze(value);
}

function sameValue(actual: unknown, expected: unknown): boolean {
  return typeof actual === "object" || typeof expected === "object"
    ? canonicalize(actual) === canonicalize(expected)
    : actual === expected;
}

function assertExactString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} is required.`);
}

function targetFor(scope: SenderScope): ShareLinkTarget {
  return {
    origin: scope.targetOrigin,
    nodeAudience: scope.nodeAudience,
    spaceId: scope.spaceId,
  };
}

function assertTarget(target: ShareLinkTarget, expected: ShareLinkTarget): void {
  if (!sameValue(target, expected)) throw new TypeError("The share target does not match the authenticated scope.");
}

async function normalizedSource(source: ContentSource): Promise<ContentSource> {
  const validated = validateSource(source);
  if (validated.kind !== "sql") return validated;
  return {
    ...validated,
    argumentsDigest: await canonicalDigest(validated.arguments),
  };
}

async function expectedPolicy(input: CreateShareLinkInput, email: string, source: ContentSource): Promise<ShareLinkPolicy> {
  const target = targetFor(input.scope);
  const policy: ShareLinkPolicy = {
    recipientEmail: email,
    source,
    action: source.action,
    resource: source.path,
    expiresAt: input.expiresAt,
    target,
  };
  if (input.target !== undefined) assertTarget(input.target, target);
  if (input.policy !== undefined) {
    const supplied = await normalizedSource(input.policy.source);
    const canonicalSupplied: ShareLinkPolicy = {
      ...input.policy,
      recipientEmail: canonicalEmail(input.policy.recipientEmail),
      source: supplied,
    };
    if (!sameValue(canonicalSupplied, policy)) throw new TypeError("The supplied policy binding does not match the share request.");
  }
  return policy;
}

function assertGenerationInputs(input: CreateShareLinkInput, email: string, source: ContentSource, now: string): void {
  assertExactString(input.shareId, "shareId");
  if (!/^[^\u0000-\u001f\u007f]{1,200}$/.test(input.shareId)) throw new TypeError("shareId is not canonical.");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(now) || !Number.isFinite(Date.parse(now))) throw new TypeError("now must be canonical UTC.");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(input.expiresAt) || !Number.isFinite(Date.parse(input.expiresAt)) || Date.parse(input.expiresAt) <= Date.parse(now)) {
    throw new TypeError("Choose an access expiry within the allowed policy window.");
  }
  if (new TextEncoder().encode(input.expiresAt).length !== 24) throw new TypeError("Expiry must be canonical UTC.");
  if (input.scope.spaceId !== source.space || !isCanonicalPathSegment(input.scope.spaceId)) throw new TypeError("The selected resource is outside the authorized space.");
  if (!isCanonicalHttpsOrigin(input.scope.shareOrigin) || !isCanonicalHttpsOrigin(input.scope.targetOrigin) || input.scope.trustedNode.targetOrigin !== input.scope.targetOrigin) throw new TypeError("Share and target origins must be canonical HTTPS origins.");
  if (input.scope.trustedNode.nodeAudience !== input.scope.nodeAudience || input.scope.nodeAudience.length === 0 || input.scope.trustedNode.invitationPublicKey.length !== 32 || !input.scope.trustedNode.enabled) throw new TypeError("The authenticated target is not trusted.");
  if (input.scope.signingCapability.publicKey.length !== 32 || input.scope.signer.publicKey.length !== 32 || input.scope.signingCapability.publicKey.some((byte, index) => byte !== input.scope.signer.publicKey[index])) throw new TypeError("The sender signing capability does not match the signer.");
  if (didKeyFromEd25519PublicKey(input.scope.signer.publicKey) !== input.scope.senderDid) throw new TypeError("The sender provenance does not match the authenticated signer.");
  if (source.action !== (source.kind === "kv" ? "tinycloud.kv/get" : "tinycloud.sql/read")) throw new TypeError("The source action is invalid.");
  if (email !== canonicalEmail(email)) throw new TypeError("The recipient email is not canonical.");
  const expiry = Date.parse(input.expiresAt);
  for (const [label, value] of [["expiryMin", input.scope.expiryMin], ["expiryMax", input.scope.expiryMax], ["expiresAt", input.scope.expiresAt]] as const) {
    if (value !== undefined && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)))) throw new TypeError(`${label} must be canonical UTC.`);
  }
  if (input.scope.expiryMin !== undefined && expiry < Date.parse(input.scope.expiryMin)) throw new TypeError("The requested expiry is below the authenticated policy minimum.");
  const upperBounds = [input.scope.expiryMax, input.scope.expiresAt].filter((value): value is string => value !== undefined).map(Date.parse);
  if (upperBounds.some((bound) => expiry > bound)) throw new TypeError("The requested expiry exceeds the authenticated policy maximum.");
  targetSchema.parse({ origin: input.scope.targetOrigin, nodeAudience: input.scope.nodeAudience, spaceId: input.scope.spaceId, resource: { kind: "exact", path: source.path } });
}

function provenanceFor(draft: InvitationDraft, scope: SenderScope): GeneratedShareLinkProvenance {
  return {
    recipientEmail: draft.email,
    source: draft.source,
    action: draft.source.action,
    resource: draft.source.path,
    expiresAt: draft.envelope.expiry,
    target: targetFor(scope),
    shareOrigin: scope.shareOrigin,
    shareId: draft.envelope.shareId,
    shareCid: draft.shareCid,
    policyCid: draft.policyCid,
    contentSourceDigest: draft.sourceDigest,
    senderDid: scope.senderDid,
    delegationCid: scope.delegationCid,
    authorityMaterialHandle: scope.authorityMaterialHandle,
    authorityMaterialDigest: scope.authorityMaterialDigest,
  };
}

function artifactFor(draft: InvitationDraft, scope: SenderScope): GeneratedShareLink {
  const source = freezeValue({ ...draft.source });
  const target = freezeValue(targetFor(scope));
  const provenance = freezeValue({ ...provenanceFor(draft, scope), source, target });
  const artifact = Object.freeze({
    shareUrl: draft.shareUrl,
    shareCid: draft.shareCid,
    shareId: draft.envelope.shareId,
    policyCid: draft.policyCid,
    recipientEmail: draft.email,
    source,
    action: draft.source.action,
    resource: draft.source.path,
    expiresAt: draft.envelope.expiry,
    target,
    provenance,
  });
  drafts.set(artifact, draft);
  provenances.set(artifact, provenance);
  return artifact as GeneratedShareLink;
}

/** Rejects forged, substituted, or mutable link artifacts before delivery. */
export function assertGeneratedShareLink(value: GeneratedShareLink): void {
  const draft = drafts.get(value as object);
  const provenance = provenances.get(value as object);
  if (draft === undefined || provenance === undefined || value.shareUrl !== draft.shareUrl || value.shareCid !== draft.shareCid || value.shareId !== draft.envelope.shareId || value.policyCid !== draft.policyCid || value.recipientEmail !== draft.email || !sameValue(value.source, draft.source) || value.action !== draft.source.action || value.resource !== draft.source.path || value.expiresAt !== draft.envelope.expiry || !sameValue(value.target, provenance.target) || !sameValue(value.provenance, provenance)) {
    throw new TypeError("The share artifact is not a generated exact-email link.");
  }
  const parsed = parseShareUrl(value.shareUrl, { expectedOrigin: provenance.shareOrigin });
  if (parsed.ciphertextCid !== value.shareCid) throw new TypeError("The generated share link was substituted.");
}

/** Creates, seals, uploads, and returns a policy-bound share link. It never sends email or reads content. */
export async function createShareLink(input: CreateShareLinkInput): Promise<GeneratedShareLink> {
  if (typeof input.adapters?.uploadEnvelope !== "function") throw new TypeError("An envelope upload adapter is required.");
  const email = canonicalEmail(input.email);
  const source = await normalizedSource(input.source);
  const now = input.now ?? new Date().toISOString();
  assertGenerationInputs(input, email, source, now);
  await expectedPolicy(input, email, source);
  const draft = await createInvitationDraft({
    email,
    source,
    scope: input.scope,
    shareId: input.shareId,
    expiresAt: input.expiresAt,
    uploadEnvelope: input.adapters.uploadEnvelope,
    now,
  });
  shareEnvelopeSchema.parse(draft.envelope);
  await input.adapters.publishBinding?.({
    capabilityId: input.scope.signingCapability.capabilityId,
    shareId: draft.envelope.shareId,
    shareCid: draft.shareCid,
    policyCid: draft.policyCid,
    recipientEmail: draft.email,
    expiry: draft.envelope.expiry,
    delegationCid: input.scope.delegationCid,
    authorityMaterialHandle: input.scope.authorityMaterialHandle,
    authorityMaterialDigest: input.scope.authorityMaterialDigest,
    contentSource: draft.source,
    contentSourceDigest: draft.sourceDigest,
    action: draft.source.action,
    resource: draft.source.path,
  });
  const artifact = artifactFor(draft, input.scope);
  assertGeneratedShareLink(artifact);
  return artifact;
}

/** @internal The delivery lane consumes only drafts created by this module. */
export function draftForGeneratedShareLink(value: GeneratedShareLink): InvitationDraft {
  const draft = drafts.get(value as object);
  const provenance = provenances.get(value as object);
  assertGeneratedShareLink(value);
  if (draft === undefined || provenance === undefined) throw new TypeError("The share artifact is not a generated exact-email link.");
  return draft;
}
