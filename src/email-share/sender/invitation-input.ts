/**
 * Prepared envelope/policy inputs for the email-claim v1 sender flow
 * (specs/email-claim-v1/schemas.json `$defs.policy`, `$defs.did`,
 * `schemas.inviteAuthorization`, `schemas.authorizationRequest`).
 *
 * {@link prepareInvitationInputs} never accepts independently trusted raw
 * fields — its only input is a {@link VerifiedEnvelopeInputs}, an opaque
 * value that by construction can only exist via
 * {@link VerifiedEnvelopeInputs.fromSealedEnvelope}, which itself runs the
 * real envelope chain (CID verification, AEAD open, strict schema parse,
 * signature verification) over untrusted bytes before deriving any field.
 * There is no other way to produce one — no exported constructor, no cast,
 * no structural shortcut — so a value of this type is, by construction,
 * already fully verified.
 *
 * From that verified envelope, {@link prepareInvitationInputs} rebuilds the
 * policy and its CID and requires them to byte-match the envelope's OWN
 * signed policy bytes/CID before either network request — a mismatch here
 * would mean the factory itself derived a field incorrectly, and fails
 * closed rather than trusting the derivation.
 *
 * Once the node returns a signed `inviteAuthorization`, the sender checks
 * that the node's shareCid/policyCid/contentSource/target/audience agree
 * with what was prepared. A node that returns an authorization for a
 * different share, policy, content source, origin, or audience must never
 * be trusted.
 */
import {
  canonicalize,
  computeCid,
  fromBase64Url,
  open,
  parseShareUrl,
  shareEnvelopeSchema,
  toBase64Url,
  verifyCid,
  verifyEnvelope,
} from "@tinycloud/share-envelope";

import { assertSqlArgumentsDigest, isContentSourceShape, type ContentSource } from "./content-source.js";
import { canonicalDigest } from "./digest.js";
import { normalizeExactEmail } from "./email.js";

const RETURN_ORIGIN = "https://share.tinycloud.xyz" as const;
const SENDER_DID = /^did:(?:web:[A-Za-z0-9.:%_-]+|pkh:[A-Za-z0-9:._-]+|key:z[1-9A-HJ-NP-Za-km-z]+)$/;
const DOCUMENT_NAME = /^[^\u0000-\u001F\u007F]+$/;

function assertSenderDid(senderDid: string): void {
  if (!SENDER_DID.test(senderDid)) {
    throw new TypeError(`invalid sender DID: ${senderDid}`);
  }
}

function assertDocumentName(documentName: string): void {
  if (documentName.length < 1 || !DOCUMENT_NAME.test(documentName)) {
    throw new TypeError(`invalid document name: ${documentName}`);
  }
  if (new TextEncoder().encode(documentName).length > 200) {
    throw new TypeError(`document name exceeds 200 UTF-8 bytes: ${documentName}`);
  }
}

export type ContentAction = "tinycloud.kv/get" | "tinycloud.sql/read";

export interface Policy {
  readonly type: "TinyCloudSharePolicy";
  readonly version: 1;
  readonly recipientEmail: string;
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly action: ContentAction;
  readonly resource: string;
  readonly expiresAt: string;
  readonly issuerDid: string;
}

export interface AuthorizationRequestBody {
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly recipientEmail: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly action: ContentAction;
  readonly resource: string;
  readonly requestBodyDigest: string;
}

export interface InviteAuthorization {
  readonly type: "TinyCloudShareInviteAuthorization";
  readonly version: 1;
  readonly jti: string;
  readonly senderDid: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly policyCid: string;
  readonly recipientEmail: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly returnOrigin: "https://share.tinycloud.xyz";
  readonly documentName: string;
  readonly senderTrust: "verified" | "unverified";
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly shareExpiresAt: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly reportAbuseToken: string;
}

export interface Proof {
  readonly alg: "EdDSA";
  readonly kid: string;
  readonly signature: string;
}

interface PreparedInvitationInputsData {
  readonly policy: Policy;
  /** Canonical JCS bytes of `policy`, base64url — the signed target's `policyBytes`. */
  readonly policyBytes: string;
  readonly policyCid: string;
  readonly authorizationRequest: AuthorizationRequestBody;
  readonly senderDid: string;
  readonly documentName: string;
}

interface VerifiedEnvelopeInputsData {
  /** The verified CIDv1/raw/sha2-256 of the sealed envelope blob itself. */
  readonly envelopeCid: string;
  /** The envelope's OWN signed `authorizationTarget.policyCid` (already CID/signature-verified). */
  readonly policyCid: string;
  /** The envelope's OWN signed `authorizationTarget.policyBytes` (base64url canonical policy bytes). */
  readonly policyBytes: string;
  readonly shareId: string;
  /** The envelope signature's verified `signerDid`. */
  readonly senderDid: string;
  /** The verified envelope `expiry` (== the policy's `expiresAt`). */
  readonly expiry: string;
  /** Already in normalized {@link normalizeExactEmail} form — checked, never re-normalized. */
  readonly recipientEmail: string;
  readonly targetOrigin: string;
  readonly nodeAudience: string;
  readonly contentSource: ContentSource;
  readonly action: ContentAction;
  readonly resource: string;
  readonly documentName: string;
}

const TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const ISSUER_DID = /^did:(?:web:[A-Za-z0-9.:%_-]+|pkh:[A-Za-z0-9:._-]+|key:z[1-9A-HJ-NP-Za-km-z]+)$/;
// $defs.digest (specs/email-claim-v1/schemas.json) — base64url(sha256(...)), always exactly 32 bytes.
const DIGEST = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/**
 * Strictly decode and shape-validate the policy JSON carried (base64url) in
 * the envelope's OWN signed `authorizationTarget.policyBytes` — the CID of
 * these exact bytes has already been checked against `policyCid` by
 * {@link verifyEnvelope} before this ever runs, but the JSON *content* is
 * still attacker-authored and is never trusted just because it parses.
 */
function parsePolicyFromBytes(policyBytesB64: string): Policy {
  const decoded = fromBase64Url(policyBytesB64);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
  const raw: unknown = JSON.parse(text);
  if (typeof raw !== "object" || raw === null) {
    throw new TypeError("policy bytes do not decode to an object");
  }
  const r = raw as Record<string, unknown>;
  if (
    r.type !== "TinyCloudSharePolicy" ||
    r.version !== 1 ||
    typeof r.recipientEmail !== "string" ||
    !isContentSourceShape(r.contentSource) ||
    typeof r.contentSourceDigest !== "string" ||
    !DIGEST.test(r.contentSourceDigest) ||
    (r.action !== "tinycloud.kv/get" && r.action !== "tinycloud.sql/read") ||
    typeof r.resource !== "string" ||
    r.resource.length < 1 ||
    typeof r.expiresAt !== "string" ||
    !TIME.test(r.expiresAt) ||
    typeof r.issuerDid !== "string" ||
    !ISSUER_DID.test(r.issuerDid) ||
    Object.keys(r).length !== 9
  ) {
    throw new TypeError("policy bytes do not match the expected strict policy shape");
  }
  return {
    type: "TinyCloudSharePolicy",
    version: 1,
    recipientEmail: r.recipientEmail,
    contentSource: r.contentSource,
    contentSourceDigest: r.contentSourceDigest,
    action: r.action,
    resource: r.resource,
    expiresAt: r.expiresAt,
    issuerDid: r.issuerDid,
  };
}

/** Module-private side table backing {@link VerifiedEnvelopeInputs} — never exported. */
const verifiedEnvelopeInputsData = new WeakMap<VerifiedEnvelopeInputs, VerifiedEnvelopeInputsData>();

/** Module-private side table making prepared inputs nominal at runtime. */
const preparedInvitationInputsData = new WeakMap<PreparedInvitationInputs, PreparedInvitationInputsData>();

function unwrap(verified: VerifiedEnvelopeInputs): VerifiedEnvelopeInputsData {
  const data = verifiedEnvelopeInputsData.get(verified);
  if (data === undefined) {
    throw new TypeError("invalid VerifiedEnvelopeInputs instance");
  }
  return data;
}

function unwrapPrepared(prepared: PreparedInvitationInputs): PreparedInvitationInputsData {
  const data = preparedInvitationInputsData.get(prepared);
  if (data === undefined) {
    throw new TypeError("invalid PreparedInvitationInputs instance");
  }
  return data;
}

type FromSealedEnvelopeParams = {
  /** The sealed envelope blob, exactly as fetched (untrusted). */
  readonly sealedBlob: Uint8Array;
  /** The share CID the blob is claimed to be addressed by (untrusted). */
  readonly shareCid: string;
  /** The 32-byte AEAD key carried in the share link's `#k=` fragment. */
  readonly fragmentKey: Uint8Array;
  /** The did:key the caller already trusts to be this envelope's sender. */
  readonly expectedSignerDid: string;
}

/**
 * Opaque, nominal result of verifying a sealed share envelope end to end.
 * The ONLY way to construct one is {@link VerifiedEnvelopeInputs.fromSealedEnvelope}
 * — there is no public constructor, no exported field access, and no
 * cast-based escape hatch. A caller holding a value of this type is holding
 * proof that `verifyCid`, AEAD `open`, strict schema parsing, and
 * `verifyEnvelope` against `expectedSignerDid` have all already succeeded.
 */
export class VerifiedEnvelopeInputs {
  private readonly brand = undefined;

  private constructor() {}

  static async fromSealedEnvelope(
    params: FromSealedEnvelopeParams,
  ): Promise<VerifiedEnvelopeInputs> {
    if (params.fragmentKey.length !== 32) {
      throw new TypeError(`fragment key must be 32 bytes, got ${params.fragmentKey.length}`);
    }
    if (!(await verifyCid(params.sealedBlob, params.shareCid))) {
      throw new TypeError("sealed envelope blob does not match the given share CID");
    }
    const plaintext = await open(params.sealedBlob, params.fragmentKey);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    const rawEnvelope: unknown = JSON.parse(text);
    const envelope = shareEnvelopeSchema.parse(rawEnvelope);
    if (!(await verifyEnvelope(envelope, { expectedSignerDid: params.expectedSignerDid }))) {
      throw new TypeError("envelope signature verification failed");
    }
    if (envelope.authorizationTarget.kind !== "policy") {
      throw new TypeError(
        `unsupported authorizationTarget kind for the email-claim flow: ${envelope.authorizationTarget.kind}`,
      );
    }

    const policy = parsePolicyFromBytes(envelope.authorizationTarget.policyBytes);
    if (policy.expiresAt !== envelope.expiry) {
      throw new TypeError("policy expiresAt does not match the envelope's own expiry");
    }
    if (policy.issuerDid !== envelope.signature.signerDid) {
      throw new TypeError("policy issuerDid does not match the envelope's verified signer");
    }
    if (
      envelope.target.spaceId !== policy.contentSource.space ||
      envelope.target.resource.kind !== "exact" ||
      envelope.target.resource.path !== policy.resource
    ) {
      throw new TypeError("envelope target does not match the verified policy resource");
    }
    if (normalizeExactEmail(policy.recipientEmail) !== policy.recipientEmail) {
      throw new TypeError("policy recipientEmail is not a normalized exact-email address");
    }
    const documentName = envelope.display.filename;
    if (documentName === undefined) {
      throw new TypeError("envelope display.filename (documentName) is required");
    }

    const data: VerifiedEnvelopeInputsData = {
      envelopeCid: params.shareCid,
      policyCid: envelope.authorizationTarget.policyCid,
      policyBytes: envelope.authorizationTarget.policyBytes,
      shareId: envelope.shareId,
      senderDid: envelope.signature.signerDid,
      expiry: envelope.expiry,
      recipientEmail: policy.recipientEmail,
      targetOrigin: envelope.target.origin,
      nodeAudience: envelope.target.nodeAudience,
      contentSource: policy.contentSource,
      action: policy.action,
      resource: policy.resource,
      documentName,
    };
    const instance = new VerifiedEnvelopeInputs();
    verifiedEnvelopeInputsData.set(instance, data);
    return instance;
  }
}

/** Module-private nominal brand; callers cannot write this property. */
const preparedInvitationInputsBrand: unique symbol = Symbol("PreparedInvitationInputs");

/**
 * Nominal, module-created result of preparing a verified envelope for the
 * sender requests. The private brand and side table prevent a caller from
 * substituting a structurally matching object at the network boundary.
 */
export interface PreparedInvitationInputs extends PreparedInvitationInputsData {
  readonly [preparedInvitationInputsBrand]: never;
}

export async function prepareInvitationInputs(
  verified: VerifiedEnvelopeInputs,
): Promise<PreparedInvitationInputs> {
  const data = unwrap(verified);
  assertSenderDid(data.senderDid);
  assertDocumentName(data.documentName);

  // The action and resource must agree with what the content source itself
  // describes — for both KV and SQL, `resource` is the exact path being
  // read, so a policy naming a different resource than its own source
  // must never be trusted.
  if (data.action !== data.contentSource.action) {
    throw new TypeError("policy action does not match contentSource action");
  }
  if (data.resource !== data.contentSource.path) {
    throw new TypeError("policy resource does not match contentSource path");
  }
  if (data.contentSource.kind === "sql") {
    await assertSqlArgumentsDigest(data.contentSource);
  }

  const contentSourceDigest = await canonicalDigest(data.contentSource);
  const policy: Policy = {
    type: "TinyCloudSharePolicy",
    version: 1,
    recipientEmail: data.recipientEmail,
    contentSource: data.contentSource,
    contentSourceDigest,
    action: data.action,
    resource: data.resource,
    expiresAt: data.expiry,
    issuerDid: data.senderDid,
  };
  const policyBytesRaw = new TextEncoder().encode(canonicalize(policy));
  const policyBytes = toBase64Url(policyBytesRaw);
  const policyCid = await computeCid(policyBytesRaw);

  // Rebuilding the policy from the verified discrete fields must byte-match
  // the envelope's OWN signed policy bytes/CID exactly — a mismatch means
  // the factory derived a field inconsistently with what the envelope
  // actually signed, and must fail closed before either network request.
  if (policyBytes !== data.policyBytes || policyCid !== data.policyCid) {
    throw new TypeError("rebuilt policy does not match the verified envelope's policy bytes/CID");
  }

  const authorizationRequestUnsigned = {
    shareCid: data.envelopeCid,
    shareId: data.shareId,
    policyCid,
    recipientEmail: data.recipientEmail,
    targetOrigin: data.targetOrigin,
    nodeAudience: data.nodeAudience,
    action: data.action,
    resource: data.resource,
  };
  const requestBodyDigest = await canonicalDigest(authorizationRequestUnsigned);
  const authorizationRequest: AuthorizationRequestBody = {
    ...authorizationRequestUnsigned,
    requestBodyDigest,
  };

  const prepared = {
    policy,
    policyBytes,
    policyCid,
    authorizationRequest,
    senderDid: data.senderDid,
    documentName: data.documentName,
  } as PreparedInvitationInputs;
  preparedInvitationInputsData.set(prepared, {
    policy,
    policyBytes,
    policyCid,
    authorizationRequest,
    senderDid: data.senderDid,
    documentName: data.documentName,
  });
  return prepared;
}

/**
 * Does the node's signed `inviteAuthorization` agree with what the sender
 * prepared? Every field the node could substitute a different share,
 * policy, content source, target, sender, or audience through is checked; a
 * single mismatch fails closed. Content-source equality is by canonical
 * bytes (JCS), not `===`, since the node echoes it back as a fresh object.
 */
export function authorizationAgreesWithPreparedInputs(
  prepared: PreparedInvitationInputs,
  authorization: InviteAuthorization,
): boolean {
  const preparedData = unwrapPrepared(prepared);
  return (
    authorization.shareCid === preparedData.authorizationRequest.shareCid &&
    authorization.shareId === preparedData.authorizationRequest.shareId &&
    authorization.senderDid === preparedData.senderDid &&
    authorization.policyCid === preparedData.policyCid &&
    authorization.recipientEmail === preparedData.policy.recipientEmail &&
    authorization.targetOrigin === preparedData.authorizationRequest.targetOrigin &&
    authorization.nodeAudience === preparedData.authorizationRequest.nodeAudience &&
    authorization.documentName === preparedData.documentName &&
    authorization.contentSourceDigest === preparedData.policy.contentSourceDigest &&
    authorization.shareExpiresAt === preparedData.policy.expiresAt &&
    canonicalize(authorization.contentSource) === canonicalize(preparedData.policy.contentSource)
  );
}

/**
 * Does the supplied share URL bind to what the sender already prepared and
 * cross-checked (shareCid, which by construction agrees with policyCid,
 * contentSource, and resource via {@link authorizationAgreesWithPreparedInputs})?
 * Parses against the exact frozen share-URL grammar — fixed origin, `/s/<cid>`
 * path, no query, `#k=<key>` fragment only — via the shipping envelope
 * package's own strict parser; ANY parse failure (wrong/malformed origin,
 * path, query, or fragment) fails closed.
 */
export function shareUrlAgreesWithPreparedInputs(
  prepared: PreparedInvitationInputs,
  shareUrl: string,
): boolean {
  let preparedData: PreparedInvitationInputsData;
  try {
    preparedData = unwrapPrepared(prepared);
  } catch {
    return false;
  }
  // `parseShareUrl` compares parsed origins, which intentionally normalizes
  // an explicit default port. Bind the raw origin first so the canonical
  // share origin is preserved byte-for-byte as well.
  if (!shareUrl.startsWith(`${RETURN_ORIGIN}/s/`)) return false;
  const prefixLength = `${RETURN_ORIGIN}/s/`.length;
  const fragmentIndex = shareUrl.indexOf("#", prefixLength);
  if (
    fragmentIndex < 0 ||
    shareUrl.slice(prefixLength, fragmentIndex) !== preparedData.authorizationRequest.shareCid
  ) {
    return false;
  }
  let parsed: { ciphertextCid: string };
  try {
    parsed = parseShareUrl(shareUrl, { expectedOrigin: RETURN_ORIGIN });
  } catch {
    return false;
  }
  return parsed.ciphertextCid === preparedData.authorizationRequest.shareCid;
}
