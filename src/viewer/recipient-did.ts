import {
  canonicalMainnetPkhDid,
  recipientDidEnvelopeV2Schema,
  verifyRecipientDidEnvelopeV2,
  type NativeVerifiedRecipientBundleV2,
  type RecipientDidDelegationBundleV2,
  type RecipientDidEnvelopeV2,
  type RecipientDidEnvelopeV2RejectCode,
} from "@tinycloud/share-envelope";

/**
 * The browser-facing SDK boundary for recipient-DID shares. Implementations
 * may wrap OpenKey and TinyCloudWeb, but the viewer never receives a raw key
 * or a general-purpose signer.
 */
export interface RecipientDidViewerAdapter {
  /** Atomic, network-free native authority verification from the v2 contract. */
  verifyDelegationBundle(
    bundle: RecipientDidDelegationBundleV2,
    now: Date,
  ): Promise<NativeVerifiedRecipientBundleV2>;
  /** Return the currently selected OpenKey account, without opening a prompt. */
  getActiveAccountDid(): Promise<string | null>;
  /** Open account selection. Call only from a user gesture. */
  connectAccount(): Promise<string>;
  /**
   * Perform one holder-signed exact read. The adapter MUST use the supplied
   * signed origin verbatim and MUST treat redirects as errors.
   */
  readExact(input: RecipientDidReadRequest): Promise<Uint8Array>;
}

export interface RecipientDidReadRequest {
  origin: string;
  nodeAudience: string;
  spaceId: string;
  path: string;
  actions: readonly string[];
  recipientDid: string;
  delegation: RecipientDidDelegationBundleV2;
  redirect: "error";
}

export type RecipientAccountMode = "active" | "connect";

const RECIPIENT_CONTINUATION_TTL_MS = 5 * 60 * 1_000;
const verifiedContinuations = new WeakSet<object>();

export interface VerifiedRecipientDidContinuation {
  readonly envelope: RecipientDidEnvelopeV2;
  readonly validUntilMs: number;
}

export type RecipientDidVerificationResult =
  | {
      state: "recipient-verified";
      continuation: VerifiedRecipientDidContinuation;
    }
  | { state: "recipient-expired"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-verification-failed"; code: RecipientDidEnvelopeV2RejectCode };

export type RecipientDidOpenResult =
  | { state: "recipient-ok"; envelope: RecipientDidEnvelopeV2; content: string }
  | {
      state: "recipient-identity-required";
      envelope: RecipientDidEnvelopeV2;
      continuation: VerifiedRecipientDidContinuation;
    }
  | {
      state: "recipient-wrong-account";
      envelope: RecipientDidEnvelopeV2;
      continuation: VerifiedRecipientDidContinuation;
    }
  | {
      state: "recipient-identity-cancelled";
      envelope: RecipientDidEnvelopeV2;
      continuation: VerifiedRecipientDidContinuation;
    }
  | { state: "recipient-node-unauthorized"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-node-not-found"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-node-unavailable"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-content-invalid"; envelope: RecipientDidEnvelopeV2 }
  | {
      state: "recipient-continuation-expired";
      envelope: RecipientDidEnvelopeV2;
    }
  | { state: "recipient-expired"; envelope: RecipientDidEnvelopeV2 }
  | { state: "recipient-verification-failed"; code: RecipientDidEnvelopeV2RejectCode };

export type RecipientNodeReadErrorCode = "unauthorized" | "not-found" | "unavailable";

/** Typed adapter error: raw node messages never cross into user-facing copy. */
export class RecipientNodeReadError extends Error {
  constructor(readonly code: RecipientNodeReadErrorCode) {
    super(`recipient node read failed: ${code}`);
    this.name = "RecipientNodeReadError";
  }
}

export interface OpenRecipientDidShareOptions {
  adapter: RecipientDidViewerAdapter;
  allowedOrigins: readonly string[];
  accountMode?: RecipientAccountMode;
  now?: Date;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function makeContinuation(
  envelope: RecipientDidEnvelopeV2,
  nowMs: number,
): VerifiedRecipientDidContinuation {
  const frozenEnvelope = deepFreeze(structuredClone(envelope));
  const continuation = Object.freeze({
    envelope: frozenEnvelope,
    validUntilMs: Math.min(
      Date.parse(frozenEnvelope.expiry),
      nowMs + RECIPIENT_CONTINUATION_TTL_MS,
    ),
  });
  verifiedContinuations.add(continuation);
  return continuation;
}

function restoreContinuationForIdentityRetry(
  continuation: VerifiedRecipientDidContinuation,
  now: Date | undefined,
): void {
  const retryNowMs = (now ?? new Date()).getTime();
  if (
    retryNowMs < Date.parse(continuation.envelope.expiry) &&
    retryNowMs < continuation.validUntilMs
  ) {
    verifiedContinuations.add(continuation);
  }
}

/** Verify the encrypted envelope once and mint an opaque, short-lived continuation. */
export async function verifyRecipientDidShare(
  input: unknown,
  options: Pick<OpenRecipientDidShareOptions, "adapter" | "allowedOrigins" | "now">,
): Promise<RecipientDidVerificationResult> {
  const now = options.now ?? new Date();
  const verified = await verifyRecipientDidEnvelopeV2(input, {
    allowedOrigins: options.allowedOrigins,
    now,
    verifyDelegationBundle: (bundle, verificationTime) =>
      options.adapter.verifyDelegationBundle(bundle, verificationTime),
  });
  if (!verified.ok) {
    if (verified.code === "expired") {
      const expiredEnvelope = recipientDidEnvelopeV2Schema.safeParse(input);
      if (expiredEnvelope.success) {
        return { state: "recipient-expired", envelope: expiredEnvelope.data };
      }
    }
    return { state: "recipient-verification-failed", code: verified.code };
  }
  return {
    state: "recipient-verified",
    continuation: makeContinuation(verified.envelope, now.getTime()),
  };
}

/** Continue from verified state without retaining/replaying the fragment URL. */
export async function continueRecipientDidShare(
  continuation: VerifiedRecipientDidContinuation,
  options: Pick<OpenRecipientDidShareOptions, "adapter" | "accountMode" | "now">,
): Promise<RecipientDidOpenResult> {
  const envelope = continuation.envelope;
  const now = options.now ?? new Date();
  if (now.getTime() >= Date.parse(envelope.expiry)) {
    verifiedContinuations.delete(continuation);
    return { state: "recipient-expired", envelope };
  }
  if (
    !verifiedContinuations.has(continuation) ||
    now.getTime() >= continuation.validUntilMs
  ) {
    verifiedContinuations.delete(continuation);
    return { state: "recipient-continuation-expired", envelope };
  }

  // Claim synchronously before the first identity await. Identity outcomes
  // that invite another user choice restore a still-live continuation; a
  // matching identity keeps the claim consumed through the one node attempt.
  verifiedContinuations.delete(continuation);

  let accountDid: string | null;
  try {
    accountDid = options.accountMode === "connect"
      ? await options.adapter.connectAccount()
      : await options.adapter.getActiveAccountDid();
  } catch {
    restoreContinuationForIdentityRetry(continuation, options.now);
    return { state: "recipient-identity-cancelled", envelope, continuation };
  }
  if (accountDid === null) {
    restoreContinuationForIdentityRetry(continuation, options.now);
    return { state: "recipient-identity-required", envelope, continuation };
  }
  // Canonicalization is validation only. Never normalize a different wire
  // identity into a match after the sender signed the exact recipient DID.
  if (
    canonicalMainnetPkhDid(accountDid) !== accountDid ||
    accountDid !== envelope.authorizationTarget.did
  ) {
    restoreContinuationForIdentityRetry(continuation, options.now);
    return { state: "recipient-wrong-account", envelope, continuation };
  }

  let bytes: Uint8Array;
  try {
    bytes = await options.adapter.readExact({
      origin: envelope.target.origin,
      nodeAudience: envelope.target.nodeAudience,
      spaceId: envelope.target.spaceId,
      path: envelope.target.resource.path,
      actions: envelope.target.actions,
      recipientDid: accountDid,
      delegation: envelope.delegation,
      redirect: "error",
    });
  } catch (error) {
    if (error instanceof RecipientNodeReadError) {
      if (error.code === "unauthorized") {
        return { state: "recipient-node-unauthorized", envelope };
      }
      if (error.code === "not-found") {
        return { state: "recipient-node-not-found", envelope };
      }
    }
    return { state: "recipient-node-unavailable", envelope };
  }

  try {
    const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { state: "recipient-ok", envelope, content };
  } catch {
    return { state: "recipient-content-invalid", envelope };
  }
}

/**
 * Verify first, identify second, contact the signed node last. This function
 * is the instrumentable ordering boundary used by both the app and tests.
 */
export async function openRecipientDidShare(
  input: unknown,
  options: OpenRecipientDidShareOptions,
): Promise<RecipientDidOpenResult> {
  const verified = await verifyRecipientDidShare(input, options);
  if (verified.state !== "recipient-verified") return verified;
  const { continuation } = verified;
  const envelope = continuation.envelope;
  if (
    envelope.target.actions.length !== 1 ||
    envelope.target.actions[0] !== "tinycloud.kv/get"
  ) {
    return { state: "recipient-verification-failed", code: "target-mismatch" };
  }
  return continueRecipientDidShare(continuation, options);
}
