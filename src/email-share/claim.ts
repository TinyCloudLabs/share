import { canonicalize, didKeyFromEd25519PublicKey, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { ed25519 } from "@noble/curves/ed25519";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import { mapTransportFailure, type ClaimChallengeResponse, type ShareTransport, type ShareTransportError } from "./transport.js";
import { SIGNATURE_DOMAINS } from "./protocol.js";
import { assertSourceBinding, digestText } from "./node-verifier.js";
import { readClaimedShare } from "./node-client.js";

const B64_128 = /^[A-Za-z0-9_-]{22}$/;
const B64_256 = /^[A-Za-z0-9_-]{43}$/;

export interface HolderKey { readonly did: string; readonly privateKey: CryptoKey; }
export interface ClaimMaterial { readonly holder: HolderKey; readonly credential: string; readonly expiresAt: string; readonly persisted: false; }
export type ClaimState =
  | { readonly state: "verifying"; readonly emailHint?: string }
  | { readonly state: "ready"; readonly emailHint: string }
  | { readonly state: "activation"; readonly emailHint: string }
  | { readonly state: "challenge"; readonly emailHint: string }
  | { readonly state: "redeeming"; readonly emailHint: string }
  | { readonly state: "otp"; readonly emailHint: string; readonly message?: string; readonly retryAfterSeconds?: number }
  | { readonly state: "resending"; readonly emailHint: string }
  | { readonly state: "claimed"; readonly claim: ClaimMaterial }
  | { readonly state: "session"; readonly claim: ClaimMaterial }
  | { readonly state: "reading"; readonly claim: ClaimMaterial }
  | { readonly state: "forgotten" }
  | { readonly state: "used" | "expired" | "revoked" | "denied"; readonly message: string; readonly retryable: boolean }
  | { readonly state: "error"; readonly code: string; readonly retryable: boolean; readonly retryAfterSeconds?: number };

export interface ClaimController {
  readonly state: ClaimState;
  subscribe(listener: (state: ClaimState) => void): () => void;
  openDocument(): Promise<void>;
  retry(): Promise<void>;
  useOtp(): void;
  submitOtp(code: string): Promise<void>;
  resend(): Promise<void>;
  read(): Promise<string | undefined>;
  forget(): void;
}

export interface CredentialTrust {
  readonly issuerDid: string;
  readonly vct: "opencredentials.email/v1";
  readonly issuerPublicKey: Uint8Array;
}

export async function createHolder(): Promise<HolderKey> {
  if (typeof crypto?.subtle?.generateKey !== "function") throw new Error("unsupported-browser");
  const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { did: didKeyFromEd25519PublicKey(publicKey), privateKey: pair.privateKey };
}

function randomB64(length: 16 | 32): string { return toBase64Url(crypto.getRandomValues(new Uint8Array(length))); }

async function holderProof(holder: HolderKey, share: VerifiedExactEmailShare, inviteId: string, challenge: ClaimChallengeResponse, redemptionId: string): Promise<{ readonly binding: Record<string, unknown>; readonly holderProof: Record<string, string> }> {
  const now = Date.now();
  const expiresAt = new Date(Math.min(now + 120_000, Date.parse(challenge.expiresAt), Date.parse(share.expiry))).toISOString();
  const binding = {
    type: "TinyCloudEmailClaimHolderBinding", version: 1, redemptionId, invitationId: inviteId, claimNonce: challenge.claimNonce,
    shareCid: share.shareCid, shareId: share.shareId, policyCid: share.policyCid, delegationCid: challenge.delegationCid,
    authorityMaterialHandle: challenge.authorityMaterialHandle, authorityMaterialDigest: challenge.authorityMaterialDigest,
    contentSource: challenge.contentSource, contentSourceDigest: challenge.contentSourceDigest, emailHash: challenge.emailHash,
    holderDid: holder.did, targetOrigin: share.nodeOrigin, nodeAudience: share.nodeAudience, requestOrigin: share.requestOrigin,
    issuedAt: new Date(now).toISOString(), expiresAt, jti: randomB64(16),
  };
  const message = new TextEncoder().encode(`${SIGNATURE_DOMAINS.holderBinding}${canonicalize(binding)}`);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", holder.privateKey, message));
  return { binding, holderProof: { alg: "EdDSA", kid: `${holder.did}#${holder.did.slice("did:key:".length)}`, signature: toBase64Url(signature) } };
}

function decodeJson(segment: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(segment))); } catch { throw new Error("credential-invalid"); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("credential-invalid");
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new Error("credential-invalid");
}

async function assertCredential(value: { format: string; credential: string; holderDid: string; expiresAt: string }, holder: HolderKey, share: VerifiedExactEmailShare, trust: CredentialTrust): Promise<void> {
  if (value.format !== "vc+sd-jwt" || value.holderDid !== holder.did || Date.parse(value.expiresAt) <= Date.now()) throw new Error("credential-invalid");
  const parts = value.credential.split("~");
  if (parts.length !== 3 || parts[2] !== "") throw new Error("credential-invalid");
  const [jws, encodedDisclosure] = parts;
  if (jws === undefined || encodedDisclosure === undefined) throw new Error("credential-invalid");
  const jwsParts = jws.split(".");
  if (jwsParts.length !== 3 || jwsParts.some((part) => part.length === 0)) throw new Error("credential-invalid");
  const [encodedHeader, encodedPayload, encodedSignature] = jwsParts;
  if (encodedHeader === undefined || encodedPayload === undefined || encodedSignature === undefined) throw new Error("credential-invalid");
  const header = decodeJson(encodedHeader); exactKeys(header, ["alg"]);
  const payload = decodeJson(encodedPayload); exactKeys(payload, ["_sd", "_sd_alg", "exp", "iat", "iss", "jti", "nbf", "sub", "tinycloud_share", "vct"]);
  if (header.alg !== "EdDSA" || payload.sub !== holder.did || payload.iss !== trust.issuerDid || payload.vct !== trust.vct || payload._sd_alg !== "sha-256" || !Array.isArray(payload._sd) || payload._sd.length !== 1 || typeof payload._sd[0] !== "string") throw new Error("credential-invalid");
  if (![payload.iat, payload.nbf, payload.exp].every((item) => typeof item === "number" && Number.isSafeInteger(item) && item >= 0) || typeof payload.jti !== "string" || payload.jti.length === 0) throw new Error("credential-invalid");
  const nowSeconds = Math.floor(Date.now() / 1000);
  if ((payload.nbf as number) > nowSeconds + 30 || (payload.exp as number) <= nowSeconds - 30 || (payload.iat as number) > (payload.nbf as number) || (payload.nbf as number) >= (payload.exp as number)) throw new Error("credential-invalid");
  if (new Date((payload.exp as number) * 1000).toISOString() !== value.expiresAt) throw new Error("credential-invalid");
  const scope = payload.tinycloud_share;
  if (typeof scope !== "object" || scope === null || Array.isArray(scope)) throw new Error("credential-invalid");
  const scopeObject = scope as Record<string, unknown>; exactKeys(scopeObject, ["node_audience", "policy_cid", "share_cid", "share_id"]);
  if (scopeObject.node_audience !== share.nodeAudience || scopeObject.policy_cid !== share.policyCid || scopeObject.share_cid !== share.shareCid || scopeObject.share_id !== share.shareId) throw new Error("credential-invalid");
  let signature: Uint8Array;
  try { signature = fromBase64Url(encodedSignature); } catch { throw new Error("credential-invalid"); }
  if (signature.length !== 64 || !ed25519.verify(signature, new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`), trust.issuerPublicKey, { zip215: false })) throw new Error("credential-invalid");
  let disclosure: unknown;
  try { disclosure = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(encodedDisclosure))); } catch { throw new Error("credential-invalid"); }
  if (!Array.isArray(disclosure) || disclosure.length !== 3 || typeof disclosure[0] !== "string" || disclosure[1] !== "email" || typeof disclosure[2] !== "string" || !B64_128.test(disclosure[0])) throw new Error("credential-invalid");
  if (await digestText(encodedDisclosure) !== payload._sd[0]) throw new Error("credential-invalid");
  if (canonicalize(disclosure[2]) !== canonicalize(share.recipientEmail)) throw new Error("credential-invalid");
}

function assertClaimChallenge(challenge: ClaimChallengeResponse, share: VerifiedExactEmailShare): void {
  if (!B64_256.test(challenge.claimNonce) || challenge.shareCid !== share.shareCid || challenge.shareId !== share.shareId || challenge.policyCid !== share.policyCid || challenge.delegationCid !== share.delegationCid || challenge.authorityMaterialHandle !== share.authorityMaterialHandle || challenge.authorityMaterialDigest !== share.authorityMaterialDigest || challenge.targetOrigin !== share.nodeOrigin || challenge.nodeAudience !== share.nodeAudience || challenge.emailHash.length !== 43 || Date.parse(challenge.expiresAt) <= Date.now() || Date.parse(challenge.expiresAt) > Date.parse(share.expiry)) throw new Error("claim-challenge-invalid");
  assertSourceBinding(challenge.contentSource, share.contentSource, share.contentSourceDigest);
  if (challenge.contentSourceDigest !== share.contentSourceDigest) throw new Error("claim-challenge-invalid");
}

function terminalFrom(error: ShareTransportError): ClaimState {
  if (error.code === "used") return { state: "used", message: "This invitation has already been used.", retryable: false };
  if (error.code === "expired") return { state: "expired", message: "This invitation has expired.", retryable: false };
  if (error.code === "revoked") return { state: "revoked", message: "This invitation is no longer available.", retryable: false };
  if (error.code === "denied") return { state: "denied", message: "This invitation could not be authorized for this recipient.", retryable: false };
  return { state: "error", code: error.code, retryable: error.retryable, ...(error.retryAfterSeconds === undefined ? {} : { retryAfterSeconds: error.retryAfterSeconds }) };
}

export function createClaimController(input: { readonly share: VerifiedExactEmailShare; readonly invitationId: string; readonly claimSecret: string; readonly transport: ShareTransport; readonly credentialTrust: CredentialTrust }): ClaimController {
  let state: ClaimState = { state: "verifying", emailHint: input.share.recipientHint };
  let holder: HolderKey | undefined;
  let claimSecret: string | undefined = input.claimSecret;
  let material: ClaimMaterial | undefined;
  let activationId: string | undefined;
  const redemptionId = randomB64(16);
  const listeners = new Set<(state: ClaimState) => void>();
  let inFlight: Promise<void> | undefined;
  let resendAvailableAt = 0;
  const setState = (next: ClaimState): void => { state = next; listeners.forEach((listener) => listener(next)); };
  const ensureHolder = async (): Promise<HolderKey> => { holder ??= await createHolder(); return holder; };
  const claim = async (mailboxProof: string, method: "magic" | "otp"): Promise<void> => {
    const key = await ensureHolder();
    if (method === "magic" && activationId === undefined) {
      const activation = await input.transport.activate({ invitationId: input.invitationId, claimSecret: mailboxProof });
      activationId = activation.activationId;
    }
    setState({ state: "challenge", emailHint: input.share.recipientHint });
    const challengeRequest = method === "magic"
      ? { invitationId: input.invitationId, method, activationId: activationId as string }
      : { invitationId: input.invitationId, method, otp: mailboxProof };
    const challenge = await input.transport.claimChallenge(challengeRequest);
    assertClaimChallenge(challenge, input.share);
    setState({ state: "redeeming", emailHint: input.share.recipientHint });
    const proof = await holderProof(key, input.share, input.invitationId, challenge, redemptionId);
    const response = await input.transport.claimRedeem({ version: "tinycloud.share-email-claim/v1", redemptionId, invitationId: input.invitationId, method, mailboxProof, ...proof });
    await assertCredential(response, key, input.share, input.credentialTrust);
    claimSecret = undefined;
    material = { holder: key, credential: response.credential, expiresAt: response.expiresAt, persisted: false };
    setState({ state: "claimed", claim: material });
  };
  const run = (operation: () => Promise<void>): Promise<void> => {
    if (inFlight !== undefined) return inFlight;
    inFlight = operation().finally(() => { inFlight = undefined; });
    return inFlight;
  };
  const openDocument = (): Promise<void> => run(async () => {
    if (state.state !== "verifying" && state.state !== "ready" && state.state !== "otp") return;
    if (claimSecret === undefined) { setState({ state: "error", code: "missing-secret", retryable: false }); return; }
    setState({ state: "activation", emailHint: input.share.recipientHint });
    try { await claim(claimSecret, "magic"); }
    catch (error) {
      if (error instanceof Error && error.message === "unsupported-browser") {
        setState({ state: "error", code: "unsupported-browser", retryable: false });
        return;
      }
      const failure = mapTransportFailure(error);
      if (failure.code === "offline" || failure.code === "capability-unavailable" || failure.code === "delivery-failed") setState({ state: "error", code: failure.code, retryable: failure.retryable, ...(failure.retryAfterSeconds === undefined ? {} : { retryAfterSeconds: failure.retryAfterSeconds }) });
      else if (failure.code === "denied") setState({ state: "otp", emailHint: input.share.recipientHint, message: "The link could not be verified. Enter the six-digit code from the email." });
      else if (failure.code === "invalid") setState({ state: "error", code: "invalid", retryable: false });
      else setState(terminalFrom(failure));
    }
  });
  return {
    get state() { return state; },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    openDocument,
    retry() {
      if (state.state !== "error" || !state.retryable) return Promise.resolve();
      setState({ state: "verifying", emailHint: input.share.recipientHint });
      return openDocument();
    },
    useOtp() {
      if (state.state === "verifying" || state.state === "ready" || state.state === "error") {
        setState({ state: "otp", emailHint: input.share.recipientHint, message: "Enter the six-digit code from the invitation email." });
      }
    },
    submitOtp(code) {
      return run(async () => {
        if (state.state !== "otp") return;
        if (!/^\d{6}$/.test(code)) { setState({ ...state, message: "Enter the six-digit code from the email." }); return; }
        setState({ state: "activation", emailHint: input.share.recipientHint });
        try { await claim(code, "otp"); }
        catch (error) { const failure = mapTransportFailure(error); if (failure.code === "used" || failure.code === "expired" || failure.code === "revoked") setState(terminalFrom(failure)); else setState({ state: "otp", emailHint: input.share.recipientHint, message: failure.code === "denied" ? "That code did not match. You can try again." : "We couldn't verify the code. Try again." }); }
      });
    },
    resend() {
      return run(async () => {
        if (claimSecret === undefined || (state.state !== "otp" && state.state !== "error") || Date.now() < resendAvailableAt) return;
        setState({ state: "resending", emailHint: input.share.recipientHint });
        try {
          const accepted = await input.transport.resend({ invitationId: input.invitationId, claimSecret });
          resendAvailableAt = Date.now() + accepted.retryAfterSeconds * 1000;
          setState({ state: "otp", emailHint: input.share.recipientHint, message: "A new code was requested. Check your inbox.", retryAfterSeconds: accepted.retryAfterSeconds });
        } catch (error) { const failure = mapTransportFailure(error); setState(terminalFrom(failure)); }
      });
    },
    read() {
      let content: string | undefined;
      return run(async () => {
        if (material === undefined || (state.state !== "claimed" && state.state !== "session" && state.state !== "reading")) return undefined;
        setState({ state: "session", claim: material });
        try {
          setState({ state: "reading", claim: material });
          content = await readClaimedShare({ share: input.share, claim: material, transport: input.transport });
        } catch (error) { const failure = mapTransportFailure(error); setState(terminalFrom(failure)); }
      }).then(() => content);
    },
    forget() { holder = undefined; material = undefined; claimSecret = undefined; setState({ state: "forgotten" }); },
  };
}
