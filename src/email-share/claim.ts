import { didKeyFromEd25519PublicKey, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { ed25519 } from "@noble/curves/ed25519";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import { canonicalize } from "@tinycloud/share-envelope";
import { mapTransportFailure, type ClaimChallengeResponse, type ShareTransport } from "./transport.js";

const HOLDER_DOMAIN = "xyz.tinycloud.share/email-claim-holder-binding/v1\0";
const B64_128 = /^[A-Za-z0-9_-]{22}$/;
const B64_256 = /^[A-Za-z0-9_-]{43}$/;

export interface HolderKey { readonly did: string; readonly privateKey: CryptoKey; }
export interface ClaimMaterial { readonly holder: HolderKey; readonly credential: string; readonly expiresAt: string; readonly persisted: false; }
export type ClaimState =
  | { readonly state: "verifying"; readonly emailHint?: string }
  | { readonly state: "ready"; readonly emailHint: string }
  | { readonly state: "opening"; readonly emailHint: string }
  | { readonly state: "otp"; readonly emailHint: string; readonly message?: string }
  | { readonly state: "resending"; readonly emailHint: string }
  | { readonly state: "claimed"; readonly claim: ClaimMaterial }
  | { readonly state: "forgotten" }
  | { readonly state: "error"; readonly code: string; readonly retryable: boolean };

export interface ClaimController {
  readonly state: ClaimState;
  subscribe(listener: (state: ClaimState) => void): () => void;
  openDocument(): Promise<void>;
  submitOtp(code: string): Promise<void>;
  resend(): Promise<void>;
  forget(): void;
}

export interface CredentialTrust {
  readonly issuerDid: string;
  readonly vct: "opencredentials.email/v1";
  readonly issuerPublicKey?: Uint8Array;
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
  const domain = new TextEncoder().encode(HOLDER_DOMAIN);
  const body = new TextEncoder().encode(canonicalize(binding));
  const bytes = new Uint8Array(domain.length + body.length); bytes.set(domain); bytes.set(body, domain.length);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", holder.privateKey, bytes));
  return { binding, holderProof: { alg: "EdDSA", kid: `${holder.did}#${holder.did.slice("did:key:".length)}`, signature: toBase64Url(signature) } };
}

function decodeJson(segment: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder().decode(fromBase64Url(segment))); } catch { throw new Error("credential-invalid"); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("credential-invalid");
  return value as Record<string, unknown>;
}

function assertCredential(value: { format: string; credential: string; holderDid: string; expiresAt: string }, holder: HolderKey, trust: CredentialTrust | undefined): void {
  if (value.format !== "vc+sd-jwt" || value.holderDid !== holder.did || Date.parse(value.expiresAt) <= Date.now()) throw new Error("credential-invalid");
  const [jws, ...disclosures] = value.credential.split("~");
  if (!jws || disclosures.length !== 1) throw new Error("credential-invalid");
  const parts = jws.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) throw new Error("credential-invalid");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (encodedHeader === undefined || encodedPayload === undefined || encodedSignature === undefined) throw new Error("credential-invalid");
  const header = decodeJson(encodedHeader);
  const payload = decodeJson(encodedPayload);
  if (header.alg !== "EdDSA" || payload.sub !== holder.did || payload.vct !== "opencredentials.email/v1" ||
      typeof payload.iss !== "string" || typeof payload.iat !== "number" || typeof payload.nbf !== "number" ||
      typeof payload.exp !== "number" || payload.exp * 1000 <= Date.now() || payload.nbf * 1000 > Date.now() + 5_000 ||
      typeof payload.tinycloud_share !== "object" || payload.tinycloud_share === null ||
      payload._sd_alg !== "sha-256" || !Array.isArray(payload._sd) || payload._sd.length !== 1) throw new Error("credential-invalid");
  if (trust === undefined || payload.iss !== trust.issuerDid) throw new Error("credential-invalid");
  if (trust.issuerPublicKey !== undefined) {
    try {
      if (!ed25519.verify(fromBase64Url(encodedSignature), new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`), trust.issuerPublicKey, { zip215: false })) throw new Error("credential-invalid");
    } catch { throw new Error("credential-invalid"); }
  } else if (fromBase64Url(encodedSignature).length !== 64) throw new Error("credential-invalid");
}

export function createClaimController(input: { readonly share: VerifiedExactEmailShare; readonly invitationId: string; readonly claimSecret: string; readonly transport: ShareTransport; readonly credentialTrust?: CredentialTrust }): ClaimController {
  let state: ClaimState = { state: "verifying", emailHint: input.share.recipientHint };
  let holder: HolderKey | undefined;
  let challenge: ClaimChallengeResponse | undefined;
  let claimSecret: string | undefined = input.claimSecret;
  const redemptionId = randomB64(16);
  const listeners = new Set<(state: ClaimState) => void>();
  const setState = (next: ClaimState): void => { state = next; listeners.forEach((listener) => listener(next)); };
  const ensureHolder = async (): Promise<HolderKey> => { holder ??= await createHolder(); return holder; };
  const claim = async (mailboxProof: string, method: "magic" | "otp"): Promise<void> => {
    const key = await ensureHolder();
    challenge = await input.transport.claimChallenge({ invitationId: input.invitationId, method, ...(method === "magic" ? { claimSecret: mailboxProof } : { otp: mailboxProof }) });
    const proof = await holderProof(key, input.share, input.invitationId, challenge, redemptionId);
    const response = await input.transport.claimRedeem({ version: "tinycloud.share-email-claim/v1", redemptionId, invitationId: input.invitationId, method, mailboxProof, ...proof });
    assertCredential(response, key, input.credentialTrust);
    claimSecret = undefined;
    setState({ state: "claimed", claim: { holder: key, credential: response.credential, expiresAt: response.expiresAt, persisted: false } });
  };
  return {
    get state() { return state; },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    async openDocument() {
      if (state.state !== "verifying" && state.state !== "ready") return;
      if (claimSecret === undefined) { setState({ state: "error", code: "missing-secret", retryable: false }); return; }
      setState({ state: "opening", emailHint: input.share.recipientHint });
      try { await claim(claimSecret, "magic"); }
      catch (error) {
        const failure = mapTransportFailure(error);
        if (failure.code === "offline" || failure.code === "denied" || failure.code === "used" || failure.code === "expired" || failure.code === "revoked") {
          setState({ state: "error", code: failure.code === "denied" ? "wrong-email-or-policy" : failure.code, retryable: failure.retryable });
        } else setState({ state: "otp", emailHint: input.share.recipientHint });
      }
    },
    async submitOtp(code) {
      if (state.state !== "otp" || !/^\d{6}$/.test(code)) { if (state.state === "otp") setState({ ...state, message: "Enter the six-digit code from the email." }); return; }
      setState({ state: "opening", emailHint: input.share.recipientHint });
      try { await claim(code, "otp"); }
      catch (error) { const failure = mapTransportFailure(error); setState({ state: "otp", emailHint: input.share.recipientHint, message: failure.code === "denied" ? "That code did not match. You can try again." : "We couldn't verify the code. Try again." }); }
    },
    async resend() {
      if (claimSecret === undefined || (state.state !== "otp" && state.state !== "error")) return;
      setState({ state: "resending", emailHint: input.share.recipientHint });
      try { await input.transport.resend({ invitationId: input.invitationId, claimSecret }); setState({ state: "otp", emailHint: input.share.recipientHint, message: "A new code was requested. Check your inbox." }); }
      catch (error) { const failure = mapTransportFailure(error); setState({ state: "error", code: failure.code, retryable: failure.retryable }); }
    },
    forget() { holder = undefined; challenge = undefined; claimSecret = undefined; setState({ state: "forgotten" }); },
  };
}
