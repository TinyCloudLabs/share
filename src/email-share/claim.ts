import { didKeyFromEd25519PublicKey, toBase64Url } from "@tinycloud/share-envelope";
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

function assertCredential(value: { format: string; credential: string; holderDid: string; expiresAt: string }, holder: HolderKey): void {
  if (value.format !== "vc+sd-jwt" || value.holderDid !== holder.did || Date.parse(value.expiresAt) <= Date.now()) throw new Error("credential-invalid");
  const payload = value.credential.split(".")[1];
  if (payload === undefined) throw new Error("credential-invalid");
  const decoded = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0))));
  if (decoded.sub !== holder.did) throw new Error("credential-invalid");
}

export function createClaimController(input: { readonly share: VerifiedExactEmailShare; readonly invitationId: string; readonly claimSecret: string; readonly transport: ShareTransport }): ClaimController {
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
    assertCredential(response, key);
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
