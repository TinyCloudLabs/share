import { captureAndScrubLaunch, type CapturedLaunch } from "./email-share/url.js";
import type { RecipientFacts, RecipientViewActions } from "./email-share/view.js";
import { canonicalize, fromBase64Url, toBase64Url, type ContentSource } from "@tinycloud/share-envelope";
import { SIGNATURE_DOMAINS } from "./email-share/protocol.js";
import { digestBytes, digestText } from "./email-share/node-verifier.js";
import type { VerifiedExactEmailShare } from "./email-share/verified-share.js";
import type { ClaimController, ClaimState } from "./email-share/claim.js";
import type { ResolveResult } from "./viewer/resolve.js";
import { mountPolicyV2Viewer } from "./viewer/policy-v2.js";

const viewerRoot = document.getElementById("viewer");

if (viewerRoot !== null) {
  // This is intentionally the first recipient-side operation. The complete
  // fragment is captured and the current history entry is scrubbed before
  // any dynamic import, hydration, configuration load, or network request.
  const captured = captureAndScrubLaunch(window.location, window.history);
  const launch = captured !== undefined && import.meta.env.VITE_SHARE_HERMETIC === "true" && window.location.hostname === "127.0.0.1"
    ? { ...captured, shareHref: `https://share.tinycloud.xyz${new URL(captured.shareHref).pathname}${new URL(captured.shareHref).search}${new URL(captured.shareHref).hash}` }
    : captured;
  void import("./email-share/recipient.css");
  void import("./viewer/viewer.css");
  void bootRecipient(viewerRoot, launch);
} else {
  // The root site is a static product/spec page. Keep its Mermaid behavior
  // isolated from the recipient route so the recipient has no decorative or
  // protocol work before its URL secret is scrubbed.
  void import("mermaid").then(({ default: mermaid }) => {
    const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    mermaid.initialize({ startOnLoad: true, theme: dark ? "dark" : "neutral", securityLevel: "strict", fontFamily: "system-ui, -apple-system, sans-serif" });
    const links = Array.from(document.querySelectorAll<HTMLAnchorElement>("nav.toc ol a[href^='#']"));
    const map = new Map<string, HTMLAnchorElement>();
    links.forEach((a) => map.set(a.getAttribute("href")!.slice(1), a));
    const targets = Array.from(map.keys()).map((id) => document.getElementById(id)).filter((target): target is HTMLElement => target !== null);
    if (!("IntersectionObserver" in window) || targets.length === 0) return;
    let current: HTMLAnchorElement | null = null;
    const visible = new Set<string>();
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => entry.isIntersecting ? visible.add(entry.target.id) : visible.delete(entry.target.id));
      const first = targets.find((target) => visible.has(target.id));
      const next = first === undefined ? null : map.get(first.id) ?? null;
      if (next === current) return;
      current?.classList.remove("active");
      current = next;
      current?.classList.add("active");
    }, { rootMargin: "-10% 0px -60% 0px" });
    targets.forEach((target) => observer.observe(target));
  });
}

async function bootRecipient(root: HTMLElement, launch: CapturedLaunch | undefined): Promise<void> {
  const [{ appendRecipientForgetAction, renderRecipientInvalid, renderRecipientLoading, renderRecipientState }, { createClaimController }] = await Promise.all([
    import("./email-share/view.js"),
    import("./email-share/claim.js"),
  ]);
  renderRecipientLoading(root);
  if (launch === undefined) {
    renderRecipientInvalid(root, "The link is incomplete. Ask the sender to resend the invitation.");
    return;
  }

  try {
    const [{ REGISTRY_BASE_URL }, { resolveShare }, { presentShare }, config, runtime] = await Promise.all([
      import("./viewer/config.js"),
      import("./viewer/resolve.js"),
      import("./viewer/present.js"),
      import("./email-share/config.js"),
      import("./email-share/runtime.js"),
    ]);
    const shareHref = launch.shareHref;
    launch.shareHref = "";
    const invite = launch.invite;
    delete launch.invite;
    const resolved: ResolveResult = await resolveShare(shareHref, { registryBaseUrl: REGISTRY_BASE_URL });
    if (resolved.state === "policy-v2-claim-required") {
      const publicConfig = await config.loadSharePublicConfig();
      const { createHolder } = await import("./email-share/claim.js");
      const holder = await createHolder();
      mountPolicyV2Viewer(root, resolved, {
        nodeOrigin: publicConfig.nodeOrigin,
        trustedNode: config.trustedNodeFromConfig(publicConfig),
        holderDid: holder.did,
        buildPresentation: async ({ challenge, envelope, policy }) => {
          // The v2 recipient adapter owns challenge binding and proof
          // verification.  A production credential is deliberately required
          // here; the UI must never turn an unverified email into access.
          if (invite === undefined) throw new Error("The invitation claim fragment is missing.");
          return buildV2Presentation({ challenge, envelope, policy, invite, publicConfig, shareCid: resolved.shareCid, holder });
        },
      });
      return;
    }
    if (resolved.state !== "policy-email-claim-required") {
      await presentShare(root, resolved);
      return;
    }
    if (invite === undefined) {
      renderRecipientInvalid(root, "This exact-email invitation is missing its email proof. Ask the sender to resend the invitation.");
      return;
    }

    renderRecipientLoading(root, "Checking invitation scope…");
    const publicConfig = await config.loadSharePublicConfig();
    const credentialTrust = config.credentialTrustFromConfig(publicConfig);
    runtime.assertProductionCredentialTrust(credentialTrust);
    const trustedNode = config.trustedNodeFromConfig(publicConfig);
    const binding = await config.loadSharePublicBinding(resolved.shareCid);
    const share = Object.freeze({
      ...(await runtime.verifyProductionEmailShare({ envelope: resolved.envelope, shareCid: resolved.shareCid, policy: resolved.policy, config: publicConfig, binding })),
      trustedNode,
    });
    const transport = (await import("./email-share/transport.js")).createHttpTransport({ nodeOrigin: publicConfig.nodeOrigin, credentialsOrigin: publicConfig.credentialsOrigin });
    const facts: RecipientFacts = { envelope: resolved.envelope, share };
    let controller: ClaimController;
    let contentShown = false;
    const render = (state: ClaimState): void => renderRecipientState(root, facts, state, actions);
    const showContent = async (content: string): Promise<void> => {
      if (contentShown) return;
      contentShown = true;
      await presentShare(root, { state: "ok", access: "policy", envelope: resolved.envelope, senderVerified: true, content });
      appendRecipientForgetAction(root, () => controller.forget());
    };
    const readDocument = async (): Promise<void> => {
      const content = await controller.read();
      if (content !== undefined) await showContent(content);
    };
    const open = async (): Promise<void> => { await controller.openDocument(); if (controller.state.state === "claimed") await readDocument(); };
    const retry = async (): Promise<void> => { await controller.retry(); if (controller.state.state === "claimed") await readDocument(); };
    const submitOtp = async (code: string): Promise<void> => { await controller.submitOtp(code); if (controller.state.state === "claimed") await readDocument(); };
    const actions: RecipientViewActions = { onOpen: () => { void open(); }, onRetry: () => { void retry(); }, onUseOtp: () => controller.useOtp(), onOtp: (code) => { void submitOtp(code); }, onResend: () => { void controller.resend(); }, onForget: () => controller.forget() };
    controller = createClaimController({ share, invitationId: invite.invitationId, claimSecret: invite.claimSecret, transport, credentialTrust });
    controller.subscribe(render);
    render({ state: "ready", emailHint: share.recipientHint });
  } catch (error) {
    const detail = error instanceof Error && /unavailable|capability|config|binding/.test(error.message)
      ? "The trusted sharing service is unavailable. Try again later; no credential or document request was completed."
      : "This invitation could not be verified. Ask the sender for a fresh invitation.";
    renderRecipientInvalid(root, detail);
  }
}

async function buildV2Presentation(input: { readonly challenge: import("@tinycloud/share-sdk").PolicyChallenge; readonly envelope: import("@tinycloud/share-envelope").ShareEnvelopeV2; readonly policy: Record<string, unknown>; readonly invite: { readonly invitationId: string; readonly claimSecret: string }; readonly shareCid: string; readonly publicConfig: Awaited<ReturnType<typeof import("./email-share/config.js").loadSharePublicConfig>>; readonly holder: import("./email-share/claim.js").HolderKey }): Promise<import("@tinycloud/share-sdk").PolicyPresentationMaterial> {
  const source = input.policy.contentSource as ContentSource;
  const recipientEmail = input.envelope.deliveryEmail;
  if (recipientEmail === undefined || (source.kind !== "kv" && source.kind !== "sql")) throw new Error("A full-email delivery claim is required for this share.");
  const [{ issueEmailClaimCredential }, { createHttpTransport }, { credentialTrustFromConfig }] = await Promise.all([
    import("./email-share/claim.js"), import("./email-share/transport.js"), import("./email-share/config.js"),
  ]);
  const transport = createHttpTransport({ nodeOrigin: input.publicConfig.nodeOrigin, credentialsOrigin: input.publicConfig.credentialsOrigin });
  const claimShare = {
    shareId: input.envelope.shareId, shareCid: input.shareCid, policyCid: input.envelope.authorizationTarget.kind === "policy" ? input.envelope.authorizationTarget.policyCid : "", recipientEmail, recipientHint: `${recipientEmail.slice(0, 1)}***@${recipientEmail.split("@").at(-1) ?? ""}`, expiry: input.envelope.expiry, nodeOrigin: input.envelope.target.origin, nodeAudience: input.envelope.target.nodeAudience, requestOrigin: input.publicConfig.shareOrigin, delegationCid: input.envelope.delegationCid, authorityMaterialHandle: source.kind === "sql" ? "amh_sql_001" : "amh_kv_001", authorityMaterialDigest: input.envelope.authorityMaterialDigest, contentSource: source, contentSourceDigest: input.envelope.contentSourceDigest, action: source.action, resource: source.path, trustedNode: { targetOrigin: input.publicConfig.nodeOrigin, nodeAudience: input.publicConfig.nodeAudience, invitationKid: input.publicConfig.nodeInvitationKid, invitationPublicKey: fromBase64Url(input.publicConfig.nodeInvitationPublicKey), keyVersion: input.publicConfig.nodeKeyVersion, enabled: input.publicConfig.nodeEnabled },
  } as VerifiedExactEmailShare;
  const claim = await issueEmailClaimCredential({ share: claimShare, invitationId: input.invite.invitationId, mailboxProof: input.invite.claimSecret, method: "magic", holder: input.holder, transport, credentialTrust: credentialTrustFromConfig(input.publicConfig) });
  const credentialDigest = await digestText(claim.credential);
  const holderBinding = { type: "TinyCloudEmailClaimHolderBinding", version: 1, redemptionId: input.envelope.shareId, invitationId: input.shareCid, claimNonce: input.challenge.nonce, challengeNonce: input.challenge.nonce, shareCid: input.shareCid, shareId: input.envelope.shareId, policyCid: claimShare.policyCid, contentSource: source, contentSourceDigest: input.envelope.contentSourceDigest, emailHash: await digestText(recipientEmail), holderDid: input.holder.did, credentialDigest, targetOrigin: input.envelope.target.origin, nodeAudience: input.envelope.target.nodeAudience, audience: input.envelope.target.nodeAudience, enforcerDid: input.challenge.enforcerDid, requestOrigin: input.envelope.target.origin, challengeId: input.challenge.challengeId, challengeRequestDigest: input.challenge.requestBodyDigest, issuedAt: new Date().toISOString(), expiresAt: input.challenge.expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))) };
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", input.holder.privateKey, new TextEncoder().encode(`${SIGNATURE_DOMAINS.holderBinding}${canonicalize(holderBinding)}`)));
  const holderJcs = canonicalize(holderBinding);
  const holderSignedBytes = new TextEncoder().encode(`${SIGNATURE_DOMAINS.holderBinding}${holderJcs}`);
  return { holderDid: input.holder.did, credential: claim.credential, credentialDigest, holderBinding: { name: "holderBinding", domain: SIGNATURE_DOMAINS.holderBinding, signerDid: input.holder.did, message: holderBinding, jcs: holderJcs, messageDigest: await digestText(holderJcs), signedBytesDigest: await digestBytes(holderSignedBytes), signatureDigest: await digestBytes(signature), signature: { alg: "EdDSA", kid: `${input.holder.did}#${input.holder.did.slice("did:key:".length)}`, value: toBase64Url(signature) } }, proof: { alg: "EdDSA", kid: `${input.holder.did}#${input.holder.did.slice("did:key:".length)}`, signature: toBase64Url(signature) }, sign: async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", input.holder.privateKey, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer)), email: recipientEmail };
}
