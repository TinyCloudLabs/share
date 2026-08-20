import { captureAndScrubLaunch, type CapturedLaunch } from "./email-share/url.js";
import type { RecipientFacts, RecipientViewActions } from "./email-share/view.js";
import { canonicalize, fromBase64Url, toBase64Url, type ContentSource } from "@tinycloud/share-envelope";
import { SIGNATURE_DOMAINS } from "./email-share/protocol.js";
import { digestBytes, digestText } from "./email-share/node-verifier.js";
import type { VerifiedExactEmailShare } from "./email-share/verified-share.js";
import type { ClaimController, ClaimState } from "./email-share/claim.js";
import type { ResolveResult } from "./viewer/resolve.js";
import { createRegisteredPolicyAuthority, createShareV2HolderBindingArtifact, SHARE_V2_PROTOCOL } from "@tinycloud/share-sdk";

// viewer.html is the ONLY page that loads this module, and it always declares
// <div id="viewer">. There is no non-viewer branch here on purpose: the
// recipient route must do no decorative work before its URL secret is scrubbed.
const viewerRoot = document.getElementById("viewer");

async function loadViewerStyles(): Promise<void> {
  await Promise.all([
    import("./email-share/recipient.css"),
    import("./viewer/viewer.css"),
  ]);
  document.documentElement.classList.remove("viewer-first-paint");
}

if (viewerRoot !== null) {
  if (new URLSearchParams(window.location.search).get("sender-launch") === "1") {
    void loadViewerStyles();
    void bootSenderViewer(viewerRoot);
  } else {
  // This is intentionally the first recipient-side operation. The complete
  // fragment is captured and the current history entry is scrubbed before
  // any dynamic import, hydration, configuration load, or network request.
  const captured = captureAndScrubLaunch(window.location, window.history, window.sessionStorage);
  const launch = captured !== undefined && import.meta.env.VITE_SHARE_VIEWER_HERMETIC === "true" && window.location.hostname === "127.0.0.1"
    ? { ...captured, shareHref: `https://share.tinycloud.xyz${new URL(captured.shareHref).pathname}${new URL(captured.shareHref).search}${new URL(captured.shareHref).hash}` }
    : captured;
  void loadViewerStyles();
  void bootRecipient(viewerRoot, launch);
  }
}

async function bootSenderViewer(root: HTMLElement): Promise<void> {
  root.replaceChildren();
  const loading = document.createElement("p");
  loading.textContent = "Waiting for the private share…";
  loading.setAttribute("role", "status");
  root.append(loading);
  let accepted = false;
  let launched = false;
  const timeout = window.setTimeout(() => {
    if (!launched) loading.textContent = "Couldn't open the preview. Close this tab and try again.";
  }, 10_000);
  const receive = (event: MessageEvent): void => {
    if (accepted || event.origin !== window.location.origin || event.data?.type !== "tinycloud-sender-channel" || event.ports.length !== 1) return;
    accepted = true;
    window.removeEventListener("message", receive);
    const port = event.ports[0]!;
    port.onmessage = (message): void => {
      if (message.data?.type !== "tinycloud-sender-launch") return;
      const url = message.data?.url;
      if (typeof url !== "string") return;
      try {
        const parsed = new URL(url);
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("origin");
        const captured = captureAndScrubLaunch(parsed as unknown as Location, window.history, window.sessionStorage);
        if (captured === undefined) throw new Error("launch");
        launched = true;
        window.clearTimeout(timeout);
        port.close();
        window.opener = null;
        void loadViewerStyles();
        void bootRecipient(root, captured);
      } catch {
        loading.textContent = "The private share was invalid or expired.";
      }
    };
    port.start();
    try { port.postMessage({ type: "tinycloud-sender-ready" }); } catch { port.close(); }
  };
  window.addEventListener("message", receive);
}

async function bootRecipient(root: HTMLElement, launch: CapturedLaunch | undefined): Promise<void> {
  const [{ appendRecipientForgetAction, renderRecipientInvalid, renderRecipientLoading, renderRecipientState }, { createClaimController }] = await Promise.all([
    import("./email-share/view.js"),
    import("./email-share/claim.js"),
  ]);
  renderRecipientLoading(root);
  if (launch === undefined) {
    renderRecipientInvalid(root, "Part of this link is missing. Copy the whole link from the message you received — including everything after the # — and paste it into a new tab.");
    return;
  }

  try {
    const [{ REGISTRY_BASE_URL }, { resolveShare, createBrowserAddressedAuthorization, presentationEnvelope }, { presentShare }, config, runtime] = await Promise.all([
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
    const shareConfig = await config.loadSharePublicConfig();
    const shareTrustedNode = config.trustedNodeFromConfig(shareConfig);
    const authority = createRegisteredPolicyAuthority({ nodeProof: { kid: shareConfig.nodeInvitationKid, publicKey: fromBase64Url(shareConfig.nodeInvitationPublicKey) }, expectedTarget: { origin: shareConfig.nodeOrigin, nodeAudience: shareConfig.nodeAudience, enforcerDid: shareConfig.enforcerDid } });
    const { createHolder } = await import("./email-share/claim.js");
    const holder = invite === undefined ? undefined : await createHolder();
    const authorization = invite === undefined || holder === undefined ? undefined : createBrowserAddressedAuthorization({
      nodeOrigin: shareConfig.nodeOrigin,
      trustedNode: shareTrustedNode,
      holderDid: holder.did,
      buildPresentation: async ({ challenge, envelope, policy }) => buildV2Presentation({ challenge, envelope, policy, invite, publicConfig: shareConfig, shareCid: "", holder }),
    });
    // Held only for the accountless route, which decrypts the body in this tab
    // rather than asking the node to decrypt it.
    let linkKey: Uint8Array | undefined;
    const resolved: ResolveResult = await resolveShare(shareHref, { registryBaseUrl: REGISTRY_BASE_URL, expectedOrigin: shareConfig.shareOrigin, trustedPolicyAuthority: authority, onKeyParsed: (key32) => { linkKey = new Uint8Array(key32); }, ...(authorization === undefined ? {} : { authorization }) });
    if (resolved.state === "recipient-did-authorization-required") {
      const { mountRecipientDidAuthorization } = await import("./viewer/recipient-did.js");
      const expectedDid = resolved.envelope.recipientMatcher.kind === "recipientDid" ? resolved.envelope.recipientMatcher.value : "";
      const { beginBrowserAddressedChallenge } = await import("./viewer/resolve.js");
      const challenge = await beginBrowserAddressedChallenge({ envelope: resolved.envelope, nodeOrigin: shareConfig.nodeOrigin, trustedNode: shareTrustedNode, holderDid: expectedDid });
      mountRecipientDidAuthorization(root, {
        expectedDid,
        resume: async () => {
          const { authenticateWithOpenKey, createTinyCloudClient } = await import("./share/openkey-session.js");
          const session = await authenticateWithOpenKey(() => undefined);
          const tinycloud = await createTinyCloudClient(session, shareConfig, [], () => undefined);
          if (tinycloud.sessionDid !== expectedDid) throw new Error("recipient-did-mismatch");
          const restored = (tinycloud as unknown as { readonly session?: { readonly delegationHeader?: { readonly Authorization?: unknown }; readonly delegationCid?: unknown } }).session;
          if (typeof restored?.delegationHeader?.Authorization !== "string" || typeof restored.delegationCid !== "string") throw new Error("openkey-session-delegation-missing");
          const proof = await buildOpenKeyAuthorizationProof({
            challenge,
            envelope: resolved.envelope,
            holderDid: tinycloud.sessionDid,
            credential: restored.delegationHeader.Authorization,
            delegationCid: restored.delegationCid,
            sign: (bytes) => tinycloud.signSessionBytes(bytes),
          });
          const didAuthorization = createBrowserAddressedAuthorization({
            nodeOrigin: shareConfig.nodeOrigin,
            trustedNode: shareTrustedNode,
            holderDid: tinycloud.sessionDid,
          });
          const next = await resolveShare(shareHref, { registryBaseUrl: REGISTRY_BASE_URL, expectedOrigin: shareConfig.shareOrigin, trustedPolicyAuthority: authority, authorization: didAuthorization, authorizationResumeToken: challenge.challengeId, authorizationProof: proof });
          await presentShare(root, next, { shareUrl: shareHref });
          return next;
        },
      });
      return;
    }
    // Accountless receive is an SDK contract.  Share hosts only its inline UI
    // and renders the locally decrypted result; the SDK performs embedded Node
    // policy admission followed by generic /delegate and /invoke.
    if (shareConfig.accountlessReceiverEnabled === true && resolved.state === "policy-v2-claim-required" && resolved.envelope.version === 3) {
      const { receiveWithSdk } = await import("./viewer/sdk-accountless-receiver.js");
      const accountlessEnvelope = resolved.envelope;
      await receiveWithSdk({
        root,
        shareUrl: shareHref,
        registryBaseUrl: REGISTRY_BASE_URL,
        config: shareConfig,
        onComplete: async (content) => {
          await presentShare(root, {
            state: "ok",
            access: "policy",
            envelope: accountlessEnvelope,
            senderVerified: true,
            contentBytes: content.bytes,
          }, { shareUrl: shareHref });
        },
      });
      return;
    }
    if (resolved.state === "policy-v2-claim-required" && resolved.envelope.version === 3) {
      const { mountCredentialReceiver } = await import("./viewer/credential-receiver.js");
      const interruptedOperation = Object.freeze({
        type: "TinyCloudInterruptedShareRead" as const,
        version: 1 as const,
        shareCid: resolved.shareCid,
        envelope: resolved.envelope,
      });
      let activeClient: Promise<import("./share/openkey-session.js").ShareTinyCloud> | undefined;
      mountCredentialReceiver(root, {
        share: { envelope: resolved.envelope, policy: resolved.policy, shareCid: resolved.shareCid },
        operation: interruptedOperation,
        openerOrigin: window.location.origin,
        connect: () => {
          if (activeClient !== undefined) return activeClient;
          const attempt = import("./share/openkey-session.js").then(async ({ authenticateWithOpenKey, createTinyCloudClient }) => {
            const session = await authenticateWithOpenKey(() => undefined);
            return createTinyCloudClient(session, shareConfig, [], () => undefined);
          });
          activeClient = attempt;
          void attempt.catch(() => {
            if (activeClient === attempt) activeClient = undefined;
          });
          return attempt;
        },
        onComplete: async (content) => {
          await presentShare(root, { state: "ok", access: "policy", envelope: resolved.envelope, senderVerified: true, contentBytes: content.bytes }, { shareUrl: shareHref });
        },
      });
      return;
    }
    if (resolved.state !== "policy-email-claim-required") {
      await presentShare(root, resolved, { shareUrl: shareHref });
      return;
    }
    if (invite === undefined) {
      renderRecipientInvalid(root, "Part of this link is missing. Ask the sender to share it again.");
      return;
    }
    const shareUrl = `${shareHref}&i=${invite.invitationId}&c=${invite.claimSecret}`;

    renderRecipientLoading(root, "Checking…");
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
    const facts: RecipientFacts = { envelope: resolved.envelope, share, shareUrl };
    let controller: ClaimController;
    let contentShown = false;
    const render = (state: ClaimState): void => renderRecipientState(root, facts, state, actions);
    const showContent = async (content: string): Promise<void> => {
      if (contentShown) return;
      contentShown = true;
      await presentShare(root, { state: "ok", access: "policy", envelope: resolved.envelope, senderVerified: true, content }, { shareUrl });
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
    console.debug("tinycloud share: recipient request failed", error);
    const detail = error instanceof Error && /unavailable|capability|config|binding/.test(error.message)
      ? "TinyCloud is temporarily unavailable. Nothing was opened — try again shortly."
      : "This invitation could not be verified. Ask the sender for a fresh invitation.";
    renderRecipientInvalid(root, detail);
  }
}

async function buildOpenKeyAuthorizationProof(input: {
  readonly challenge: import("@tinycloud/share-sdk").SharePolicyChallenge;
  readonly envelope: import("@tinycloud/share-envelope").ShareEnvelopeV2;
  readonly holderDid: string;
  readonly credential: string;
  readonly delegationCid: string;
  readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;
}): Promise<Record<string, unknown>> {
  const authority = input.envelope.ownerAuthority;
  if (authority === undefined) throw new Error("addressed-owner-authority-missing");
  const nativeAction = (action: string): string => action === "list" ? "tinycloud.kv/list" : action === "edit" ? "tinycloud.kv/put" : "tinycloud.kv/get";
  const actions = [...new Set(input.envelope.actions.map(nativeAction))].sort();
  const action = input.envelope.actions.includes("list") ? "tinycloud.kv/list" : input.envelope.actions.includes("edit") ? "tinycloud.kv/put" : "tinycloud.kv/get";
  const policyCid = input.envelope.authorizationTarget.kind === "policy" ? input.envelope.authorizationTarget.policyCid : "";
  if (input.credential.length === 0 || input.delegationCid.length === 0) throw new Error("openkey-session-delegation-missing");
  const credentialDigest = await digestText(input.credential);
  const enforcerDid = input.challenge.enforcerDid;
  if (enforcerDid === undefined) throw new Error("share-v2-challenge-enforcer-missing");
  const presentation = {
    type: "TinyCloudSharePolicyPresentation",
    version: 2,
    challengeId: input.challenge.challengeId,
    nonce: input.challenge.nonce,
    shareCid: authority.shareCid,
    shareId: input.envelope.shareId,
    delegationCid: input.envelope.delegationCid,
    policyCid,
    contentSource: input.envelope.contentSource,
    contentSourceDigest: input.envelope.contentSourceDigest,
    holderDid: input.holderDid,
    targetOrigin: input.envelope.target.origin,
    nodeAudience: input.envelope.target.nodeAudience,
    enforcerDid,
    credentialDigest,
    action,
    actions,
    resource: input.envelope.resource.path.replace(/\/$/, ""),
    requestBodyDigest: input.challenge.requestBodyDigest,
    issuedAt: new Date().toISOString(),
    expiresAt: input.challenge.expiresAt,
    jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const jti = presentation.jti;
  const signedBytes = new TextEncoder().encode(`${SHARE_V2_PROTOCOL.sessionDomain}${canonicalize(presentation)}`);
  const signature = toBase64Url(await input.sign(signedBytes));
  const presentationProof = { alg: "EdDSA", kid: `${input.holderDid}#${input.holderDid.slice("did:key:".length)}`, signature };
  const holderBinding = await createShareV2HolderBindingArtifact({
    holderDid: input.holderDid,
    sign: input.sign,
    message: {
      type: SHARE_V2_PROTOCOL.holderBindingType,
      version: SHARE_V2_PROTOCOL.holderBindingVersion,
      holderDid: input.holderDid,
      challengeId: input.challenge.challengeId,
      challengeNonce: input.challenge.nonce,
      shareId: input.envelope.shareId,
      policyCid,
      credentialDigest,
      delegationCid: input.delegationCid,
      targetOrigin: input.envelope.target.origin,
      nodeAudience: input.envelope.target.nodeAudience,
      enforcerDid,
      expiresAt: input.challenge.expiresAt,
      jti,
    },
  });
  return { presentation, presentationProof, proof: presentationProof, nonce: input.challenge.nonce, credential: input.credential, holderDid: input.holderDid, holderBinding, sign: input.sign };
}

async function buildV2Presentation(input: { readonly challenge: import("@tinycloud/share-sdk").SharePolicyChallenge; readonly envelope: import("@tinycloud/share-envelope").ShareEnvelopeV2; readonly policy: Record<string, unknown>; readonly invite: { readonly invitationId: string; readonly claimSecret: string }; readonly shareCid: string; readonly publicConfig: Awaited<ReturnType<typeof import("./email-share/config.js").loadSharePublicConfig>>; readonly holder: import("./email-share/claim.js").HolderKey }): Promise<import("@tinycloud/share-sdk").SharePresentationMaterial> {
  const ownerOuter = input.envelope.ownerAuthority?.outerEnvelope as Record<string, unknown> | undefined;
  const outerSource = ownerOuter?.contentSource as Record<string, unknown> | undefined;
  const source = (outerSource === undefined ? input.policy.contentSource : { ...outerSource, action: input.challenge.action }) as ContentSource;
  const recipientEmail = input.envelope.deliveryEmail ?? "";
  if (source.kind !== "kv" && source.kind !== "sql") throw new Error("We couldn't read this share. Ask the sender for a fresh link.");
  const [{ issueEmailClaimCredential }, { createHttpTransport }, { credentialTrustFromConfig }] = await Promise.all([
    import("./email-share/claim.js"), import("./email-share/transport.js"), import("./email-share/config.js"),
  ]);
  const transport = createHttpTransport({ nodeOrigin: input.publicConfig.nodeOrigin, credentialsOrigin: input.publicConfig.credentialsOrigin });
  const claimShare = {
    shareId: input.envelope.shareId, shareCid: input.envelope.ownerAuthority?.shareCid ?? input.shareCid, policyCid: input.envelope.authorizationTarget.kind === "policy" ? input.envelope.authorizationTarget.policyCid : "", recipientEmail, recipientMatcher: input.policy.recipientMatcher as import("@tinycloud/share-envelope").RecipientMatcher, recipientHint: recipientEmail === "" ? "verified domain mailbox" : `${recipientEmail.slice(0, 1)}***@${recipientEmail.split("@").at(-1) ?? ""}`, expiry: input.envelope.expiry, nodeOrigin: input.envelope.target.origin, nodeAudience: input.envelope.target.nodeAudience, requestOrigin: input.publicConfig.shareOrigin, delegationCid: input.envelope.delegationCid, authorityMaterialHandle: input.envelope.authorityMaterialHandle, authorityMaterialDigest: input.envelope.authorityMaterialDigest, contentSource: source, contentSourceDigest: ownerOuter?.contentSourceDigest as string ?? input.envelope.contentSourceDigest, action: source.action, resource: source.path, trustedNode: { targetOrigin: input.publicConfig.nodeOrigin, nodeAudience: input.publicConfig.nodeAudience, invitationKid: input.publicConfig.nodeInvitationKid, invitationPublicKey: fromBase64Url(input.publicConfig.nodeInvitationPublicKey), keyVersion: input.publicConfig.nodeKeyVersion, enabled: input.publicConfig.nodeEnabled },
  } as VerifiedExactEmailShare;
  const claim = await issueEmailClaimCredential({ share: claimShare, invitationId: input.invite.invitationId, mailboxProof: input.invite.claimSecret, method: "magic", holder: input.holder, transport, credentialTrust: credentialTrustFromConfig(input.publicConfig) });
  const credentialDigest = await digestText(claim.credential);
  const claimantEmail = claim.email;
  const holderBinding = { type: "TinyCloudEmailClaimHolderBinding", version: 1, redemptionId: input.envelope.shareId, invitationId: input.shareCid, claimNonce: input.challenge.nonce, challengeNonce: input.challenge.nonce, shareCid: input.envelope.ownerAuthority?.shareCid ?? input.shareCid, shareId: input.envelope.shareId, policyCid: claimShare.policyCid, contentSource: source, contentSourceDigest: ownerOuter?.contentSourceDigest as string ?? input.envelope.contentSourceDigest, emailHash: await digestText(claimantEmail), holderDid: input.holder.did, credentialDigest, targetOrigin: input.envelope.target.origin, nodeAudience: input.envelope.target.nodeAudience, audience: input.envelope.target.nodeAudience, enforcerDid: input.challenge.enforcerDid, requestOrigin: input.envelope.target.origin, challengeId: input.challenge.challengeId, challengeRequestDigest: input.challenge.requestBodyDigest, issuedAt: new Date().toISOString(), expiresAt: input.challenge.expiresAt, jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))) };
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", input.holder.privateKey, new TextEncoder().encode(`${SIGNATURE_DOMAINS.holderBinding}${canonicalize(holderBinding)}`)));
  const holderJcs = canonicalize(holderBinding);
  const holderSignedBytes = new TextEncoder().encode(`${SIGNATURE_DOMAINS.holderBinding}${holderJcs}`);
  return { holderDid: input.holder.did, credential: claim.credential, credentialDigest, holderBinding: { name: "holderBinding", domain: SIGNATURE_DOMAINS.holderBinding, signerDid: input.holder.did, message: holderBinding, jcs: holderJcs, messageDigest: await digestText(holderJcs), signedBytesDigest: await digestBytes(holderSignedBytes), signatureDigest: await digestBytes(signature), signature: { alg: "EdDSA", kid: `${input.holder.did}#${input.holder.did.slice("did:key:".length)}`, value: toBase64Url(signature) } }, proof: { alg: "EdDSA", kid: `${input.holder.did}#${input.holder.did.slice("did:key:".length)}`, signature: toBase64Url(signature) }, sign: async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", input.holder.privateKey, bytes as unknown as BufferSource)), email: claimantEmail };
}
