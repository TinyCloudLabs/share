/**
 * Viewer entry (viewer.html), active on /s/<cid>#k=… routes.
 *
 * Key hygiene: the fragment key is captured into a local string ONCE, then
 * immediately scrubbed out of location.hash and the current history entry
 * (scrubKeyFragment) BEFORE anything is fetched or rendered — so a later
 * same-origin XSS cannot read the key back out of the URL bar or history.
 * resolveShare consumes the parsed key in memory and zeroes it on every
 * return path. Nothing here logs, stores, or transmits the fragment.
 */
import "./viewer.css";

import { canonicalize } from "@tinycloud/share-envelope";
import { REGISTRY_BASE_URL } from "./config.js";
import { presentShare } from "./present.js";
import { resolveShare } from "./resolve.js";
import { renderEmailClaimState, renderEmailClaimUnavailable, renderResolving } from "./ui.js";
import { hrefForParse, scrubKeyFragment } from "./url.js";

import type { CapturedLaunch } from "../email-share/url.js";
import { createClaimController, type ClaimState, type CredentialTrust } from "../email-share/claim.js";
import type { ShareTransport } from "../email-share/transport.js";
import type { VerifiedExactEmailShare } from "../email-share/verified-share.js";
import { assertTrustedNodeScope } from "../email-share/node-verifier.js";
import { assertProductionCredentialTrust, verifyProductionEmailShare } from "../email-share/runtime.js";
import { credentialTrustFromConfig, loadSharePublicBinding, loadSharePublicConfig, trustedNodeFromConfig } from "../email-share/config.js";
import { createHttpTransport } from "../email-share/transport.js";

async function boot(): Promise<void> {
  const root = document.getElementById("viewer");
  if (root === null) throw new Error("viewer root element missing");
  // Capture the href (the only read of the fragment), then scrub the key
  // from the address bar + history BEFORE any network or render work. The
  // loopback http→https rewrite inside hrefForParse is dev-build-only.
  const href = hrefForParse(window.location, import.meta.env.DEV);
  scrubKeyFragment(window.location, window.history);
  renderResolving(root);
  const result = await resolveShare(href, {
    registryBaseUrl: REGISTRY_BASE_URL,
  });
  await presentShare(root, result);
}

export interface EmailClaimRuntime {
  readonly transport: ShareTransport;
  readonly credentialTrust: CredentialTrust;
  readonly verify: (input: { readonly envelope: import("@tinycloud/share-envelope").ShareEnvelope; readonly shareCid: string; readonly policy: Record<string, unknown> }) => Promise<VerifiedExactEmailShare>;
}

async function configuredRuntime(): Promise<EmailClaimRuntime> {
  const config = await loadSharePublicConfig();
  const credentialTrust = credentialTrustFromConfig(config);
  assertProductionCredentialTrust(credentialTrust);
  const trustedNode = trustedNodeFromConfig(config);
  const transport = createHttpTransport({ nodeOrigin: config.nodeOrigin, credentialsOrigin: config.credentialsOrigin });
  return {
    transport,
    credentialTrust,
    verify: async ({ envelope, shareCid, policy }) => {
      const binding = await loadSharePublicBinding(shareCid);
      return { ...(await verifyProductionEmailShare({ envelope, shareCid, policy, config, binding })), trustedNode };
    },
  };
}

function appendPersistentForgetAction(root: HTMLElement, onForget: () => void): void {
  root.querySelector("[data-forget-key]")?.remove();
  const footer = root.querySelector(".viewer-footer") ?? root;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "viewer-secondary-action viewer-forget-key";
  button.dataset.forgetKey = "true";
  button.textContent = "Forget this browser key";
  button.setAttribute("aria-label", "Forget the private browser key for this share");
  button.addEventListener("click", onForget, { once: true });
  footer.append(button);
}

export async function bootDefault(launch: CapturedLaunch | undefined, runtime?: EmailClaimRuntime): Promise<void> {
  const root = document.getElementById("viewer");
  if (root === null) throw new Error("viewer root element missing");
  if (launch === undefined) {
    renderResolving(root);
    root.textContent = "This invitation link is incomplete. Ask the sender to resend it.";
    return;
  }
  const result = await resolveShare(launch.shareHref, { registryBaseUrl: REGISTRY_BASE_URL });
  if (result.state !== "policy-email-claim-required" || launch.invite === undefined) {
    await presentShare(root, result);
    return;
  }
  let configured: EmailClaimRuntime;
  try { configured = runtime ?? await configuredRuntime(); } catch { renderEmailClaimUnavailable(root); return; }
  try {
    assertProductionCredentialTrust(configured.credentialTrust);
    const share = await configured.verify({ envelope: result.envelope, shareCid: result.shareCid, policy: result.policy });
    if (result.envelope.authorizationTarget.kind !== "policy" || share.shareCid !== result.shareCid || share.shareId !== result.envelope.shareId || share.policyCid !== result.envelope.authorizationTarget.policyCid || share.nodeOrigin !== result.envelope.target.origin || share.nodeAudience !== result.envelope.target.nodeAudience || share.expiry !== result.envelope.expiry || result.policy.recipientEmail !== share.recipientEmail || result.policy.expiresAt !== share.expiry || result.policy.action !== share.action || result.policy.resource !== share.resource || result.policy.contentSourceDigest !== share.contentSourceDigest || canonicalize(result.policy.contentSource) !== canonicalize(share.contentSource)) throw new Error("runtime-share-binding-invalid");
    assertTrustedNodeScope(share, share.trustedNode);
    const controller = createClaimController({ share, invitationId: launch.invite.invitationId, claimSecret: launch.invite.claimSecret, transport: configured.transport, credentialTrust: configured.credentialTrust });
    const render = (state: ClaimState): void => renderEmailClaimState(root, state, {
      onOpen: () => { void controller.openDocument(); },
      onRetry: () => { void controller.retry(); },
      onUseOtp: () => controller.useOtp(),
      onOtp: (code) => { void controller.submitOtp(code); },
      onResend: () => { void controller.resend(); },
      onForget: () => controller.forget(),
    });
    controller.subscribe(render);
    render(controller.state);
    controller.subscribe((state) => {
      if (state.state === "claimed") void controller.read().then((content) => { if (content !== undefined) void presentShare(root, { state: "ok", access: "policy", envelope: result.envelope, senderVerified: true, content }).then(() => appendPersistentForgetAction(root, () => controller.forget())); });
    });
  } catch { renderEmailClaimUnavailable(root); }
}
