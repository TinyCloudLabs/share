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
import { accessSharedContent, type ClaimController } from "@tinycloud/share-sdk";

import type { CapturedLaunch } from "../email-share/url.js";
import { type ClaimState, type CredentialTrust } from "../email-share/claim.js";
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
      let binding;
      try { binding = await loadSharePublicBinding(shareCid); } catch (error) { console.error(`email-claim stage=binding-load:${error instanceof Error ? error.message : "invalid"}`); throw new Error("binding-unavailable"); }
      try { return { ...(await verifyProductionEmailShare({ envelope, shareCid, policy, config, binding })), trustedNode }; } catch { console.error("email-claim stage=share-verify"); throw new Error("share-verification-failed"); }
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

function assertRuntimeShareBinding(result: Extract<Awaited<ReturnType<typeof resolveShare>>, { state: "policy-email-claim-required" }>, share: VerifiedExactEmailShare): void {
  const policyTarget = result.envelope.authorizationTarget;
  if (policyTarget.kind !== "policy") throw new Error("runtime-share-binding-invalid:target-kind");
  const checks: readonly [string, boolean][] = [
    ["target-kind", true],
    ["share-cid", share.shareCid === result.shareCid],
    ["share-id", share.shareId === result.envelope.shareId],
    ["policy-cid", share.policyCid === policyTarget.policyCid],
    ["node-origin", share.nodeOrigin === result.envelope.target.origin],
    ["node-audience", share.nodeAudience === result.envelope.target.nodeAudience],
    ["expiry", share.expiry === result.envelope.expiry],
    ["recipient", result.policy.recipientEmail === share.recipientEmail],
    ["policy-expiry", result.policy.expiresAt === share.expiry],
    ["action", result.policy.action === share.action],
    ["resource", result.policy.resource === share.resource],
    ["source-digest", result.policy.contentSourceDigest === share.contentSourceDigest],
    ["source", canonicalize(result.policy.contentSource) === canonicalize(share.contentSource)],
  ];
  const failed = checks.find(([, passed]) => !passed)?.[0];
  if (failed !== undefined) throw new Error(`runtime-share-binding-invalid:${failed}`);
}

export async function bootDefault(launch: CapturedLaunch | undefined): Promise<void> {
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
  try { configured = await configuredRuntime(); } catch { console.error("email-claim stage=runtime-config"); console.error("email-claim stage=unavailable"); renderEmailClaimUnavailable(root); return; }
  try {
    assertProductionCredentialTrust(configured.credentialTrust);
    const share = await configured.verify({ envelope: result.envelope, shareCid: result.shareCid, policy: result.policy });
    assertRuntimeShareBinding(result, share);
    assertTrustedNodeScope(share, share.trustedNode);
    let controller: ClaimController | undefined;
    let confirmOpen: (() => void) | undefined;
    let confirmed = false;
    const confirmation = new Promise<boolean>((resolve) => { confirmOpen = () => { if (!confirmed) { confirmed = true; resolve(true); } }; });
    let rendered = false;
    const showContent = (content: string): void => {
      if (rendered) return;
      rendered = true;
      void presentShare(root, { state: "ok", access: "policy", envelope: result.envelope, senderVerified: true, content }).then(() => appendPersistentForgetAction(root, () => controller?.forget()));
    };
    const render = (state: ClaimState): void => renderEmailClaimState(root, state, {
      onOpen: () => { confirmOpen?.(); },
      onRetry: () => { void controller?.retry(); },
      onUseOtp: () => controller?.useOtp(),
      onOtp: (code) => { void controller?.submitOtp(code); },
      onResend: () => { void controller?.resend(); },
      onForget: () => controller?.forget(),
    });
    render({ state: "ready", emailHint: share.recipientHint });
    void accessSharedContent({
      shareUrl: `${launch.shareHref}&i=${launch.invite.invitationId}&c=${launch.invite.claimSecret}`,
      invitation: launch.invite,
      confirmAccess: () => confirmation,
      dependencies: {
        registryBaseUrl: REGISTRY_BASE_URL,
        transport: configured.transport,
        credentialTrust: configured.credentialTrust,
        resolve: async () => result,
        verifyShare: async () => share,
        scrub: () => scrubKeyFragment(window.location, window.history),
        onController: (next) => {
          controller = next;
          render(next.state);
          next.subscribe(render);
        },
      },
    }).then((access) => showContent(access.content)).catch(() => undefined);
  } catch (error) { console.error("email-claim stage=runtime-verify"); if (error instanceof Error && error.message.startsWith("runtime-share-binding-invalid:")) console.error(`email-claim stage=${error.message}`); console.error("email-claim stage=unavailable"); renderEmailClaimUnavailable(root); }
}
