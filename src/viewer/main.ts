/** The viewer entry point. It captures and scrubs the launch fragment before
 * any network operation, then routes verified v1 claims through the existing
 * credential flow. v2 addressed links use the same claim/runtime boundary;
 * they never fall back to bearer rendering. */
import "./viewer.css";

import { REGISTRY_BASE_URL } from "./config.js";
import { presentShare } from "./present.js";
import { resolveShare } from "./resolve.js";
import { renderEmailClaimState, renderEmailClaimUnavailable, renderResolving } from "./ui.js";
import { accessSharedContent, type ClaimController } from "@tinycloud/share-sdk";
import { captureAndScrubLaunch, type CapturedLaunch } from "../email-share/url.js";
import { type ClaimState, type CredentialTrust } from "../email-share/claim.js";
import { assertTrustedNodeScope } from "../email-share/node-verifier.js";
import { assertProductionCredentialTrust, verifyProductionEmailShare } from "../email-share/runtime.js";
import { credentialTrustFromConfig, loadSharePublicBinding, loadSharePublicConfig, trustedNodeFromConfig } from "../email-share/config.js";
import { createHttpTransport, type ShareTransport } from "../email-share/transport.js";

export interface EmailClaimRuntime {
  readonly transport: ShareTransport;
  readonly credentialTrust: CredentialTrust;
  readonly verify: (input: { readonly envelope: import("@tinycloud/share-envelope").ShareEnvelope; readonly shareCid: string; readonly policy: Record<string, unknown> }) => Promise<import("../email-share/verified-share.js").VerifiedExactEmailShare>;
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
  const button = document.createElement("button"); button.type = "button"; button.className = "viewer-secondary-action viewer-forget-key"; button.dataset.forgetKey = "true"; button.textContent = "Forget this browser key"; button.addEventListener("click", onForget, { once: true }); footer.append(button);
}

function assertRuntimeShareBinding(result: Extract<Awaited<ReturnType<typeof resolveShare>>, { state: "policy-email-claim-required" }>, share: import("../email-share/verified-share.js").VerifiedExactEmailShare): void {
  const target = result.envelope.authorizationTarget;
  if (target.kind !== "policy" || share.shareCid !== result.shareCid || share.shareId !== result.envelope.shareId || share.policyCid !== target.policyCid || share.nodeOrigin !== result.envelope.target.origin || share.nodeAudience !== result.envelope.target.nodeAudience || share.expiry !== result.envelope.expiry || result.policy.recipientEmail !== share.recipientEmail || result.policy.expiresAt !== share.expiry || result.policy.contentSourceDigest !== share.contentSourceDigest) throw new Error("runtime-share-binding-invalid");
}

function mountExactClaim(root: HTMLElement, result: Extract<Awaited<ReturnType<typeof resolveShare>>, { state: "policy-email-claim-required" }>, launch: CapturedLaunch, runtime: EmailClaimRuntime): void {
  if (launch.invite === undefined) { renderEmailClaimUnavailable(root); return; }
  let controller: ClaimController | undefined;
  let confirmed = false;
  let confirmOpen = (): void => {};
  const confirmation = new Promise<boolean>((resolve) => {
    confirmOpen = (): void => { if (!confirmed) { confirmed = true; resolve(true); } };
  });
  void runtime.verify({ envelope: result.envelope, shareCid: result.shareCid, policy: result.policy }).then((share) => {
    assertRuntimeShareBinding(result, share); assertTrustedNodeScope(share, share.trustedNode);
    const render = (state: ClaimState): void => renderEmailClaimState(root, state, { onOpen: confirmOpen, onRetry: () => { void controller?.retry(); }, onUseOtp: () => controller?.useOtp(), onOtp: (code) => { void controller?.submitOtp(code); }, onResend: () => { void controller?.resend(); }, onForget: () => controller?.forget() });
    render({ state: "ready", emailHint: share.recipientHint });
    void accessSharedContent({ shareUrl: `${launch.shareHref}&i=${launch.invite!.invitationId}&c=${launch.invite!.claimSecret}`, invitation: launch.invite!, confirmAccess: () => confirmation, dependencies: { registryBaseUrl: REGISTRY_BASE_URL, transport: runtime.transport, credentialTrust: runtime.credentialTrust, resolve: async () => result, verifyShare: async () => share, scrub: () => {}, onController: (next) => { controller = next; render(next.state); next.subscribe(render); } } }).then((access) => void presentShare(root, { state: "ok", access: "policy", envelope: result.envelope, senderVerified: true, content: access.content })).catch(() => undefined);
  }).catch(() => renderEmailClaimUnavailable(root));
}

export async function bootDefault(launch: CapturedLaunch | undefined): Promise<void> {
  const root = document.getElementById("viewer"); if (root === null) throw new Error("viewer root element missing");
  if (launch === undefined) { renderResolving(root); root.textContent = "This invitation link is incomplete. Ask the sender to resend it."; return; }
  const href = launch.shareHref; const invite = launch.invite; launch.shareHref = ""; delete launch.invite; renderResolving(root);
  const result = await resolveShare(href, { registryBaseUrl: REGISTRY_BASE_URL });
  if (result.state !== "policy-email-claim-required") { await presentShare(root, result); return; }
  try { const runtime = await configuredRuntime(); mountExactClaim(root, result, { shareHref: href, ...(invite === undefined ? {} : { invite }) }, runtime); } catch { renderEmailClaimUnavailable(root); }
}

export function captureViewerLaunch(): CapturedLaunch | undefined { return captureAndScrubLaunch(window.location, window.history); }
