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

import { REGISTRY_BASE_URL } from "./config.js";
import { presentShare } from "./present.js";
import { resolveShare } from "./resolve.js";
import { renderEmailClaimState, renderEmailClaimUnavailable, renderResolving } from "./ui.js";
import { hrefForParse, scrubKeyFragment } from "./url.js";

import type { CapturedLaunch } from "../email-share/url.js";
import { createClaimController, type ClaimState } from "../email-share/claim.js";
import { readClaimedShare } from "../email-share/node-client.js";
import type { ShareTransport } from "../email-share/transport.js";
import type { VerifiedExactEmailShare } from "../email-share/verified-share.js";

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
  readonly verify: (input: { readonly envelope: import("@tinycloud/share-envelope").ShareEnvelope; readonly shareCid: string; readonly policy: Record<string, unknown> }) => Promise<VerifiedExactEmailShare>;
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
  if (runtime === undefined) {
    renderEmailClaimUnavailable(root);
    return;
  }
  try {
    const share = await runtime.verify({ envelope: result.envelope, shareCid: result.shareCid, policy: result.policy });
    const controller = createClaimController({ share, invitationId: launch.invite.invitationId, claimSecret: launch.invite.claimSecret, transport: runtime.transport });
    const render = (state: ClaimState): void => renderEmailClaimState(root, state, {
      onOpen: () => { void controller.openDocument(); },
      onOtp: (code) => { void controller.submitOtp(code); },
      onResend: () => { void controller.resend(); },
      onForget: () => controller.forget(),
    });
    controller.subscribe(render);
    render(controller.state);
    controller.subscribe((state) => {
      if (state.state === "claimed") void readClaimedShare({ share, claim: state.claim, transport: runtime.transport }).then((content) => presentShare(root, { state: "ok", access: "policy", envelope: result.envelope, senderVerified: true, content })).catch(() => renderEmailClaimState(root, { state: "error", code: "node-unavailable", retryable: true }, { onOpen: () => { void controller.openDocument(); }, onOtp: () => {}, onResend: () => {}, onForget: () => controller.forget() }));
    });
  } catch { renderEmailClaimUnavailable(root); }
}
