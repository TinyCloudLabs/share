import { captureAndScrubLaunch, type CapturedLaunch } from "./email-share/url.js";
import type { RecipientFacts, RecipientViewActions } from "./email-share/view.js";
import type { ClaimController, ClaimState } from "./email-share/claim.js";
import type { ResolveResult } from "./viewer/resolve.js";

const viewerRoot = document.getElementById("viewer");

if (viewerRoot !== null) {
  // This is intentionally the first recipient-side operation. The complete
  // fragment is captured and the current history entry is scrubbed before
  // any dynamic import, hydration, configuration load, or network request.
  const launch = captureAndScrubLaunch(window.location, window.history);
  void import("./email-share/recipient.css");
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
