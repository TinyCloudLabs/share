import { captureAndScrubLaunch, type CapturedLaunch } from "./email-share/url.js";
import { purgeLegacyReceiverStorage } from "./email-share/receiver-storage.js";
import type { ResolveResult } from "./viewer/resolve.js";

// viewer.html is the ONLY page that loads this module, and it always declares
// <div id="viewer">. There is no non-viewer branch here on purpose: the
// recipient route must do no decorative work before its URL secret is scrubbed.
const viewerRoot = document.getElementById("viewer");

async function loadViewerStyles(): Promise<void> {
  const documentElement = document.documentElement;
  await Promise.all([
    import("./email-share/recipient.css"),
    import("./viewer/viewer.css"),
  ]);
  documentElement.classList.remove("viewer-first-paint");
}

if (viewerRoot !== null) {
  // This is intentionally the first recipient-side operation. The complete
  // fragment is captured and the current history entry is scrubbed before
  // any dynamic import, hydration, configuration load, or network request.
  const captured = captureAndScrubLaunch(window.location, window.history);
  // Drop a receiver key record an earlier build left in this tab before anything else can read it.
  purgeLegacyReceiverStorage();
  if (captured !== undefined && import.meta.env.VITE_SHARE_VIEWER_HERMETIC === "true" && window.location.hostname === "127.0.0.1") {
    const capturedUrl = new URL(captured.shareHref);
    captured.shareHref = `https://share.tinycloud.xyz${capturedUrl.pathname}${capturedUrl.search}${capturedUrl.hash}`;
  }
  void loadViewerStyles();
  void bootRecipient(viewerRoot, captured);
}

async function bootRecipient(root: HTMLElement, launch: CapturedLaunch | undefined): Promise<void> {
  const { renderRecipientInvalid, renderRecipientLoading } = await import("./email-share/view.js");
  renderRecipientLoading(root);
  if (launch === undefined) {
    const { renderLinkNeeded } = await import("./viewer/ui.js");
    renderLinkNeeded(root);
    return;
  }

  // The launch URL is scrubbed from the address bar and kept in memory only, so
  // "Try again" must re-run the receive from this copy rather than reload the page.
  let retryHref: string | undefined;
  try {
    const [config, { presentShare }, { createSaveToTinyCloud }] = await Promise.all([
      import("./email-share/config.js"),
      import("./viewer/present.js"),
      import("./viewer/save-copy.js"),
    ]);
    const shareHref = launch.shareHref;
    launch.shareHref = "";
    retryHref = shareHref;
    const shareConfig = await config.loadSharePublicConfig();
    // Only builds the function Save calls. OpenKey and the account SDK load on that click, never before.
    const saveToTinyCloud = createSaveToTinyCloud(shareConfig);
    if (launch.kind === "bearer") {
      const { receiveNativeBearerAccess } = await import("./viewer/native-bearer.js");
      // The fragment was already captured and scrubbed before config or this
      // SDK construction. Receiving the capability is the first network work.
      const access = await receiveNativeBearerAccess(shareHref);
      const { presentationEnvelope } = await import("./viewer/resolve.js");
      await presentShare(root, {
        state: "ok",
        access: "bearer",
        senderVerified: false,
        contentBytes: access.bytes,
        envelope: presentationEnvelope({
          protocol: "tinycloud-share",
          version: 1,
          shareId: access.path,
          origin: shareConfig.shareOrigin,
          target: { kind: "bearer", origin: access.ownerNodeOrigin, nodeAudience: "", spaceId: access.spaceId },
          resource: { kind: "exact", path: access.path },
          actions: ["tinycloud.kv/get"],
          display: access.path.split("/").at(-1) === undefined ? {} : { filename: access.path.split("/").at(-1)! },
          expiresAt: access.expiresAt,
        }),
      }, { shareUrl: shareHref, saveToTinyCloud });
      return;
    }
    const { resolveShare } = await import("./viewer/resolve.js");
    const resolved: ResolveResult = await resolveShare(shareHref, { expectedOrigin: shareConfig.shareOrigin });
    // Accountless receive is an SDK contract.  Share hosts only its inline UI
    // and renders the locally decrypted result; the SDK performs embedded Node
    // policy admission followed by generic /delegate and /invoke.
    if (shareConfig.accountlessReceiverEnabled === true && resolved.state === "policy-authorization-required") {
      const { receiveWithSdk } = await import("./viewer/sdk-accountless-receiver.js");
      const { availabilityTarget } = await import("./email-share/share-status.js");
      const accountlessEnvelope = resolved.envelope;
      await receiveWithSdk({
        root,
        shareUrl: shareHref,
        config: shareConfig,
        availability: availabilityTarget(accountlessEnvelope),
        invitation: {
          ...(accountlessEnvelope.display.filename === undefined ? {} : { filename: accountlessEnvelope.display.filename }),
          expiresAt: accountlessEnvelope.expiry,
          actions: accountlessEnvelope.actions,
        },
        onComplete: async (content) => {
          await presentShare(root, {
            state: "ok",
            access: "policy",
            envelope: accountlessEnvelope,
            senderVerified: true,
            contentBytes: content.bytes,
          }, { shareUrl: shareHref, saveToTinyCloud });
        },
      });
      return;
    }
    await presentShare(root, resolved, { shareUrl: shareHref, saveToTinyCloud });
  } catch (error) {
    console.debug("tinycloud share: recipient request failed");
    // Bearer links fail with a typed reason; revoked, expired and unavailable
    // each get their own screen, and nothing from the share is ever shown.
    const href = retryHref;
    const retry = href === undefined ? undefined : (): void => { void bootRecipient(root, { ...launch, shareHref: href }); };
    const { NativeBearerError } = await import("./viewer/native-bearer.js");
    if (error instanceof NativeBearerError && error.reason !== "unverified") {
      const { renderShareUnavailable } = await import("./viewer/ui.js");
      renderShareUnavailable(root, error.reason, error.expiresAt, retry);
      return;
    }
    if (error instanceof Error && error.name === "ShareReceiverKeyUnavailableError") {
      renderRecipientInvalid(root, "This browser can’t create the private key needed to open this file. Nothing was opened. Open the link in a current version of Chrome, Edge, Firefox or Safari.");
      return;
    }
    if (error instanceof Error && error.name === "ShareReceiverSessionEndedError") {
      renderRecipientInvalid(root, "Your verification on this page has ended. Open the link from your email again and verify again.");
      return;
    }
    if (error instanceof Error && /unavailable|capability|config|binding/.test(error.message)) {
      const { renderShareUnavailable } = await import("./viewer/ui.js");
      renderShareUnavailable(root, "unavailable", undefined, retry);
      return;
    }
    renderRecipientInvalid(root, "This invitation could not be verified. Ask the sender for a fresh invitation.");
  }
}
