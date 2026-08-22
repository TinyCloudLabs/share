import { captureAndScrubLaunch, type CapturedLaunch } from "./email-share/url.js";
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
  const { renderRecipientInvalid, renderRecipientLoading } = await import("./email-share/view.js");
  renderRecipientLoading(root);
  if (launch === undefined) {
    renderRecipientInvalid(root, "Part of this link is missing. Copy the complete link from the message you received and paste it into a new tab.");
    return;
  }

  try {
    const [config, { presentShare }] = await Promise.all([
      import("./email-share/config.js"),
      import("./viewer/present.js"),
    ]);
    const shareHref = launch.shareHref;
    launch.shareHref = "";
    const shareConfig = await config.loadSharePublicConfig();
    if (new URL(shareHref).pathname === "/viewer" && new URL(shareHref).search === "" && new URL(shareHref).hash.startsWith("#tc1=")) {
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
      }, { shareUrl: shareHref });
      return;
    }
    const addressedUrl = new URL(shareHref);
    if (addressedUrl.pathname !== "/viewer" || addressedUrl.hash !== "" || addressedUrl.searchParams.size !== 1 || addressedUrl.searchParams.get("tc2") === null || addressedUrl.search !== `?tc2=${addressedUrl.searchParams.get("tc2")}`) {
      throw new Error("unsupported pre-native share link");
    }
    const { resolveShare } = await import("./viewer/resolve.js");
    const resolved: ResolveResult = await resolveShare(shareHref, { expectedOrigin: shareConfig.shareOrigin });
    // Accountless receive is an SDK contract.  Share hosts only its inline UI
    // and renders the locally decrypted result; the SDK performs embedded Node
    // policy admission followed by generic /delegate and /invoke.
    if (shareConfig.accountlessReceiverEnabled === true && resolved.state === "policy-authorization-required") {
      const { receiveWithSdk } = await import("./viewer/sdk-accountless-receiver.js");
      const accountlessEnvelope = resolved.envelope;
      await receiveWithSdk({
        root,
        shareUrl: shareHref,
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
    await presentShare(root, resolved, { shareUrl: shareHref });
  } catch (error) {
    console.debug("tinycloud share: recipient request failed", error instanceof Error ? error.message : error);
    const detail = error instanceof Error && /unavailable|capability|config|binding/.test(error.message)
      ? "TinyCloud is temporarily unavailable. Nothing was opened — try again shortly."
      : "This invitation could not be verified. Ask the sender for a fresh invitation.";
    renderRecipientInvalid(root, detail);
  }
}
