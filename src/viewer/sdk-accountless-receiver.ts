import { TinyCloudWeb } from "@tinycloud/web-sdk";
import { fromBase64Url } from "@tinycloud/share-envelope";
import type { SharePublicConfig } from "../email-share/config.js";

/**
 * The Share app owns presentation, while the web SDK owns the receiver
 * ceremony.  Keeping that seam here prevents the viewer from reimplementing
 * credential custody, policy admission, delegation import, or invocation.
 */
export async function receiveWithSdk(input: {
  readonly root: HTMLElement;
  readonly shareUrl: string;
  readonly registryBaseUrl: string;
  readonly config: SharePublicConfig;
  readonly onComplete: (content: { readonly bytes: Uint8Array }) => Promise<void>;
}): Promise<void> {
  const mountTarget = document.createElement("div");
  mountTarget.className = "viewer-credential-acquisition";
  input.root.replaceChildren(mountTarget);

  const tinycloud = new TinyCloudWeb({
    shareReceiver: {
      origin: window.location.origin,
      expectedShareOrigin: input.config.shareOrigin,
      registryBaseUrl: input.registryBaseUrl,
      trustedNode: {
        invitationKid: input.config.nodeInvitationKid,
        invitationPublicKey: fromBase64Url(input.config.nodeInvitationPublicKey),
      },
      expectedEnforcerDid: input.config.enforcerDid,
    },
  });
  const received = await tinycloud.share.receive(input.shareUrl, {
    identity: "auto",
    interaction: { kind: "inline", mountTarget },
  });
  await input.onComplete(await received.get());
}
