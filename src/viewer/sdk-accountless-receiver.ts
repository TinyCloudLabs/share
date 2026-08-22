import type { SharePublicConfig } from "../email-share/config.js";
import { createShareReceiverClient } from "../share/receiver.js";

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

  const tinycloud = await createShareReceiverClient(input.config, input.registryBaseUrl);
  const received = await tinycloud.share.receive(input.shareUrl, {
    identity: "auto",
    interaction: { kind: "inline", mountTarget },
  });
  await input.onComplete(await received.get());
}
