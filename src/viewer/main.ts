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

import { ALLOWED_NODE_ORIGINS, REGISTRY_BASE_URL } from "./config.js";
import { presentShare } from "./present.js";
import {
  continueRecipientDidResolution,
  resolveShare,
  type ResolveResult,
} from "./resolve.js";
import { renderRecipientIdentityLoading, renderResolving } from "./ui.js";
import type {
  RecipientDidViewerAdapter,
  VerifiedRecipientDidContinuation,
} from "./recipient-did.js";
import { RECIPIENT_DID_VIEWER_ADAPTER } from "./sdk-adapter.js";
import { hrefForParse, scrubKeyFragment } from "./url.js";

export interface ViewerRuntime {
  /** Injected by the SDK integration lane; omitted builds fail closed. */
  recipientDidAdapter?: RecipientDidViewerAdapter;
}

/** Capture once, scrub synchronously, and return without retaining the href. */
function takeShareHref(): string {
  const href = hrefForParse(window.location, import.meta.env.DEV);
  scrubKeyFragment(window.location, window.history);
  return href;
}

async function resolveInitialShare(
  root: HTMLElement,
  runtime: ViewerRuntime,
): Promise<ResolveResult> {
  // The key-bearing href is captured/scrubbed by a synchronous helper, then
  // owned only by resolveShare's isolated decrypt stage. Account retries use
  // only the opaque verified continuation.
  renderResolving(root);
  return resolveShare(takeShareHref(), {
    registryBaseUrl: REGISTRY_BASE_URL,
    allowedNodeOrigins: ALLOWED_NODE_ORIGINS,
    recipientAccountMode: "active",
    ...(runtime.recipientDidAdapter !== undefined
      ? { recipientDidAdapter: runtime.recipientDidAdapter }
      : {}),
  });
}

function continuationOf(
  result: ResolveResult,
): VerifiedRecipientDidContinuation | undefined {
  switch (result.state) {
    case "recipient-identity-required":
    case "recipient-wrong-account":
    case "recipient-identity-cancelled":
      return result.continuation;
    default:
      return undefined;
  }
}

export async function boot(runtime: ViewerRuntime = {}): Promise<void> {
  const root = document.getElementById("viewer");
  if (root === null) throw new Error("viewer root element missing");
  const adapter = runtime.recipientDidAdapter;
  const presentResult = async (result: ResolveResult): Promise<void> => {
    const continuation = continuationOf(result);
    await presentShare(root, result, {}, {
      ...(continuation !== undefined && adapter !== undefined
        ? {
            onSelectRecipientAccount: () => {
              renderRecipientIdentityLoading(root);
              void continueRecipientDidResolution(continuation, {
                adapter,
                accountMode: "connect",
              })
                .then(presentResult)
                .catch(() =>
                  presentResult({
                    state: "recipient-node-unavailable",
                    envelope: continuation.envelope,
                  }),
                );
            },
          }
        : {}),
    });
  };
  await presentResult(await resolveInitialShare(root, runtime));
}

void boot({
  ...(RECIPIENT_DID_VIEWER_ADAPTER !== undefined
    ? { recipientDidAdapter: RECIPIENT_DID_VIEWER_ADAPTER }
    : {}),
});
