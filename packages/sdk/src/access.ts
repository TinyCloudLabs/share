import {
  captureAndScrubLaunch,
  type CapturedLaunch,
} from "../../../src/email-share/url.js";
import {
  createClaimController,
  type ClaimController,
  type ClaimState,
  type CredentialTrust,
} from "../../../src/email-share/claim.js";
import type { ShareTransport } from "../../../src/email-share/transport.js";
import {
  resolveShare,
} from "../../../src/viewer/resolve.js";
import type { VerifiedExactEmailShare } from "../../../src/email-share/verified-share.js";
import type { ShareEnvelope } from "@tinycloud/share-envelope";

export interface ContentAccessResult {
  readonly content: string;
  readonly shareCid: string;
  readonly shareId: string;
  readonly holderDid: string;
}

export interface ContentAccessDependencies {
  /** Resolve the untrusted URL into a CID- and envelope-verified policy share. */
  readonly resolve?: typeof resolveShare;
  /** Re-check the policy CID, sender signature, target, and source bindings. */
  readonly verifyShare: (input: {
    readonly envelope: ShareEnvelope;
    readonly shareCid: string;
    readonly policy: Record<string, unknown>;
  }) => Promise<VerifiedExactEmailShare>;
  /** Pinned OpenCredentials issuer profile and public key. */
  readonly credentialTrust: CredentialTrust;
  /** Production OpenCredentials and Node policy/read transport. */
  readonly transport: ShareTransport;
  readonly registryBaseUrl: string;
  /** Injectable claim implementation; the default creates a non-extractable holder key. */
  readonly createController?: typeof createClaimController;
  readonly onController?: (controller: ClaimController) => void;
  /** Called synchronously while the complete URL fragment is being captured. */
  readonly scrub?: () => void;
}

function captureAccessLaunch(shareUrl: string, scrub: (() => void) | undefined): CapturedLaunch {
  let location: URL;
  try {
    location = new URL(shareUrl);
  } catch {
    throw new TypeError("The share URL is invalid.");
  }

  const launch = captureAndScrubLaunch(location as unknown as Location, {
    replaceState: () => scrub?.(),
  } as unknown as History);
  if (launch === undefined) {
    throw new TypeError("The share URL is not a complete exact-email invitation.");
  }
  return launch;
}

function accessStateError(state: ClaimState): Error {
  return new Error(`share-access-${state.state}`);
}

/**
 * Independently opens a pre-generated exact-email share.
 *
 * Fragment capture/scrubbing is synchronous. No claim or node operation runs
 * until the verified policy share has passed the caller's explicit
 * confirmation, so scanners that only perform GET/prefetch cannot redeem it.
 */
export async function accessSharedContent(input: {
  readonly shareUrl: string;
  readonly confirmAccess: () => boolean | Promise<boolean>;
  readonly invitation?: {
    readonly invitationId: string;
    readonly claimSecret: string;
  };
  readonly dependencies: ContentAccessDependencies;
}): Promise<ContentAccessResult> {
  const launch = captureAccessLaunch(input.shareUrl, input.dependencies.scrub);
  const invitation = input.invitation ?? launch.invite;
  if (invitation === undefined) {
    throw new TypeError("The invitation claim fragment is missing.");
  }
  if (
    launch.invite !== undefined &&
    (launch.invite.invitationId !== invitation.invitationId ||
      launch.invite.claimSecret !== invitation.claimSecret)
  ) {
    throw new TypeError("The invitation claim fragment was substituted.");
  }

  const resolve = input.dependencies.resolve ?? resolveShare;
  const resolved = await resolve(launch.shareHref, {
    registryBaseUrl: input.dependencies.registryBaseUrl,
  });
  if (resolved.state !== "policy-email-claim-required") {
    throw new Error(`share-access-${resolved.state}`);
  }

  const share = await input.dependencies.verifyShare({
    envelope: resolved.envelope,
    shareCid: resolved.shareCid,
    policy: resolved.policy,
  });

  const controllerFactory =
    input.dependencies.createController ?? createClaimController;
  const controller: ClaimController = controllerFactory({
    share,
    invitationId: invitation.invitationId,
    claimSecret: invitation.claimSecret,
    transport: input.dependencies.transport,
    credentialTrust: input.dependencies.credentialTrust,
  });
  input.dependencies.onController?.(controller);

  // This is deliberately after all untrusted URL/envelope/policy/source
  // checks and before activation, claim, credential issuance, or node access.
  if (!(await input.confirmAccess())) {
    throw new Error("access-not-confirmed");
  }

  {
    await controller.openDocument();
    const claimState = controller.state;
    if (
      claimState.state !== "claimed" &&
      claimState.state !== "session" &&
      claimState.state !== "reading"
    ) {
      throw accessStateError(claimState);
    }

    const content = await controller.read();
    if (content === undefined) {
      throw accessStateError(controller.state);
    }

    return {
      content,
      shareCid: share.shareCid,
      shareId: share.shareId,
      holderDid: claimState.claim.holder.did,
    };
  }
}

export type { ClaimController, ClaimState, CredentialTrust };
