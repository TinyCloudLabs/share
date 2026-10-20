/**
 * The page's sign-in: one adapter over Share's reusable `signInWithManifest`.
 *
 * The session is the courier manifest (see scope.ts) plus what the SDK adds to
 * every sign-in for the account's own space registry (`signInWithManifest`
 * documents it). It lives in memory only, for at most an hour, and `dispose()`
 * closes any OpenKey window and clears it. Nothing here is written to storage,
 * logged or put in the address bar.
 *
 * This page never hosts a space: `hostSpaces` is empty. A mailbox that does not
 * exists yet reads as `no-space`, and the page says how to set it up.
 */
import type { SharePublicConfig } from "../email-share/config.js";
import { endSenderSession } from "../share/sender-chrome.js";
import type { ApprovalGuard, ManifestSignIn, ShareTinyCloud, WalletApprovalFailure } from "../share/openkey-session.js";
import { withWalletApproval } from "../share/revoke-flight.js";
import { COURIER_APP_NAME, COURIER_MANIFEST_SCOPE, COURIER_SESSION_MS, COURIER_SPACE, assertCourierPermissions, courierManifest } from "./scope.js";
import { createKvStore, type CourierStore } from "./store.js";

export interface CourierSession {
  readonly address: string;
  readonly store: CourierStore;
  /** Closes the OpenKey flow and clears the SDK session. Safe to call twice; never rejects. */
  dispose(): Promise<void>;
  /** Ends the SDK session, then OpenKey's own sign-in. True when OpenKey confirmed it ended its sign-in. */
  signOut(): Promise<boolean>;
}

export interface SignInProgress {
  /** True while an OpenKey approval is open, false when it closes. */
  approval(open: boolean): void;
  status(message: string): void;
}

export type SignInFailureReason = WalletApprovalFailure | "busy" | "failed";

export class CourierSignInError extends Error {
  readonly reason: SignInFailureReason;
  constructor(reason: SignInFailureReason, options?: { readonly cause?: unknown }) {
    super(`courier-sign-in-${reason}`, options);
    this.name = "CourierSignInError";
    this.reason = reason;
  }
}

/** A person's own choice, an unanswered window or a second request is not a fault: a quiet note, not an alert. */
export function signInFailureMessage(error: unknown): { readonly message: string; readonly neutral: boolean } {
  const reason: SignInFailureReason = error instanceof CourierSignInError ? error.reason : "failed";
  switch (reason) {
    case "cancelled": return { message: "Sign-in cancelled. Nothing was changed.", neutral: true };
    case "timeout": return { message: "OpenKey didn't answer in time. Try again.", neutral: true };
    case "busy": return { message: "Another OpenKey request is waiting. Finish or cancel it, then try again.", neutral: true };
    case "wrong-account": return { message: "That approval came from a different account than the one signed in. Try again.", neutral: false };
    default: return { message: "We couldn't sign you in. Try again.", neutral: false };
  }
}

function guardReason(error: unknown): SignInFailureReason | undefined {
  if (!(error instanceof Error)) return undefined;
  if (error.message === "revoke-approval-abandoned") return "timeout";
  if (error.message === "revoke-another-approval") return "busy";
  return undefined;
}

/** Called by the Sign in click, never before: OpenKey and the Web SDK load on demand. */
export async function signInToCourier(config: SharePublicConfig, progress: SignInProgress): Promise<CourierSession> {
  // Fail closed: the manifest this page signs is checked, resolved, against its own allow-list first.
  const manifest = courierManifest();
  assertCourierPermissions(manifest);
  let client: ShareTinyCloud | undefined;
  let observed: SignInFailureReason | undefined;
  let takeFailure: ((tinycloud: ShareTinyCloud) => WalletApprovalFailure | undefined) | undefined;
  const guardApproval: ApprovalGuard = async (wait) => {
    try {
      return await withWalletApproval({ setApproval: (open) => progress.approval(open) }, () => wait());
    } catch (error) {
      observed ??= guardReason(error);
      throw error;
    }
  };
  let signedIn: ManifestSignIn | undefined;
  try {
    // Dynamic on purpose (as the viewer's Save does): the signed-out page must not load OpenKey or the account SDK before the click.
    const openkey = await import("../share/openkey-session.js");
    takeFailure = openkey.takeWalletApprovalFailure;
    signedIn = await openkey.signInWithManifest({
      manifest,
      ...COURIER_MANIFEST_SCOPE,
      config,
      appName: COURIER_APP_NAME,
      sessionPrefix: "tinycloud-courier",
      expiry: COURIER_SESSION_MS,
      hostSpaces: [],
      guardApproval,
      onStatus: progress.status,
      onClient: (created) => { client = created; },
    });
    const kv = signedIn.tinycloud.space(COURIER_SPACE).kv;
    const connected = signedIn;
    return {
      address: connected.session.address,
      store: createKvStore(kv),
      dispose: connected.dispose,
      signOut: () => endSenderSession({ session: connected.session, tinycloud: connected.tinycloud }),
    };
  } catch (error) {
    await signedIn?.dispose();
    // The SDK folds a plain `{ code }` rejection from OpenKey into "[object Object]", so ask what the approval itself said.
    const reason = observed ?? (client === undefined ? undefined : takeFailure?.(client)) ?? "failed";
    throw new CourierSignInError(reason, { cause: error });
  }
}
