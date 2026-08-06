/**
 * Orchestrator + reducer/status for the email-claim v1 sender flow: request
 * the node's signed invite authorization, cross-check it against what was
 * prepared, then request the OpenCredentials invitation. Every failure
 * state carries a generic, privacy-safe status text — never the recipient
 * email, never raw transport/server detail, and the success text is
 * EXACTLY "Invitation requested" (this flow requests delivery; it never
 * observes or claims delivery itself, so status text must never say
 * "Email delivered" or similar).
 */
import {
  authorizationAgreesWithPreparedInputs,
  shareUrlAgreesWithPreparedInputs,
} from "./invitation-input.js";
import type { PreparedInvitationInputs } from "./invitation-input.js";
import { requestInvitation } from "./invitation-client.js";
import { requestNodeAuthorization } from "./node-authorization-client.js";
import { SenderHttpError, SenderNetworkError } from "./errors.js";

export const INVITATION_REQUESTED_TEXT = "Invitation requested" as const;
const CAPABILITY_UNAVAILABLE_TEXT = "This sharing option isn't available right now.";
const REQUEST_FAILED_TEXT = "We couldn't request this invitation. Please try again.";

// Frozen capability-descriptor routes (specs/email-claim-v1/domains.json
// `capabilities.node.routes` / `capabilities.witness.routes` +
// `capabilities.witness.origin`) — the ONLY authorize path and witness
// origin/path this flow will ever call. No alternate path, port, userinfo,
// query, or fragment is ever accepted, regardless of what a caller supplies.
const NODE_AUTHORIZE_PATH = "/share/v1/invitations/authorize";
const WITNESS_ORIGIN = "https://witness.credentials.org";
const WITNESS_INVITATION_PATH = "/v1/share-email/invitations";

/**
 * Strict, exact binding: the ORIGINAL input string must equal the expected
 * URL byte-for-byte BEFORE any URL parsing — parsing (e.g. `new URL(...)`)
 * normalizes away things like an explicit default port (`:443`), and dot
 * segments, duplicate slashes, percent-encoding variants, userinfo, query,
 * and fragment can all round-trip through a parser into something that
 * looks equal post-parse without being byte-identical pre-parse. Exact
 * string equality is therefore the PRIMARY check; a parse afterward is only
 * a secondary, defense-in-depth sanity check on the (now known-exact) URL.
 */
function urlBindsToExactly(url: string, expected: string): boolean {
  if (url !== expected) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return (
    parsed.protocol === "https:" &&
    parsed.username === "" &&
    parsed.password === "" &&
    parsed.search === "" &&
    parsed.hash === ""
  );
}

export type SendInvitationState =
  | { readonly status: "idle" }
  | { readonly status: "requesting-authorization" }
  | { readonly status: "requesting-invitation" }
  | { readonly status: "requested"; readonly statusText: typeof INVITATION_REQUESTED_TEXT }
  | { readonly status: "unavailable"; readonly statusText: string }
  | { readonly status: "failed"; readonly statusText: string };

export interface SendInvitationOptions {
  readonly nodeAuthorizationUrl: string;
  readonly invitationUrl: string;
  readonly fetchFn?: typeof globalThis.fetch;
}

export async function sendEmailInvitation(
  prepared: PreparedInvitationInputs,
  shareUrl: string,
  options: SendInvitationOptions,
): Promise<SendInvitationState> {
  const fetchOptions = options.fetchFn !== undefined ? { fetchFn: options.fetchFn } : {};

  // The share URL must bind to the already-verified/prepared inputs before
  // EITHER network request is made — a wrong/malformed origin, path, query,
  // fragment, or share CID must never reach the node or OpenCredentials.
  if (!shareUrlAgreesWithPreparedInputs(prepared, shareUrl)) {
    return { status: "failed", statusText: REQUEST_FAILED_TEXT };
  }

  // Likewise, the node-authorization and invitation URLs must bind to the
  // prepared targetOrigin and the frozen capability-descriptor routes
  // before EITHER network request — a wrong origin, port, userinfo, path
  // variant, query, or fragment must never reach any server.
  if (
    !urlBindsToExactly(
      options.nodeAuthorizationUrl,
      prepared.authorizationRequest.targetOrigin + NODE_AUTHORIZE_PATH,
    ) ||
    !urlBindsToExactly(options.invitationUrl, WITNESS_ORIGIN + WITNESS_INVITATION_PATH)
  ) {
    return { status: "failed", statusText: REQUEST_FAILED_TEXT };
  }

  let authorization;
  let proof;
  try {
    ({ authorization, proof } = await requestNodeAuthorization(
      options.nodeAuthorizationUrl,
      prepared.authorizationRequest,
      fetchOptions,
    ));
  } catch (error) {
    if (error instanceof SenderNetworkError || error instanceof SenderHttpError) {
      return { status: "unavailable", statusText: CAPABILITY_UNAVAILABLE_TEXT };
    }
    return { status: "failed", statusText: REQUEST_FAILED_TEXT };
  }

  if (!authorizationAgreesWithPreparedInputs(prepared, authorization)) {
    return { status: "failed", statusText: REQUEST_FAILED_TEXT };
  }

  try {
    await requestInvitation(
      options.invitationUrl,
      { authorization, proof, shareUrl },
      fetchOptions,
    );
  } catch (error) {
    if (error instanceof SenderNetworkError || error instanceof SenderHttpError) {
      return { status: "unavailable", statusText: CAPABILITY_UNAVAILABLE_TEXT };
    }
    return { status: "failed", statusText: REQUEST_FAILED_TEXT };
  }

  return { status: "requested", statusText: INVITATION_REQUESTED_TEXT };
}
