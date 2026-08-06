/**
 * Strict fetch client for the OpenCredentials create-invitation endpoint
 * (specs/email-claim-v1/schemas.json `schemas.createInvitationRequest` /
 * `schemas.createInvitationResponse`). The request body carries the node's
 * OWN signed `authorization` + `proof` back to it, plus the `shareUrl`; the
 * only valid success response is the fixed `{ status: "accepted",
 * retryAfterSeconds: 20 }` shape — anything else is a malformed response.
 */
import {
  SenderHttpError,
  SenderInvalidResponseError,
  SenderNetworkError,
} from "./errors.js";
import type { InviteAuthorization, Proof } from "./invitation-input.js";

export interface CreateInvitationRequestBody {
  readonly authorization: InviteAuthorization;
  readonly proof: Proof;
  readonly shareUrl: string;
}

export interface CreateInvitationResponse {
  readonly status: "accepted";
  readonly retryAfterSeconds: 20;
}

export interface RequestInvitationOptions {
  readonly fetchFn?: typeof globalThis.fetch;
}

function isValidCreateInvitationResponse(value: unknown): value is CreateInvitationResponse {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.status === "accepted" &&
    record.retryAfterSeconds === 20 &&
    Object.keys(record).length === 2
  );
}

/**
 * POST the create-invitation request to the OpenCredentials endpoint at
 * `url`. Throws {@link SenderNetworkError} on transport failure,
 * {@link SenderHttpError} on a non-2xx status, and
 * {@link SenderInvalidResponseError} on a body that is not valid JSON or
 * does not match the fixed success shape.
 */
export async function requestInvitation(
  url: string,
  body: CreateInvitationRequestBody,
  options: RequestInvitationOptions = {},
): Promise<CreateInvitationResponse> {
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  let response: Response;
  try {
    response = await fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new SenderNetworkError(
      error instanceof Error ? error.message : "create-invitation request failed",
    );
  }
  if (!response.ok) {
    throw new SenderHttpError("create-invitation request failed", response.status);
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    throw new SenderInvalidResponseError("create-invitation response is not JSON");
  }
  if (!isValidCreateInvitationResponse(parsed)) {
    throw new SenderInvalidResponseError("create-invitation response has an unexpected shape");
  }
  return parsed;
}
