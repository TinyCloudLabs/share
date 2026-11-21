import type { PermissionEntry } from "@tinycloud/web-sdk";
import { takeWalletApprovalFailure, type ShareTinyCloud } from "./openkey-session.js";

/** What a step-up came to: whether it was granted, and when the earliest grant the SDK issued ends (epoch ms) if it said. */
export interface StepUpResult {
  readonly approved: boolean;
  readonly expiresAt?: number;
}

type StepUpClient = Pick<ShareTinyCloud, "requestPermissions" | "hasPermissions">;

/** The step-up in progress, if any: the handler swap below is one shared field, so requests run one at a time. */
let queue: Promise<unknown> = Promise.resolve();

/**
 * Asks OpenKey for access beyond what the library signed in with. Share signs in with the SDK's own windows turned off,
 * so the SDK's "requests additional access" question has no window to show. The person has already pressed the button
 * that leads here (or is being told what is happening in the status line), so that question is answered as approved and
 * OpenKey's own screen is where the approval is given. The SDK's handler is put back as it was once the request ends.
 * A request made while another is open waits for it, so each one sets and restores the handler in turn.
 * Resolves `approved: false` when OpenKey does not grant it.
 */
export function requestInOpenKeyUntil(tinycloud: StepUpClient, permissions: PermissionEntry[], options?: { readonly expiryMs?: number }): Promise<StepUpResult> {
  const run = queue.then(() => requestNow(tinycloud, permissions, options));
  // A request that fails does not hold up the ones behind it.
  queue = run.catch(() => undefined);
  return run;
}

/** `requestInOpenKeyUntil`, for a caller that only needs to know whether it was granted. */
export async function requestInOpenKey(tinycloud: StepUpClient, permissions: PermissionEntry[], options?: { readonly expiryMs?: number }): Promise<boolean> {
  return (await requestInOpenKeyUntil(tinycloud, permissions, options)).approved;
}

/**
 * The earliest end among the delegations the SDK issued for the grant. Each carries its real expiry (a Date, or an ISO
 * string once serialized), set before signing and held to the session's end. Undefined when none carries a usable one.
 */
function earliestExpiry(delegations: ReadonlyArray<{ readonly expiry?: unknown }> | undefined): number | undefined {
  const ends = (delegations ?? [])
    .map(({ expiry }) => expiry instanceof Date ? expiry.getTime() : typeof expiry === "string" ? Date.parse(expiry) : Number.NaN)
    .filter(Number.isFinite);
  return ends.length === 0 ? undefined : Math.min(...ends);
}

async function requestNow(tinycloud: StepUpClient, permissions: PermissionEntry[], options?: { readonly expiryMs?: number }): Promise<StepUpResult> {
  // The SDK reads its permission-window handler from this one field; the pinned version is in package.json.
  const previous = Reflect.get(tinycloud, "_testHooks");
  const hooks = typeof previous === "object" && previous !== null ? previous : {};
  if (!Reflect.set(tinycloud, "_testHooks", { ...hooks, showModal: async () => ({ approved: true }) })) {
    throw new Error("permission-request-unavailable");
  }
  try {
    const result = await tinycloud.requestPermissions(permissions, options);
    const expiresAt = result.approved ? earliestExpiry(result.delegations) : undefined;
    return expiresAt === undefined ? { approved: result.approved } : { approved: result.approved, expiresAt };
  } catch (error) {
    // OpenKey ends a cancelled approval by rejecting; that is the person saying no, not a failure. A grant the SDK had
    // already activated before the rejection is still held, and is reported as held.
    if (takeWalletApprovalFailure(tinycloud) === "cancelled") return { approved: tinycloud.hasPermissions(permissions) };
    throw error;
  } finally {
    Reflect.set(tinycloud, "_testHooks", previous);
  }
}
