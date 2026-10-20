import { fail } from "./sender-failure.js";

/** Stable support code carried by the failure and named in the sender-visible text. */
export const SPACE_NOT_READY_CODE = "SPACE_NOT_READY";

/** The slice of a KV write result this check reads. Structural, so SDK and fake clients both fit. */
export interface KvWriteOutcome {
  readonly ok: boolean;
  readonly error?: { readonly message?: string; readonly meta?: { readonly status?: unknown } };
}

/**
 * A node with no row for the space answers a write with `404 - Space not found`.
 * A write never reports a missing key, so this is the only 404 a write gets.
 */
export function isSpaceNotFound(outcome: KvWriteOutcome): boolean {
  if (outcome.ok) return false;
  const message = outcome.error?.message ?? "";
  if (!/space not found/i.test(message)) return false;
  return outcome.error?.meta?.status === 404 || /\b404\b/.test(message);
}

/**
 * Turn a failed share upload into the typed, sender-facing failure when the
 * node reports the space as not found. Every other outcome is left to the
 * caller. The node's own error rides on `cause` and never reaches the UI.
 */
export function failIfSpaceNotReady(outcome: KvWriteOutcome): void {
  if (!isSpaceNotFound(outcome)) return;
  throw fail("spaceNotReady", "owner node reported the space as not found", { code: SPACE_NOT_READY_CODE, cause: outcome.error });
}
