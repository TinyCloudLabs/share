/**
 * The `cap/*` wire contract between an installed app's frame and its runner
 * page. One table, shared by the three places that speak it:
 *
 *   child (the app's `@tinycloud/app` module, app-module.ts)
 *     → bridge document (JSX_BRIDGE_SCRIPT in ../../viewer/jsx-frame.ts)
 *       → parent (the runner page: ../../apps/bridge.ts)
 *
 * and back as `cap/result`. Everything on the wire is plain data: strings,
 * numbers, booleans, null, arrays, plain objects and Uint8Array. No session,
 * token, key, DID or URL is ever part of a request or a result.
 */

/** The operations v1 knows. Anything else under `cap/` is dropped by the bridge. */
export const CAP_OPS = ["kv.get", "kv.put", "kv.list", "kv.del", "sql.query", "sql.execute"] as const;
export type CapOp = (typeof CAP_OPS)[number];

export const CAP_TYPE_PREFIX = "cap/";
/** Allowed `type` values of a request, as they appear on the wire. */
export const CAP_TYPES: readonly string[] = CAP_OPS.map((op) => `${CAP_TYPE_PREFIX}${op}`);
/** The reply type, parent → bridge → child. */
export const CAP_RESULT_TYPE = "cap/result";

/** Request ids are small decimal counters chosen by the frame's module. */
export const CAP_ID_PATTERN = /^[0-9]{1,9}$/;

export const CAP_LIMITS = Object.freeze({
  /** Size of a request's arguments (strings as UTF-8, binary as is, 8 bytes per other value) and of a result. */
  maxMessageBytes: 1_000_000,
  /** Calls running at once; the next one is refused with BUSY, not queued. */
  maxInFlight: 4,
  /** The parent gives up on a call after this long. The call may still have been applied. */
  timeoutMs: 30_000,
  /** A slot of a call that timed out is held until the call settles, but never longer than this. */
  slotHoldMs: 60_000,
  /** The module in the frame stops waiting a little after the parent does. */
  clientWaitMs: 35_000,
  /** Nesting the bridge and parent accept in a request. */
  maxDepth: 6,
  maxPathChars: 1024,
  maxParams: 256,
});

export const CAP_ERROR_CODES = [
  "PERMISSION_DENIED",
  "NOT_FOUND",
  "PRECONDITION_FAILED",
  "SQL_ERROR",
  "BAD_REQUEST",
  "TOO_LARGE",
  "BUSY",
  "TIMEOUT",
  "INTERNAL",
  "NOT_CONNECTED",
] as const;
export type CapErrorCode = (typeof CAP_ERROR_CODES)[number];

export interface CapError {
  readonly ok: false;
  readonly error: { readonly code: CapErrorCode; readonly message: string };
}

export type CapResult = CapError | ({ readonly ok: true } & Record<string, unknown>);

/** Longest error message a result carries. */
export const CAP_MAX_ERROR_CHARS = 500;

export function capError(code: CapErrorCode, message: string): CapError {
  return { ok: false, error: { code, message: message.slice(0, CAP_MAX_ERROR_CHARS) } };
}

/** The request body the parent sees: `{ id, args }` under the standard `{v,type,nonce,body}` envelope. */
export interface CapRequestBody {
  readonly id: string;
  readonly args: Readonly<Record<string, unknown>>;
}
