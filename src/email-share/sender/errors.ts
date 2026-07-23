/**
 * Typed, fail-closed error hierarchy for the email-claim v1 sender flow's
 * network clients. No error here is ever swallowed into a fallback —
 * callers must handle each kind explicitly.
 */

/** Base class so callers can `catch (e instanceof SenderClientError)` for all client failures. */
export class SenderClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The request never reached the server, or the server never responded (network failure). */
export class SenderNetworkError extends SenderClientError {}

/** The server answered with a non-2xx HTTP status. */
export class SenderHttpError extends SenderClientError {
  readonly status: number;

  constructor(message: string, status: number) {
    super(`${message} (status ${status})`);
    this.status = status;
  }
}

/** The server's response body is not JSON, or does not match the expected strict shape. */
export class SenderInvalidResponseError extends SenderClientError {}
