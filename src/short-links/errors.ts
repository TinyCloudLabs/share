/**
 * `gone`: the server has no live link for this id (404 for unknown, expired, and deleted alike).
 * `unavailable`: the lookup could not be completed, or the response is not usable.
 */
export type ShortLinkFailure = "gone" | "unavailable";

export class ShortLinkError extends Error {
  readonly reason: ShortLinkFailure;

  constructor(reason: ShortLinkFailure, message: string) {
    super(message);
    this.name = "ShortLinkError";
    this.reason = reason;
  }
}
