/**
 * Every user-facing string this feature adds, in one place for wording review.
 * Wording is PROPOSED (contract section 15, OD22) until it is approved.
 * Screens that already exist keep their own text and are not repeated here.
 */

/** Contract 8.2. Shown by the composer when a share lasts longer than 30 days. */
export const LINK_LONG_LIFE_NOTICE =
  "This share lasts longer than 30 days, so it is sent as a full link instead of a short one. The full link is long. Learn how permissions work: https://tinycloud.xyz/delegations?from=link-expiry";

/** Contract 8.3. Shown by the composer when the link service refuses or cannot be reached. */
export const SHORT_LINK_UNAVAILABLE_NOTICE = "Short link unavailable: using the full link";

/** Shown instead of an email send when the share has only a full link (contract 7.7). */
export const FULL_LINK_NO_EMAIL = "Invitation emails need a short link, and this share has only the full link. Copy the link above to send it yourself.";

/** The viewer asks for a click before it fetches or opens anything (contract 7.5, step 0). */
export const OPEN_CONFIRM_TITLE = "Open this link";
export const OPEN_CONFIRM_DETAIL = "Nothing is fetched or opened until you press the button.";
export const OPEN_CONFIRM_BUTTON = "Open";
