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

/** Shown when the sealed share is over the one link size limit; nothing is uploaded or registered. */
export const SHARE_TOO_LARGE_FOR_LINK = "This share is too large to send as a link, so nothing was shared. Use a shorter path or fewer folders.";

/** The viewer asks for a click before it fetches or opens anything (contract 7.5, step 0). */
export const OPEN_CONFIRM_TITLE = "Open this link";
export const OPEN_CONFIRM_DETAIL = "Nothing is fetched or opened until you press the button.";
export const OPEN_CONFIRM_BUTTON = "Open";

/** The sender's button on a share whose link has expired. The label is Sam's wording. */
export const SEND_AGAIN_LABEL = "Send the link again";
/** Shown at the top of the composer opened by that button; the file is not kept, so it is attached again. */
export const SEND_AGAIN_ATTACH_HINT = "Attach the file again to send the link again.";
export const sendAgainAttachNamedHint = (filename: string): string => `Attach ${filename} again to send the link again.`;
/** Shown when the saved share could not be read to open the composer. */
export const SEND_AGAIN_FAILED = "We couldn't open this share to send it again. Try again.";
