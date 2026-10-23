/** The one size limit for the sealed body of a stored link, whatever its type: 64 KiB. */
export const LINK_BODY_MAX_BYTES = 65_536;

/** The longest fragment a reader accepts for a full link: it bounds the record the link can carry. */
export const MAX_FULL_LINK_FRAGMENT = 700_000;
