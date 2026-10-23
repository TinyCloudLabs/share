/** The one size limit for the sealed body of a stored link, whatever its type: 64 KiB. */
export const LINK_BODY_MAX_BYTES = 65_536;

/** The longest fragment a reader accepts for a full link: a body at the size limit, base64url twice over, fits. */
export const MAX_FULL_LINK_FRAGMENT = 131_072;
