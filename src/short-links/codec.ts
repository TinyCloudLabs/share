/** `/s/<id>`: 130 random bits as 26 base32 characters. Accepted case-insensitively, stored lowercase. */
const SHORT_PATH = /^\/s\/([a-z2-7]{26})$/i;
/** `#v=3&k=<key>&c=<cid>`: exactly these two parameters, in this order. `k` is 32 bytes as 43 base64url characters. */
const SHORT_FRAGMENT = /^#v=3&k=([A-Za-z0-9_-]{43})&c=(bafkrei[a-z2-7]{52})$/;

export interface ShortLinkParts {
  /** Lowercase link id. */
  readonly id: string;
  /** Unpadded base64url of the 32-byte content key. Never sent to the server. */
  readonly key: string;
  /** CIDv1 raw sha2-256 base32 of the sealed bytes. */
  readonly cid: string;
}

/** Parse a `https://<host>/s/<id>#v=3&k=<key>&c=<cid>` link. Returns undefined for anything else. */
export function parseShortLink(href: string): ShortLinkParts | undefined {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return undefined;
  }
  if (url.search !== "") return undefined;
  const path = SHORT_PATH.exec(url.pathname);
  const fragment = SHORT_FRAGMENT.exec(url.hash);
  if (path === null || fragment === null) return undefined;
  return { id: (path[1] ?? "").toLowerCase(), key: fragment[1] ?? "", cid: fragment[2] ?? "" };
}
