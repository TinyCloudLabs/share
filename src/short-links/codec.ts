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

/** `#v=2&p=<payload>`: the inline form, payload as unpadded base64url. */
const INLINE_FRAGMENT = /^#v=2&p=([A-Za-z0-9_-]+)$/;
/** Unpadded base64url. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;
/** Unpadded base64url of a 32-byte content key. */
const KEY = /^[A-Za-z0-9_-]{43}$/;
/** CIDv1 raw sha2-256 base32. */
const CID = /^bafkrei[a-z2-7]{52}$/;
/** Lowercase 26-character base32 id. */
const ID = /^[a-z2-7]{26}$/;

/**
 * Convert a v2 inline link into the short link for the same share, keeping the inline link's
 * origin. `id` is the short id the server assigned. Returns undefined when the input is not a
 * well-formed v2 inline link or when `id` is not a short-link id.
 */
export function splitInlineToShort(inlineHref: string, id: string): string | undefined {
  const shortId = id.toLowerCase();
  if (!ID.test(shortId)) return undefined;
  let url: URL;
  try {
    url = new URL(inlineHref);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:" || url.search !== "") return undefined;
  const fragment = INLINE_FRAGMENT.exec(url.hash);
  if (fragment === null) return undefined;
  const payload = decodePayload(fragment[1] ?? "");
  if (payload === undefined) return undefined;
  return `${url.origin}/s/${shortId}#v=3&k=${payload.k}&c=${payload.cid}`;
}

/** Decode the inline payload, which must be exactly JCS-ordered `{c, cid, k, v: 2}`. */
function decodePayload(encoded: string): { readonly k: string; readonly cid: string } | undefined {
  const json = decodeBase64UrlText(encoded);
  if (json === undefined) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null || JSON.stringify(value) !== json) return undefined;
  if (Object.keys(value).join(",") !== "c,cid,k,v") return undefined;
  const { c, cid, k, v } = value as Record<string, unknown>;
  if (typeof c !== "string" || !BASE64URL.test(c)) return undefined;
  if (typeof cid !== "string" || !CID.test(cid)) return undefined;
  if (typeof k !== "string" || !KEY.test(k)) return undefined;
  if (v !== 2) return undefined;
  return { k, cid };
}

/** Decode unpadded base64url to UTF-8 text. Undefined for anything that is not valid base64url UTF-8. */
function decodeBase64UrlText(encoded: string): string | undefined {
  if (!BASE64URL.test(encoded)) return undefined;
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=");
  try {
    const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
