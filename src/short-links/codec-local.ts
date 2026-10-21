/**
 * Local mirror of the short-link codec. The share-envelope SDK owns the
 * canonical version; this copy is kept in step with it by the shared vector
 * file, and is switched to the SDK helpers at the next pin bump.
 */

const B64URL = /^[A-Za-z0-9_-]+$/;
const CID = /^bafk[a-z2-7]+$/;
const SHORT_ID = /^[a-z2-7]{26}$/;

export interface InlineSharePayload {
  readonly v: 2;
  readonly c: string;
  readonly cid: string;
  readonly k: string;
}

function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

/** Reads the `v=2&p=<base64url JSON>` fragment of an inline share link. */
export function parseInlineSharePayload(inlineUrl: string): InlineSharePayload {
  const fragment = new URLSearchParams(new URL(inlineUrl).hash.slice(1));
  const p = fragment.get("p");
  if (fragment.get("v") !== "2" || p === null || !B64URL.test(p)) throw new Error("inline link has no v=2 payload");
  const parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(p))) as Partial<Record<keyof InlineSharePayload, unknown>>;
  if (parsed.v !== 2 || typeof parsed.c !== "string" || typeof parsed.cid !== "string" || typeof parsed.k !== "string") throw new Error("inline link payload is malformed");
  if (!B64URL.test(parsed.c) || !CID.test(parsed.cid) || !B64URL.test(parsed.k)) throw new Error("inline link payload is malformed");
  return { v: 2, c: parsed.c, cid: parsed.cid, k: parsed.k };
}

/** `https://share.tinycloud.xyz/s/<id>#v=3&k=<key>&c=<cid>` for the inline link's key and CID. */
export function splitInlineToShort(inlineUrl: string, id: string): string {
  if (!SHORT_ID.test(id)) throw new Error("short link id is malformed");
  const payload = parseInlineSharePayload(inlineUrl);
  return `${new URL(inlineUrl).origin}/s/${id}#v=3&k=${payload.k}&c=${payload.cid}`;
}

/** Rebuilds the inline-equivalent payload from a short link and the fetched ciphertext. */
export function rebuildInlineFromShort(shortUrl: string, ciphertextB64Url: string): InlineSharePayload {
  const fragment = new URLSearchParams(new URL(shortUrl).hash.slice(1));
  const k = fragment.get("k");
  const cid = fragment.get("c");
  if (fragment.get("v") !== "3" || k === null || cid === null) throw new Error("short link fragment is malformed");
  return { v: 2, c: ciphertextB64Url, cid, k };
}
