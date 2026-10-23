import { MAX_FULL_LINK_FRAGMENT } from "./limits.js";
import { canonicalize, fromBase64Url, isCanonicalRawCid, toBase64Url } from "@tinycloud/share-envelope";

export type LinkType = "openkey-login" | "courier" | "share";

/** Path letter in a short link, per type. */
export const PATH_LETTER: Readonly<Record<LinkType, string>> = Object.freeze({ "openkey-login": "l", courier: "c", share: "s" });
const TYPE_BY_LETTER: Readonly<Record<string, LinkType>> = Object.freeze({ l: "openkey-login", c: "courier", s: "share" });

export type LinkRefusal =
  | "not_a_url" | "not_https" | "userinfo" | "origin_not_trusted" | "not_canonical" | "query_present"
  | "removed_version" | "path_grammar" | "fragment_grammar" | "key_noncanonical" | "cid_grammar"
  | "record_encoding" | "record_json" | "record_not_canonical";

export type ParsedLink =
  | { readonly form: "short"; readonly origin: string; readonly pathType: LinkType; readonly id: string; readonly key: string; readonly cid: string }
  | { readonly form: "full"; readonly origin: string; readonly key: string; readonly record: unknown };

export type LinkParse = { readonly ok: true; readonly link: ParsedLink } | { readonly ok: false; readonly reason: LinkRefusal };

const SHORT_PATH = /^\/(s|c|l)\/([A-Za-z2-7]{26})$/;
const SHORT_FRAGMENT = /^#v=4&k=([A-Za-z0-9_-]{43})&c=(bafkrei[a-z2-7]{52})$/;
const FULL_FRAGMENT = /^#v=4&k=([A-Za-z0-9_-]{43})&r=([A-Za-z0-9_-]+)$/;
const REMOVED_VERSION = /^#v=[23](&|$)/;
const ID = /^[a-z2-7]{26}$/;

const no = (reason: LinkRefusal): LinkParse => ({ ok: false, reason });

function strictBytes(text: string): Uint8Array | undefined {
  try {
    return fromBase64Url(text);
  } catch {
    return undefined;
  }
}

/**
 * The strict link grammar (contract 7.3). The link must be the exact string
 * `origin + pathname + search + hash` of its parsed URL and its origin must be
 * one the reader trusts. Nothing is fetched here.
 */
export function parseLink(href: string, trustedOrigins: readonly string[]): LinkParse {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return no("not_a_url");
  }
  if (url.protocol !== "https:") return no("not_https");
  if (url.username !== "" || url.password !== "") return no("userinfo");
  if (!trustedOrigins.includes(url.origin)) return no("origin_not_trusted");
  if (href !== `${url.origin}${url.pathname}${url.search}${url.hash}`) return no("not_canonical");
  if (url.search !== "") return no("query_present");
  if (REMOVED_VERSION.test(url.hash)) return no("removed_version");
  const short = SHORT_PATH.exec(url.pathname);
  const full = url.pathname === "/s/full";
  if (short === null && !full) return no("path_grammar");
  if (short !== null) {
    const fragment = SHORT_FRAGMENT.exec(url.hash);
    if (fragment === null) return no("fragment_grammar");
    if (strictBytes(fragment[1]!)?.length !== 32) return no("key_noncanonical");
    if (!isCanonicalRawCid(fragment[2]!)) return no("cid_grammar");
    return { ok: true, link: { form: "short", origin: url.origin, pathType: TYPE_BY_LETTER[short[1]!]!, id: short[2]!.toLowerCase(), key: fragment[1]!, cid: fragment[2]! } };
  }
  const fragment = FULL_FRAGMENT.exec(url.hash);
  if (fragment === null || url.hash.length > MAX_FULL_LINK_FRAGMENT) return no("fragment_grammar");
  if (strictBytes(fragment[1]!)?.length !== 32) return no("key_noncanonical");
  const raw = strictBytes(fragment[2]!);
  if (raw === undefined) return no("record_encoding");
  let record: unknown;
  let json: string;
  try {
    json = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    record = JSON.parse(json);
  } catch {
    return no("record_json");
  }
  if (canonicalize(record) !== json) return no("record_not_canonical");
  return { ok: true, link: { form: "full", origin: url.origin, key: fragment[1]!, record } };
}

/** `https://<origin>/<p>/<id>#v=4&k=<k>&c=<c>`. */
export function buildShortLink(parts: { readonly origin: string; readonly type: LinkType; readonly id: string; readonly key: string; readonly cid: string }): string {
  if (!ID.test(parts.id)) throw new TypeError("link id is malformed");
  return `${parts.origin}/${PATH_LETTER[parts.type]}/${parts.id}#v=4&k=${parts.key}&c=${parts.cid}`;
}

/** `https://<origin>/s/full#v=4&k=<k>&r=<base64url JCS record>`. */
export function buildFullLink(parts: { readonly origin: string; readonly key: string; readonly record: unknown }): string {
  return `${parts.origin}/s/full#v=4&k=${parts.key}&r=${toBase64Url(new TextEncoder().encode(canonicalize(parts.record)))}`;
}

/** The id of a short link, or undefined for a full link or any other text. */
export function shortLinkId(href: string, trustedOrigins: readonly string[]): string | undefined {
  const parsed = parseLink(href, trustedOrigins);
  return parsed.ok && parsed.link.form === "short" ? parsed.link.id : undefined;
}
