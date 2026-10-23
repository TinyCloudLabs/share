import { fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { createLink, type LinkApiOptions } from "./client.js";
import { buildFullLink, buildShortLink } from "./codec.js";
import { ShareTooLargeForLink } from "./errors.js";
import { LINK_BODY_MAX_BYTES, MAX_FULL_LINK_FRAGMENT } from "./limits.js";
import { buildHeader, HEADER_DOMAIN, LINK_TYPES, MIN_LIFE_SECONDS, signObject } from "./record.js";
import { LINK_LONG_LIFE_NOTICE, SHORT_LINK_UNAVAILABLE_NOTICE } from "./strings.js";

export interface LinkChoice {
  readonly form: "short" | "full";
  /** True when the share is longer than the service keeps a link, so the sender is told why the link is long. */
  readonly warning: boolean;
}

/** Contract 8.1: which link a share of this life (expiry minus now, in seconds) gets. */
export function chooseLink(lifetimeSeconds: number): LinkChoice {
  if (lifetimeSeconds > LINK_TYPES.share.maxLifeSeconds) return { form: "full", warning: true };
  if (lifetimeSeconds < MIN_LIFE_SECONDS) return { form: "full", warning: false };
  return { form: "short", warning: false };
}

/** What the SDK reports at publish time about the sealed bytes it made. */
export interface LinkMaterial {
  /** base64url of the sealed bytes. */
  readonly sealedEnvelope: string;
  /** base64url of the 32-byte key. It goes only into the link fragment. */
  readonly envelopeKey: string;
  /** CID of the sealed bytes. */
  readonly shareCid: string;
}

export interface LinkPublication {
  readonly url: string;
  readonly form: "short" | "full";
  /** Set when the sender should be told why the link is the full one. */
  readonly notice?: string;
}

export interface LinkSigner {
  /** The issuer's did:key: the same key that signs the share envelope. */
  readonly issuerDid: string;
  readonly sign: (digest: Uint8Array) => Promise<Uint8Array>;
}

/**
 * Makes the link for a published share: a short link through the API when the share's life allows it,
 * otherwise (or when the API refuses or cannot be reached) the full link, with a visible notice.
 * Only a failure to build or sign the link itself throws; the link service never fails a publish.
 */
export async function publishLink(input: {
  readonly material: LinkMaterial;
  /** The share's own expiry. */
  readonly expiresAt: string;
  readonly signer: LinkSigner;
  readonly shareOrigin: string;
  readonly now?: () => number;
} & LinkApiOptions): Promise<LinkPublication> {
  const now = (input.now ?? Date.now)();
  const expiresMs = Date.parse(input.expiresAt);
  if (!Number.isFinite(expiresMs)) throw new TypeError("share expiry is not a date");
  const body = fromBase64Url(input.material.sealedEnvelope);
  // One limit for every link, stored or full: a share over it has no link.
  if (body.byteLength > LINK_BODY_MAX_BYTES) throw new ShareTooLargeForLink();
  const header = await buildHeader({ type: "share", issuer: input.signer.issuerDid, audience: input.apiOrigin, issuedAt: new Date(now), expiresAt: new Date(expiresMs), body });
  if (header.bodyCid !== input.material.shareCid) throw new Error("sealed share does not match its content id");
  const signature = await signObject(HEADER_DOMAIN, header, input.signer.sign);
  const choice = chooseLink((expiresMs - now) / 1000);
  const full = (notice: string | undefined): LinkPublication => {
    const url = buildFullLink({ origin: input.shareOrigin, key: input.material.envelopeKey, record: { body: toBase64Url(body), header, signature } });
    if (url.length - url.indexOf("#") > MAX_FULL_LINK_FRAGMENT) throw new ShareTooLargeForLink();
    return { url, form: "full", ...(notice === undefined ? {} : { notice }) };
  };
  if (choice.form === "full") return full(choice.warning ? LINK_LONG_LIFE_NOTICE : undefined);
  try {
    const created = await createLink({ header, signature, body }, input);
    return { url: buildShortLink({ origin: input.shareOrigin, type: "share", id: created.id, key: input.material.envelopeKey, cid: header.bodyCid }), form: "short" };
  } catch {
    return full(SHORT_LINK_UNAVAILABLE_NOTICE);
  }
}
