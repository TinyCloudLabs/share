/**
 * The reader pipeline for a `v=4` link (contract 7.5): parse, fetch (short form), check the record,
 * open the body, check the bindings between link, path, record and seal.
 *
 * The key stays in this module's memory: it is never sent in a request and never logged.
 * Every outcome the link or the record decides is `not-found`; only a failed or unusable
 * exchange with the API is `unavailable`.
 */
import { fromBase64Url } from "@tinycloud/share-envelope";
import { LinkApiError, readLinkRecord, type LinkApiOptions } from "./client.js";
import { parseLink, type LinkRefusal } from "./codec.js";
import { LINK_BODY_MAX_BYTES } from "./limits.js";
import { checkRecord, type LinkHeader, type RecordRefusal } from "./record.js";

export type ReadRefusal = LinkRefusal | RecordRefusal | "gone" | "not_viewable";

export class LinkReadError extends Error {
  /** `not-found`: the link or the record says there is nothing to open. `unavailable`: the lookup could not be completed. */
  readonly kind: "not-found" | "unavailable";
  /** A label for tests. It is never shown and never logged. */
  readonly reason: ReadRefusal | "transport";

  constructor(kind: "not-found" | "unavailable", reason: ReadRefusal | "transport") {
    super(kind);
    this.name = "LinkReadError";
    this.kind = kind;
    this.reason = reason;
  }
}

export interface ResolvedLink {
  readonly type: "share" | "courier";
  readonly header: LinkHeader;
  /** The opened plaintext, a JSON object whose issuer binding was checked. Shape beyond that is the type owner's. */
  readonly plaintext: Record<string, unknown>;
  /** The sealed body bytes and the key that opened them, for the existing receive pipeline. */
  readonly sealedBody: Uint8Array;
  readonly key: Uint8Array;
}

export interface ResolveOptions extends LinkApiOptions {
  /** Viewer origins this reader trusts, from configuration. */
  readonly trustedOrigins: readonly string[];
  readonly now?: () => number;
}

const notFound = (reason: ReadRefusal): LinkReadError => new LinkReadError("not-found", reason);

function strictBody(text: unknown): Uint8Array | undefined {
  if (typeof text !== "string") return undefined;
  try {
    return fromBase64Url(text);
  } catch {
    return undefined;
  }
}

/** A full link's record: exactly `body`, `header` and optionally `signature`. */
function embeddedRecord(value: unknown): { readonly header: unknown; readonly signature?: unknown; readonly body: Uint8Array } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw notFound("record_shape");
  const fields = Object.keys(value).sort().join(",");
  if (fields !== "body,header" && fields !== "body,header,signature") throw notFound("record_fields");
  const { header, signature, body } = value as { header: unknown; signature?: unknown; body: unknown };
  const bytes = strictBody(body);
  if (bytes === undefined) throw notFound("body_encoding");
  return signature === undefined ? { header, body: bytes } : { header, signature, body: bytes };
}

export async function resolveLink(href: string, options: ResolveOptions): Promise<ResolvedLink> {
  const parsed = parseLink(href, options.trustedOrigins);
  if (!parsed.ok) throw notFound(parsed.reason);
  const { link } = parsed;
  // The login page never fetches; the Share viewer serves shares and invitations only.
  if (link.form === "short" && link.pathType === "openkey-login") throw notFound("not_viewable");
  let record: { readonly header: unknown; readonly signature?: unknown; readonly body: Uint8Array };
  if (link.form === "short") {
    try {
      const fetched = await readLinkRecord(link.id, LINK_BODY_MAX_BYTES, options);
      if (fetched === undefined) throw notFound("gone");
      record = fetched;
    } catch (error) {
      if (error instanceof LinkReadError) throw error;
      // A body over the cap or an unreadable response is a record the link cannot use.
      if (error instanceof LinkApiError && error.reason === "invalid_response") throw notFound("record_shape");
      throw new LinkReadError("unavailable", "transport");
    }
  } else {
    record = embeddedRecord(link.record);
  }
  const key = fromBase64Url(link.key);
  const checked = await checkRecord(record, { now: (options.now ?? Date.now)(), key, maxBodyBytes: LINK_BODY_MAX_BYTES });
  if ("refusal" in checked) throw notFound(checked.refusal);
  const { header, plaintext } = checked;
  if (link.form === "short") {
    if (link.pathType !== header.type) throw notFound("type_path_mismatch");
    if (link.cid !== header.bodyCid) throw notFound("link_cid_mismatch");
  } else if (header.type !== "share") {
    throw notFound("full_non_share");
  }
  if (header.type === "openkey-login") throw notFound("not_viewable");
  return { type: header.type, header, plaintext, sealedBody: record.body, key };
}
