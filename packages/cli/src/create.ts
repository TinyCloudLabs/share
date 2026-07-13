/**
 * Bearer CREATE flow (blueprint §2.1 embedded-key target, §11 slice 1) — the
 * library entry the CLI and the e2e suite share. For a BEARER share of one
 * markdown file it:
 *
 *   1. generates a fresh ed25519 SESSION keypair (the bearer key) and derives
 *      its did:key — this is the principal every link holder becomes;
 *   2. mints the bearer delegation with `mintBearerDelegation` (the SAME
 *      module the viewer's `checkBearerDelegation` lives in, so the resource
 *      convention and abilities cannot drift) — a self-issued stand-in for
 *      the owner-signed chain that replaces it in the policy/recipient-DID
 *      slices;
 *   3. seals the FILE CONTENT as its own AEAD blob under a fresh content key
 *      (stage-4 content path: the registry serves the bytes because
 *      possession of the link IS the bearer authority; later slices fetch
 *      from the node instead and carry no `content` pointer);
 *   4. builds + signs the ShareEnvelope (bearerKey target, exact resource,
 *      signed `content` pointer carrying the content blob's CID + key);
 *      the SENDER key is itself fresh and self-issued — bearer senders are
 *      unverified by design and the viewer must render them as such;
 *   5. uploads content blob then envelope blob (create-only, required
 *      deleteAfter = share expiry) — content first, so a published link
 *      never points at not-yet-uploaded content;
 *   6. returns the `/s/<envelopeCid>#k=<envelopeKey>` share URL.
 *
 * Fail closed everywhere: bad inputs throw before anything is uploaded, and
 * a minted envelope is re-checked with the viewer's own binding check before
 * it is sealed (a create/verify drift aborts the create, it never ships).
 */
import { ed25519 } from "@noble/curves/ed25519";

import {
  bearerResourceUri,
  checkBearerDelegation,
  didKeyFromEd25519PublicKey,
  encodeShareUrl,
  generateKey,
  isCanonicalHttpsOrigin,
  mintBearerDelegation,
  seal,
  signEnvelope,
  toBase64Url,
  type ShareEnvelope,
  type UnsignedShareEnvelope,
} from "@tinycloud/share-envelope";
import { DEFAULT_MAX_BLOB_BYTES, putBlob } from "@tinycloud/share-registry";

/** Default share lifetime when --expires is not given: 30 days. */
export const DEFAULT_EXPIRES_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Sealed-blob framing overhead (version byte + 12-byte nonce + 16-byte GCM
 * tag): the largest file the registry's blob cap can carry.
 */
export const SEAL_OVERHEAD_BYTES = 1 + 12 + 16;
export const MAX_CONTENT_BYTES = DEFAULT_MAX_BLOB_BYTES - SEAL_OVERHEAD_BYTES;

const DEFAULT_VIEWER_ORIGIN = "https://share.tinycloud.xyz";
const DEFAULT_NODE_AUDIENCE = "did:web:node.tinycloud.xyz";
const DEFAULT_SPACE_ID = "bearer";

export interface CreateBearerShareOptions {
  /** The file bytes to share (markdown in this slice). */
  content: Uint8Array;
  /** Display filename; becomes the last segment of the share path. */
  filename: string;
  /** Registry base URL (dev registry or production front door). */
  registryBaseUrl: string;
  /** Share expiry; default now + 30 days. Must be in the future. */
  expiresAt?: Date;
  /** Optional display sender name (UNVERIFIED in bearer mode, by design). */
  senderName?: string;
  /**
   * Target node origin for the signed target/resource URI. The bearer slice
   * has no owner node, so this is a convention placeholder; later slices set
   * the real node origin here. Default: the viewer origin.
   */
  origin?: string;
  /** Advisory node audience DID recorded in the signed target. */
  nodeAudience?: string;
  /** Space id used in the signed target + resource URI convention. */
  spaceId?: string;
  /** Origin the printed /s/… link uses. Default https://share.tinycloud.xyz. */
  viewerOrigin?: string;
  /** Fetch override — tests inject the in-process dev-registry handler. */
  fetchFn?: typeof globalThis.fetch;
  /** Clock override. */
  now?: () => number;
  /**
   * Observability hook: receives every secret key buffer this flow generates
   * (session private key, sender private key, content key, envelope key) at
   * generation time. Exists so tests can assert the key-hygiene contract —
   * every buffer is zeroed on EVERY exit path, success and failure alike.
   * Never use it to copy key material.
   */
  onKeyBuffer?: (key: Uint8Array) => void;
}

export interface CreateBearerShareResult {
  /** The share link: `<viewerOrigin>/s/<envelopeCid>#k=<key>`. */
  url: string;
  shareId: string;
  /** CID of the sealed ENVELOPE blob (what the link addresses). */
  envelopeCid: string;
  /** CID of the sealed CONTENT blob (what envelope.content points at). */
  contentCid: string;
  /** Signed envelope expiry (ISO 8601). */
  expiry: string;
  /** Effective registry retention for the envelope blob (may be clamped). */
  registryDeleteAfter: string;
  /** The signed envelope, for inspection/tests. Contains the session key. */
  envelope: ShareEnvelope;
}

/** One path segment: no separators, no traversal, no empty/dot names. */
function assertSafeFilename(filename: string): void {
  if (
    filename.length === 0 ||
    filename === "." ||
    filename === ".." ||
    /[/\\\u0000]/.test(filename)
  ) {
    throw new TypeError(`filename must be a single safe path segment, got ${JSON.stringify(filename)}`);
  }
}

export async function createBearerShare(
  options: CreateBearerShareOptions,
): Promise<CreateBearerShareResult> {
  const {
    content,
    filename,
    registryBaseUrl,
    senderName,
    fetchFn,
  } = options;
  const nowMs = options.now?.() ?? Date.now();
  const viewerOrigin = options.viewerOrigin ?? DEFAULT_VIEWER_ORIGIN;
  const origin = options.origin ?? viewerOrigin;
  const nodeAudience = options.nodeAudience ?? DEFAULT_NODE_AUDIENCE;
  const spaceId = options.spaceId ?? DEFAULT_SPACE_ID;

  assertSafeFilename(filename);
  if (!isCanonicalHttpsOrigin(origin)) {
    throw new TypeError(`origin must be a canonical https origin, got ${origin}`);
  }
  if (content.byteLength === 0) {
    throw new TypeError("content is empty — refusing to share an empty file");
  }
  if (content.byteLength > MAX_CONTENT_BYTES) {
    throw new RangeError(
      `content is ${content.byteLength} bytes; the bearer-slice registry cap allows at most ${MAX_CONTENT_BYTES}`,
    );
  }
  const expiresAt = options.expiresAt ?? new Date(nowMs + DEFAULT_EXPIRES_MS);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= nowMs) {
    throw new RangeError(`expiresAt must be a valid future time, got ${String(options.expiresAt)}`);
  }
  const expiry = expiresAt.toISOString();

  // Unguessable 128-bit share id; each share is its own subtree
  // (blueprint §4 layout convention: shares/<shareId>/…).
  const shareId = toBase64Url(
    globalThis.crypto.getRandomValues(new Uint8Array(16)),
  );
  const path = `shares/${shareId}/${filename}`;

  // 1. Fresh bearer SESSION keypair — the delegatee every link holder becomes.
  const sessionPrivateKey = ed25519.utils.randomPrivateKey();
  options.onKeyBuffer?.(sessionPrivateKey);

  // Fresh self-issued SENDER key. In the bearer slice the sender identity is
  // unverifiable by design (the viewer renders "unverified"); later slices
  // use the owner's real signing key here.
  const senderPrivateKey = ed25519.utils.randomPrivateKey();
  options.onKeyBuffer?.(senderPrivateKey);

  let contentKey: Uint8Array | undefined;
  let envelopeKey: Uint8Array | undefined;
  try {
    const sessionPublicKey = ed25519.getPublicKey(sessionPrivateKey);
    const sessionDid = didKeyFromEd25519PublicKey(sessionPublicKey);

    // 2. Bearer delegation — minted by the SAME module the viewer checks
    //    with. The delegation `exp` is epoch SECONDS while the envelope
    //    expiry is millisecond-precision ISO 8601: CEIL to the next whole
    //    second so delegation exp >= envelope expiry ALWAYS — there is never
    //    a window where the delegation is expired but the envelope (and its
    //    content fetch) is still live.
    const delegation = mintBearerDelegation({
      issuerPrivateKey: senderPrivateKey,
      audienceDid: sessionDid,
      resourceUri: bearerResourceUri(origin, spaceId, path),
      expiresAtSeconds: Math.ceil(expiresAt.getTime() / 1000),
    });

    // 3. Seal the file content as its own blob under a fresh content key.
    contentKey = generateKey();
    options.onKeyBuffer?.(contentKey);
    const sealedContent = await seal(content, contentKey);

    // 4. Build + sign the envelope; the signature covers the content pointer.
    const unsigned: UnsignedShareEnvelope = {
      version: 1,
      shareId,
      delegation,
      authorizationTarget: {
        kind: "bearerKey",
        sessionJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: toBase64Url(sessionPublicKey),
          d: toBase64Url(sessionPrivateKey),
        },
      },
      target: {
        origin,
        nodeAudience,
        spaceId,
        resource: { kind: "exact", path },
      },
      display: {
        ...(senderName !== undefined && senderName.length > 0
          ? { senderName }
          : {}),
        filename,
      },
      expiry,
      content: { cid: sealedContent.cid, key: toBase64Url(contentKey) },
    };
    const envelope = signEnvelope(unsigned, senderPrivateKey);

    // Anti-drift runtime guard: the viewer's own binding check (including
    // the real signature + expiry verification) must accept what we just
    // minted, or the create aborts before anything is uploaded.
    const binding = checkBearerDelegation(envelope, { now: () => nowMs });
    if (!binding.ok) {
      throw new Error(
        `create/verify drift: minted delegation fails the viewer check: ${binding.detail}`,
      );
    }

    // 5. Seal the envelope under the fragment key and upload CONTENT FIRST so
    //    a returned link never points at missing content.
    envelopeKey = generateKey();
    options.onKeyBuffer?.(envelopeKey);
    const sealedEnvelope = await seal(
      new TextEncoder().encode(JSON.stringify(envelope)),
      envelopeKey,
    );
    const putOptions = fetchFn !== undefined ? { fetchFn } : {};
    await putBlob(registryBaseUrl, sealedContent.blob, expiry, putOptions);
    const envelopePut = await putBlob(
      registryBaseUrl,
      sealedEnvelope.blob,
      expiry,
      putOptions,
    );

    // 6. The link. Fragment carries ONLY the envelope key (blueprint §2.1).
    const url = encodeShareUrl({
      origin: viewerOrigin,
      ciphertextCid: sealedEnvelope.cid,
      key32: envelopeKey,
    });

    return {
      url,
      shareId,
      envelopeCid: sealedEnvelope.cid,
      contentCid: sealedContent.cid,
      expiry,
      registryDeleteAfter: envelopePut.deleteAfter,
      envelope,
    };
  } finally {
    // Key hygiene on EVERY exit path — seal/upload/guard failures included,
    // not just success: zero every key buffer this function still holds.
    // (The session private key and content key also live base64url-encoded
    // inside the envelope — that is the bearer design, not a leak.)
    sessionPrivateKey.fill(0);
    senderPrivateKey.fill(0);
    contentKey?.fill(0);
    envelopeKey?.fill(0);
  }
}
