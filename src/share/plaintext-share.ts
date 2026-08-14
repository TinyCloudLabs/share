import { canonicalize, computeCid, encodeInlineShareUrl, parseInlineShareUrl } from "@tinycloud/share-envelope";
import type { SenderShareRecord } from "@tinycloud/share-sdk";

export interface PlaintextShareManifest { readonly type: "tinycloud.public-share/v1"; readonly filename: string; readonly mediaType: string; readonly byteLength: number; readonly contentCid: string; readonly expiresAt: string; readonly origin: string }

const MANIFEST_KEYS = ["byteLength", "contentCid", "expiresAt", "filename", "mediaType", "origin", "type"] as const;
const MAX_MANIFEST_BYTES = 16 * 1024;
const MAX_CONTENT_BYTES = 100 * 1024 * 1024;
const CID = /^b[a-z2-7]+$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateManifest(value: unknown, expectedOrigin: string, now: number): PlaintextShareManifest {
  if (!isPlainObject(value) || Object.keys(value).sort().join("\0") !== [...MANIFEST_KEYS].sort().join("\0")) throw new Error("plaintext manifest invalid");
  const { type, filename, mediaType, byteLength, contentCid, expiresAt, origin } = value;
  const expiry = typeof expiresAt === "string" ? Date.parse(expiresAt) : Number.NaN;
  if (
    type !== "tinycloud.public-share/v1"
    || typeof filename !== "string"
    || filename.length === 0
    || filename !== filename.trim()
    || new TextEncoder().encode(filename).byteLength > 240
    || /[\/\\\u0000-\u001f\u007f]/.test(filename)
    || typeof mediaType !== "string"
    || mediaType.length === 0
    || mediaType.length > 255
    || !/^[\x21-\x7e]+\/[\x21-\x7e]+$/.test(mediaType)
    || !Number.isSafeInteger(byteLength)
    || (byteLength as number) < 1
    || (byteLength as number) > MAX_CONTENT_BYTES
    || typeof contentCid !== "string"
    || !CID.test(contentCid)
    || typeof expiresAt !== "string"
    || !Number.isFinite(expiry)
    || new Date(expiry).toISOString() !== expiresAt
    || expiry <= now
    || origin !== expectedOrigin
  ) throw new Error("plaintext manifest invalid");
  return value as unknown as PlaintextShareManifest;
}

async function readBounded(response: Response, maxBytes: number, label: string): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) throw new Error(`${label} exceeds size limit`);
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error(`${label} exceeds size limit`);
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export function plaintextHistoryRecord(input: { cid: string; url: string; filename: string; origin: string; expiresAt: string; registeredAt: string }): SenderShareRecord {
  return { shareId: input.cid, target: { origin: input.origin, nodeAudience: "public", spaceId: "public" }, resource: { kind: "exact", path: input.filename }, actions: ["tinycloud.kv/get"], recipientMatcher: { kind: "bearer" }, targetKind: "bearer", registeredAt: input.registeredAt, expiresAt: input.expiresAt, link: input.url, filename: input.filename };
}

export async function publishPlaintextShare(input: { bytes: Uint8Array; filename: string; mediaType: string; expiresAt: string; origin: string; inline: boolean; upload: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void> }): Promise<{ url: string; cid: string }> {
  const contentCid = await computeCid(input.bytes);
  const manifest: PlaintextShareManifest = { type: "tinycloud.public-share/v1", filename: input.filename, mediaType: input.mediaType, byteLength: input.bytes.byteLength, contentCid, expiresAt: input.expiresAt, origin: input.origin };
  const blob = new TextEncoder().encode(canonicalize(manifest));
  const cid = await computeCid(blob);
  await input.upload(contentCid, input.bytes, input.expiresAt);
  if (!input.inline) await input.upload(cid, blob, input.expiresAt);
  return { cid, url: input.inline ? await encodeInlineShareUrl({ origin: input.origin, ciphertext: blob }) : `${input.origin}/s/${cid}` };
}

export async function resolvePlaintextShare(href: string, input: { expectedOrigin: string; registryBaseUrl: string; fetchFn: typeof fetch; now?: () => number }): Promise<{ manifest: PlaintextShareManifest; bytes: Uint8Array; cid: string } | undefined> {
  const url = new URL(href);
  if (url.origin !== input.expectedOrigin) return undefined;
  let blob: Uint8Array; let cid: string;
  if (url.pathname === "/s/inline") {
    const parsed = parseInlineShareUrl(href, { expectedOrigin: input.expectedOrigin });
    if (parsed.key32 !== undefined) return undefined;
    blob = parsed.ciphertext; cid = parsed.ciphertextCid;
    if (blob.byteLength > MAX_MANIFEST_BYTES) throw new Error("plaintext manifest exceeds size limit");
  } else if (/^\/s\/b[a-z2-7]+$/.test(url.pathname) && url.hash === "") {
    cid = url.pathname.slice(3);
    const response = await input.fetchFn.call(globalThis, `${input.registryBaseUrl}/ipfs/${cid}`);
    if (!response.ok) return undefined;
    blob = await readBounded(response, MAX_MANIFEST_BYTES, "plaintext manifest");
  } else return undefined;
  if (await computeCid(blob) !== cid) throw new Error("plaintext manifest CID mismatch");
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(blob);
    parsed = JSON.parse(text) as unknown;
  } catch {
    // A compact encrypted URL without its fragment has the same keyless URL
    // shape. Let the encrypted receiver report that incomplete-link state.
    return undefined;
  }
  if (!isPlainObject(parsed) || parsed.type !== "tinycloud.public-share/v1") return undefined;
  const value = validateManifest(parsed, input.expectedOrigin, input.now?.() ?? Date.now());
  if (canonicalize(value) !== text) throw new Error("plaintext manifest invalid");
  const contentResponse = await input.fetchFn.call(globalThis, `${input.registryBaseUrl}/ipfs/${value.contentCid}`);
  if (!contentResponse.ok) throw new Error("plaintext content unavailable");
  const bytes = await readBounded(contentResponse, value.byteLength, "plaintext content");
  if (bytes.byteLength !== value.byteLength || await computeCid(bytes) !== value.contentCid) throw new Error("plaintext content integrity failure");
  return { manifest: value, bytes, cid };
}
