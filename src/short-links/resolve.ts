import { encodeSealedInlineShareUrl, fromBase64Url, verifyCid } from "@tinycloud/share-envelope";
import { parseShortLink } from "./codec.js";
import { ShortLinkError } from "./errors.js";

/** Sealed bytes above this size are refused. The contract cap is 128 KiB; the SDK inline limit is 256 KiB. */
export const MAX_SEALED_BYTES = 128 * 1024;
const TIMEOUT_MS = 15_000;

/**
 * Fetch the sealed bytes for a short link and return the equivalent inline `v=2` link.
 *
 * The request carries only the lowercased id in its path. The content key and CID never
 * leave the browser: the CID is checked locally against the fetched bytes.
 */
export async function inlineHrefForShortLink(
  shortHref: string,
  shareOrigin: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const parts = parseShortLink(shortHref);
  if (parts === undefined) throw new ShortLinkError("unavailable", "short link is malformed");
  const url = new URL(`/api/share-links/${parts.id}`, shareOrigin);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        signal: controller.signal,
      });
    } catch {
      throw new ShortLinkError("unavailable", "short link lookup failed");
    }
    if (response.status === 404) throw new ShortLinkError("gone", "share is no longer available");
    if (response.status !== 200) throw new ShortLinkError("unavailable", "short link lookup returned an unexpected status");
    const contentType = (response.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
    if (contentType !== "application/octet-stream") {
      throw new ShortLinkError("unavailable", "short link response has an unexpected content type");
    }
    const declared = response.headers.get("content-length");
    if (declared !== null && Number(declared) > MAX_SEALED_BYTES) {
      throw new ShortLinkError("unavailable", "short link response is too large");
    }
    const bytes = await readCapped(response, controller.signal);
    if (bytes.byteLength === 0) throw new ShortLinkError("unavailable", "short link response is empty");
    if (!(await verifyCid(bytes, parts.cid))) {
      throw new ShortLinkError("unavailable", "short link response does not match its content id");
    }
    return encodeSealedInlineShareUrl({
      origin: shareOrigin,
      ciphertext: bytes,
      key32: fromBase64Url(parts.key),
    });
  } catch (error) {
    if (error instanceof ShortLinkError) throw error;
    throw new ShortLinkError("unavailable", "short link lookup failed");
  } finally {
    clearTimeout(timer);
  }
}

async function readCapped(response: Response, signal: AbortSignal): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let aborted = false;
  const onAbort = (): void => {
    aborted = true;
    void reader.cancel();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_SEALED_BYTES) {
        await reader.cancel();
        throw new ShortLinkError("unavailable", "short link response is too large");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ShortLinkError) throw error;
    throw new ShortLinkError("unavailable", aborted ? "short link lookup timed out" : "short link response could not be read");
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
