import { encodeSealedInlineShareUrl } from "@tinycloud/share-envelope";
import type { ResolvedLink } from "./resolve.js";

/**
 * The receive pipeline in the pinned `@tinycloud/share-sdk` reads the sealed bytes and key from one
 * link string. After this app has verified a `v=4` record, it hands the SDK the same bytes and key in
 * that form, in memory only: the string is never shown, stored, copied or sent by this app. This
 * module goes away when the SDK reads `v=4` links itself.
 */
export async function sdkReceiveLink(resolved: ResolvedLink, shareOrigin: string): Promise<string> {
  return encodeSealedInlineShareUrl({ origin: shareOrigin, ciphertext: resolved.sealedBody, key32: resolved.key });
}
