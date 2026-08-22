import { createNativeShare, type NativeSharingService } from "@tinycloud/share-sdk";

export { createNativeShare, openNativeShare, parseNativeShareUrl, type NativeSharingService } from "@tinycloud/share-sdk";

/** The tiny bearer-only compose seam. It has no registry, policy, or delivery dependency. */
export interface NativeBearerOwner {
  /** Resolved authenticated session space used by SharingService.generate(). */
  readonly spaceId: string | undefined;
  readonly kvForSpace: (spaceId: string) => { put(path: string, bytes: Uint8Array, options?: { readonly contentType?: string }): Promise<{ readonly ok: boolean; readonly error?: { readonly message?: string } }> };
  readonly sharing: NativeSharingService;
}

export async function composeNativeBearer(
  owner: NativeBearerOwner,
  input: { readonly path: string; readonly bytes: Uint8Array; readonly expiresAt: Date; readonly viewerOrigin: string; readonly contentType?: string },
): Promise<{ readonly url: string; readonly delegationCid: string; readonly expiresAt: Date; readonly spaceId: string }> {
  const spaceId = owner.spaceId;
  if (spaceId === undefined || spaceId.length === 0) throw new Error("TinyCloud owner session has no resolved applications space");
  const written = await owner.kvForSpace(spaceId).put(input.path, input.bytes.slice(), input.contentType === undefined ? undefined : { contentType: input.contentType });
  if (!written.ok) throw new Error(written.error?.message || "TinyCloud owner node rejected shared bytes");
  const share = await createNativeShare(owner.sharing, {
    path: input.path,
    expiresAt: input.expiresAt,
    viewerOrigin: input.viewerOrigin,
  });
  if (share.spaceId !== spaceId) throw new Error("TinyCloud delegation authority does not match the authenticated owner space");
  return share;
}
