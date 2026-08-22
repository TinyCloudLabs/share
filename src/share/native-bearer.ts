import { createNativeShare, type NativeSharingService } from "@tinycloud/share-sdk";

/** The tiny bearer-only compose seam. It has no registry, policy, or delivery dependency. */
export interface NativeBearerOwner {
  /** The authenticated owner's applications space, selected by the caller. */
  readonly kvForSpace: (space: "applications") => { put(path: string, bytes: Uint8Array, options?: { readonly contentType?: string }): Promise<{ readonly ok: boolean; readonly error?: { readonly message?: string } }> };
  readonly sharing: NativeSharingService;
}

export async function composeNativeBearer(
  owner: NativeBearerOwner,
  input: { readonly path: string; readonly bytes: Uint8Array; readonly expiresAt: Date; readonly viewerOrigin: string; readonly contentType?: string },
): Promise<string> {
  const written = await owner.kvForSpace("applications").put(input.path, input.bytes.slice(), input.contentType === undefined ? undefined : { contentType: input.contentType });
  if (!written.ok) throw new Error(written.error?.message || "TinyCloud owner node rejected shared bytes");
  return createNativeShare(owner.sharing, {
    path: input.path,
    expiresAt: input.expiresAt,
    viewerOrigin: input.viewerOrigin,
  });
}
