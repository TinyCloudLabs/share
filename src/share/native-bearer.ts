import { createNativeShare, type NativeSharingService } from "@tinycloud/share-sdk";

/** The tiny bearer-only compose seam. It has no registry, policy, or delivery dependency. */
export interface NativeBearerOwner {
  readonly kv: { put(path: string, bytes: Uint8Array): Promise<{ readonly ok: boolean }> };
  readonly sharing: NativeSharingService;
}

export async function composeNativeBearer(
  owner: NativeBearerOwner,
  input: { readonly path: string; readonly bytes: Uint8Array; readonly expiresAt: Date; readonly viewerOrigin: string },
): Promise<string> {
  const written = await owner.kv.put(input.path, input.bytes.slice());
  if (!written.ok) throw new Error("TinyCloud owner node rejected shared bytes");
  return createNativeShare(owner.sharing, {
    path: input.path,
    expiresAt: input.expiresAt,
    viewerOrigin: input.viewerOrigin,
  });
}
