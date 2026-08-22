import { openNativeShare, type NativeSharingService } from "@tinycloud/share-sdk";

type ReceivedAccess = { readonly ok: true; readonly data: { readonly path: string; readonly spaceId: string; readonly delegation: { readonly expiry: Date }; readonly kv: { get(path: string): Promise<{ readonly ok: boolean; readonly data?: { readonly data?: Uint8Array } }> } } } | { readonly ok: false; readonly error: { readonly message: string } };

/** Receive the fragment token through TinyCloud SDK and invoke the delegated owner path. */
export async function receiveNativeBearerAccess(sharing: NativeSharingService, href: string): Promise<{ readonly path: string; readonly spaceId: string; readonly expiresAt: string; readonly bytes: Uint8Array }> {
  const received = await openNativeShare(sharing, href) as ReceivedAccess;
  if (!received.ok) throw new Error(received.error.message);
  // SharingService configures the received KV service with the delegated
  // exact key as its prefix. An empty relative key therefore invokes that
  // exact key once; repeating `path` would turn it into `path/path`.
  const read = await received.data.kv.get("");
  if (!read.ok || !(read.data?.data instanceof Uint8Array)) throw new Error("TinyCloud owner node denied shared read");
  return { path: received.data.path, spaceId: received.data.spaceId, expiresAt: received.data.delegation.expiry.toISOString(), bytes: read.data.data.slice() };
}

export async function receiveNativeBearer(sharing: NativeSharingService, href: string): Promise<Uint8Array> {
  return (await receiveNativeBearerAccess(sharing, href)).bytes;
}
