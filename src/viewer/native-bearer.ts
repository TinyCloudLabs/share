import { openNativeShare, type NativeSharingService } from "@tinycloud/share-sdk";

type ReceivedAccess = { readonly ok: true; readonly data: { readonly path: string; readonly kv: { get(path: string): Promise<{ readonly ok: boolean; readonly data?: { readonly data?: Uint8Array } }> } } } | { readonly ok: false; readonly error: { readonly message: string } };

/** Receive the fragment token through TinyCloud SDK and invoke the delegated owner path. */
export async function receiveNativeBearer(sharing: NativeSharingService, href: string): Promise<Uint8Array> {
  const received = await openNativeShare(sharing, href) as ReceivedAccess;
  if (!received.ok) throw new Error(received.error.message);
  // KVService accepts the exact owner-node key. Do not use an empty relative
  // key: its path-prefix configuration is metadata, not request rewriting.
  const read = await received.data.kv.get(received.data.path);
  if (!read.ok || !(read.data?.data instanceof Uint8Array)) throw new Error("TinyCloud owner node denied shared read");
  return read.data.data.slice();
}
