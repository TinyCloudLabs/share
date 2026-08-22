import { parseNativeShareUrl } from "@tinycloud/share-sdk";
import { TinyCloudWeb } from "@tinycloud/web-sdk";

type ReceivedAccess = { readonly ok: true; readonly data: { readonly data: unknown; readonly path: string; readonly spaceId: string; readonly host: string; readonly delegation: { readonly expiry: Date | string } } } | { readonly ok: false; readonly error: { readonly message: string } };

/** Receive the fragment token through TinyCloud SDK and invoke the delegated owner path. */
export async function receiveNativeBearerAccess(href: string, receive: (token: string) => Promise<unknown> = (token) => TinyCloudWeb.receiveShare<Uint8Array>(token, undefined, { binary: true })): Promise<{ readonly path: string; readonly spaceId: string; readonly ownerNodeOrigin: string; readonly expiresAt: string; readonly bytes: Uint8Array }> {
  const received = await receive(parseNativeShareUrl(href)) as ReceivedAccess;
  if (!received.ok) throw new Error(received.error.message);
  if (!(received.data.data instanceof Uint8Array)) throw new Error("TinyCloud owner node returned invalid shared bytes");
  const expiresAt = new Date(received.data.delegation.expiry);
  if (!Number.isFinite(expiresAt.getTime())) throw new Error("TinyCloud delegation expiry is invalid");
  return { path: received.data.path, spaceId: received.data.spaceId, ownerNodeOrigin: received.data.host, expiresAt: expiresAt.toISOString(), bytes: received.data.data.slice() };
}

export async function receiveNativeBearer(href: string, receive?: (token: string) => Promise<unknown>): Promise<Uint8Array> {
  return (await receiveNativeBearerAccess(href, receive)).bytes;
}
