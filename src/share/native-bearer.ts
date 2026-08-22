/**
 * This structural boundary intentionally mirrors the public share-sdk adapter.
 * Share's release build consumes the published SDK, so it cannot import an
 * export that is still being added in the companion SDK PR.  Keeping the
 * small boundary here lets the two PRs land independently without changing
 * the authority protocol: `sharing` is the public TinyCloud service.
 */
export interface NativeSharingService {
  generate(params: { readonly path: string; readonly actions: string[]; readonly expiry: Date }): Promise<unknown>;
  receive(token: string, options: { readonly autoSubdelegate: false; readonly useSessionKey: false }): Promise<unknown>;
}

function canonicalViewerUrl(viewerOrigin: string): URL {
  const url = new URL(viewerOrigin);
  if (url.protocol !== "https:" || url.origin !== viewerOrigin || url.pathname !== "/" || url.search || url.hash) throw new TypeError("viewer origin must be a canonical HTTPS origin");
  url.pathname = "/viewer";
  return url;
}

async function createNativeShare(sharing: NativeSharingService, input: { readonly path: string; readonly expiresAt: Date; readonly viewerOrigin: string }): Promise<{ readonly url: string; readonly delegationCid: string; readonly expiresAt: Date }> {
  const generated = await sharing.generate({ path: input.path, actions: ["tinycloud.kv/get"], expiry: input.expiresAt }) as { readonly ok?: unknown; readonly data?: { readonly token?: unknown; readonly delegation?: { readonly cid?: unknown }; readonly expiresAt?: unknown }; readonly error?: { readonly message?: unknown } };
  if (generated.ok !== true) throw new Error(typeof generated.error?.message === "string" ? generated.error.message : "TinyCloud sharing service rejected delegation generation");
  if (typeof generated.data?.token !== "string" || typeof generated.data.delegation?.cid !== "string" || !(generated.data.expiresAt instanceof Date)) throw new Error("TinyCloud sharing service returned incomplete delegation metadata");
  const url = canonicalViewerUrl(input.viewerOrigin);
  url.hash = `tc1=${encodeURIComponent(generated.data.token)}`;
  return { url: url.toString(), delegationCid: generated.data.delegation.cid, expiresAt: generated.data.expiresAt };
}

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
): Promise<{ readonly url: string; readonly delegationCid: string; readonly expiresAt: Date }> {
  const spaceId = owner.spaceId;
  if (spaceId === undefined || spaceId.length === 0) throw new Error("TinyCloud owner session has no resolved applications space");
  const written = await owner.kvForSpace(spaceId).put(input.path, input.bytes.slice(), input.contentType === undefined ? undefined : { contentType: input.contentType });
  if (!written.ok) throw new Error(written.error?.message || "TinyCloud owner node rejected shared bytes");
  return createNativeShare(owner.sharing, {
    path: input.path,
    expiresAt: input.expiresAt,
    viewerOrigin: input.viewerOrigin,
  });
}
