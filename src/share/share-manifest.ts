import type { Manifest, PermissionEntry } from "@tinycloud/sdk-core";

export const SHARE_APPLICATION_SPACE = "applications";
export const SHARE_APPLICATION_PREFIX = "xyz.tinycloud.share/";
export const FILES_FOR_YOU_SPACE = "files-for-you";
export const FILES_FOR_YOU_PREFIX = "v1/";

/** The account space, which holds the account's own registry (its spaces, apps and delegation list). */
export const ACCOUNT_SPACE = "account";

/*
 * The owner-policy path works only inside the authenticated sender's
 * applications space. Reads build the library picker; new encrypted share
 * objects are written below `xyz.tinycloud.share/shares/`. These grants never
 * delegate authority or content to the static Share host. The trailing slash
 * is a resource boundary, and `del` is deliberately absent.
 */
export function ownerSpacePermissions(): PermissionEntry[] {
  return [
    { service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: SHARE_APPLICATION_PREFIX, actions: ["get", "list", "metadata"], skipPrefix: true },
    { service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: `${SHARE_APPLICATION_PREFIX}shares/`, actions: ["put"], skipPrefix: true },
  ];
}

export function historyPermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.vault", space: SHARE_APPLICATION_SPACE, path: "sender-history/v2/records/", actions: ["put", "get", "list", "del"], skipPrefix: true }];
}

export function credentialSpacePermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.kv", space: SHARE_APPLICATION_SPACE, path: `${SHARE_APPLICATION_PREFIX}credentials/v1/`, actions: ["get", "put", "list"], skipPrefix: true }];
}

/** Private, recipient-owned copies created only by the post-render save action. */
export function filesForYouPermissions(): PermissionEntry[] {
  return [{ service: "tinycloud.kv", space: FILES_FOR_YOU_SPACE, path: FILES_FOR_YOU_PREFIX, actions: ["get", "put", "list"], skipPrefix: true }];
}

/*
 * The account-registry rows the library reads itself: the delegation list
 * (share status and owner revoke list the account's grants) and the space
 * records (a restored session is checked with one read of its space's record).
 */
export function accountRegistryReadPermissions(): PermissionEntry[] {
  return [
    { service: "tinycloud.delegation", space: ACCOUNT_SPACE, path: "", actions: ["list"], skipPrefix: true },
    { service: "tinycloud.kv", space: ACCOUNT_SPACE, path: "spaces/", actions: ["get"], skipPrefix: true },
  ];
}

/** What Share's own library needs: the owner space, history, credentials and the private copies area, and decrypt on the share/ prefix. */
export const shareManifest: Manifest = {
  manifest_version: 1,
  app_id: "xyz.tinycloud.share",
  name: "TinyCloud Share",
  description: "Create and reopen encrypted shares.",
  space: SHARE_APPLICATION_SPACE,
  prefix: "",
  defaults: false,
  includePublicSpace: false,
  permissions: [
    ...ownerSpacePermissions(),
    ...historyPermissions(),
    ...credentialSpacePermissions(),
    ...filesForYouPermissions(),
    // Decrypt on the share/ prefix with the SDK's {owner} placeholder: resolves to the signer's
    // EIP-55 did:pkh at sign-in so one published /.well-known/openkey-manifest.json matches every owner.
    { service: "tinycloud.encryption", path: "urn:tinycloud:encryption:{owner}:default/share/", actions: ["tinycloud.encryption/decrypt"] },
    ...accountRegistryReadPermissions(),
  ],
};

/** Exact bytes published at `/.well-known/openkey-manifest.json`. */
export const OPENKEY_MANIFEST_PATH = "/.well-known/openkey-manifest.json";

export function renderOpenKeyManifestJson(): string {
  return `${JSON.stringify(shareManifest, null, 2)}\n`;
}
