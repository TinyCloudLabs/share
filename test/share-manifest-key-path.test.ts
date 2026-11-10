// The library signs in once with decrypt on the default network's share/ prefix: the node registers a share's policy only for an owner
// holding decrypt on that share's key, and records the key itself. No key creation is asked for. The entry comes from the SDK; the
// sign-in scope guard accepts exactly it and nothing broader.
import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import { resolveManifest } from "@tinycloud/sdk-core";
import type { PermissionEntry } from "@tinycloud/web-sdk";
import { defaultEncryptionNetworkForOwner, pathBoundSessionPermissions } from "@tinycloud/share-sdk";
import { assertManifestInScope, ManifestRejectedError, type ManifestScope } from "../src/share/manifest-policy.js";
import { ownerEncryptionNetwork, SHARE_MANIFEST_SCOPE, shareManifest } from "../src/share/openkey-session.js";

const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const OTHER_ADDRESS = "0x1111111111111111111111111111111111111111";
const DECRYPT = "tinycloud.encryption/decrypt";
const KEY_CREATE = "tinycloud.encryption/key.create";

describe("the library's sign-in manifest", () => {
  it("asks for decrypt on the share/ prefix of the account's own default network, exactly as the SDK names it, and never for key creation", () => {
    const [entry] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: ADDRESS }) });
    expect(shareManifest(ADDRESS).permissions).toContainEqual(expect.objectContaining({ service: "tinycloud.encryption", path: entry!.path }));
    const resources = resolveManifest(shareManifest(ADDRESS)).resources;
    const prefix = resources.filter((resource) => resource.path === `urn:tinycloud:encryption:did:pkh:eip155:1:${getAddress(ADDRESS)}:default/share/`);
    expect(prefix).toHaveLength(1);
    expect(prefix[0]!.actions).toEqual([DECRYPT]);
    expect(resources.some((resource) => resource.actions.includes(KEY_CREATE))).toBe(false);
  });

  it("stays inside the library's sign-in scope, whatever the case of the address", () => {
    expect(() => assertManifestInScope(shareManifest(ADDRESS), SHARE_MANIFEST_SCOPE, ADDRESS)).not.toThrow();
    expect(() => assertManifestInScope(shareManifest(ADDRESS), SHARE_MANIFEST_SCOPE, getAddress(ADDRESS))).not.toThrow();
  });

  const [own] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: ADDRESS }) });
  const [other] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: OTHER_ADDRESS }) });

  it.each<[string, PermissionEntry[]]>([
    ["key.create on the share/ prefix", [{ service: "tinycloud.encryption", path: own!.path, actions: [DECRYPT, KEY_CREATE] }]],
    ["key.create on the bare network", [{ service: "tinycloud.encryption", path: ownerEncryptionNetwork(ADDRESS), actions: [KEY_CREATE] }]],
    ["another account's prefix", [{ service: "tinycloud.encryption", path: other!.path, actions: [DECRYPT] }]],
    ["the prefix on another chain", [{ service: "tinycloud.encryption", path: own!.path.replace(":eip155:1:", ":eip155:10:"), actions: [DECRYPT] }]],
    ["key.create on a kv path (the bare action must not be a wildcard)", [{ service: "tinycloud.kv", path: "xyz.tinycloud.share/x", actions: ["key.create"] }]],
  ])("refuses %s", (_name, permissions) => {
    const manifest = shareManifest(ADDRESS);
    manifest.permissions = [...manifest.permissions!, ...permissions];
    expect(() => assertManifestInScope(manifest, SHARE_MANIFEST_SCOPE, ADDRESS)).toThrow();
  });
});

describe("a scope without the checksum placeholder", () => {
  it("never parses the address as one: a malformed address is not an address error", () => {
    const scope: ManifestScope = { allowedSpaces: ["applications"], allowedServices: ["kv"], allowedActions: ["get"], allowedPathPrefixes: [{ space: "applications", prefix: "app/" }] };
    const manifest = {
      manifest_version: 1, app_id: "app", name: "App", space: "applications", prefix: "app/", defaults: false, includePublicSpace: false,
      permissions: [{ service: "tinycloud.kv", space: "applications", path: "app/x", actions: ["tinycloud.kv/get"] }],
    } as never;
    let thrown: unknown;
    try { assertManifestInScope(manifest, scope, "not-an-address"); } catch (error) { thrown = error; }
    expect(thrown === undefined || thrown instanceof ManifestRejectedError).toBe(true);
    expect((thrown as { name?: string } | undefined)?.name).not.toBe("InvalidAddressError");
  });
});
