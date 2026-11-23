// @vitest-environment node
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { getAddress } from "viem";
import type { Plugin } from "vite";
import {
  composeManifestRequest,
  extractRecapAttenuations,
  MANIFEST_OWNER_PLACEHOLDER,
  manifestUsesOwnerPlaceholder,
  ManifestValidationError,
  pkhDid,
  resolveManifest,
  resolveManifestOwner,
  type ISigner,
  type Manifest,
} from "@tinycloud/sdk-core";
import { NodeUserAuthorization, NodeWasmBindings } from "@tinycloud/node-sdk";
import { defaultEncryptionNetworkForOwner, pathBoundSessionPermissions, planPathBoundShare } from "@tinycloud/share-sdk";
import { decryptNetworkPermission } from "../src/share/history-unlock.js";
import { assertManifestInScope, MANIFEST_CHECK_ADDRESS, ManifestRejectedError } from "../src/share/manifest-policy.js";
import { createNetworkSetup } from "../src/share/network-setup.js";
import {
  accountRegistryReadPermissions,
  credentialSpacePermissions,
  filesForYouPermissions,
  historyPermissions,
  ownerSpacePermissions,
  SHARE_APPLICATION_SPACE,
  SHARE_MANIFEST_SCOPE,
  shareManifest,
} from "../src/share/openkey-session.js";
import viteConfig from "../vite.config.ts";

const LOWERCASE_OWNER = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const MIXED_CASE_OWNER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const SAMPLE_SHARE_ID = "0123456789abcdef0123456789abcdef";

/** Canonical JSON SHA-256 digest matching OpenKey's /authorize-sign-prepare check. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function manifestDigestHex(manifest: unknown): string {
  return createHash("sha256").update(canonicalJson(JSON.parse(JSON.stringify(manifest)))).digest("hex");
}

/** Exact pre-TC-3714 `main` shareManifest(address) output for regression comparison. */
function legacyShareManifest(address: string): Manifest {
  return {
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
      ...pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address }) }),
      ...accountRegistryReadPermissions(),
    ],
  };
}

function stubSigner(address: string): ISigner {
  return {
    getAddress: async () => address,
    getChainId: async () => 1,
    signMessage: async () => { throw new Error("not used in prepareOpenKeySignIn"); },
  };
}

/** Runs the Vite config's `openkey-manifest` plugin and returns the emitted asset source. */
function emitPublishedOpenKeyManifest(): { fileName: string; source: string } {
  const resolved = typeof viteConfig === "function"
    ? viteConfig({ command: "build", mode: "production", isSsrBuild: false, isPreview: false })
    : viteConfig;
  if (resolved instanceof Promise) throw new Error("unexpected async vite config");
  const plugins = (resolved.plugins ?? []).flat();
  const plugin = plugins.find(
    (entry) => typeof entry === "object" && entry !== null && "name" in entry && entry.name === "openkey-manifest",
  ) as Plugin | undefined;
  const hook = plugin?.generateBundle;
  const fn = typeof hook === "function" ? hook : hook?.handler;
  if (fn === undefined) throw new Error("openkey-manifest Vite plugin generateBundle not found");
  const emitted: Array<{ fileName: string; source: string }> = [];
  (fn as (this: { emitFile(file: { type: "asset"; fileName: string; source: string }): void }) => void).call({
    emitFile(file) {
      emitted.push({ fileName: file.fileName, source: file.source });
    },
  });
  expect(emitted).toHaveLength(1);
  return emitted[0]!;
}

/** Walks every JSON key and string value, returning JSON paths that contain `token`. */
function findTokenLocations(value: unknown, token: string, path = "$"): string[] {
  if (typeof value === "string") return value.includes(token) ? [path] : [];
  if (Array.isArray(value)) return value.flatMap((item, index) => findTokenLocations(item, token, `${path}[${index}]`));
  if (value !== null && typeof value === "object") {
    const found: string[] = [];
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (key.includes(token)) found.push(`${path}.<key:${key}>`);
      found.push(...findTokenLocations(inner, token, `${path}.${key}`));
    }
    return found;
  }
  return [];
}

/** Asserts that a `urn:tinycloud:encryption:did:pkh:eip155:1:<addr>:...` path carries the exact EIP-55 address. */
function expectEip55EncryptionOwner(path: string, inputAddress: string): void {
  const checksummed = getAddress(inputAddress);
  expect(checksummed).not.toBe(checksummed.toLowerCase());
  const match = /^urn:tinycloud:encryption:did:pkh:eip155:1:(0x[0-9a-fA-F]{40}):default(?:\/.*)?$/.exec(path);
  expect(match, `unexpected encryption path shape: ${path}`).not.toBeNull();
  expect(match![1]).toBe(checksummed);
}

describe("TC-3714 static shareManifest with {owner} placeholder", () => {
  const wasmBindings = new NodeWasmBindings();

  it("(a) published /.well-known/openkey-manifest.json digest equals the SDK's presentation digest for 2 owners (including mixed case)", async () => {
    const asset = emitPublishedOpenKeyManifest();
    expect(asset.fileName).toBe(".well-known/openkey-manifest.json");
    expect(asset.source).toBe(`${JSON.stringify(shareManifest, null, 2)}\n`);

    const publishedObject = JSON.parse(asset.source) as Manifest;
    const publishedDigest = manifestDigestHex(publishedObject);
    const digests: string[] = [];

    for (const owner of [LOWERCASE_OWNER, MIXED_CASE_OWNER]) {
      const auth = new NodeUserAuthorization({
        signer: stubSigner(owner),
        wasmBindings,
        domain: "share.tinycloud.xyz",
        spacePrefix: SHARE_APPLICATION_SPACE,
        manifest: shareManifest,
        includeAccountRegistryPermissions: true,
        tinycloudHosts: ["https://tee.node.tinycloud.xyz"],
        autoDiscoverLocalNode: false,
      });
      const prepared = await auth.prepareOpenKeySignIn({ host: "https://tee.node.tinycloud.xyz" });
      const presentation = prepared.request.presentation;
      expect(presentation).toBeDefined();
      expect(presentation!.manifestDigest).toBe(publishedDigest);
      expect(presentation!.owner).toBe(`did:pkh:eip155:1:${getAddress(owner)}`);
      expect(presentation!.manifests?.[0]?.payload).toEqual(publishedObject);
      digests.push(presentation!.manifestDigest!);
    }

    expect(digests[0]).toBe(digests[1]);
  });

  it.each([
    ["lowercase", LOWERCASE_OWNER],
    ["mixed-case", MIXED_CASE_OWNER],
  ])("(b) resolved capability request is identical to main shareManifest(address) for a %s address", async (_label, address) => {
    const ownerDid = pkhDid(address, 1);
    const resolvedFromTemplate = resolveManifestOwner(shareManifest, ownerDid);
    const legacy = legacyShareManifest(address);

    expect(resolvedFromTemplate).toEqual(legacy);
    expect(JSON.stringify(resolveManifest(resolvedFromTemplate))).toBe(JSON.stringify(resolveManifest(legacy)));

    for (const includeAccountRegistryPermissions of [true, false]) {
      const fromTemplate = composeManifestRequest([resolvedFromTemplate], { includeAccountRegistryPermissions });
      const fromLegacy = composeManifestRequest([legacy], { includeAccountRegistryPermissions });
      expect(fromTemplate).toEqual(fromLegacy);
      expect(JSON.stringify(fromTemplate)).toBe(JSON.stringify(fromLegacy));
    }

    // End-to-end through NodeUserAuthorization: the SIWE ReCap attenuations match byte-for-byte.
    const makeAuth = (manifest: Manifest) => new NodeUserAuthorization({
      signer: stubSigner(address),
      wasmBindings,
      domain: "share.tinycloud.xyz",
      spacePrefix: SHARE_APPLICATION_SPACE,
      manifest,
      includeAccountRegistryPermissions: true,
      tinycloudHosts: ["https://tee.node.tinycloud.xyz"],
      autoDiscoverLocalNode: false,
    });
    const templatePrepared = await makeAuth(shareManifest).prepareOpenKeySignIn({ host: "https://tee.node.tinycloud.xyz" });
    const legacyPrepared = await makeAuth(legacy).prepareOpenKeySignIn({ host: "https://tee.node.tinycloud.xyz" });
    expect(extractRecapAttenuations(templatePrepared.prepared.siwe)).toEqual(
      extractRecapAttenuations(legacyPrepared.prepared.siwe),
    );
  });

  it("(c) {owner} appears only in permissions[].path and manifest-policy accepts shareManifest for any owner", () => {
    const asset = emitPublishedOpenKeyManifest();
    const published = JSON.parse(asset.source) as Manifest;

    expect(manifestUsesOwnerPlaceholder(shareManifest)).toBe(true);
    const locations = findTokenLocations(published, MANIFEST_OWNER_PLACEHOLDER);
    expect(locations.length).toBeGreaterThan(0);
    for (const location of locations) {
      expect(location).toMatch(/^\$\.permissions\[\d+\]\.path$/);
    }

    const encryptionEntries = shareManifest.permissions!.filter((entry) => entry.service === "tinycloud.encryption");
    expect(encryptionEntries).toEqual([
      {
        service: "tinycloud.encryption",
        path: "urn:tinycloud:encryption:{owner}:default/share/",
        actions: ["tinycloud.encryption/decrypt"],
      },
    ]);

    for (const address of [MANIFEST_CHECK_ADDRESS, LOWERCASE_OWNER, MIXED_CASE_OWNER]) {
      expect(() => assertManifestInScope(shareManifest, SHARE_MANIFEST_SCOPE, address)).not.toThrow();
      const resolved = resolveManifestOwner(shareManifest, pkhDid(address, 1));
      expect(manifestUsesOwnerPlaceholder(resolved)).toBe(false);
    }

    // {owner} outside permissions[].path is refused by both the SDK and manifest-policy.
    const misplaced: Manifest = { ...shareManifest, description: "For {owner}" };
    expect(() => resolveManifestOwner(misplaced, pkhDid(MIXED_CASE_OWNER, 1))).toThrow(ManifestValidationError);
    expect(() => assertManifestInScope(misplaced, SHARE_MANIFEST_SCOPE, MIXED_CASE_OWNER)).toThrow(ManifestRejectedError);
  });

  it.each([
    ["lowercase", LOWERCASE_OWNER],
    ["mixed-case", MIXED_CASE_OWNER],
  ])("(d) every tinycloud.encryption key or prefix path Share emits uses the EIP-55 owner for a %s input address", async (_label, inputAddress) => {
    const checksummed = getAddress(inputAddress);

    // 1. Resolved shareManifest capability request (both composeManifestRequest and SIWE ReCap).
    const resolved = composeManifestRequest([resolveManifestOwner(shareManifest, pkhDid(inputAddress, 1))], {
      includeAccountRegistryPermissions: true,
    });
    const resolvedEncryption = resolved.resources.filter((resource) => resource.service === "tinycloud.encryption");
    expect(resolvedEncryption).toHaveLength(1);
    expectEip55EncryptionOwner(resolvedEncryption[0]!.path, inputAddress);
    expect(resolvedEncryption[0]!.path).toBe(`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default/share/`);

    const auth = new NodeUserAuthorization({
      signer: stubSigner(inputAddress),
      wasmBindings,
      domain: "share.tinycloud.xyz",
      spacePrefix: SHARE_APPLICATION_SPACE,
      manifest: shareManifest,
      includeAccountRegistryPermissions: true,
      tinycloudHosts: ["https://tee.node.tinycloud.xyz"],
      autoDiscoverLocalNode: false,
    });
    const prepared = await auth.prepareOpenKeySignIn({ host: "https://tee.node.tinycloud.xyz" });
    const recapEncryptionKeys = Object.keys(extractRecapAttenuations(prepared.prepared.siwe)).filter((resource) =>
      resource.startsWith("urn:tinycloud:encryption:"),
    );
    expect(recapEncryptionKeys).toEqual([`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default/share/`]);

    // 2. SHARE_MANIFEST_SCOPE after {checksumAddress} substitution: accepts EIP-55, refuses lowercase prefix.
    const scopeEncryptionEntries = (SHARE_MANIFEST_SCOPE.allowedPathPrefixes ?? []).filter(
      (entry): entry is { readonly space: string; readonly prefix: string } => typeof entry !== "string" && entry.space === "encryption",
    );
    expect(scopeEncryptionEntries).toHaveLength(1);
    const substitutedScopePrefix = scopeEncryptionEntries[0]!.prefix.replaceAll("{checksumAddress}", getAddress(inputAddress));
    expectEip55EncryptionOwner(substitutedScopePrefix, inputAddress);
    expect(substitutedScopePrefix).toBe(`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default/share/`);

    const lowercasePrefixManifest: Manifest = {
      ...shareManifest,
      permissions: shareManifest.permissions!.map((entry) =>
        entry.service === "tinycloud.encryption"
          ? { ...entry, path: `urn:tinycloud:encryption:did:pkh:eip155:1:${inputAddress.toLowerCase()}:default/share/` }
          : entry,
      ),
    };
    expect(() => assertManifestInScope(lowercasePrefixManifest, SHARE_MANIFEST_SCOPE, inputAddress)).toThrow(ManifestRejectedError);

    // 3. Per-share key path and registration prefix (composer.ts & owner-revoke.ts ownKeyResource: defaultEncryptionNetworkForOwner + planPathBoundShare).
    const encryptionNetwork = defaultEncryptionNetworkForOwner({ address: inputAddress });
    expectEip55EncryptionOwner(encryptionNetwork, inputAddress);
    const plan = planPathBoundShare({ shareId: SAMPLE_SHARE_ID, encryptionNetwork });
    expectEip55EncryptionOwner(plan.keyResource, inputAddress);
    expect(plan.keyResource).toBe(`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default/share/${SAMPLE_SHARE_ID}`);
    expect(plan.registrationPermissions).toHaveLength(1);
    expectEip55EncryptionOwner(plan.registrationPermissions[0]!.path, inputAddress);
    expect(plan.registrationPermissions[0]!.path).toBe(`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default/share/`);

    // 4. History unlock permission builder (src/share/history-unlock.ts decryptNetworkPermission).
    const historyUnlock = decryptNetworkPermission(inputAddress);
    expect(historyUnlock.service).toBe("tinycloud.encryption");
    expectEip55EncryptionOwner(historyUnlock.path, inputAddress);
    expect(historyUnlock.path).toBe(`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default`);

    // 5. Network setup permission & networkId builder (src/share/network-setup.ts createNetworkSetup).
    const seenRequested: string[] = [];
    const seenEnsured: string[] = [];
    const setup = createNetworkSetup(
      {
        getEncryptionNetwork: async (id) => { expect(id).toBeTypeOf("string"); expectEip55EncryptionOwner(id!, inputAddress); return null; },
        ensureEncryptionNetwork: async (id) => { expect(id).toBeTypeOf("string"); seenEnsured.push(id!); return {} as never; },
        hasPermissions: () => false,
        requestPermissions: async (entries) => {
          for (const entry of entries) if (entry.service === "tinycloud.encryption") seenRequested.push(entry.path);
          return { approved: true } as never;
        },
      },
      { address: inputAddress },
    );
    await setup.ensure();
    expect(seenRequested).toEqual([`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default`]);
    expect(seenEnsured).toEqual([`urn:tinycloud:encryption:did:pkh:eip155:1:${checksummed}:default`]);
  });
});
