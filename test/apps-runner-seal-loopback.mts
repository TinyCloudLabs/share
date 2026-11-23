// Run with: npx tsx test/apps-runner-seal-loopback.mts http://127.0.0.1:<node-port> http://127.0.0.1:<registry-port>
// Use a disposable named-key-enabled node. The local wallet stands in for the
// approval callback only; the SDK prepares, verifies and activates the grant.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { NodeWasmBindings, PrivateKeySigner, TinyCloudNode } from "@tinycloud/node-sdk";
import * as sdk from "@tinycloud/sdk-core";

import { createAppData } from "../src/apps/app-data.ts";
import { createCapabilityBridge } from "../src/apps/bridge.ts";
import { makeAuthorizer } from "../src/apps/grants.ts";
import { signInPlan } from "../src/apps/run.ts";
import { bindSeal } from "../src/apps/seal.ts";
import type { CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import { assertManifestInScope, MANIFEST_CHECK_ADDRESS } from "../src/share/manifest-policy.ts";

const host = new URL(process.argv[2] ?? "");
const registry = new URL(process.argv[3] ?? "");
assert.match(registry.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(host.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
const info = await fetch(new URL("/info", host)).then((response) => response.json());
assert.ok(info.features.includes("encryption-named-keys-v1"));
const wasmBindings = new NodeWasmBindings();
const signer = new PrivateKeySigner(randomBytes(32).toString("hex"));
const config = {
  host: host.origin, tinycloudRegistryUrl: registry.origin, signer, wasmBindings,
  domain: "share.tinycloud.xyz", autoBootstrapAccount: false, autoCreateSpace: true,
  enablePublicSpace: false,
};
const owner = new TinyCloudNode({
  ...config,
  manifest: {
    app_id: "xyz.tinycloud.share", name: "Fixture setup", space: "applications",
    includePublicSpace: false,
    permissions: [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:{owner}:default", actions: ["network.create"] }],
  },
});
await owner.signIn();
await owner.ensureEncryptionNetwork();
await owner.ensureOwnedSpaceHosted("applications");

const appId = "xyz.tinycloud.tinyapps.contacts";
const keyPath = `apps/xyz.tinycloud.share/${appId}/seal-v1`;
const manifest: sdk.Manifest = {
  app_id: appId, name: "Contacts", defaults: false, space: "applications", includePublicSpace: false,
  permissions: [{ service: "tinycloud.kv", path: "person/", actions: ["get", "put"] }],
  keys_app_id: "xyz.tinycloud.share",
  keys: [{ path: keyPath, abilities: ["decrypt", "key.create"] }],
};
const plan = signInPlan({ ok: true, manifest }, sdk);
assertManifestInScope(plan.manifest, plan.scope, MANIFEST_CHECK_ADDRESS);
const client = new TinyCloudNode({ ...config, manifest: plan.manifest, includeAccountRegistryPermissions: false });
let approvals = 0;
await client.signInWithOpenKey(async ({ siwe }) => {
  approvals += 1;
  const all = sdk.extractRecapAttenuations(siwe);
  const encryption = Object.entries(all).filter(([resource]) => resource.startsWith("urn:tinycloud:encryption:"));
  assert.equal(encryption.length, 1);
  assert.equal(encryption[0]?.[0], `${owner.getDefaultEncryptionNetworkId()}/${keyPath}`);
  assert.deepEqual(Object.keys(encryption[0]![1]).sort(), ["tinycloud.encryption/decrypt", "tinycloud.encryption/key.create"]);
  const permissions = Object.entries(all).map(([resource, actions]) => ({
    ...sdk.parseCanonicalRecapResource(resource),
    service: Object.keys(actions)[0]!.split("/")[0]!,
    actions: Object.keys(actions),
  }));
  return {
    protocolVersion: 1,
    address: await signer.getAddress(),
    signature: await signer.signMessage(siwe),
    signedMessage: siwe,
    selectedActionKeys: permissions.flatMap(({ service, space, path, actions }) =>
      actions.map((ability) => [service, space, path, ability].join("\0")),
    ),
    permissions,
  };
});
assert.equal(approvals, 1);
const session = client.session;
assert.ok(session);
const seal = await bindSeal(keyPath, {
  address: session.address, chainId: session.chainId, walletAddress: session.address,
  sessionKey: session.sessionKey, siwe: session.siwe, signature: session.signature,
}, () => client.keys);
assert.ok(seal);
const space = client.space("applications");
const data = createAppData(space.kv, client.sqlForSpace(space.id));
let reply: (result: CapResult) => void;
const bridge = createCapabilityBridge({
  appId, authorize: makeAuthorizer(plan.manifest, sdk), data, seal,
  reply: (_id, result) => reply(result),
});
let count = 0;
function call(op: string, args: Record<string, unknown>): Promise<CapResult> {
  return new Promise((resolve) => {
    reply = resolve;
    bridge.handle({ type: `cap/${op}`, body: { id: String(++count), args } });
  });
}
const value = { email: "alex@example.com", tags: ["Amis"], memo: "Écrire bientôt." };
const encrypted = await call("seal.encrypt", { value });
assert.ok(encrypted.ok && typeof encrypted.sealed === "string", JSON.stringify(encrypted));
assert.ok(!encrypted.sealed.includes(value.email));
const written = await call("kv.put", { key: "person/alex", body: JSON.stringify({ name: "Alex", sealed: encrypted.sealed }) });
assert.equal(written.ok, true, JSON.stringify(written));
const read = await call("kv.get", { key: "person/alex" });
assert.ok(read.ok && read.bytes instanceof Uint8Array, JSON.stringify(read));
const saved = JSON.parse(new TextDecoder().decode(read.bytes));
assert.deepEqual(await call("seal.decrypt", { sealed: saved.sealed }), { ok: true, value });
assert.equal(approvals, 1);
bridge.close();
console.log("One exact-key grant and one versioned approval signed. Sealed JSON survived a KV write/read and opened with the packaged SDK and node.");
