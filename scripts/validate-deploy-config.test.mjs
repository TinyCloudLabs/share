import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

const script = new URL("./validate-deploy-config.mjs", import.meta.url);
const bundle = JSON.stringify({
  version: "tinycloud.share-email-trust-bundle/v1",
  shareOrigin: "https://share.tinycloud.xyz",
  returnOrigin: "https://share.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://witness.credentials.org",
  nodeOrigin: "https://node.tinycloud.xyz",
  nodeAudience: "did:web:node.tinycloud.xyz",
  nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-key-1",
  nodeInvitationPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  nodeKeyVersion: 1,
  nodeEnabled: true,
  issuerDid: "did:web:issuer.credentials.org",
  issuerVct: "opencredentials.email/v1",
  issuerKid: "did:web:issuer.credentials.org#email-signing-key-1",
  issuerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  issuerKeyVersion: 1,
  issuerEnabled: true,
});

function run(overrides = {}) {
  return execFileSync(process.execPath, [script.pathname], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, SHARE_API_IMAGE: `ghcr.io/tinycloudlabs/share-api@sha256:${"a".repeat(64)}`, SHARE_TRUST_BUNDLE: bundle, SHARE_RELEASE_PROVENANCE: JSON.stringify({ releaseId: "release-test", shareCommit: "a".repeat(40), nodeCommit: "b".repeat(40), openCredentialsCommit: "c".repeat(40), sdkCommit: "d".repeat(40), shareApiImage: `ghcr.io/tinycloudlabs/share-api@sha256:${"a".repeat(64)}`, configurationDigest: `sha256:${"e".repeat(64)}`, migrationVersion: "migration-1", rollbackImage: `ghcr.io/tinycloudlabs/share-api@sha256:${"f".repeat(64)}`, rollbackReleaseId: "release-previous" }), ...overrides },
  });
}

test("requires immutable Share API deployment provenance", () => {
  assert.match(run(), /valid production composition/);
  assert.throws(() => run({ SHARE_API_IMAGE: "ghcr.io/tinycloudlabs/share-api:latest" }), /immutable registry digest/);
  assert.throws(() => run({ SHARE_BINDING_STORE_ROOT: "/tmp/share-review-root" }), /fixed to the named Share volume/);
  assert.throws(() => run({ SHARE_RELEASE_PROVENANCE: undefined }), /SHARE_RELEASE_PROVENANCE is required/);
  assert.throws(() => run({ SHARE_RELEASE_PROVENANCE: JSON.stringify({ releaseId: "release-test" }) }), /bind reviewed commits/);
});

test("forbids hermetic loopback/browser-origin CSP and auth variables in production deployment configuration", () => {
  for (const name of ["SHARE_HERMETIC_OPENKEY_ORIGIN", "SHARE_HERMETIC_WALLET_ORIGIN", "SHARE_HERMETIC_BROWSER_ORIGIN", "SHARE_HERMETIC_REGISTRY_ORIGIN"]) {
    assert.throws(() => run({ [name]: "http://127.0.0.1:4200" }), new RegExp(`${name} is forbidden in production deployment configuration`));
  }
});

// TC-372. The trust bundle holds no secret, so a deployment may take it from
// the reviewed document in the repository instead of a sealed environment.
test("accepts the committed trust bundle as a deploy source", () => {
  assert.match(run({ SHARE_TRUST_BUNDLE: undefined, SHARE_TRUST_BUNDLE_SOURCE: "committed" }), /valid production composition/);
  assert.match(run({ SHARE_TRUST_BUNDLE_SOURCE: "environment" }), /valid production composition/);
});

test("refuses an ambiguous or unrecognised trust bundle source", () => {
  assert.throws(() => run({ SHARE_TRUST_BUNDLE_SOURCE: "committed" }), /exactly one Share trust bundle source/);
  assert.throws(() => run({ SHARE_TRUST_BUNDLE: undefined, SHARE_TRUST_BUNDLE_SOURCE: "committed", SHARE_TRUST_BUNDLE_FILE: "/dev/null" }), /exactly one Share trust bundle source/);
  assert.throws(() => run({ SHARE_TRUST_BUNDLE_SOURCE: "url" }), /must be exactly "committed" or "environment"/);
  assert.throws(() => run({ SHARE_TRUST_BUNDLE: undefined }), /SHARE_TRUST_BUNDLE or SHARE_TRUST_BUNDLE_FILE is required/);
});

test("still rejects the test escape hatch and legacy sender authority under the committed source", () => {
  const committed = { SHARE_TRUST_BUNDLE: undefined, SHARE_TRUST_BUNDLE_SOURCE: "committed" };
  assert.throws(() => run({ ...committed, SHARE_TRUST_BUNDLE_ALLOW_TEST: "true" }), /SHARE_TRUST_BUNDLE_ALLOW_TEST is forbidden/);
  assert.throws(() => run({ ...committed, SHARE_SENDER_PRIVATE_KEY: "some-value" }), /static sender authority variables are forbidden/);
});
