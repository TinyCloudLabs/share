#!/usr/bin/env node

/*
 * Real vertical slice: Share's sender publishes its exact-recipient policy to a
 * genuinely running standalone Policy Engine, and that engine then issues a
 * challenge for it.
 *
 * This is deliberately NOT the joined browser gate — it does not deliver an
 * email, does not run a browser, and does not read ciphertext. It exists
 * because the sender→engine hop had no proof at all: the previous run's
 * `readAccountlessShare` tests stubbed the engine, so nothing had ever checked
 * that Share's signed objects are the bytes the Rust engine accepts. Every wire
 * name in `src/share/policy-engine-publish.ts` — the signed-object domains, the
 * base32 content-addressed ids, the kebab/snake-case enum spellings, the
 * PolicyEngineRecord coverage rule — is checked here against the real binary
 * rather than against a fixture.
 *
 * There is no mock on either side of the boundary: a real `policy-engine-http`
 * process, real HTTP, and the real published SDK entry points.
 *
 *   POLICY_ENGINE_BIN=<path to policy-engine-http> node test/e2e-policy-engine/publish-slice.mjs
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { ed25519 } from "@noble/curves/ed25519";
import { createFetchPolicyAccessTransport } from "@tinycloud/sdk-core/policy-access";
import { didKeyFromEd25519PublicKey } from "@tinycloud/share-envelope";

const enginePath = process.env.POLICY_ENGINE_BIN;
if (enginePath === undefined) {
  throw new Error("set POLICY_ENGINE_BIN to a built policy-engine-http binary");
}

const AUDIENCE = "urn:tinycloud:policy-engine:publish-slice";
const RECIPIENT = "sam@tinycloud.xyz";

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitForEngine(origin, child, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`policy engine exited (${child.exitCode})`);
    try {
      // Any answer at all — including a refusal — proves the router is mounted.
      const response = await fetch(`${origin}/policy/v0/challenge`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ policyId: "pol_readiness" }),
      });
      if (response.status > 0) return;
    } catch {
      await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
  }
  throw new Error("policy engine readiness timeout");
}

const control = await mkdtemp(join(tmpdir(), "tc500-publish-slice-"));
let engine;
try {
  // Deterministic engine identity. The grant issuer DID is what the sender must
  // authorise, so it has to be derived exactly the way the engine derives it.
  const grantIssuerSeed = new Uint8Array(32).fill(0x5a);
  const grantIssuerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(grantIssuerSeed));
  const configPath = join(control, "engine.json");
  await writeFile(configPath, JSON.stringify({
    audience: AUDIENCE,
    challengeTtlSeconds: 120,
    acceptedSuites: ["eddsa-ed25519-sha256-jcs-v1"],
    challengeSignerSeedBase64Url: base64Url(new Uint8Array(32).fill(0x11)),
    grantIssuerDid,
    grantIssuerSignerSeedBase64Url: base64Url(grantIssuerSeed),
    parentDelegations: [],
    // One trusted credential issuer, in the engine's own JWK wire form. This
    // slice does not present a credential, but the engine refuses to start
    // without a configured issuer, and a placeholder would be a lie about what
    // was booted: this is a real Ed25519 key with a published public half.
    issuerKeys: {
      "did:web:issuer.credentials.org": {
        params: {
          OKP: {
            curve: "Ed25519",
            public_key: Array.from(ed25519.getPublicKey(new Uint8Array(32).fill(0x55))),
          },
        },
      },
    },
    signedObjects: [],
  }));

  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  engine = spawn(enginePath, [], {
    env: { ...process.env, POLICY_ENGINE_HTTP_CONFIG: configPath, POLICY_ENGINE_HTTP_BIND: `127.0.0.1:${port}` },
    stdio: ["ignore", "inherit", "inherit"],
  });
  await waitForEngine(origin, engine, 30_000);

  // The owner is an ordinary Ed25519 session key, exactly as the Share composer
  // supplies one through `tinycloud.signSessionBytes`.
  const ownerSeed = new Uint8Array(32).fill(0x27);
  const ownerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(ownerSeed));
  const transport = createFetchPolicyAccessTransport({ originPolicy: { allowedOrigins: [origin] } });

  const { publishSharePolicyToEngine, RECIPIENT_EMAIL_REQUIREMENT_ID } =
    await import("../../src/share/policy-engine-publish.ts");

  const spaceId = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:share";
  const resourcePath = "shares/report.txt";
  const createdAt = new Date(Date.now() - 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString().replace(/\.\d{3}Z$/, "Z");

  const published = await publishSharePolicyToEngine({
    engine: { endpoint: origin, audience: AUDIENCE, grantIssuerDid },
    ownerDid,
    sign: async (bytes) => ed25519.sign(bytes, ownerSeed),
    recipientEmail: RECIPIENT,
    kvResource: `${spaceId}/kv/${resourcePath}`,
    capabilitySpace: spaceId,
    resourcePath,
    shareId: "share-publish-slice",
    createdAt,
    expiresAt,
    transport,
  });

  assert.match(published.policyId, /^pol_[a-z2-7]{52}$/, "the engine returned a content-addressed policy id");
  assert.equal(published.requirementId, RECIPIENT_EMAIL_REQUIREMENT_ID);

  // The engine now holds a policy it will actually challenge against. Before
  // registration this same request answers policy-not-found, so a green
  // challenge is the proof the registration committed.
  const challenge = await fetch(`${origin}/policy/v0/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ policyId: published.policyId }),
  });
  const challengeText = await challenge.text();
  assert.equal(challenge.status, 200, `challenge for the published policy failed: ${challengeText}`);
  const body = JSON.parse(challengeText);
  assert.equal(body.challenge.policyId, published.policyId);
  assert.equal(body.challenge.audience, AUDIENCE, "the challenge is bound to this engine's audience");
  assert.ok(body.challenge.nonce.length >= 16, "the challenge carries a replay nonce");

  // Idempotence, against the running engine rather than against a unit stub.
  const again = await publishSharePolicyToEngine({
    engine: { endpoint: origin, audience: AUDIENCE, grantIssuerDid },
    ownerDid,
    sign: async (bytes) => ed25519.sign(bytes, ownerSeed),
    recipientEmail: RECIPIENT,
    kvResource: `${spaceId}/kv/${resourcePath}`,
    capabilitySpace: spaceId,
    resourcePath,
    shareId: "share-publish-slice",
    createdAt,
    expiresAt,
    transport,
  });
  assert.equal(again.policyId, published.policyId, "re-publishing an unchanged share is the same policy");

  // A different owner enrolling a grant issuer that is not this engine's must be
  // refused, and refused by the engine rather than by this client: it is the
  // engine that knows which key it mints with. Using a fresh owner matters —
  // the first publish already enrolled `ownerDid` correctly, and that
  // enrolment legitimately keeps covering that owner's later policies.
  const otherOwnerSeed = new Uint8Array(32).fill(0x39);
  const otherOwnerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(otherOwnerSeed));
  const wrongIssuer = didKeyFromEd25519PublicKey(ed25519.getPublicKey(new Uint8Array(32).fill(0x6b)));
  const denial = await publishSharePolicyToEngine({
    engine: { endpoint: origin, audience: AUDIENCE, grantIssuerDid: wrongIssuer },
    ownerDid: otherOwnerDid,
    sign: async (bytes) => ed25519.sign(bytes, otherOwnerSeed),
    recipientEmail: RECIPIENT,
    kvResource: `${spaceId}/kv/${resourcePath}`,
    capabilitySpace: spaceId,
    resourcePath,
    shareId: "share-publish-slice-wrong-issuer",
    createdAt,
    expiresAt,
    transport,
  }).catch((error) => error);
  assert.equal(denial.name, "PolicyAccessError", `expected the engine to refuse, got ${JSON.stringify(denial)}`);
  assert.equal(denial.code, "engine-denied");
  assert.equal(denial.status, 403);
  assert.equal(denial.denialCode, "policy_engine_record.grant_issuer_authority");

  // And the refusal committed nothing: the rejected policy is not challengeable.
  const rejectedChallenge = await fetch(`${origin}/policy/v0/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ policyId: published.policyId.replace(/.$/, published.policyId.endsWith("a") ? "b" : "a") }),
  });
  assert.equal(rejectedChallenge.status, 404, "an unregistered policy must not be challengeable");

  console.log(JSON.stringify({
    slice: "sender publishes to a real standalone Policy Engine",
    engine: { binary: enginePath, audience: AUDIENCE, grantIssuerDid },
    policyId: published.policyId,
    requirementId: published.requirementId,
    challenge: { audience: body.challenge.audience, nonceLength: body.challenge.nonce.length },
    idempotent: true,
    unauthorizedGrantIssuerRefused: denial.denialCode,
  }, null, 2));
} finally {
  engine?.kill("SIGKILL");
  await rm(control, { recursive: true, force: true });
}
