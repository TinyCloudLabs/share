/**
 * A closed, synthetic world for opening an email share through the real receive path: a publisher that signs a
 * Policy/v3 share with throwaway keys, a fake OpenCredentials witness (vendored, see
 * `opencredentials-witness/PROVENANCE.md`), a registry record and a fake owner node that answers the policy
 * challenge, the delegation, the KV read and the node-signed X25519 decrypt reply. Everything is real public SDK
 * crypto and verification on the receiving side; only the servers are fakes, reached through one `fetch`.
 *
 * The pattern follows the node-sdk receive tests of TinyCloudLabs/js-sdk (share-receive.test.ts).
 */
import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { signLocationRecord, httpUrlToMultiaddr } from "@tinycloud/sdk-core";
import { TinyCloudNode } from "@tinycloud/node-sdk";
import { prepareAddressedShare, publishAddressedShare } from "@tinycloud/share-sdk";
import { canonicalize, didKeyFromEd25519PublicKey, signCompactUcanAuthorization, toBase64Url, verifyCompactUcanAuthorization } from "@tinycloud/share-envelope";
import { publishLink } from "../../src/short-links/publish.js";
import type { WitnessStub } from "./opencredentials-witness/witness-stub.mjs";

const seed = (value: number): Uint8Array => new Uint8Array(32).fill(value);
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const base64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

export const SHARE_ORIGIN = "https://share.tinycloud.xyz";
export const REGISTRY_ORIGIN = "https://registry.fixture.test";
export const NODE_ORIGIN = "https://node.fixture.test";
export const WITNESS_ORIGIN = "https://witness.credentials.org";
export const RECIPIENT_EMAIL = "reader@example.com";

const OWNER_KEY = seed(21);
const NODE_KEY = seed(22);
const OWNER_DID = didKeyFromEd25519PublicKey(ed25519.getPublicKey(OWNER_KEY));
const NODE_DID = didKeyFromEd25519PublicKey(ed25519.getPublicKey(NODE_KEY));
const SYMMETRIC_KEY = seed(41);

/** Which wrapped-key digest the owner registered, and for which kind of source. */
export type ShareKind =
  /** An older share: no key path, the registered digest is the envelope's canonical hash. */
  | "legacy"
  /** A path-bound share: `share/<id>`, the registered digest is SHA-256 of the decoded wrapped key. */
  | "path-bound"
  /** A path-bound source that registered the canonical hash. */
  | "path-bound-canonical-digest"
  /** A no-path source that registered the raw digest. */
  | "legacy-raw-digest"
  /** A path-bound source whose registered digest is not the digest of its wrapped key. */
  | "path-bound-tampered-digest";

async function aesEncrypt(key: Uint8Array, plain: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt"]);
  return Uint8Array.from([...iv, ...new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, plain as BufferSource))]);
}

/** The parts of the SDK's delivery material and signed envelope the fake node reads. The SDK types them more widely. */
interface PublishedEnvelope {
  readonly policy: { readonly policyId: string };
  readonly policyCid: string;
  readonly policyRoot: { readonly cid: string; readonly authorization: string };
  readonly enforcementRoot: { readonly cid: string };
  readonly contentSourceDigestHex: string;
}
interface DeliveryMaterial { readonly sealedEnvelope: string; readonly envelopeKey: string; readonly shareCid: string; readonly envelope: PublishedEnvelope }
interface RootFacts {
  readonly att: never;
  readonly fct: readonly { readonly policyDigestHex: string; readonly capabilityCeilingHashHex: string; readonly nativeProjectionHashHex: string }[];
}

export interface ShareReceiverWorld {
  readonly link: string;
  readonly fetchFn: typeof fetch;
  /** Every request the receiver made, `METHOD origin/path`. */
  readonly calls: string[];
  /** How many decrypt requests reached the node (a KV read is not one). */
  readonly decryptRequests: () => number;
  /** The shape of the share's key as it was registered and stored. */
  readonly registered: { readonly keyPath: string | undefined; readonly digestHex: string };
}

export async function buildShareReceiverWorld(options: { readonly kind: ShareKind; readonly plaintext: string; readonly witness: WitnessStub }): Promise<ShareReceiverWorld> {
  const pathBound = options.kind !== "legacy" && options.kind !== "legacy-raw-digest";
  const shareId = `world-${options.kind}-0123456789`;
  const keyPath = pathBound ? `share/${shareId}` : undefined;
  const networkId = `urn:tinycloud:encryption:${OWNER_DID}:default`;
  const spaceId = "tinycloud:test-space";
  const resourcePath = `xyz.tinycloud.share/shares/${shareId}/report.md`;

  const wrappedBytes = Uint8Array.from({ length: 93 }, (_, index) => (index * 5 + 7) % 256);
  const encryptedSymmetricKey = base64(wrappedBytes);
  const canonicalHash = hex(sha256(new TextEncoder().encode(canonicalize(encryptedSymmetricKey))));
  const rawDigest = hex(sha256(wrappedBytes));
  const registeredDigest = options.kind === "legacy" || options.kind === "path-bound-canonical-digest"
    ? canonicalHash
    : options.kind === "path-bound-tampered-digest"
      ? rawDigest.replace(/^./, (character) => (character === "0" ? "1" : "0"))
      : rawDigest;

  const stored = new TextEncoder().encode(canonicalize({
    v: pathBound ? 2 : 1, networkId, ...(keyPath === undefined ? {} : { keyPath }), alg: "x25519-aes256gcm/v1", keyVersion: 1,
    encryptedSymmetricKey, encryptedSymmetricKeyHash: canonicalHash,
    ciphertext: base64(await aesEncrypt(SYMMETRIC_KEY, new TextEncoder().encode(options.plaintext))),
    metadata: { contentType: "text/markdown" },
  }));

  const now = Date.now();
  const expiresAt = new Date(now + 30 * 86_400_000);
  const request = { target: { kind: "email", address: RECIPIENT_EMAIL }, actions: ["read"], policyActions: ["tinycloud.kv/get", "tinycloud.kv/metadata"], filename: "report.md" } as const;
  const { credentialRequirement } = prepareAddressedShare({ ...request, actions: [...request.actions], policyActions: [...request.policyActions] });
  const sign = async (bytes: Uint8Array): Promise<Uint8Array> => ed25519.sign(bytes, OWNER_KEY);
  // Only what `createUnifiedOwnerRoot` reads from `this`; the real class needs a signed-in session.
  const ownerSigner: never = { credentialHolderDid: OWNER_DID, signSessionBytes: sign } as never;
  let delivery: DeliveryMaterial | undefined;
  await publishAddressedShare({
    shareId, shareOrigin: SHARE_ORIGIN, nodeOrigin: NODE_ORIGIN, nodeAudience: NODE_DID, enforcerDid: NODE_DID, spaceId,
    target: { ...request.target }, actions: [...request.actions], policyActions: [...request.policyActions], filename: request.filename,
    resource: { kind: "exact", path: resourcePath }, ...(credentialRequirement === undefined ? {} : { credentialRequirement }), mediaType: "text/markdown", byteLength: options.plaintext.length, expiresAt,
    contentSource: {
      shareId, kvResource: `${spaceId}/kv/${resourcePath}`, selector: "exact", encryptionNetwork: networkId,
      ...(keyPath === undefined ? {} : { encryptionKeyPath: keyPath }),
      encryptedSymmetricKeyDigestHex: registeredDigest, keyVersion: 1, mode: "immutable", initialCiphertextDigestHex: hex(sha256(stored)),
    },
    // The SDK's material type is wider than what the fake node reads; narrowing it once, here.
    onDeliveryMaterial: (material) => { delivery = material as unknown as DeliveryMaterial; },
    authority: {
      ownerDid: OWNER_DID, sign,
      // The SDK's own root builder, with the owner's session key as its only dependency.
      createOwnerRoot: (input) => TinyCloudNode.prototype.createUnifiedOwnerRoot.call(ownerSigner, input),
      async registerPolicy(input) {
        const unsigned = {
          schema: "xyz.tinycloud.policy/attested-enforcer/v2" as const, enforcerDid: NODE_DID, nodeAudience: NODE_DID,
          attestationBindingDigestHex: hex(sha256(new TextEncoder().encode(canonicalize({ enforcerDid: NODE_DID, nodeAudience: NODE_DID })))),
          issuedAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 40 * 86_400_000).toISOString(),
        };
        const digest = sha256(new TextEncoder().encode(`xyz.tinycloud.policy/AttestedEnforcerBinding/v2\0${canonicalize(unsigned)}`));
        return {
          policyCid: input.policyCid, policyRootCid: input.policyRoot.cid, enforcementRootCid: input.enforcementRoot.cid,
          attestedEnforcerBinding: { ...unsigned, signature: { suite: "Ed25519" as const, signerDid: NODE_DID, value: toBase64Url(ed25519.sign(digest, NODE_KEY)) } },
        };
      },
    },
  });
  if (delivery === undefined) throw new Error("the publisher returned no delivery material");
  const envelope = delivery.envelope;
  const link = (await publishLink({
    material: { sealedEnvelope: delivery.sealedEnvelope, envelopeKey: delivery.envelopeKey, shareCid: delivery.shareCid },
    expiresAt: expiresAt.toISOString(), signer: { issuerDid: OWNER_DID, sign }, shareOrigin: SHARE_ORIGIN, apiOrigin: "https://api.tinycloud.xyz",
    fetchFn: (async () => { throw new Error("no links service in this world"); }) as unknown as typeof fetch, now: () => now,
  })).url;

  const record = await signLocationRecord(
    { version: 1, subject: OWNER_DID, multiaddrs: [httpUrlToMultiaddr(NODE_ORIGIN)], updated_at: new Date().toISOString(), sequence: 1 },
    { type: "did:key", signBytes: sign },
  );
  const { witness } = options;
  const rootFact = verifyCompactUcanAuthorization(envelope.policyRoot.authorization).payload as unknown as RootFacts;
  const fact = rootFact.fct[0]!;
  let holderDid = "";
  let session: { cid: string; authorization: string } | undefined;
  const calls: string[] = [];
  let decryptRequests = 0;

  const fetchFn = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "object" && "url" in input ? input.url : String(input));
    calls.push(`${init?.method ?? "GET"} ${url.origin}${url.pathname}`);
    if (url.origin === WITNESS_ORIGIN) return witness.fetch(input, init);
    if (url.origin === REGISTRY_ORIGIN) return Response.json({ record });
    if (url.origin !== NODE_ORIGIN) throw new Error(`the world has no route for ${url.origin}`);
    if (url.pathname === "/info") return Response.json({ nodeId: NODE_DID });
    if (url.pathname.startsWith("/policy/v3/status/")) return Response.json({ rootCid: decodeURIComponent(url.pathname.split("/").pop()!), state: "active", checkpoint: { freshUntil: new Date(now + 20 * 86_400_000).toISOString() } });
    if (url.pathname === "/policy/v3/challenges") {
      const body = JSON.parse(String(init?.body)) as { recipientDid?: string };
      holderDid = body.recipientDid ?? holderDid;
      return Response.json({ challengeId: "challenge-1", nonce: "nonce-1", policyCid: envelope.policyCid, recipientDid: holderDid, nodeAudience: NODE_DID, expiresAt: new Date(Date.now() + 45_000).toISOString() });
    }
    if (url.pathname === "/policy/v3/delegations") {
      const issued = Math.floor(Date.now() / 1000);
      session = await signCompactUcanAuthorization({
        issuerDid: NODE_DID, audienceDid: holderDid, attenuation: rootFact.att,
        facts: [{
          profile: "policy-session-ucan/v1", ownerDid: OWNER_DID, policyId: envelope.policy.policyId, policyDigestHex: fact.policyDigestHex, policyCid: envelope.policyCid,
          policyDelegationCid: envelope.policyRoot.cid, enforcementDelegationCid: envelope.enforcementRoot.cid, contentSourceDigestHex: envelope.contentSourceDigestHex,
          capabilityCeilingHashHex: fact.capabilityCeilingHashHex, nativeProjectionHashHex: fact.nativeProjectionHashHex, enforcerDid: NODE_DID, nodeAudience: NODE_DID, recipientDid: holderDid,
          challengeId: "challenge-1", claimDigestHex: "4".repeat(64), claimJti: "claim-1", vpDigestHex: "5".repeat(64), credentialEvidenceDigestHex: "6".repeat(64),
          decisionContextDigestHex: "7".repeat(64), issuanceAuditDigestHex: "8".repeat(64), remainingRedelegationDepth: 8, credentialIdAuditDigestHex: "9".repeat(64), presentationJtiAuditDigestHex: "a".repeat(64),
        }],
        proofs: [envelope.policyRoot.cid, envelope.enforcementRoot.cid], notBefore: issued, expiresAt: issued + 45, nonce: "session-1",
        sign: async (bytes) => ed25519.sign(bytes, NODE_KEY),
      });
      return Response.json({ admitted: true, sessionCid: session.cid, authorization: session.authorization });
    }
    if (url.pathname === "/delegate") return new Response(null, { status: 204 });
    if (url.pathname === "/invoke" && init?.body === undefined) return new Response(stored);
    if (url.pathname === "/invoke") {
      decryptRequests += 1;
      const body = JSON.parse(String(init!.body)) as Record<string, unknown>;
      const receiverPublic = Uint8Array.from(Buffer.from(String(body.receiverPublicKey), "base64"));
      const ephemeral = seed(42);
      const wrapped = await aesEncrypt(x25519.getSharedSecret(ephemeral, receiverPublic), SYMMETRIC_KEY);
      const invocation = verifyCompactUcanAuthorization(new Headers(init?.headers).get("Authorization")!);
      const bodyHash = hex(sha256(new TextEncoder().encode(canonicalize(body))));
      const unsigned = {
        type: "tinycloud.encryption.decrypt-result/v1", targetNode: NODE_DID, networkId, invocationCid: invocation.cid, encryptedSymmetricKeyHash: canonicalHash,
        receiverPublicKeyHash: body.receiverPublicKeyHash, wrappedKey: base64(Uint8Array.from([...x25519.getPublicKey(ephemeral), 1, ...wrapped])),
        alg: "x25519-aes256gcm/v1", keyVersion: 1, requestHash: hex(sha256(new TextEncoder().encode(`${invocation.cid}${bodyHash}`))), nodeId: NODE_DID,
      };
      return Response.json({ ...unsigned, nodeSignature: base64(ed25519.sign(new TextEncoder().encode(canonicalize(unsigned)), NODE_KEY)) });
    }
    throw new Error(`the world has no route for ${url.pathname}`);
  }) as typeof fetch;

  return { link, fetchFn, calls, decryptRequests: () => decryptRequests, registered: { keyPath, digestHex: registeredDigest } };
}
