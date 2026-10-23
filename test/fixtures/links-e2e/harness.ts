/**
 * Browser harness for the composer's link step. The composer, the size check, the SDK's envelope
 * builder, the issuer signing and the link publisher are the real code; the owner's session and the
 * node are fakes with real local signing. Requests to the links API go out as real browser fetches
 * (the browser run answers them with the local mock of the API).
 *
 * Query: `screen=composer`; `prefill=1` opens it as "Send the link again" does.
 */
import "../../../src/email-share/sender.css";
import { ed25519 } from "@noble/curves/ed25519";
import { signCompactUcanRootAuthorization } from "@tinycloud/sdk-core";
import { toBase64Url } from "@tinycloud/share-envelope";
import { mountShareComposer } from "../../../src/share/composer.js";
import { mountSenderChrome } from "../../../src/share/sender-chrome.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../../../src/share/openkey-session.js";

const SEED = new Uint8Array(32).fill(0x11);
const ISSUER_DID = "did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S";
const NODE_DID = "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK";
const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:applications`;
const sign = async (bytes: Uint8Array): Promise<Uint8Array> => ed25519.sign(bytes, SEED);

const qa = { links: [] as string[], writes: [] as string[], deliveries: [] as unknown[] };
(window as unknown as { __qa: typeof qa }).__qa = qa;

const tinycloud = {
  spaceId: SPACE,
  credentialHolderDid: ISSUER_DID,
  activeNodeIdentity: async () => ({ origin: "https://node.example.invalid", nodeDid: NODE_DID }),
  publishActiveNodeLocation: async () => undefined,
  signSessionBytes: sign,
  signOut: async () => undefined,
  encryption: { encryptToNetwork: async (network: string) => ({ ok: true, data: { v: 1, networkId: network, alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AAAA", nonce: "AAAA" } }) },
  kvForSpace: () => ({ put: async (path: string) => { qa.writes.push(path); return { ok: true }; } }),
  createUnifiedOwnerRoot: async (input: { audienceDid: string; role: string; policyId: string; policyCid: string; nodeAudience: string; notBefore: Date; expiresAt: Date; capabilities: { kind: string; resource: string; selector: string }[] }) => {
    const kv = input.capabilities.find((capability) => capability.kind === "kv")!;
    const root = await signCompactUcanRootAuthorization({
      issuerDid: ISSUER_DID, audienceDid: input.audienceDid,
      attenuation: { [kv.resource]: { "tinycloud.kv/get": [{ type: "xyz.tinycloud.resource/selector", kind: kv.selector, value: kv.resource }] } },
      facts: [{ role: input.role, policyId: input.policyId, policyCid: input.policyCid, ownerDid: ISSUER_DID, nodeAudience: input.nodeAudience }],
      notBefore: Math.floor(input.notBefore.getTime() / 1000), expiresAt: Math.floor(input.expiresAt.getTime() / 1000),
      nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(16))), sign,
    });
    return { cid: root.cid, delegationHeader: { Authorization: root.authorization }, delegateDID: input.audienceDid, spaceId: SPACE, path: "", actions: [], expiry: input.expiresAt };
  },
  registerPolicy: async (registration: { policyCid: string; policyRoot: { cid: string }; enforcementRoot: { cid: string }; enforcerDid: string; expectedNodeAudience: string }) => {
    qa.writes.push("registerPolicy");
    return {
      policyCid: registration.policyCid, policyRootCid: registration.policyRoot.cid, enforcementRootCid: registration.enforcementRoot.cid,
      attestedEnforcerBinding: {
        schema: "xyz.tinycloud.policy/attested-enforcer/v2", enforcerDid: registration.enforcerDid, nodeAudience: registration.expectedNodeAudience, attestationBindingDigestHex: "c".repeat(64),
        issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 40 * 86_400_000).toISOString(), signature: { suite: "Ed25519", signerDid: registration.expectedNodeAudience, value: toBase64Url(new Uint8Array(64).fill(7)) },
      },
    };
  },
  authorizeShareDeliveryV3: async (input: { shareUrl: string }) => { qa.deliveries.push(input.shareUrl); return { request: { returnLink: input.shareUrl } }; },
} as unknown as ShareTinyCloud;

const session = { address: ADDRESS, openkey: { disconnect: () => undefined, signOut: async () => ({ requestId: "r", revoked: true }) }, auth: {} } as unknown as OpenKeyShareSession;
const params = new URLSearchParams(location.search);
const root = document.getElementById("share-app")!;
const chrome = document.createElement("div");
const view = document.createElement("div");
root.append(chrome, view);
mountSenderChrome(chrome, { session, tinycloud, onSignedOut: () => undefined });
mountShareComposer(view, {
  origin: "https://share.tinycloud.xyz",
  openKeyAddress: ADDRESS,
  session,
  tinycloud,
  onBack: () => undefined,
  persistShare: async ({ share }) => { if (share.record?.link !== undefined) qa.links.push(share.record.link); },
  ...(params.get("prefill") === "1" ? { prefill: { recipient: { kind: "exactEmail" as const, value: "reader@example.com" }, deliveryEmails: [], expiry: "30d" as const, filename: "report.md" } } : {}),
});
document.documentElement.dataset.ready = "yes";
