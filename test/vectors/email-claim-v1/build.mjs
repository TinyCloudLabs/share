#!/usr/bin/env node
/* Deterministic, test-only contract builder. It deliberately has no runtime-package dependency. */
import { createCipheriv, createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../../");
const spec = resolve(root, "specs/email-claim-v1");
const utf8 = (value) => new TextEncoder().encode(value);
const b64 = (value) => Buffer.from(value).toString("base64url");
const sha256 = (value) => new Uint8Array(createHash("sha256").update(value).digest());
const digest = (value) => b64(sha256(value));
const hex = (value) => new Uint8Array(Buffer.from(value, "hex"));
const fixedBytes = (length, start = 0) => Uint8Array.from({ length }, (_, index) => (start + index) & 255);

function assertString(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = value.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) throw new TypeError("lone surrogate");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new TypeError("lone surrogate");
  }
}
function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "string") { assertString(value); return JSON.stringify(value); }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("unsafe number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => { if (item === undefined) throw new TypeError("undefined"); return jcs(item); }).join(",")}]`;
  if (typeof value !== "object" || value === null || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new TypeError("non-plain value");
  return `{${Object.keys(value).sort().map((key) => { assertString(key); if (value[key] === undefined) throw new TypeError("undefined"); return `${JSON.stringify(key)}:${jcs(value[key])}`; }).join(",")}}`;
}
function b32(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let buffer = 0; let bits = 0; let out = "";
  for (const byte of bytes) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; out += alphabet[(buffer >>> bits) & 31]; } }
  if (bits) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}
function cid(bytes) { return `b${b32(Uint8Array.of(1, 0x55, 0x12, 0x20, ...sha256(bytes)))}`; }
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function privateKey(seed) { return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" }); }
function publicKey(seed) { return new Uint8Array(createPublicKey(privateKey(seed)).export({ format: "der", type: "spki" }).subarray(-32)); }
const alphabet58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) { let n = 0n; let result = ""; for (const byte of bytes) n = (n << 8n) | BigInt(byte); while (n) { result = alphabet58[Number(n % 58n)] + result; n /= 58n; } for (const byte of bytes) { if (byte) break; result = `1${result}`; } return result; }
function didKey(seed) { return `did:key:z${base58(Uint8Array.of(0xed, 1, ...publicKey(seed)))}`; }
function kid(did) { return `${did}#${did.slice("did:key:".length)}`; }
function signed(name, domains, message, seed, signerDid, keyId) {
  const domain = domains.domains[name];
  if (typeof domain !== "string" || !domain.endsWith("\u0000")) throw new Error(`missing registry domain: ${name}`);
  const text = jcs(message);
  const signingBytes = Buffer.concat([utf8(domain), utf8(text)]);
  const signature = sign(null, signingBytes, privateKey(seed));
  return { name, domain, signerDid, message, jcs: text, messageDigest: digest(utf8(text)), signedBytesDigest: digest(signingBytes), signatureDigest: digest(signature), signature: { alg: "EdDSA", kid: keyId, value: b64(signature) } };
}
function shippingEnvelope(unsigned, seed, domains) {
  const domain = domains.domains.envelope;
  const text = jcs(unsigned);
  const signature = sign(null, Buffer.concat([utf8(domain), utf8(text)]), privateKey(seed));
  return { ...unsigned, signature: { signerDid: didKey(seed), algorithm: "Ed25519", value: b64(signature) } };
}
function sourceFor(kind) {
  const space = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
  if (kind === "kv") return { kind, space, path: "documents/plan.md", action: "tinycloud.kv/get" };
  const args = { document_id: "doc_123" };
  return { kind, space, database: "documents", path: "shared/plan", statement: "shared_document_by_id", arguments: args, argumentsDigest: digest(utf8(jcs(args))), action: "tinycloud.sql/read" };
}
function bodyDigest(body) { return digest(utf8(jcs(body))); }
function artifactProof(artifact) { return { alg: "EdDSA", kid: artifact.signature.kid, signature: artifact.signature.value }; }
function sealEnvelope(plaintext, key, nonce) {
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  cipher.setAAD(Buffer.from("tinycloud-share-envelope-v1", "utf8"));
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
  return Uint8Array.of(1, ...nonce, ...ciphertext);
}

const domains = JSON.parse(await readFile(resolve(spec, "domains.json"), "utf8"));
const domainNames = ["envelope", "policy", "inviteAuthorization", "holderBinding", "policyChallenge", "policyPresentation", "policySession", "readInvocation"];
for (const name of domainNames) if (typeof domains.domains[name] !== "string" || !domains.domains[name].endsWith("\u0000")) throw new Error(`invalid domain registry entry: ${name}`);

const seeds = { sender: hex("44".repeat(32)), node: hex("42".repeat(32)), issuer: hex("43".repeat(32)), holder: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60") };
const ids = { senderDid: didKey(seeds.sender), holderDid: didKey(seeds.holder), nodeDid: "did:web:node.example", issuerDid: "did:web:issuer.credentials.org", nodeKid: "did:web:node.example#invitation-key-1", senderKid: kid(didKey(seeds.sender)), holderKid: kid(didKey(seeds.holder)) };
const times = { issued: "2026-07-16T12:00:00.000Z", bindingExpires: "2026-07-16T12:02:00.000Z", claimExpires: "2026-07-23T12:00:00.000Z", challengeExpires: "2026-07-16T12:02:00.000Z", sessionExpires: "2026-07-16T12:05:00.000Z", readExpires: "2026-07-16T12:01:00.000Z" };
const canonicalEmail = "Alice+Notes@example.com";
const emailHash = digest(utf8(canonicalEmail));
const maxDomain253 = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(61)}`;
const maxDomain252 = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(60)}`;
const canonicalization = { accepted: [
  { id: "local-64-atext-bytes", input: `${"a".repeat(64)}@example.com`, canonical: `${"a".repeat(64)}@example.com`, localBytes: 64, domainBytes: 11, totalBytes: 76 },
  { id: "local-dot-atom-preserved", input: "Alice.O+Notes@EXAMPLE.COM", canonical: "Alice.O+Notes@example.com", localBytes: 13, domainBytes: 11, totalBytes: 25 },
  { id: "total-254-bytes", input: `a@${maxDomain252}`, canonical: `a@${maxDomain252}`, localBytes: 1, domainBytes: 252, totalBytes: 254 }
], domainBoundary: { id: "domain-253-byte-component", input: maxDomain253, canonical: maxDomain253, domainBytes: 253, validLdhLabels: true } };
const emailRejects = [
  ["leading-space", " Alice@example.com"], ["trailing-space", "Alice@example.com "], ["tab", "Alice@\texample.com"], ["newline", "Alice@example.com\n"], ["inner-space", "Alice Notes@example.com"], ["leading-dot-local", ".Alice@example.com"], ["trailing-dot-local", "Alice.@example.com"], ["repeated-dot-local", "Alice..Notes@example.com"], ["empty-local", "@example.com"], ["empty-domain", "Alice@"], ["multiple-at", "Alice@gmail.com@example.com"], ["quoted-local", '"Alice"@example.com'], ["comment-local", "Alice(comment)@example.com"], ["backslash-local", "Alice\\Bob@example.com"], ["angle-form", "Alice <alice@example.com>"], ["unicode-local", "álíce@example.com"], ["unicode-domain", "Alice@bücher.example"], ["local-over-64", `${"a".repeat(65)}@example.com`], ["label-over-63", `Alice@${"a".repeat(64)}.com`], ["empty-domain-label", "Alice@example..com"], ["trailing-domain-dot", "Alice@example.com."], ["leading-hyphen", "Alice@-example.com"], ["trailing-hyphen", "Alice@example-.com"], ["domain-over-253", `a@${maxDomain253}x`], ["total-over-254", `aa@${maxDomain252}`]
].map(([id, input]) => ({ id, input }));

function makeScenario(kind) {
  const source = sourceFor(kind);
  const sourceDigest = digest(utf8(jcs(source)));
  const policy = { type: "TinyCloudSharePolicy", version: 1, recipientEmail: canonicalEmail, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, expiresAt: times.claimExpires, issuerDid: ids.senderDid };
  const policyBytes = utf8(jcs(policy));
  if (new TextDecoder().decode(policyBytes).includes("policyCid")) throw new Error("policy bytes self-reference policyCid");
  const policyCid = cid(policyBytes);
  const shareId = `share-${kind}-001`;
  const unsignedEnvelope = { version: 1, shareId, delegation: `uCAESA.${kind}.terminal`, authorizationTarget: { kind: "policy", policyCid, policyBytes: b64(policyBytes) }, target: { origin: "https://node.example", nodeAudience: ids.nodeDid, spaceId: source.space, resource: { kind: "exact", path: source.path } }, display: { senderName: "TinyCloud sender", filename: "Project plan.md", recipientHint: "A***@example.com" }, expiry: times.claimExpires };
  const envelope = shippingEnvelope(unsignedEnvelope, seeds.sender, domains);
  const envelopeJcs = jcs(envelope);
  const envelopeKey = fixedBytes(32, kind === "kv" ? 0 : 0x40);
  const envelopeNonce = fixedBytes(12, kind === "kv" ? 0x10 : 0x20);
  const sealedBlob = sealEnvelope(utf8(envelopeJcs), envelopeKey, envelopeNonce);
  const shareCid = cid(sealedBlob);
  const invitationId = b64(fixedBytes(16));
  const claimSecret = b64(fixedBytes(32, 0x20));
  const claimNonce = b64(fixedBytes(32, 0xa0));
  const redemptionId = b64(fixedBytes(16, 0x40));
  const challengeId = b64(fixedBytes(32, 0x60));
  const sessionId = b64(fixedBytes(16, 0x80));
  const jti = b64(fixedBytes(16, 0xc0));
  const readJti = b64(fixedBytes(16, 0xd0));
  const reportAbuseToken = b64(fixedBytes(16, 0xe0));
  const delegationCid = cid(utf8(`deterministic-terminal-delegation-${kind}`));
  const auth = { type: "TinyCloudShareInviteAuthorization", version: 1, jti: b64(fixedBytes(16, kind === "kv" ? 1 : 2)), senderDid: ids.senderDid, shareCid, shareId, policyCid, recipientEmail: canonicalEmail, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, returnOrigin: "https://share.tinycloud.xyz", documentName: "Project plan.md", senderTrust: "verified", contentSource: source, contentSourceDigest: sourceDigest, shareExpiresAt: times.claimExpires, issuedAt: times.issued, expiresAt: "2026-07-16T12:05:00.000Z", reportAbuseToken };
  const policyArtifact = signed("policy", domains, policy, seeds.sender, ids.senderDid, ids.senderKid);
  const envelopeArtifact = { name: "envelope", domain: domains.domains.envelope, signerDid: ids.senderDid, message: unsignedEnvelope, jcs: jcs(unsignedEnvelope), messageDigest: digest(utf8(jcs(unsignedEnvelope))), signedBytesDigest: digest(Buffer.concat([utf8(domains.domains.envelope), utf8(jcs(unsignedEnvelope))])), signatureDigest: digest(Buffer.from(envelope.signature.value, "base64url")), signature: { alg: "EdDSA", kid: ids.senderKid, value: envelope.signature.value } };
  const authArtifact = signed("inviteAuthorization", domains, auth, seeds.node, ids.nodeDid, ids.nodeKid);
  const binding = { type: "TinyCloudEmailClaimHolderBinding", version: 1, redemptionId, invitationId, claimNonce, shareCid, shareId, policyCid, contentSource: source, contentSourceDigest: sourceDigest, emailHash, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, requestOrigin: "https://share.tinycloud.xyz", issuedAt: times.issued, expiresAt: times.bindingExpires, jti };
  const readBody = { sessionId, shareCid, shareId, policyCid, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path };
  const requestBodyDigest = bodyDigest(readBody);
  const challenge = { type: "TinyCloudSharePolicyChallenge", version: 1, challengeId, nonce: claimNonce, shareCid, shareId, delegationCid, policyCid, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, requestBodyDigest, issuedAt: times.issued, expiresAt: times.challengeExpires };
  const issuerClaims = { iss: ids.issuerDid, sub: ids.holderDid, iat: 1784203200, nbf: 1784203200, exp: 1784808000, jti: `urn:uuid:${kind}-credential-001`, vct: "opencredentials.email/v1", tinycloud_share: { share_cid: shareCid, share_id: shareId, policy_cid: policyCid, node_audience: ids.nodeDid }, _sd: [] };
  const disclosure = b64(utf8(jcs(["email", canonicalEmail])));
  const disclosureDigest = digest(utf8(disclosure)); issuerClaims._sd = [disclosureDigest];
  const header = b64(utf8(jcs({ alg: "EdDSA", typ: "JWT" }))); const payload = b64(utf8(jcs(issuerClaims))); const issuerInput = `${header}.${payload}`; const issuerSig = b64(sign(null, utf8(issuerInput), privateKey(seeds.issuer))); const credentialString = `${issuerInput}.${issuerSig}~${disclosure}~`;
  const credential = { format: "vc+sd-jwt", credential: credentialString, holderDid: ids.holderDid, expiresAt: times.claimExpires, issuerDid: ids.issuerDid, vct: "opencredentials.email/v1", claims: issuerClaims, disclosures: [{ path: "/email", encoded: disclosure, digest: disclosureDigest, value: canonicalEmail }], credentialDigest: digest(utf8(credentialString)), issuerJws: { signingInput: issuerInput, signingInputDigest: digest(utf8(issuerInput)), signature: issuerSig } };
  const presentation = { type: "TinyCloudSharePolicyPresentation", version: 1, challengeId, nonce: claimNonce, shareCid, shareId, delegationCid, policyCid, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, credentialDigest: credential.credentialDigest, action: source.action, resource: source.path, requestBodyDigest, issuedAt: times.issued, expiresAt: times.challengeExpires, jti: b64(fixedBytes(16, 0x11)) };
  const session = { type: "TinyCloudSharePolicySession", version: 1, sessionId, shareCid, shareId, delegationCid, policyCid, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, credentialDigest: credential.credentialDigest, issuedAt: times.issued, expiresAt: times.sessionExpires };
  const read = { type: "TinyCloudShareReadInvocation", version: 1, sessionId, shareCid, shareId, policyCid, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, requestBodyDigest, issuedAt: times.issued, expiresAt: times.readExpires, jti: readJti };
  const artifacts = [policyArtifact, envelopeArtifact, authArtifact, signed("holderBinding", domains, binding, seeds.holder, ids.holderDid, ids.holderKid), signed("policyChallenge", domains, challenge, seeds.node, ids.nodeDid, ids.nodeKid), signed("policyPresentation", domains, presentation, seeds.holder, ids.holderDid, ids.holderKid), signed("policySession", domains, session, seeds.node, ids.nodeDid, ids.nodeKid), signed("readInvocation", domains, read, seeds.holder, ids.holderDid, ids.holderKid)];
  const enrollment = { targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, invitationKid: ids.nodeKid, invitationPublicKey: b64(publicKey(seeds.node)), keyVersion: 1, enabled: true };
  const authorizationProof = artifactProof(authArtifact);
  const shareUrl = `https://share.tinycloud.xyz/s/${shareCid}#k=${b64(envelopeKey)}`;
  const bodies = {
    authorizationRequest: { shareCid, shareId, policyCid, recipientEmail: canonicalEmail, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, requestBodyDigest },
    authorizationResponse: { authorization: auth, proof: authorizationProof },
    createInvitationRequest: { authorization: auth, proof: authorizationProof, shareUrl },
    createInvitationResponse: { status: "accepted", retryAfterSeconds: 20 }, resendRequest: { invitationId, claimSecret }, resendResponse: { status: "accepted", retryAfterSeconds: 20 },
    claimChallengeMagicRequest: { invitationId, method: "magic", claimSecret }, claimChallengeOtpRequest: { invitationId, method: "otp", otp: "042731" }, claimChallengeResponse: { claimNonce, shareCid, shareId, policyCid, contentSource: source, contentSourceDigest: sourceDigest, emailHash, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, expiresAt: times.challengeExpires },
    claimRedeemRequest: { version: "tinycloud.share-email-claim/v1", redemptionId, invitationId, method: "magic", mailboxProof: claimSecret, binding, holderProof: { alg: "EdDSA", kid: ids.holderKid, signature: artifacts[3].signature.value } }, claimRedeemResponse: { format: "vc+sd-jwt", credential: credentialString, holderDid: ids.holderDid, expiresAt: times.claimExpires },
    policyChallengeRequest: { shareCid, shareId, delegationCid, policyCid, contentSource: source, contentSourceDigest: sourceDigest, holderDid: ids.holderDid, targetOrigin: "https://node.example", nodeAudience: ids.nodeDid, action: source.action, resource: source.path, requestBodyDigest }, policyChallengeResponse: { challenge },
    policySessionRequest: { presentation, credential: credentialString, proof: { alg: "EdDSA", kid: ids.holderKid, signature: artifacts[5].signature.value } }, policySessionResponse: { session },
    kvReadRequest: { sessionId, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, requestBodyDigest, invocation: read, proof: { alg: "EdDSA", kid: ids.holderKid, signature: artifacts[7].signature.value } },
    sqlReadRequest: { sessionId, contentSource: source, contentSourceDigest: sourceDigest, action: source.action, resource: source.path, requestBodyDigest, invocation: read, proof: { alg: "EdDSA", kid: ids.holderKid, signature: artifacts[7].signature.value } },
    readResponse: { mediaType: "text/markdown; charset=utf-8", content: "# Project plan\n", contentSourceDigest: sourceDigest, bodyDigest: digest(utf8("# Project plan\n")) }
  };
  const failures = { authorizationFailure: { error: { code: "invitation_authorization_invalid" } }, createInvitationFailure: { error: { code: "capability_unavailable" } }, resendFailure: { error: { code: "invalid_or_expired_claim" } }, claimChallengeFailure: { error: { code: "invalid_or_expired_claim" } }, claimRedeemFailure: { error: { code: "claim_already_used" } }, policyChallengeFailure: { error: { code: "policy_denied" } }, policySessionFailure: { error: { code: "invalid_credential_profile" } }, kvReadFailure: { error: { code: "read_denied" } }, sqlReadFailure: { error: { code: "read_denied" } } };
  const preimages = Object.fromEntries(Object.entries({ ...bodies, ...failures }).map(([name, body]) => [name, { body, jcs: jcs(body), digest: bodyDigest(body) }]));
  const signedBytePreimages = Object.fromEntries(artifacts.map((artifact) => [artifact.name, { domain: artifact.domain, jcs: artifact.jcs, digest: artifact.signedBytesDigest }]));
  return { kind, testOnly: true, canonicalEmail, emailHash, shareCid, shareId, policyCid, policyBytes: b64(policyBytes), policy, source, sourceDigest, envelopeKey: b64(envelopeKey), sealedBlob: b64(sealedBlob), envelope, authorization: auth, enrollment, credential, artifacts, preimages, signedBytePreimages, reportAbuseToken };
}

const positive = { version: "tinycloud.share-email-claim/v1", generatedBy: "build.mjs", testOnly: true, keyWarning: "NON-PRODUCTION TEST VECTORS ONLY", canonicalization, scenarios: [makeScenario("kv"), makeScenario("sql")] };
const negative = { version: "tinycloud.share-email-claim/v1", testOnly: true, cases: [
  ...emailRejects.map(({ id }) => ({ id, kind: "email", target: "canonicalEmail", mutation: "reject-input", expected: "reject" })),
  { id: "policy-cid-is-real", kind: "cid", target: "policyBytes", mutation: "replace-policy-bytes-with-other-bytes", expected: "reject" }, { id: "policy-bytes-self-policy-cid", kind: "policy", target: "policyBytes", mutation: "insert-policyCid-self-reference", expected: "reject" }, { id: "share-cid-is-real", kind: "cid", target: "sealedBlob", mutation: "flip-one-blob-byte", expected: "reject" }, { id: "sealed-blob-aead-tamper", kind: "aead", target: "sealedBlob", mutation: "flip-authenticated-byte", expected: "reject" },
  { id: "envelope-policy-target-missing-kind", kind: "schema", target: "envelope.authorizationTarget", mutation: "delete-kind", expected: "reject" }, { id: "envelope-policy-target-missing-bytes", kind: "schema", target: "envelope.authorizationTarget", mutation: "delete-policyBytes", expected: "reject" }, { id: "envelope-policy-target-mismatch", kind: "envelope", target: "envelope.authorizationTarget", mutation: "re-sign-policyCid-with-other-policyBytes", expected: "reject" }, { id: "envelope-origin-mismatch", kind: "envelope", target: "envelope.target.origin", mutation: "re-sign-origin", expected: "reject" }, { id: "envelope-domain-from-unregistered-label", kind: "signature", target: "envelope", mutation: "verify-with-nonregistry-domain", expected: "reject" },
  { id: "jcs-lone-surrogate", kind: "jcs", target: "all", mutation: "insert-lone-surrogate", expected: "reject" }, { id: "jcs-unsafe-number", kind: "jcs", target: "all", mutation: "insert-unsafe-number", expected: "reject" }, { id: "jcs-undefined", kind: "jcs", target: "all", mutation: "insert-undefined", expected: "reject" }, { id: "noncanonical-b64url-16-tail", kind: "encoding", target: "invitationId", mutation: "set-nonzero-trailing-bits", expected: "reject" }, { id: "noncanonical-b64url-64-tail", kind: "encoding", target: "signature", mutation: "set-nonzero-trailing-bits", expected: "reject" },
  { id: "noncanonical-holder-kid", kind: "signature", target: "holderBinding", mutation: "use-did-key-with-wrong-fragment", expected: "reject" }, { id: "small-order-did-key", kind: "did-key", target: "holderBinding", mutation: "identity-public-key", expected: "reject" }, { id: "noncanonical-ed25519-s", kind: "signature", target: "holderBinding", mutation: "set-s-to-group-order", expected: "reject" }, { id: "short-signature", kind: "signature", target: "readInvocation", mutation: "truncate-signature", expected: "reject" },
  { id: "wrong-source-digest", kind: "source", target: "sql.argumentsDigest", mutation: "change-one-argument", expected: "reject" }, { id: "sql-arguments-too-large", kind: "source", target: "sql.arguments", mutation: "exceed-4096-byte-jcs", expected: "reject" }, { id: "sql-arbitrary-query-field", kind: "schema", target: "sqlSource", mutation: "add-query", expected: "reject" }, { id: "policy-action-source-mismatch", kind: "binding", target: "policy", mutation: "change-action-only", expected: "reject" }, { id: "content-source-propagation", kind: "binding", target: "policyPresentation", mutation: "change-path-one-field", expected: "reject" },
  { id: "credential-sub-mismatch", kind: "credential", target: "credential.claims.sub", mutation: "sender-did", expected: "reject" }, { id: "credential-legacy-email-path", kind: "credential", target: "credential.disclosures", mutation: "email-address-path", expected: "reject" }, { id: "credential-unsupported-status", kind: "credential", target: "credential.claims", mutation: "add-status", expected: "reject" }, { id: "different-holder-valid-signature", kind: "signature", target: "holderBinding", mutation: "replace-holder-and-resign", expected: "reject" },
  { id: "policy-challenge-replay", kind: "state", target: "nonce", mutation: "consume-twice", expected: "reject" }, { id: "session-token-only", kind: "state", target: "read", mutation: "omit-holder-proof", expected: "reject" }, { id: "old-secret-after-resend", kind: "state", target: "invitation", mutation: "use-v1-after-v2-accepted", expected: "reject" }, { id: "otp-after-five-wrong", kind: "state", target: "otp", mutation: "correct-code-after-lock", expected: "reject" }, { id: "scanner-get", kind: "state", target: "fragment", mutation: "GET-consumes-claim", expected: "reject" }, { id: "resend-recipient-supplied-email", kind: "schema", target: "resendRequest", mutation: "add-email", expected: "reject" }, { id: "capability-extra-route", kind: "capability", target: "witness", mutation: "add-route", expected: "reject" }, { id: "capability-wildcard-origin", kind: "capability", target: "node", mutation: "wildcard-origin", expected: "reject" }, { id: "read-body-one-field-mutation", kind: "preimage", target: "sqlReadRequest", mutation: "change-one-argument", expected: "reject" }
] };
const states = { version: "tinycloud.share-email-claim/v1", testOnly: true, delivery: [
  { name: "create-accepted", events: [["ABSENT","PENDING_DELIVERY(v1)"],["PENDING_DELIVERY(v1)","ACTIVE(v1)"],["ACTIVE(v1)","REDEEMING(v1,redemption-001)"],["REDEEMING(v1,redemption-001)","CONSUMED(v1)"]], providerIdempotencyKey: "invite:create:auth-kv-001", encryptedUntilProviderAcceptance: true, atomicActivation: true, materialDeletedAfterAccept: true },
  { name: "resend-accepted", events: [["ACTIVE(v1)","PENDING_DELIVERY(v2)"],["PENDING_DELIVERY(v2)","ACTIVE(v2)"],["ACTIVE(v2)","REDEEMING(v2,redemption-002)"],["REDEEMING(v2,redemption-002)","CONSUMED(v2)"]], providerIdempotencyKey: "invite:resend:invitation-001:v2", oldVersionRemainsActiveWhilePending: true, oldVersionInvalidatedOnlyAfterAccept: true, replacementMaterialEncryptedUntilAcceptance: true, atomicActivation: true },
  { name: "resend-provider-failure", events: [["ACTIVE(v1)","PENDING_DELIVERY(v2)"],["PENDING_DELIVERY(v2)","ACTIVE(v1)"],["ACTIVE(v1)","REDEEMING(v1,redemption-003)"],["REDEEMING(v1,redemption-003)","CONSUMED(v1)"]], providerIdempotencyKey: "invite:resend:invitation-001:v2", oldVersionRemainsUsable: true, replacementDiscardedOnFailure: true },
  { name: "crash-after-provider-accept", events: [["ACTIVE(v1)","PENDING_DELIVERY(v2)"],["PENDING_DELIVERY(v2)","RECOVERING_PROVIDER_ACCEPT(v2)"],["RECOVERING_PROVIDER_ACCEPT(v2)","ACTIVE(v2)"]], providerAcceptedBeforeCrash: true, sameIdempotencyKeyOnRetry: true, recoveryReconcilesProviderAcceptance: true, oneEffectiveSend: true, oldVersionInvalidatedAfterRecovery: true }
], invitation: ["ABSENT","ACTIVE(v1)","REDEEMING(v1,redemption-001)","CONSUMED(v1)"], nonce: ["ISSUED","VERIFYING","CONSUMED"], session: ["ACTIVE","EXPIRED","REVOKED"], operations: ["create_persist_outbox","provider_accept","activate_v1","wrong_otp_x5","lock_v1","resend_persist_v2","provider_accept_v2","invalidate_v1","claim_v2","consume_nonce","crash_after_provider_accept","retry_same_provider_idempotency","same_redemption_idempotent","different_redemption_rejected","scanner_get_no_state_change"], semantics: { claimMaterial: { encryptedUntilProviderAcceptance: true, deletedAfterProviderAcceptance: true }, resend: { oldVersionActiveWhilePending: true, invalidatedOnlyAfterProviderAcceptance: true, providerIdempotent: true }, sameRedemptionConcurrency: { attempts: 20, effectiveIssuances: 1, sameResultForSameId: true }, otp: { wrongAttemptsBeforeLock: 5, correctAfterLock: "reject", invalidMagicDoesNotIncrementOtp: true } } };

async function put(path, value) { await mkdir(dirname(path), { recursive: true }); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8"); }
await put(resolve(here, "positive.json"), positive); await put(resolve(here, "negative.json"), negative); await put(resolve(here, "states.json"), states);
const files = {}; for (const name of ["positive.json", "negative.json", "states.json", "build.mjs", "validate.mjs", "loader.ts", "rust/Cargo.toml", "rust/Cargo.lock", "rust/src/main.rs"]) files[name] = digest(await readFile(resolve(here, name))); for (const name of ["domains.json", "schemas.json", "README.md"]) files[name] = digest(await readFile(resolve(spec, name)));
const manifestCore = { manifestVersion: 1, contractVersion: "tinycloud.share-email-claim/v1", files, testOnly: true }; await put(resolve(here, "manifest.json"), { ...manifestCore, manifestDigest: digest(utf8(jcs(manifestCore))) });
console.log(JSON.stringify({ manifestDigest: digest(utf8(jcs(manifestCore))), files }, null, 2));
