# TinyCloud exact-email claim v1 — frozen Wave 0 contract

This directory is the language-neutral contract. Consumers load and verify
`test/vectors/email-claim-v1/manifest.json` before using any fixture. The
fixture set is test-only; its private keys MUST never be used in production.

## Canonical bytes

All protocol messages use RFC 8785 JCS UTF-8. The implementation rejects
non-finite numbers, unsafe integers, `-0`, undefined/functions/symbols,
non-plain objects, and lone UTF-16 surrogates. Object keys are sorted by UTF-16
code unit. Binary is strict unpadded base64url. A normal signed artifact is
`UTF8(domains[artifact]) || UTF8(JCS(message))`, including the frozen envelope
domain. The checked-in shipping envelope signer still signs bare JCS; the
runtime conformance gap and required domain-separation patch are recorded
below.

The shipped envelope body is the strict object:

```json
{"version":1,"shareId":"…","delegation":"…","authorizationTarget":{"kind":"policy","policyCid":"…","policyBytes":"…"},"target":{"origin":"https://…","nodeAudience":"did:web:…","spaceId":"…","resource":{"kind":"exact","path":"…"}},"display":{},"expiry":"…"}
```

The signed target is a discriminated union. A policy target always contains
`kind`, `policyCid`, and `policyBytes`; policy bytes are canonical bytes of a
policy descriptor that contains neither `policyCid` nor `shareCid`. The CID is
computed independently as CIDv1/raw/SHA-256 over those exact bytes and the
bytes are embedded in the target. The share CID is computed over the complete
shipping sealed blob (`version || nonce || ciphertext`) using the same
CIDv1/raw/SHA-256 rule; fixture blobs are deterministic test blobs.

## Email and sources

The protocol accepts only an ASCII addr-spec. The local part is RFC 5322
`dot-atom-text` using `atext` and is preserved byte-for-byte; only the domain
is ASCII-lowercased. Leading, trailing, repeated, or interior whitespace,
quoted/commented locals, Unicode, multiple `@`, and invalid LDH/A-label DNS
labels are rejected. Limits are byte limits, not JavaScript character counts.

`contentSource` is a strict KV or named-SQL union. SQL arguments are a plain
JSON object whose JCS UTF-8 bytes are separately digested and bounded. Raw SQL
transport is never part of this contract. Both source and source digest are
carried byte-for-byte by every signed artifact.

## API and state coverage

`schemas.json` covers every invitation-create, resend, claim-challenge,
claim-redeem, policy-challenge, policy-session, and read request, success, and
failure surface from product spec §§6 and 9. Capability descriptors are
validated against their strict schema and route allowlists. `negative.json` is
executable: every row drives a real schema/CID/JCS/DID/signature/reference
validator or a re-signed mutation. `states.json` is executed as a transactional
model covering resend/provider acceptance/crash recovery, OTP, JTI, nonce,
redemption idempotency, and scanner GET boundaries.

The envelope domain is `xyz.tinycloud.share/envelope/v1\0`. The checked-in
shipping envelope package currently signs and verifies its envelope body as
JCS-only; it has no domain-registry input. This fixture suite intentionally
uses the frozen registry domain and records the compatibility gap here. A
future runtime conformance patch must add the registry domain to the shipping
package's envelope sign/verify input, then update its local tests; runtime
files are outside this contract recovery change.

Run the complete contract suite with:

```sh
node test/vectors/email-claim-v1/build.mjs
node test/vectors/email-claim-v1/validate.mjs
tsc --noEmit --target ES2022 --module ESNext --moduleResolution bundler --strict --skipLibCheck test/vectors/email-claim-v1/loader.ts
bun test/vectors/email-claim-v1/loader.ts
cargo test --offline --manifest-path test/vectors/email-claim-v1/rust/Cargo.toml
```
