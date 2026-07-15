# TinyCloud recipient-DID share envelope v2

Status: normative Stage 0A contract for TC-224. **MUST**, **MUST NOT**,
**SHOULD**, and **MAY** are normative. Bearer envelope v1 is unchanged.

## Wire shape

Every object is strict and rejects unknown fields. The executable schema is
`packages/envelope/src/recipient-did-v2.ts`.

```json
{
  "version": 2,
  "shareId": "share-id",
  "delegation": {
    "format": "tinycloud-recipient-delegation-v2",
    "routing": {
      "origin": "https://node.tinycloud.xyz",
      "nodeAudience": "did:web:node.tinycloud.xyz"
    },
    "grant": {
      "kind": "ucan",
      "cid": "<CIDv1/raw/blake3-256>",
      "encoding": "jwt",
      "value": "<header.payload.signature>"
    },
    "issuerProofs": [
      {
        "kind": "cacao",
        "cid": "<CIDv1/raw/blake3-256>",
        "encoding": "dag-cbor-base64url-pad",
        "value": "<padded base64url DAG-CBOR>"
      }
    ]
  },
  "authorizationTarget": {
    "kind": "recipientDid",
    "did": "did:pkh:eip155:1:<EIP-55 address>"
  },
  "target": {
    "origin": "https://node.tinycloud.xyz",
    "nodeAudience": "did:web:node.tinycloud.xyz",
    "spaceId": "tinycloud:pkh:eip155:1:<EIP-55 address>:<space-name>",
    "resource": { "kind": "exact", "path": "path" },
    "actions": ["tinycloud.kv/get"]
  },
  "display": {},
  "expiry": "2096-10-02T07:06:40.000Z",
  "signature": {
    "signerDid": "did:key:<active session multibase>",
    "algorithm": "Ed25519",
    "value": "<64-byte unpadded base64url>"
  }
}
```

`issuerProofs` is authority order: exactly one owner-signed Cacao root followed
by zero or more UCAN session proofs. `grant` is the final recipient UCAN. Every
CID appears exactly once. Missing, duplicated, extra, or misordered artifacts
are invalid.

## Genuine TinyCloud transports and CIDs

The artifact discriminant is normative; guessing type from whether a string
contains `.` is forbidden at the envelope boundary.

- `cacao`: the exact current `TinyCloudDelegation::Cacao` `HeaderEncode`
  output. `value` is canonical URL-safe base64 **with required padding** of the
  decoded DAG-CBOR bytes. The CID preimage is those decoded DAG-CBOR bytes.
- `ucan`: the exact current `TinyCloudDelegation::Ucan` output. `value` is
  exactly three non-empty, canonical, unpadded base64url JWT segments. The CID
  preimage is the UTF-8 bytes of the encoded JWT string.

Both use CIDv1, raw codec `0x55`, Blake3-256 multihash `0x1e`, canonical lower
base32. The envelope package recomputes these CIDs before crossing the native
authority boundary.

The positive vector was generated with `tinycloud-sdk-wasm` 1.3.0 at
tinycloud-node `390253aca30628f2ac2be28e64d8e3830da07aaa` using
`prepare_session`, `complete_session_setup`, and `Session.create_delegation`.
It contains a genuine owner Cacao and session UCAN, not invented transport
strings. The checked-in native Rust oracle decodes and cryptographically
verifies the complete chain at that exact commit. The test-only JWK seed is
fixture input; no production API accepts or exports private key material.

## Sender signature

The active TinyCloud session key signs the envelope and is also the verified
issuer principal of the recipient grant. Construct the complete envelope with
`signature: {signerDid, algorithm:"Ed25519"}` and no `signature.value`. The
exact bytes are:

```text
UTF8("xyz.tinycloud.share/envelope/v2\0") || RFC8785_JCS(envelope)
```

Thus signer DID and algorithm are signed. Verification is strict RFC 8032
Ed25519, not ZIP-215. The signature is canonical unpadded base64url of exactly
64 bytes. Production package exports provide signing bytes only; the later SDK
lane MUST expose one fixed-purpose session operation and MUST NOT expose a raw
private key or general arbitrary-message signer.

`signerDid` is accepted only if base58btc decoding, Ed25519 multicodec `0xed`,
32-byte length, curve-point decoding, and canonical re-encoding all succeed.
Malformed signer/signature input returns rejection and never escapes as a
decoder exception.

## DID principals and space ownership

Recipient and owner identities are canonical sdk-core chain-1/EIP-55
`did:pkh` strings. Noncanonical casing and other chains are rejected on wire.
Email discovery is out of scope.

The target space is the full canonical SDK space ID:

```text
tinycloud:pkh:eip155:1:<EIP-55 address>:<space-name>
```

The owner encoded by that address MUST equal the root owner returned by native
authority verification. A valid session belonging to another owner therefore
cannot share data from this target space.

UCAN issuers are DID URLs. The current accepted session verification method is
only:

```text
did:key:<multibase>#<same multibase>
```

Its principal is the substring before `#`, and MUST equal
`signature.signerDid`. Missing, arbitrary, or mismatched fragments are invalid.

## Atomic native authority boundary

Per-artifact signature checks or adjacency alone are insufficient. The SDK
MUST expose one atomic, network-free `verifyDelegationBundle` operation. It
returns success only after all of the following are true together:

1. every Cacao/UCAN parses and its genuine signature verifies;
2. every supplied CID is recomputed from the correct preimage;
3. the Cacao SIWE ReCap grants authority over the reported owner space/scope;
4. each edge's issuer principal equals its parent audience principal and cites
   exactly its authority-contributing parent CID(s);
5. capability resource, action, caveat, and delegation-mode attenuation holds
   at every edge—never merely at the final grant;
6. every not-before/expiry bound is currently valid and attenuates its parent;
7. the complete ordered artifact set was authority-contributing, with no
   missing, unmatched, duplicate, or extra proof;
8. root owner, session principal and verification method, recipient, ordered
   proof CIDs, final grant CID, exact scope, and effective time bounds are
   returned as a single typed result.

The envelope verifier validates that result and then enforces:

- root owner equals the owner encoded by `target.spaceId`;
- session principal/verification method equals the envelope signer;
- ordered proof CIDs and grant CID equal the transported bundle;
- recipient equals `authorizationTarget.did`;
- verified space, exact path, sorted actions, and expiry equal `target`;
- session-signed `delegation.routing` exactly equals target origin/audience.

No mock individual-artifact claims are an authority proof. Mock verified-output
cases in tests are secondary semantic boundary tests only.

## Routing and network order

Origin is a canonical, default-port HTTPS origin with a lowercase DNS hostname
and must exact-match a static deployment allowlist. Stage 0A deliberately does
not support IP literals, localhost, single-label names, non-default ports, or
`did:web` path/port encodings. Its sole audience grammar is lowercase
`did:web:<dns-host>`, with no fragment, whitespace, control character, or DID
URL suffix, and it MUST equal the mechanical origin mapping exactly. The same
rule applies independently to `delegation.routing` and `target`, and those two
signed pairs MUST also be byte-equal.

CSP `connect-src` and OpenKey `frame-src` derive from the same deployment
configuration. Consumers use the signed origin and node audience exactly;
redirects use error mode, and unsigned discovery cannot replace either value.

The only permitted order is:

1. registry envelope fetch, CID verification, decryption and fragment scrub;
2. strict schema and artifact CID verification;
3. envelope signature verification;
4. atomic native authority verification;
5. static signed route allowlisting and owner/recipient/route/scope/time
   binding verification;
6. OpenKey account selection and canonical recipient DID equality;
7. target-node request to the exact signed origin.

No invalid envelope signature reaches the native authority boundary. No
OpenKey or target-node access occurs before step 5; no target-node access
occurs before step 6. Recipient content is never fetched directly from the
registry.

Stage 0A performs no OpenKey or node I/O; it only returns a verified result.
Stage 1 integration therefore carries an explicit ordering risk: starting
OpenKey, following a redirect, or contacting the target node before that result
would recreate the confused-deputy and credential-exfiltration boundary this
contract closes. Integration tests MUST assert zero OpenKey and target-node
calls for every checked-in reject vector.

The Stage 1 harness now covers network call order, deployment-derived CSP,
OpenKey account equality, redirect error mode, exact target-origin requests,
and an opaque one-shot continuation that retains neither the fragment href nor
key. Production SDK/native/OpenKey/node adapters and their genuine end-to-end
test remain upstream integration work; fail-closed undefined adapters are not
claimed as that integration. A future fixture MUST also add a genuine
intermediate session UCAN between the Cacao and recipient grant so the
multi-hop native adapter path is exercised cryptographically; the Stage 0A
schema and atomic result already define its required root-to-leaf ordering.

## Golden vectors

`packages/envelope/test/vectors/recipient-did-v2.json` freezes the genuine SDK
chain, CID preimages, domain/JCS bytes, signature, atomic native result, and
reject catalog for proof order/membership, native and envelope signatures,
owner-space mismatch, route/scope/time attenuation, and noncanonical
DID/CID/base64/audience encodings. The contract test iterates every catalog
entry. Changing any frozen byte is a protocol-versioning event.
