# Native recipient-DID fixture oracle

This oracle prevents the JSON fixture from asserting authority merely because
its checked-in `nativeVerified` object says so. It uses the exact pinned
tinycloud-node source and native Rust types to:

- decode Cacao and UCAN using `TinyCloudDelegation::decode`;
- recompute their distinct CID preimages;
- cryptographically verify both signatures and current time;
- parse the Cacao SIWE ReCap and UCAN capabilities;
- verify owner -> session -> recipient principals/proof CID;
- verify resource, ability, caveat, and time attenuation;
- derive and exact-compare every field of the checked-in atomic native output,
  including the verification marker, normalized signer principal and DID URL,
  ordered proof CIDs, complete exact scope, and effective temporal bounds.

Temporal validity is checked at the same frozen instant as the TypeScript
contract tests (`2029-01-01T00:00:00Z`), so the oracle does not depend on the
machine clock.

Run from this share repository with a clean tinycloud-node checkout:

```sh
TINYCLOUD_NODE_DIR=/path/to/tinycloud-node node packages/envelope/test/native-fixture/run.mjs
```

The runner refuses any commit other than
`390253aca30628f2ac2be28e64d8e3830da07aaa`, creates an isolated temporary
Cargo package using that checkout and its lockfile, and removes it afterward.
