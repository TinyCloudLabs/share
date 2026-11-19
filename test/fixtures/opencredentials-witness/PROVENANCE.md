# OpenCredentials witness fixture

A fake OpenCredentials witness used by the through-receiver tests. It serves the acquisition endpoints,
checks the holder signature and issues a real SD-JWT signed by a throwaway issuer key. No network is used.

Source: `TinyCloudLabs/js-sdk` at commit `396ba7111d38f1d2390d165230749520aa6729ea`.

| file here | upstream path |
| --- | --- |
| `witness-stub.mjs` | `packages/node-sdk/src/credentials/test-support/witness-stub.mjs` |
| `golden-descriptor-digests.json` | `packages/sdk-core/test-fixtures/opencredentials-v1/golden-descriptor-digests.json` |

License: the upstream repository's EGPL v1.5 (copyright (c) 2026 TinyCloud Labs), the same terms as the
TinyCloud packages this repository already depends on. `golden-descriptor-digests.json` is unmodified.

Changes to `witness-stub.mjs`, all test-local: the golden descriptor is read from this directory (a path relative to the repository root, where the
tests run) instead of the upstream path, and the issuer metadata route `/.well-known/opencredentials/issuer` (read by a browser
receiver, which upstream's node-sdk tests pin instead) is served from the stub's own issuer key.
`witness-stub.d.mts` is new and only types the import.
