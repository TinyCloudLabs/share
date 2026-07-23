# Production registry

Deploy from this directory with `npx wrangler deploy --config wrangler.jsonc`. Create the R2 bucket `tinycloud-share-registry` first, then grant the Worker only that bucket. Set `REGISTRY_AUTH_PUBLIC_KEY` to the existing Node/delegation public key; the Worker rejects writes without the signed `x-tinycloud-authorization` contract and never accepts trust fixtures. The custom route is `registry.tinycloud.xyz`; it is independent of the marketing Pages project.

Do not publish trust-bundle changes until the real Node and issuer keys are live. Verify `GET /ipfs/<cid>?format=raw` returns `application/vnd.ipld.raw` bytes and that overwrite mismatches are rejected.
