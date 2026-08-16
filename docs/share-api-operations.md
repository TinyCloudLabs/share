# Share API operations

Pages must set `SHARE_API_ORIGIN` to the exact literal
`https://api.share.tinycloud.xyz`. The root Pages Function rejects whitespace,
alternate ports or hosts, HTTP, credentials, paths, queries, fragments, and
missing values; it proxies
only readiness, well-known, registry, Share API, and email-share routes. All
other requests fall through to Pages assets/SPA. Browser origin and upstream
host are canonicalized and credential cookies are retained.

The `share-api` CVM persists `/var/lib/tinycloud/share` and defaults
`SHARE_SENDER_ENABLED` to `false` (auth-only), ignoring stale sender settings
in that mode. Compose passes through the sender inputs, removes empty optional
values before startup validation, and defaults the binding journal to
`/var/lib/tinycloud/share/bindings.ndjson` inside that persistent volume.
Auth-only sessions may write bounded encrypted bearer-share blobs
through `/api/share/link-only/registry/blobs`; this does not enable email,
sender signing, policy authorization, or binding publication. Direct public
registry writes remain closed. The CVM creates one dedicated Ed25519 upload
key at `/var/lib/tinycloud/share/registry-upload.key`, reuses it across
restarts, and signs only short-lived authorizations bound to the authenticated
session, ciphertext digest, size, and retention. Configure the corresponding
public key as `REGISTRY_LINK_UPLOAD_PUBLIC_KEY` on the existing registry
Worker; it is separate from the Node/email authorization key and cannot
authorize bindings or reads. Share signs production replay and quota operations
to the Worker at `POST /internal/upload-authorizations`; the Worker stores them
in the `UploadAuthorization` Durable Object. The host fails closed if that
endpoint or its Durable Object binding is unavailable, so independent host
instances and restarts share one atomic JTI and twenty-upload window. Deploy
`compose.share-api.yml` with
`SHARE_API_IMAGE` set to the
exact merged-main GHCR digest and `CLOUDFLARE_TUNNEL_TOKEN` injected through
Phala sealed environment storage. The trust bundle comes from
`SHARE_TRUST_BUNDLE_SOURCE`, a literal in the compose file: `environment`
decodes `SHARE_TRUST_BUNDLE_BASE64` out of that same sealed storage, and
`committed` uses the reviewed `config/trust-bundle.production.json` baked into
the pinned image. Prefer `committed`. The bundle carries public keys and origins
only, and a sealed environment can only be replaced wholesale, so updating the
bundle through the sealed path also rewrites `CLOUDFLARE_TUNNEL_TOKEN` — which
cannot be regenerated here. `docs/share-host-deployment.md`, "Where the trust
bundle comes from", has the key-correction procedure. The
pinned Cloudflare Tunnel sidecar exposes only the internal
Share API service at `api.share.tinycloud.xyz`; the API container publishes no
host port. `authReady` means nonce, OpenKey proof, replay, origin, and session
issuance work. `SHARE_SENDER_ENABLED=true` requires an enabled trusted node, a
writable durable binding store, and a resolvable sender signing identity.
Static sender key and capability variables are forbidden and are not a startup
input; there is no deployment variable that carries sender authority. The
sender root seed is created once at `SHARE_SENDER_ROOT_KEY_PATH`
(`/var/lib/tinycloud/share/sender-root.key`), 0600, inside the same persistent
volume, and each authenticated wallet gets a distinct sender `did:key` derived
from it. `senderReady` therefore means "the sender path is configured and can
serve an authenticated session", not "a specific static key exists". Whether a
given session holds sender authority is a per-request fact:
`GET /api/share/sender-identity` returns that session's `senderDid`,
`POST /api/share/capabilities` admits a capability bound to that identity and
to the session's own wallet as policy owner, and a session holding none gets
JSON `409 sender_capability_required`. The capability descriptor itself is
minted outside the Share host: the node resolves it against operator-supplied
authority material whose `senderDid` is fixed at node boot, so a wallet's
`senderDid` must be provisioned into that material before its sends are
authorized. Without an enabled sender, email sender actions fail closed with
JSON `503 sender_not_ready`; no authority is invented during CVM creation.
Enable the OpenCredentials email capability only after its durable migrations,
provider inputs, and readiness gate are healthy; run the controlled E2E only
when both services advertise readiness. Roll back by disabling both flags and
restoring the prior image/configuration. Do not send email during smoke tests.

Record the merged main commit and image provenance, create/update the CVM,
attach `api.share.tinycloud.xyz` through authenticated Cloudflare, set the
Pages variable, and deploy Functions. Verify public TLS, readiness, nonce,
well-known JSON, and the sender boundary. Roll back by restoring the prior
Pages deployment and CVM image/commit. Do not send email during smoke tests.

## Automated Phala release path

`.github/workflows/share-api-phala-production.yml` runs only after the
successful `Share API image` workflow for `main`. That image workflow records
its build-action digest as a retained artifact; the deploy workflow downloads
that exact artifact by the successful workflow-run ID rather than resolving a
mutable tag. It verifies the GitHub build attestation before updating the
existing `PHALA_SHARE_API_CVM_ID` under the protected GitHub `production`
environment. Deployments serialize; they never create a CVM. Configure only
the production-environment `PHALA_CLOUD_API_KEY` secret and the CVM ID and
release-provenance variables there. Changes to the rendered
`compose.share-api.yml` also publish a reviewed main image and therefore enter
this release path. The deploy does not expose CVM logs publicly.

The workflow passes no `phala -e` flags. The sealed tunnel token and all other
sealed environment inputs remain intact; it writes only the digest and public
strict release-provenance record into a temporary compose file. It retains the
currently-running immutable `share-api` digest as the rollback target (or a
manual dispatch must explicitly provide one). GitHub production variables
`SHARE_NODE_COMMIT`, `SHARE_OPEN_CREDENTIALS_COMMIT`, `SHARE_SDK_COMMIT`, and
`SHARE_MIGRATION_VERSION` are required to form provenance.

Manual dispatch is for digest-pinned rollback/recovery only: it requires the
attested image digest and its protected-main `share_commit`, and checks the
commit remains reachable from main. It verifies the image attestation with
`--source-digest` set to that exact commit and binds the signer to the image
workflow, so an attestation from another commit or workflow cannot be paired
with an arbitrary main ancestor. Manual recovery checks out that source commit
before rendering its configuration provenance, rather than using a later
protected-main checkout; the workflow retains full main history for this
ancestor proof. All image-workflow actions are commit-pinned.
To roll back, dispatch the known-good digest and commit; the currently running
digest is captured as the new immutable rollback target. Each deployment waits for the target `share-api`
container to report Docker health `healthy`, then checks public `https://share.tinycloud.xyz` readiness,
the published trust contract, and the exact OpenKey nonce/proof boundary. A
failed check leaves the workflow failed for operator rollback; it never rolls
forward using a tag or changes sealed inputs.
