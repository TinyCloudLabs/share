# TinyCloud Sharing

TinyCloud Sharing is the browser UX for TinyCloud's native delegation and invocation protocol. It does not store shared content or run a parallel capability service.

## Architecture

- The sender writes content to the sender's TinyCloud applications space.
- Bearer sharing creates one read-only TinyCloud delegation and transports it in the secret `#tc1` fragment.
- DID, email, and policy sharing create signed Policy/v3 metadata, seal it locally, and place the sealed invitation plus its key only in the `#v=2&p=…` fragment.
- The recipient proves the required identity, then invokes the owner's TinyCloud node under that delegation or policy.
- `registry.tinycloud.xyz` discovers a user's TinyCloud node. It is not a share blob store.
- `witness.credentials.org/v1/credential-invitations` is OpenCredentials' generic delivery endpoint. It receives the owner-node receipt and sends the invitation; Share has no mail, admission, or data-plane service.

See [docs/tinycloud-native-sharing.md](docs/tinycloud-native-sharing.md) for the protocol boundaries, [docs/html-artifact-sharing.md](docs/html-artifact-sharing.md) and [docs/jsx-artifact-sharing.md](docs/jsx-artifact-sharing.md) for artifact rendering, and [docs/user-content-origin.md](docs/user-content-origin.md) for serving the sandbox documents from a separate origin.

## Development

`npm install`, then use `npm run dev`, `npm test`, `npm run typecheck`, and `npm run build`.

The Vite output in `dist/` is a static Cloudflare Pages site. Share deploys no server-side package.

## Landing page: recipient kinds

The rotating line on the landing page lists only recipient kinds that work end to end today (`src/landing/share-targets.ts`, `SHARE_TARGETS`). When a new recipient kind or claim type is live in Share, add its phrase to that array in the same release.

Planned, not yet live. Do not add these to `SHARE_TARGETS` until the kind works end to end in Share:

- your family
- your team
- your friend group
- your group chat

They join the rotation when group credentials and their claim type work end to end.

When "your team" goes live (group credentials), it replaces "your team's domain" in the array; it is not added beside it.
