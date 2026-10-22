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

## Landing page: recipients

The landing headline ("Share what your agent makes with …") types the phrases in `SHARE_TARGETS` (`src/landing/share-targets.ts`) one after another, on one line. If you add a phrase longer than "an email address", raise the fit divisor in `.share-target` (`src/landing/landing.css`).
