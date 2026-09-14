# TinyCloud Sharing

TinyCloud Sharing is the browser UX for TinyCloud's native delegation and invocation protocol. It does not store shared content or run a parallel capability service.

## Architecture

- The sender writes content to the sender's TinyCloud applications space.
- Bearer sharing creates one read-only TinyCloud delegation and transports it in the secret `#tc1` fragment.
- DID, email, and policy sharing create signed Policy/v3 metadata. The public, fragment-free `?tc2` invitation points back to encrypted content on the owner's node.
- The recipient proves the required identity, then invokes the owner's TinyCloud node under that delegation or policy.
- `registry.tinycloud.xyz` discovers a user's TinyCloud node. It is not a share blob store.
- `email.tinycloud.xyz/v1/email` is the existing OpenCredentials delivery endpoint. It receives the owner-node receipt and sends the invitation; Share has no mail, admission, or data-plane service.

See [docs/tinycloud-native-sharing.md](docs/tinycloud-native-sharing.md) for the protocol boundaries and [docs/html-artifact-sharing.md](docs/html-artifact-sharing.md) for artifact rendering.

## Development

`npm install`, then use `npm run dev`, `npm test`, `npm run typecheck`, and `npm run build`.

The Vite output in `dist/` is a static Cloudflare Pages site. Share deploys no server-side package.
