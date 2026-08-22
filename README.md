# TinyCloud Sharing

TinyCloud Sharing is the browser UX for TinyCloud's native delegation and invocation protocol. It does not store shared content or run a parallel capability service.

## Architecture

- The sender writes content to the sender's TinyCloud applications space.
- Bearer sharing creates one read-only TinyCloud delegation and transports it in the secret `#tc1` fragment.
- DID, email, and policy sharing create signed Policy/v3 metadata. The public, fragment-free `?tc2` invitation points back to encrypted content on the owner's node.
- The recipient proves the required identity, then invokes the owner's TinyCloud node under that delegation or policy.
- `registry.tinycloud.xyz` discovers a user's TinyCloud node. It is not a share blob store.
- `api.share.tinycloud.xyz/v1/email` verifies a node- and sender-signed, short-lived, single-use delivery receipt and sends the exact invitation through Resend. It cannot mint access, read or proxy content, store capabilities, or resolve policy.

See [docs/tinycloud-native-sharing.md](docs/tinycloud-native-sharing.md) for the protocol boundaries and [docs/html-artifact-sharing.md](docs/html-artifact-sharing.md) for artifact rendering.

## Development

`npm install`, then use `npm run dev`, `npm test`, `npm run typecheck`, and `npm run build`.

The Vite output in `dist/` is a static Cloudflare Pages site. The only server-side package in this repository is the optional email-delivery Worker under `packages/email/`.
