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

The rotating phrase under the landing headline (`src/landing/share-targets.ts`, `SHARE_TARGETS`) is this list, in this order. `test/landing-share-targets.test.ts` fails if the array and the list differ. Each phrase completes "Share what your agent makes …", so every entry starts with "with".

The rotation deliberately includes kinds that are not live yet. This was a product decision on 22 Oct 2026 and replaces the earlier rule of showing only live kinds. Do not remove an entry because its kind is not live; the marker after each entry is information for maintainers, not a filter.

- with a person (live)
- with an email address (live)
- with your team (not live yet)
- with your friends (not live yet)
- with your family (not live yet)
- with your group chat (not live yet)
- with everyone at your company (live)
- with your clients (not live yet)
- with your classmates (not live yet)
- with your neighbours (not live yet)

"with a person" is first because it is the phrase shown without JavaScript and under reduced motion. "with everyone at your company" is the domain recipient kind. Group kinds (team, friends, family, group chat) become live with group credentials and their claim type.

Details: TC-1422
