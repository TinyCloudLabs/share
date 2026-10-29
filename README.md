# TinyCloud Sharing

TinyCloud Sharing is the browser UX for TinyCloud's native delegation and invocation protocol. It does not store shared content or run a parallel capability service.

## Architecture

- The sender writes content to the sender's TinyCloud applications space.
- Bearer sharing creates one read-only TinyCloud delegation and transports it in the secret `#tc1` fragment.
- DID, email, and policy sharing create signed Policy/v3 metadata, seal it locally, store the sealed invitation behind a short `/s/<id>` link (or carry it in a full link), and place its key only in the `#v=4` fragment.
- The recipient proves the required identity, then invokes the owner's TinyCloud node under that delegation or policy.
- `registry.tinycloud.xyz` discovers a user's TinyCloud node. It is not a share blob store.
- `witness.credentials.org/v1/credential-invitations` is OpenCredentials' generic delivery endpoint. It receives the owner-node receipt and sends the invitation; Share has no mail, admission, or data-plane service.

See [docs/tinycloud-native-sharing.md](docs/tinycloud-native-sharing.md) for the protocol boundaries, [docs/html-artifact-sharing.md](docs/html-artifact-sharing.md) and [docs/jsx-artifact-sharing.md](docs/jsx-artifact-sharing.md) for artifact rendering, and [docs/user-content-origin.md](docs/user-content-origin.md) for serving the sandbox documents from a separate origin.

## Shared by me pagination

Shared by me loads the next page once and hides Load more after the final share. Retrying a later page keeps the shares already displayed and resumes that page; TinyCloud status checks are reported separately. Details: TC-1740

## Development

`npm install`, then use `npm run dev`, `npm test`, `npm run typecheck`, and `npm run build`.

The Vite output in `dist/` is a static Cloudflare Pages site. Share deploys no server-side package.

### Production sender smoke

`npm run test:e2e:sender-signin` creates a fresh throwaway OpenKey account and verifies sign-in, link-only sharing, and recipient read-back against production services. `SHARE_SMOKE_CANDIDATE=dist` serves a local Share build inside the runner's browser; OpenKey and TinyCloud remain real.

Use Puppeteer element clicks for approval, not DOM `.click()` inside `evaluate()`: OpenKey intentionally rejects untrusted approval events in iframes. Keep that security guard and the approval-count limits intact.

## Landing page: recipients

The landing headline is three lines with no period: "Share what your" / "agent makes with" / a recipient typed from `SHARE_TARGETS` (`src/landing/share-targets.ts`), one after another. The headline scales so its longest line fits the column. If you add a phrase longer than "an email address", raise the divisor in `#hero-title` (`src/landing/landing.css`).

The list may include recipient kinds that don't work end to end yet (family, club, community and so on). Sam decided this on 2026-10-22, so don't bring back the old rule that only live kinds may appear.

Accessibility: the `<h1>` carries the whole sentence as its `aria-label` (`HEADLINE_LABEL` in `src/landing/brand.ts`) and the typed part is `aria-hidden`. Typing runs `CYCLES` passes, then stops on the first phrase. Under `prefers-reduced-motion` it doesn't animate.

Agent buttons: the tiles under the prompt (`src/landing/agent-links.html`) open each agent with the prompt, which points it at `https://agents.tinycloud.xyz/share`. The Hermes tile installs that URL as a skill. So agents.tinycloud.xyz is in the skill-install trust path: whatever it serves is what those agents follow.
