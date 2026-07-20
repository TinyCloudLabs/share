# TinyCloud Sharing

The UX blueprint, specs, wireframes, and spec site for **TinyCloud Sharing** (share.tinycloud.xyz) — email-addressed, end-to-end verifiable share links where possession of the link is necessary but not sufficient: addressed shares also require proof.

## Repo map

| Path | What it is |
|---|---|
| [`specs/sharing-ux-blueprint.md`](specs/sharing-ux-blueprint.md) | UX blueprint — sender flow, human-recipient flow, agent-recipient flow, link anatomy, claim protocol, decision record |
| [`specs/sharing-viewer-and-registry.md`](specs/sharing-viewer-and-registry.md) | Viewer product (share.tinycloud.xyz) + share registry service spec |
| [`wireframes/`](wireframes/) | 14 low-fi SVG wireframes + [`annotations.md`](wireframes/annotations.md) — the canonical, annotated source of truth |
| `index.html`, `src/`, `public/` | The Vite spec site rendering the blueprint as a single page |

Note: `wireframes/` is canonical; `public/wireframes/` is a build-time copy used as site assets. Re-sync after editing SVGs with `npm run sync:wireframes`.

## Local dev

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

Output goes to `dist/`.

## Deploying to Cloudflare Pages

- Framework preset: **Vite**
- Build command: `npm run build:deploy` with the deployment variables in
  [`docs/share-host-deployment.md`](docs/share-host-deployment.md)
- Build output directory: `dist`

One-liner alternative:

```bash
npx wrangler pages deploy dist --project-name share
```
