# JSX artifact sharing

A `.jsx` or `.tsx` file shared with an anyone-with-the-link (bearer) share renders
in the viewer instead of downloading. The file is a React component with a
default export; the viewer compiles and runs it inside a sandboxed frame.
Addressed (email/domain) links keep the download: the viewer on those links holds
the recipient's session material, so sender code does not run there.

A file is treated as JSX when its signed media type is `text/jsx` or `text/tsx`,
or when an unsigned bearer key ends in `.jsx` or `.tsx`. A signed non-JSX media
type wins over the extension, as for HTML.

## Writing an artifact

```jsx
import { useState } from "react";
import { Plus } from "lucide-react";

export default function Counter() {
  const [count, setCount] = useState(0);
  return (
    <button className="rounded-tc-lg bg-tc-accent px-4 py-2 text-tc-on-accent" onClick={() => setCount(count + 1)}>
      <Plus size={16} /> {count}
    </button>
  );
}
```

- JSX, TypeScript and ES `import` are compiled in the frame (sucrase). Only
  the default export is mounted, under an ErrorBoundary.
- Library set: `react` 19 (with `react-dom`, `react-dom/client`,
  `react/jsx-runtime`), `lucide-react`, `recharts`, `d3` (without `d3-delaunay`),
  `mermaid`. Tailwind v4's browser runtime is always on, mapped to the TinyCloud
  tokens: `bg-tc-surface`, `text-tc-muted`, `border-tc-border`, `bg-tc-accent`,
  `rounded-tc-md`, `font-tc-sans`, and so on. Light and dark follow the system.
- Anything else (`import x from "left-pad"`) shows "x isn't available" with the
  list above. Bundle the code into the file or publish a self-contained HTML page.
- Source is limited to 1 MB; the frame has 15 seconds to start.
- Examples: `examples/jsx-artifact/`.

## How it is isolated

```
viewer ─ <iframe sandbox="allow-scripts" allow="" referrerpolicy="no-referrer"
                 src="…/jsx-sandbox.html#<128-bit nonce>">
            └─ <iframe sandbox="allow-scripts" srcdoc="…">      (created by the bridge)
```

- Neither frame has `allow-same-origin`, popups, top-navigation, forms, modals or
  downloads, so both are opaque (`origin === "null"`) on whatever host serves them.
- Frame policy, identical in `public/_headers` and the document's meta tag (the
  header adds `frame-ancestors`):
  `default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'; img-src data: blob:; font-src data: blob:; media-src data: blob:; connect-src 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`.
  The bridge also sends a `Permissions-Policy` that turns off fullscreen,
  Picture-in-Picture and powerful features.
- Messages are `{v:1, type, nonce, …}`. The viewer accepts only
  `event.source === bridge.contentWindow`, `event.origin === "null"`, the nonce and
  an allowlist of types (`bridge-ready`, `ready`, `error`, `restore-controls`);
  the bridge accepts `render` only from its parent and child messages only from
  its own child. Anything else is dropped without a reply. The reserved `cap/*`
  namespace is dropped by default.
- What enters the frame: `{v,type,nonce,kind,source,modules,theme}`. Never the
  link or its fragment, session or delegation material, keys, the sender's
  identity or storage handles.
- Library files are fetched by the viewer, accepted only if their sha256 equals
  the manifest embedded in the viewer build, and inlined into the child as classic
  scripts. The artifact source is embedded as escaped JSON data, never as markup.
- The viewer never parses or evaluates the source: it runs a bounded string scan
  for import specifiers.

## What an artifact can and cannot do

It can run JavaScript, draw DOM/SVG/canvas, play `data:`/`blob:` media and keep
in-memory state. It cannot make a content or script request (measured in
Chromium with a loopback server: img, CSS `url()`/`@import`/`@font-face`,
video/audio, `<link>` stylesheet/prefetch, XHR, fetch, WebSocket, EventSource,
`sendBeacon`, `<object>`, `<embed>`: zero requests and zero connections). It
cannot read viewer storage or cookies, navigate the top window, open popups, submit
forms, start workers or go fullscreen.

### Privacy: what is and is not blocked

The frame cannot make ANY content or script request (img/CSS url/@import/@font-face/video/audio/link/XHR/fetch/WebSocket/EventSource/sendBeacon/object/embed: measured: zero requests and zero connections). It can still cause connection-level signals that CSP cannot block: preconnect / navigation attempts (one TCP connect before the frame-src block) / prerender / dns-prefetch / WebRTC: a hostile author can learn the viewer's IP and the time of opening. Mitigation is product-level notice; the separate registrable domain (S9) does not change this (it is network egress, not isolation).

| Class | Observed (Chromium 142, loopback server) | Mitigation |
|---|---|---|
| Content/script requests | none: zero requests, zero connections | CSP, asserted by `npm run test:e2e:jsx` |
| `<link rel=preconnect>` | one TCP connection, no HTTP request | notice |
| iframe `src`, meta refresh, `location` assignment | one TCP connection before the `frame-src` block; no HTTP request | notice |
| `<link rel=prerender>` | one GET and one connection | notice |
| `<link rel=dns-prefetch>` | DNS lookup (not observable on loopback) | notice |
| WebRTC (ICE to a STUN server) | UDP packets to the server | notice. The CSP `webrtc` directive is not recognised by the Chromium used here, so it is not set. |

The viewer says so above the frame: "This page runs the sender's code. The sender
can tell that you opened it." It is rendered by the viewer, outside the frame,
and is dismissed only by a click on its own button (remembered per share and
reachable afterwards). Nothing in the frame can hide, cover or dismiss it: the
frame is an isolated, clipped box stacked below it; `position: fixed`, z-index and
`pointer-events` inside the frame only affect the frame; the frame gets no
fullscreen or Picture-in-Picture; the recall shortcut (Alt+Shift+C) is captured
before any artifact listener and only reveals the notice and moves focus to it.
`npm run test:e2e:jsx` runs a hostile fixture against all of this.

A runtime busy loop can freeze the viewer tab: the frame shares the viewer's
process on browsers that do not isolate opaque-origin frames.

## Errors

A panel in the viewer, never partial output: compile errors show the message and
line; an unknown import lists the library set; a runtime error comes from the
frame's ErrorBoundary; a failed library digest (a deploy in progress) says "This
artifact viewer is updating. Try again in a minute." Each has "Download source".

## Licences

`NOTICE` lists every bundled package with its licence text (MIT, ISC,
Apache-2.0, BSD, 0BSD only). `npm run notice:jsx` regenerates it from the build,
the build fails on any other licence, and a test fails when the file is stale.
`d3-delaunay` is left out of the d3 file because its dependency `robust-predicates`
is Unlicense.

## Extension points

- Capabilities: a handler for the reserved `cap/*` messages can be registered on
  `createJsxSandbox({ onCapability })`. The default handler does not exist and the
  messages are dropped. The bridge does not forward them yet.
- The runner entry `renderJsxPage(container, sourceTextOrBytes, options)` takes
  source bytes and an options object (theme, title, preloaded verified modules); it
  knows nothing about shares. `content.ts` adapts a share to it.
