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
- Forms work as on any page, without submitting: a sandbox without `allow-forms` refuses a form
  submission before the browser fires the `submit` event, so the runtime (`form-events.ts`) cancels
  the browser's own attempt and dispatches `submit` to the page's handlers itself when a submit
  button is clicked, Enter is pressed in a field (the HTML implicit-submission rules) or
  `requestSubmit()` is called. Nothing is sent or navigated; `form.submit()` stays blocked.
- Anything else (`import x from "left-pad"`) shows "x isn't available" with the
  list above. Bundle the code into the file or publish a self-contained HTML page.
- Source is limited to 512 KB (checked before the viewer scans it for imports); the frame has 15 seconds to start.
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
  namespace is dropped by the viewer. The bridge relays six known `cap/*` operations
  (bounded: plain data, 1 MB, 4 in flight) to its parent, and only a registered
  handler answers them: the installed-app runner ([tiny-app-runner.md](tiny-app-runner.md)).
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
video/audio, `<link>` stylesheet and prefetch, XHR, fetch, WebSocket, EventSource,
`sendBeacon`, `<object>`, `<embed>`: zero requests and zero connections). It
cannot read viewer storage or cookies, navigate the top window, open popups, submit
forms, start workers or go fullscreen.

### Privacy: what is and is not blocked

CSP blocks every content and script request the frame could make (img/CSS url/@import/@font-face/video/audio/link stylesheet and prefetch/XHR/fetch/WebSocket/EventSource/sendBeacon/object/embed: measured: zero requests and zero connections). Prerender, preconnect, navigation attempts, dns-prefetch and WebRTC can still reach out: a prerender can send an HTTP GET with author-chosen query data (and whatever cookies the target site would send on such a request, see [HTML artifact sharing](html-artifact-sharing.md)), a navigation attempt opens one TCP connection before the `frame-src` block, and WebRTC sends STUN packets. A hostile author can learn the viewer's IP, the time, and that the page was opened. Mitigation is product-level: the notice above the frame. A separate registrable domain for user content does not change this (it is network egress, not isolation).

| Class | Observed (Chromium 142, loopback server) | Mitigation |
|---|---|---|
| Content/script requests | none: zero requests, zero connections | CSP, asserted by `npm run test:e2e:jsx` |
| `<link rel=preconnect>` | one TCP connection, no HTTP request | notice |
| iframe `src`, meta refresh, `location` assignment | one TCP connection before the `frame-src` block; no HTTP request | notice |
| `<link rel=prerender>` | one HTTP GET to the author's address carrying author-chosen query data (`/link-prerender?data=author-chosen-value` in the test), plus a connection | notice |
| `<link rel=dns-prefetch>` | DNS lookup (not observable on loopback) | notice |
| WebRTC (ICE to a STUN server) | UDP packets to the server | notice. The CSP `webrtc` directive is not recognised by the Chromium used here, so it is not set. |

The viewer says so above the frame: "This page runs the sender's code. The sender
can tell that you opened it." It is rendered by the viewer, outside the frame,
and is dismissed only by a click or key press on its own button (remembered per
share under a hashed key, and reachable afterwards). Nothing in the frame can hide,
cover or dismiss it:

- the frame is an isolated, clipped box stacked below it; `position: fixed`, z-index
  and `pointer-events` inside the frame only affect the frame; the frame gets no
  fullscreen or Picture-in-Picture (`allow=""` and a Permissions-Policy on the
  sandbox documents);
- no frame message dismisses it. A frame can ask for the chrome to be revealed
  (`restore-controls`, which a user's Alt+Shift+C also sends), at most once a second
  and only after the page started; the viewer then shows the notice and, only if
  focus was in the frame, focuses the notice itself, never a button. Pressing Space
  or Enter right after therefore does nothing; "Got it" always takes the person's
  own Tab or click.

`npm run test:e2e:jsx` runs a hostile fixture against all of this, including a
`restore-controls` posted from inside the frame followed by Space and Enter.

A runtime busy loop can freeze the viewer tab: the frame shares the viewer's
process on browsers that do not isolate opaque-origin frames.

## Loading and errors

Until the page reports its first render the viewer covers the frame with a
skeleton and a status line ("Loading the page…", `role="status"`, still under
`prefers-reduced-motion`). After 15 seconds it says "This page is taking a long
time to start" with Try again (it keeps waiting); if the frame still has not
started, that becomes the panel.

Errors are a panel in the viewer, never partial output, written for the person
opening the link: compile errors show the message and line; an unknown import
lists the library set; a runtime error comes from the frame's ErrorBoundary; a
failed library digest (a deploy in progress) says "This artifact viewer is
updating. Try again in a minute." The notice stays above every panel. Each panel
has "Download source".

## Licences

`NOTICE` lists every bundled package with its licence text (MIT, ISC,
Apache-2.0, BSD, 0BSD only). `npm run notice:jsx` regenerates it from the build,
the build fails on any other licence, and a test fails when the file is stale.
`d3-delaunay` is left out of the d3 file because its dependency `robust-predicates`
is Unlicense.

## Extension points

- Capabilities: the handler for the reserved `cap/*` messages is registered on
  `createJsxSandbox({ onCapability })` (or `renderJsxPage`'s `onCapability`) as
  `(request, reply) => void`; `reply(id, result)` posts the `cap/result`. The default is no handler:
  the messages are dropped, and the share viewer registers none and never sends the
  `@tinycloud/app` client module. The installed-app runner registers the one handler
  (`src/apps/bridge.ts`); see [tiny-app-runner.md](tiny-app-runner.md).
- The runner entry `renderJsxPage(container, sourceTextOrBytes, options)` takes
  source bytes and an options object (theme, title, preloaded verified modules); it
  knows nothing about shares. `content.ts` adapts a share to it.
