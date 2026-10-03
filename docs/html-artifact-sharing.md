# HTML artifact sharing

TinyCloud can open a shared folder as a full-page HTML artifact when the
authorized KV prefix contains exactly one canonical root file named
`index.html`. Choose the folder in the composer; nested paths below the selected
folder are preserved. A folder without that entry remains an ordinary folder
share, preserving existing behavior.

The encrypted envelope stores one additional discriminator,
`metadata.artifact: "html"`. The entry filename is fixed by the protocol, and
no filenames, authority material, recipient identity, or share-link fragment
are sent to analytics or any Share-host service.

## Supported bundle behavior

- HTML pages, stylesheets, classic scripts, JSON/text, images, fonts, audio,
  video, and other inert static files can live at nested relative paths.
- Relative `src`, `href`, `srcset`, CSS `url(...)`, and CSS `@import` references
  are resolved within the one authorized prefix. Query strings are ignored for
  file lookup and fragments are retained where meaningful.
- Links between HTML files in the same bundle are supported.
- Stylesheet `media` values are validated against a safe subset before they
  are wrapped, and unsupported `<link>` relations such as preload,
  modulepreload, and prefetch fail closed instead of being skipped.
- Benign local helper names like `open` remain compatible; the hardening gate
  blocks explicit browser-navigation primitives, not ordinary identifier names.
- Every required resource is read through the verified recipient policy
  session before rendering. Missing files fail the whole render with
  recipient-safe recovery copy.

The initial format intentionally does not support ES modules, dynamic imports,
workers, runtime `fetch`/XHR/WebSocket/EventSource, forms, embedded frames,
plugins, a document `<base>`, external URLs, inline HTML event handlers, or
runtime-generated relative resource requests. Classic scripts and statically
discoverable resources are the safe compatibility boundary. Authors should not
weaken this boundary to make a site work; publish a static build instead.

Bundles are limited to 1,000 files, 100 MB of source data, 10 MB of renderable
text/SVG data, 5 MB per text file, 10,000 static references, and 16 nested
stylesheet imports. Paths must be canonical Unicode, relative to the bundle,
and free of control characters, backslashes, encoded separator aliases, empty
segments, and `.` or `..` traversal. Case-folding collisions are rejected.

## Isolation

Artifact code runs in a sandboxed iframe without `allow-same-origin`, nested
inside a second sandboxed bridge frame. Both documents have opaque origins.
The inner document receives only locally rewritten data URLs and inlined
classic scripts/styles. CSP refuses fetch/XHR/WebSocket/EventSource/beacon
connections, network images and fonts, frames, objects, forms, and base URLs;
the sandbox refuses popups and top-level navigation; referrers are disabled.
Inline HTML event handlers are rejected before render. The bridge accepts
render requests only from its direct parent and navigation messages only from
its direct child (`event.source` checks). The per-frame nonce in the bridge URL
binds messages to one frame pair but is not a secret: srcdoc children can read
it through `document.baseURI`. Unexpected iframe navigation destroys the
artifact document.

This boundary prevents access to the TinyCloud parent DOM, cookies,
local/session storage, the share link and its fragment, wallet state, opener,
and top-level navigation. The page cannot read responses, cookies, storage, or
the TinyCloud session, and fetch, XHR, beacon, image, and form requests are
refused. It is not a network block, though:

- CSP does not govern WebRTC, so ICE gathering sends STUN/TURN traffic to a
  server the page's author chooses and reveals the viewer's IP address.
- Resource hints are not limited to opening a connection. Chrome handles
  `<link rel="prerender">` (static or inserted by script, before or after
  load) as NoStatePrefetch, which ignores `default-src 'none'` — there is no
  `prefetch-src` left to block it — and sends a full HTTP GET to any URL the
  page picks, with arbitrary query data, a `Purpose: prefetch` header, and the
  target origin's SameSite=Lax cookies, including on the viewer origin. The
  page cannot read the response. TinyCloud keeps its session in browser
  storage, not cookies, so the GET carries no TinyCloud credential; it is a
  tracking beacon and a cookie-bearing GET to whatever origin the page names.
  `<link rel="preconnect">` likewise opens a TCP connection.

The bridge's `frame-src 'none'` refuses every child navigation and the
navigation watchdog closes the document when one happens after it has loaded.
It fails closed rather than claiming that hostile, obfuscated script can be
made safe through source inspection alone.

The page runs in the viewer's renderer process (the sandbox gives it an
opaque origin, not its own process), so a busy loop in its script can freeze
the whole tab, including the viewer's controls. If the loop starts before the
page's load event, the bridge's 15-second render timeout cannot fire either.
The planned fix is TC-544: serve the sandbox from a separate registrable
user-content domain so the page gets its own process.

## Single-file HTML pages

Only bearer `#tc1` links render single-file HTML. They carry no signed media
type, so the key's `.html` or `.htm` extension selects the page renderer.
Addressed links (DID, email, policy) stay download-only with a “Preview isn't
available for this link type yet” note, whatever their signed media type or
filename: the sender's script would run in the same renderer process that
holds the recipient's session key and email credential, which side channels
could target. HTML provenance comes from the link type only, never from a
media type. Addressed HTML can render once the sandbox moves to a separate
registrable user-content domain.

The page is shown exactly as sent — scripts (including `eval`), inline styles,
and inline event handlers run — but only inside the same two-frame sandbox:
the decrypted bytes reach the bridge as a postMessage string and become the
inner frame's `srcdoc`; nothing is fetched. The bundle rewriting and script
inspection above do not apply to single files, so the CSP and sandbox are the
whole boundary, with the same guarantees and the same IP-address, prerender,
and busy-loop gaps. Nothing
is inserted into or rewritten in the page. External stylesheets, scripts,
images, and fonts do not load; inline them or use `data:` URLs. A page that
navigates itself after it has loaded is closed and replaced with a download
prompt. A page that navigates itself before it finishes loading is refused
by `frame-src 'none'`, so the frame shows the browser's blocked-content page
instead of the page; the download stays available.

Pages use the 1 MB preview budget shared with Markdown, text, and images;
larger or non-UTF-8 files stay download-only. The viewer keeps its filename
bar, a notice that the page comes from the sender (including the IP-address
caveat), and the footer “Download original” action, which is present whether
or not the preview succeeds.

## Mermaid diagrams in Markdown

A ` ```mermaid ` block is rendered in the `/mermaid-sandbox` frame: an
opaque-origin sandbox (`sandbox="allow-scripts"`, no network) that receives
only the diagram text and runs Mermaid with `securityLevel: "strict"` and
`htmlLabels: false`. `htmlLabels` is on Mermaid's secure-key list, so an init
directive or frontmatter config in the diagram cannot turn HTML labels back
on. Before the SVG leaves the frame, the bridge copies each element's
computed paint and font properties onto it as presentation attributes and
removes the theme `<style>`, so labels are SVG `<text>` and node styling no
longer depends on a stylesheet; an SVG that still contains `foreignObject`
is reported as a failed render. The viewer sanitizes the SVG again —
`script`, `foreignObject` and `<style>` are removed, and `url()` values must
point inside the SVG — before it joins the scriptless Markdown preview frame,
where it sits on a white card in both colour schemes (the light `neutral`
theme draws edges and free-standing labels in dark grey). If the sandbox
cannot load, a render fails, or it times out, the diagram source stays
visible as code.

Dev and preview serve the sandbox on both `/mermaid-sandbox` and
`/mermaid-sandbox.html` with the frame headers `public/_headers` gives those
routes in production.

`npm run test:e2e:mermaid` renders flowchart (plain, init directive,
frontmatter), sequence and gantt fixtures from
`test/fixtures/markdown-share/` in Chromium in light and dark mode. It checks
the sandbox route headers, that every diagram renders, that labels are SVG
text with at least 4.5:1 contrast, and that nodes are not filled black. To
check a deployment, set `MERMAID_E2E_ORIGIN` to its origin (route headers),
and for each fixture to render, share the fixture file unchanged as a bearer
link and pass it as `MERMAID_E2E_URL_<FIXTURE>`, for example
`MERMAID_E2E_URL_FLOWCHART` or `MERMAID_E2E_URL_FLOWCHART_INIT`. Fixtures
without a link are skipped and listed.

## Production headers

Cloudflare Pages appends, rather than replaces, a header set by more than one
matching `_headers` rule. The sandbox routes (`/artifact-sandbox`,
`/mermaid-sandbox`, and their `.html` forms, which Cloudflare redirects to the
extensionless paths) therefore detach the site-wide policy
(`! Content-Security-Policy`) before setting their own; otherwise the site's
`frame-ancestors 'none'` and `script-src 'self'` would also apply and the
sandbox could neither be framed nor run its bridge.

## TinyCloud controls

The small overlay begins expanded. Collapse it to a 44-pixel cloud control or
choose “Hide permanently” to store a per-share preference in local browser
storage. No URL or recipient data is stored.

To restore hidden controls, press **Alt+Shift+C**. The keyboard shortcut also
toggles expanded and collapsed states, and it still works when focus is inside
the sandboxed artifact frame. “Share” uses the operating-system share sheet
when available and otherwise uses TinyCloud’s clipboard fallback; the private
URL remains in a JavaScript closure and is never rendered into the document.

The example bundle in [`examples/html-artifact/`](../examples/html-artifact/)
contains separate HTML, CSS, classic JavaScript, and nested SVG files.
