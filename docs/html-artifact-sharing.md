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
and top-level navigation, and it rules out credentialed requests as the viewer
or as your session. It is not a network block: CSP does not govern WebRTC, so
a page can send STUN/TURN traffic to a server its author chooses and learn the
viewer's IP address. The bridge's `frame-src 'none'` refuses every child
navigation and the navigation watchdog closes the document when one is
attempted. It fails closed rather than claiming that hostile, obfuscated script
can be made safe through source inspection alone.

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
whole boundary, with the same guarantees and the same WebRTC gap. External
stylesheets, scripts, images, and fonts do not load; inline them or use
`data:` URLs. A small load-signal script is inserted after the doctype so the
bridge can tell the intended document from a replacement or error page: a page
that navigates before or after it loads is closed and replaced with a download
prompt.

Pages use the 1 MB preview budget shared with Markdown, text, and images;
larger or non-UTF-8 files stay download-only. The viewer keeps its filename
bar, a notice that the page comes from the sender (including the IP-address
caveat), and the footer “Download original” action, which is present whether
or not the preview succeeds.

## Production headers

Cloudflare Pages appends, rather than replaces, a header set by more than one
matching `_headers` rule. The artifact sandbox routes (`/artifact-sandbox`
and its `.html` form, which Cloudflare redirects to the extensionless path)
therefore detach the site-wide policy
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
