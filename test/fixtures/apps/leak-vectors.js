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

  // ---- DOM paths that put a node or a value where the first guards missed it. Every one of these leaked once (a prerender GET
  // carrying the marker, or a preconnect), so each is kept: the frame must keep every one of them closed.
  {
    const parsedLink = (rel, href) => { const doc = new DOMParser().parseFromString(`<link rel="${rel}" href="${href}">`, "text/html"); return document.adoptNode(doc.querySelector("link")); };
    const xhtmlLink = (rel, href) => { const doc = new DOMParser().parseFromString(`<html xmlns="http://www.w3.org/1999/xhtml"><head><link rel="${rel}" href="${href}"/></head><body/></html>`, "application/xhtml+xml"); return document.importNode(doc.querySelector("link"), true); };
    const anchorText = () => { const t = document.createTextNode(""); document.head.append(t); return t; };
    const prerender = (name) => parsedLink("prerender", u(name));
    for (const rel of ["prerender", "prefetch", "preconnect", "dns-prefetch", "preload", "modulepreload"]) {
      const href = rel === "preconnect" || rel === "dns-prefetch" ? BASE : u(`x-cd-after-${rel}`);
      await run(`x-cd-after-${rel}`, async () => { anchorText().after(parsedLink(rel, href)); await wait(50); return "done"; });
    }
    await run("x-cd-before-prerender", async () => { anchorText().before(prerender("x-cd-before")); await wait(50); return "done"; });
    await run("x-cd-replaceWith-prerender", async () => { anchorText().replaceWith(prerender("x-cd-replaceWith")); await wait(50); return "done"; });
    await run("x-comment-after-prerender", async () => { const c = document.createComment("x"); document.head.append(c); c.after(prerender("x-comment-after")); await wait(50); return "done"; });
    await run("x-comment-before-preconnect", async () => { const c = document.createComment("x"); document.head.append(c); c.before(parsedLink("preconnect", BASE)); await wait(50); return "done"; });
    await run("x-doctype-after", async () => { const d = document.implementation.createDocumentType("html", "", ""); try { document.replaceChild(d, document.doctype || d); } catch (error) { /* only one doctype */ } if (document.doctype) document.doctype.after(prerender("x-doctype-after")); await wait(50); return "done"; });
    for (const rel of ["prerender", "prefetch", "preconnect"]) {
      const href = rel === "preconnect" ? BASE : u(`x-attr-value-${rel}`);
      await run(`x-attr-value-${rel}`, async () => { const l = document.createElement("link"); l.rel = rel; l.setAttribute("href", "#"); document.head.append(l); l.getAttributeNode("href").value = href; await wait(50); return l.isConnected ? "connected" : "removed"; });
    }
    await run("x-setAttributeNode-prerender", async () => { const l = document.createElement("link"); l.rel = "prerender"; document.head.append(l); const a = document.createAttribute("href"); a.value = u("x-setAttributeNode"); l.setAttributeNode(a); await wait(50); return "done"; });
    await run("x-setAttributeNodeNS-prerender", async () => { const l = document.createElement("link"); l.rel = "prerender"; document.head.append(l); const a = document.createAttributeNS(null, "href"); a.value = u("x-setAttributeNodeNS"); l.setAttributeNodeNS(a); await wait(50); return "done"; });
    await run("x-setNamedItem-prefetch", async () => { const l = document.createElement("link"); l.rel = "prefetch"; document.head.append(l); const a = document.createAttribute("href"); a.value = u("x-setNamedItem"); l.attributes.setNamedItem(a); await wait(50); return "done"; });
    await run("x-setNamedItemNS-prerender", async () => { const l = document.createElement("link"); l.rel = "prerender"; document.head.append(l); const a = document.createAttributeNS(null, "href"); a.value = u("x-setNamedItemNS"); l.attributes.setNamedItemNS(a); await wait(50); return "done"; });
    await run("x-attr-nodeValue-prerender", async () => { const l = document.createElement("link"); l.rel = "prerender"; l.setAttribute("href", "#"); document.head.append(l); l.getAttributeNode("href").nodeValue = u("x-attr-nodeValue"); await wait(50); return "done"; });
    await run("x-attr-textContent-prerender", async () => { const l = document.createElement("link"); l.rel = "prerender"; l.setAttribute("href", "#"); document.head.append(l); l.getAttributeNode("href").textContent = u("x-attr-textContent"); await wait(50); return "done"; });
    await run("x-attr-prerender-before-insert", async () => { const l = document.createElement("link"); l.rel = "prerender"; const a = document.createAttribute("href"); a.value = u("x-attr-detached"); l.setAttributeNode(a); document.head.append(l); await wait(50); return "done"; });
    await run("x-link-href-after-insert", async () => { const l = document.createElement("link"); l.rel = "prerender"; document.head.append(l); l.href = u("x-link-href-after-insert"); await wait(50); return "done"; });
    await run("x-link-rel-after-href", async () => { const l = document.createElement("link"); l.setAttribute("href", "data:text/css,a{}"); document.head.append(l); l.rel = "prerender"; l.setAttribute("href", u("x-link-rel-after-href")); await wait(50); return "done"; });
    await run("x-toggleAttribute", async () => { const l = document.createElement("link"); l.rel = "prerender"; document.head.append(l); l.toggleAttribute("href"); l.setAttribute("href", u("x-toggle")); await wait(50); return "done"; });
    await run("x-xhtml-link-after", async () => { anchorText().after(xhtmlLink("prerender", u("x-xhtml-link-after"))); await wait(50); return "done"; });
    await run("x-xhtml-link-append", async () => { document.head.append(xhtmlLink("prerender", u("x-xhtml-link-append"))); await wait(50); return "done"; });
    await run("x-createElementNS-link", async () => { const l = document.createElementNS("http://www.w3.org/1999/xhtml", "link"); l.setAttribute("rel", "prerender"); l.setAttribute("href", u("x-createElementNS")); document.head.append(l); await wait(50); return "done"; });
    // ---- every insertion method, with a parsed (never-guarded-at-creation) link
    await run("x-replaceChildren-element", async () => { const box = document.createElement("div"); document.body.append(box); box.replaceChildren(prerender("x-replaceChildren")); await wait(50); return "done"; });
    await run("x-replaceChildren-document", async () => { document.head.replaceChildren(prerender("x-document-replaceChildren")); await wait(50); return "done"; });
    await run("x-insertAdjacentElement", async () => { const box = document.createElement("div"); document.body.append(box); box.insertAdjacentElement("beforeend", prerender("x-insertAdjacentElement")); await wait(50); return "done"; });
    await run("x-range-insertNode", async () => { const box = document.createElement("div"); document.body.append(box); const r = document.createRange(); r.selectNodeContents(box); r.insertNode(prerender("x-range-insertNode")); await wait(50); return "done"; });
    await run("x-range-surroundContents", async () => { const box = document.createElement("div"); box.textContent = "x"; document.body.append(box); const r = document.createRange(); r.selectNodeContents(box); r.surroundContents(prerender("x-range-surround")); await wait(50); return "done"; });
    await run("x-insertBefore", async () => { document.head.insertBefore(prerender("x-insertBefore"), null); await wait(50); return "done"; });
    await run("x-replaceChild", async () => { const mark = document.createElement("i"); document.head.append(mark); document.head.replaceChild(prerender("x-replaceChild"), mark); await wait(50); return "done"; });
    await run("x-fragment-then-insert", async () => { const f = document.createDocumentFragment(); f.append(document.createElement("b")); const l = prerender("x-fragment"); f.firstChild.after(l); document.head.append(f); await wait(50); return "done"; });
    await run("x-template-content-clone", async () => { const t = document.createElement("template"); t.content.append(prerender("x-template-clone")); document.head.append(t.content.cloneNode(true)); await wait(50); return "done"; });
    await run("x-template-innerHTML-then-content", async () => { const t = document.createElement("template"); t.innerHTML = `<link rel="prerender" href="${u("x-template-innerHTML")}">`; document.head.append(t.content); await wait(50); return "done"; });
    await run("x-template-in-body", async () => { const box = document.createElement("div"); document.body.append(box); box.innerHTML = `<template><link rel="prerender" href="${u("x-template-in-body")}"></template>`; document.head.append(box.firstChild.content.cloneNode(true)); await wait(50); return "done"; });
    await run("x-importNode-and-append", async () => { const d = new DOMParser().parseFromString(`<link rel="prerender" href="${u("x-importNode")}">`, "text/html"); document.head.append(document.importNode(d.querySelector("link"), true)); await wait(50); return "done"; });
    await run("x-adoptNode-append", async () => { const d = new DOMParser().parseFromString(`<link rel="prerender" href="${u("x-adoptNode")}">`, "text/html"); document.head.appendChild(document.adoptNode(d.querySelector("link"))); await wait(50); return "done"; });
    await run("x-cloneNode-of-parsed", async () => { document.head.append(prerender("x-cloneNode").cloneNode(true)); await wait(50); return "done"; });
    await run("x-outerHTML", async () => { const box = document.createElement("div"); document.body.append(box); const inner = document.createElement("i"); box.append(inner); inner.outerHTML = `<link rel="prerender" href="${u("x-outerHTML")}">`; await wait(50); return "done"; });
    await run("x-insertAdjacentHTML", async () => { document.head.insertAdjacentHTML("beforeend", `<link rel="prerender" href="${u("x-insertAdjacentHTML")}"><link rel="preconnect" href="${BASE}">`); await wait(50); return "done"; });
    await run("x-innerHTML-head", async () => { document.head.innerHTML += `<link rel="prerender" href="${u("x-innerHTML-head")}">`; await wait(50); return "done"; });
    await run("x-setHTML", async () => { const box = document.createElement("div"); document.body.append(box); if (typeof box.setHTML === "function") box.setHTML(`<link rel="prerender" href="${u("x-setHTML")}">`); await wait(50); return "done"; });
    await run("x-createContextualFragment", async () => { const r = document.createRange(); r.selectNode(document.head); document.head.append(r.createContextualFragment(`<link rel="prerender" href="${u("x-createContextualFragment")}">`)); await wait(50); return "done"; });
    await run("x-execCommand-insertHTML", async () => { const box = document.createElement("div"); box.contentEditable = "true"; document.body.append(box); box.focus(); const r = document.createRange(); r.selectNodeContents(box); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); const ok = document.execCommand("insertHTML", false, `<link rel="prerender" href="${u("x-execCommand")}"><link rel="preconnect" href="${BASE}">`); await wait(50); return `exec=${ok} links=${box.querySelectorAll("link").length}`; });
    await run("x-execCommand-insertImage", async () => { const box = document.createElement("div"); box.contentEditable = "true"; document.body.append(box); box.focus(); const r = document.createRange(); r.selectNodeContents(box); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); document.execCommand("insertImage", false, u("x-insertImage")); await wait(50); return "done"; });
    // ---- shadow roots: open and closed, imperative and declarative
    for (const mode of ["open", "closed"]) {
      await run(`x-shadow-${mode}-append`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); root.append(prerender(`x-shadow-${mode}-append`)); await wait(50); return "done"; });
      await run(`x-shadow-${mode}-appendChild`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); root.appendChild(prerender(`x-shadow-${mode}-appendChild`)); await wait(50); return "done"; });
      await run(`x-shadow-${mode}-insertBefore`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); root.insertBefore(prerender(`x-shadow-${mode}-insertBefore`), null); await wait(50); return "done"; });
      await run(`x-shadow-${mode}-innerHTML`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); root.innerHTML = `<link rel="prerender" href="${u(`x-shadow-${mode}-innerHTML`)}"><link rel="preconnect" href="${BASE}">`; await wait(50); return "done"; });
      await run(`x-shadow-${mode}-replaceChildren`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); root.replaceChildren(prerender(`x-shadow-${mode}-replaceChildren`)); await wait(50); return "done"; });
      await run(`x-shadow-${mode}-text-after`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); const t = document.createTextNode(""); root.append(t); t.after(prerender(`x-shadow-${mode}-text-after`)); await wait(50); return "done"; });
      await run(`x-shadow-${mode}-built-then-attached`, async () => { const host = document.createElement("div"); const root = host.attachShadow({ mode }); root.append(document.createElement("b")); const l = prerender(`x-shadow-${mode}-built`); root.firstChild.after(l); document.body.append(host); await wait(50); return "done"; });
      await run(`x-shadow-${mode}-attribute-after`, async () => { const host = document.createElement("div"); document.body.append(host); const root = host.attachShadow({ mode }); const l = document.createElement("link"); l.rel = "prerender"; root.append(l); l.getAttributeNode("rel"); const a = document.createAttribute("href"); a.value = u(`x-shadow-${mode}-attr`); l.setAttributeNode(a); await wait(50); return "done"; });
    }
    await run("x-dsd-setHTMLUnsafe", async () => { const box = document.createElement("div"); document.body.append(box); if (typeof box.setHTMLUnsafe !== "function") return "n/a"; box.setHTMLUnsafe(`<div><template shadowrootmode="open"><link rel="prerender" href="${u("x-dsd-setHTMLUnsafe")}"><link rel="preconnect" href="${BASE}"></template></div>`); await wait(50); const host = box.firstElementChild; return `shadow=${host && host.shadowRoot ? host.shadowRoot.querySelectorAll("link").length : "none"}`; });
    await run("x-dsd-setHTMLUnsafe-closed", async () => { const box = document.createElement("div"); document.body.append(box); if (typeof box.setHTMLUnsafe !== "function") return "n/a"; box.setHTMLUnsafe(`<div><template shadowrootmode="closed"><link rel="prerender" href="${u("x-dsd-closed")}"></template></div>`); await wait(50); return "done"; });
    await run("x-dsd-parseHTMLUnsafe", async () => { if (typeof Document.parseHTMLUnsafe !== "function") return "n/a"; const doc = Document.parseHTMLUnsafe(`<div id="h"><template shadowrootmode="open"><link rel="prerender" href="${u("x-dsd-parse")}"></template></div>`); const host = document.adoptNode(doc.getElementById("h")); document.body.append(host); await wait(50); return `shadow=${host.shadowRoot ? host.shadowRoot.querySelectorAll("link").length : "none"}`; });
    await run("x-dsd-parseHTMLUnsafe-nested", async () => { if (typeof Document.parseHTMLUnsafe !== "function") return "n/a"; const doc = Document.parseHTMLUnsafe(`<div id="h"><template shadowrootmode="open"><div id="i"><template shadowrootmode="closed"><link rel="prerender" href="${u("x-dsd-nested")}"></template></div></template></div>`); document.body.append(document.adoptNode(doc.getElementById("h"))); await wait(50); return "done"; });
    await run("x-dsd-document-write", async () => { document.write(`<div><template shadowrootmode="open"><link rel="prerender" href="${u("x-dsd-document-write")}"></template></div>`); await wait(50); return "done"; });
    await run("x-document-write-split-tag", async () => { document.write(`<link rel="prerender" hr`); document.write(`ef="${u("x-document-write-split")}">`); await wait(50); return "done"; });
    await run("x-document-write-plain", async () => { document.write(`<link rel="prerender" href="${u("x-document-write-link")}">`); await wait(50); return "done"; });
    await run("x-dsd-innerHTML-then-attach", async () => { const box = document.createElement("div"); document.body.append(box); box.innerHTML = `<div><template shadowrootmode="open"><link rel="prerender" href="${u("x-dsd-innerHTML")}"></template></div>`; await wait(50); return `template=${box.querySelectorAll("template").length}`; });
    await run("x-custom-element-shadow", async () => { class Probe extends HTMLElement { connectedCallback() { const root = this.attachShadow({ mode: "closed" }); root.innerHTML = `<link rel="prerender" href="${u("x-custom-element")}">`; root.append(prerender("x-custom-element-append")); } } customElements.define("x-leak-probe", Probe); document.body.append(document.createElement("x-leak-probe")); await wait(50); return "done"; });
    await run("x-moveBefore", async () => { const box = document.createElement("div"); document.body.append(box); const l = prerender("x-moveBefore"); document.head.append(l); if (typeof box.moveBefore === "function") { try { box.moveBefore(l, null); } catch (error) { return `threw ${error.name}`; } } await wait(50); return "done"; });
    await run("x-xslt", async () => { if (typeof XSLTProcessor !== "function") return "n/a"; const xsl = new DOMParser().parseFromString(`<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><link xmlns="http://www.w3.org/1999/xhtml" rel="prerender" href="${u("x-xslt")}"/></xsl:template></xsl:stylesheet>`, "application/xml"); const p = new XSLTProcessor(); p.importStylesheet(xsl); const frag = p.transformToFragment(new DOMParser().parseFromString("<a/>", "application/xml"), document); anchorText().after(frag); await wait(50); return "done"; });
    await run("x-xslt-document", async () => { if (typeof XSLTProcessor !== "function") return "n/a"; const xsl = new DOMParser().parseFromString(`<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><html xmlns="http://www.w3.org/1999/xhtml"><head><link rel="prerender" href="${u("x-xslt-document")}"/></head></html></xsl:template></xsl:stylesheet>`, "application/xml"); const p = new XSLTProcessor(); p.importStylesheet(xsl); const out = p.transformToDocument(new DOMParser().parseFromString("<a/>", "application/xml")); document.head.append(document.adoptNode(out.querySelector("link"))); await wait(50); return "done"; });
    await run("x-observer-race-preconnect", async () => { const t = anchorText(); for (let i = 0; i < 5; i += 1) t.after(parsedLink("preconnect", BASE)); await wait(50); return "done"; });
    await run("x-specrules-prefetch", async () => { const s = document.createElement("script"); s.type = "speculationrules"; s.text = JSON.stringify({ prefetch: [{ source: "list", urls: [u("x-specrules-prefetch")] }] }); anchorText().after(s); await wait(300); return "done"; });
    await run("x-specrules-prerender", async () => { const s = document.createElement("script"); s.type = "speculationrules"; s.text = JSON.stringify({ prerender: [{ source: "list", urls: [u("x-specrules-prerender")] }] }); document.head.append(s); await wait(300); return "done"; });
    await run("x-webtransport", () => { if (typeof WebTransport !== "function") return "n/a"; try { const wt = new WebTransport(`https://${new URL(BASE).host}/v/x-webtransport`); return wt.ready.then(() => "open", (e) => `refused ${e && e.name}`); } catch (e) { return `threw ${e.name}`; } });
    await run("x-adoptedStyleSheets-replace", async () => { const sheet = new CSSStyleSheet(); await sheet.replace(`@import url(${u("x-sheet-replace-import")}); body{background:url(${u("x-sheet-replace-url")})}`); document.adoptedStyleSheets = [sheet]; await wait(50); return "done"; });
  }

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
