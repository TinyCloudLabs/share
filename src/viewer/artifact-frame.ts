export const ARTIFACT_SANDBOX_PATH = "/artifact-sandbox.html";

/**
 * Policy of the bridge document; srcdoc children inherit it. 'unsafe-eval'
 * adds no capability inside the opaque, network-refusing frame and lets
 * single-file pages use eval-based libraries; prepared bundle pages add their
 * own stricter meta policy. Navigation is bounded by `frame-src 'none'` (the
 * bridge refuses every child navigation) plus the bridge's load watchdog;
 * the never-shipped `navigate-to` directive is deliberately absent. CSP does
 * not govern WebRTC, so a page can still send STUN/TURN traffic.
 */
export const ARTIFACT_SANDBOX_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline' 'unsafe-eval'",
  "style-src 'unsafe-inline'",
  "img-src data: blob:",
  "font-src data: blob:",
  "media-src data: blob:",
  "connect-src 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

/**
 * The served document's complete HTTP policy. It must carry the full frame
 * CSP, not only frame-ancestors: srcdoc children inherit every policy of the
 * bridge, and a header without script-src 'unsafe-inline' would stop the
 * bridge itself. Production `public/_headers` detaches the site-wide policy
 * for the sandbox routes and sends exactly this value.
 */
export const ARTIFACT_SANDBOX_HTTP_CSP = `${ARTIFACT_SANDBOX_CSP}; frame-ancestors 'self'`;

export const ARTIFACT_SANDBOX_HTTP_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ["content-security-policy", ARTIFACT_SANDBOX_HTTP_CSP],
  ["x-frame-options", "SAMEORIGIN"],
  ["cache-control", "no-store"],
  ["referrer-policy", "no-referrer"],
  ["x-content-type-options", "nosniff"],
];

/**
 * `ready: "artifact"` — a prepared bundle page; success is the injected
 * bootstrap's `artifact-ready` message, and bundle navigation is honored.
 * `ready: "load"` — one arbitrary single-file HTML document prepared with
 * withLoadSignal(); success is that document's own load signal carrying
 * `loadToken`, together with exactly one child load. A first load without
 * the signal is a replacement document or an error page (the page navigated
 * before it finished loading) and fails the render. In both modes any later
 * child load is navigation and destroys the document.
 *
 * The nonce binds messages to one frame pair but is NOT a secret: srcdoc
 * children see the bridge URL, fragment included, via `document.baseURI`.
 * Message authority comes from the `event.source` checks on both sides.
 */
export interface ArtifactRenderRequest {
  readonly type: "render";
  readonly id: string;
  readonly nonce: string;
  readonly entry: string;
  readonly pages: Readonly<Record<string, string>>;
  readonly ready: "artifact" | "load";
  readonly loadToken?: string;
}

/** How long the bridge waits for a document's load signal after its first child load. */
const LOAD_SIGNAL_GRACE_MS = 2_000;

/**
 * Insert the load-signal script ahead of the document's own content (after a
 * leading doctype, so standards mode is kept). Running first, it holds the
 * real parent window and the first window `load` listener before any page
 * script runs. The page can read or forge the token; that only lets it claim
 * it loaded, which it can do anyway — it is a liveness signal, not authority.
 */
export function withLoadSignal(html: string, token: string): string {
  const signal = `<script>(function(){var p=window.parent;addEventListener("load",function(){p.postMessage({type:"tc-document-loaded",token:"${token}"},"*");});})();</script>`;
  const at = /^(?:\s|<!--[\s\S]*?-->|<\?[^>]*>)*<!doctype[^>]*>/i.exec(html)?.[0].length ?? 0;
  return `${html.slice(0, at)}${signal}${html.slice(at)}`;
}

export const ARTIFACT_BRIDGE_SCRIPT = `(function(){
  "use strict";
  var nonce=decodeURIComponent(window.location.hash.slice(1));
  if(self.origin!=="null"||!/^[0-9a-f]{32}$/.test(nonce))return;
  var child=null;
  var pages=null;
  var activeId="";
  var activeReady="artifact";
  var activeToken="";
  var activeFragment="";
  var childReady=false;
  var seenInitialLoad=false;
  var loadCount=0;
  var loadSignaled=false;
  var loadGrace=0;
  function post(message){window.parent.postMessage(Object.assign({nonce:nonce},message),"*");}
  function clearGrace(){if(loadGrace){clearTimeout(loadGrace);loadGrace=0;}}
  function destroyChild(){clearGrace();if(child){child.remove();child=null;}}
  function navigated(){post({type:"result",id:activeId,ok:false,error:"navigation"});destroyChild();}
  function loaded(){clearGrace();childReady=true;post({type:"result",id:activeId,ok:true});}
  function show(path,fragment){
    if(!pages||typeof pages[path]!=="string"){post({type:"result",id:activeId,ok:false,error:"missing"});destroyChild();return;}
    destroyChild();
    activeFragment=typeof fragment==="string"&&/^#[^\\u0000-\\u001f\\u007f]{1,1024}$/.test(fragment)?fragment:"";
    child=document.createElement("iframe");
    child.setAttribute("sandbox","allow-scripts");
    child.setAttribute("title","Shared HTML artifact");
    child.setAttribute("referrerpolicy","no-referrer");
    child.className="artifact-document";
    childReady=false;
    seenInitialLoad=false;
    loadCount=0;
    loadSignaled=false;
    child.addEventListener("load",function(){
      if(activeReady==="load"){
        loadCount++;
        if(loadCount>1){navigated();return;}
        if(loadSignaled){loaded();return;}
        loadGrace=setTimeout(navigated,${LOAD_SIGNAL_GRACE_MS});
        return;
      }
      if(!seenInitialLoad){seenInitialLoad=true;return;}
      navigated();
    });
    child.srcdoc=pages[path];
    document.body.replaceChildren(child);
  }
  window.addEventListener("message",function(event){
    if(event.source===window.parent){
      var data=event.data;
      if(!data||data.type!=="render"||data.nonce!==nonce||typeof data.id!=="string"||typeof data.entry!=="string"||!data.pages||typeof data.pages!=="object")return;
      if(data.ready==="load"){if(typeof data.loadToken!=="string"||!/^[0-9a-f]{32}$/.test(data.loadToken))return;activeToken=data.loadToken;}
      else if(data.ready!=="artifact")return;
      activeId=data.id;activeReady=data.ready;pages=data.pages;show(data.entry,"");return;
    }
    if(child&&activeReady==="load"&&event.source===child.contentWindow&&event.origin==="null"){
      var signal=event.data;
      if(signal&&signal.type==="tc-document-loaded"&&signal.token===activeToken&&!loadSignaled&&!childReady&&loadCount<=1){
        loadSignaled=true;
        if(loadCount===1)loaded();
      }
      return;
    }
    if(child&&activeReady==="artifact"&&event.source===child.contentWindow&&event.origin==="null"){
      var childData=event.data;
      if(childData&&childData.type==="artifact-ready"&&!childReady){
        childReady=true;
        if(activeFragment)child.contentWindow.postMessage({type:"artifact-fragment",fragment:activeFragment},"*");
        post({type:"result",id:activeId,ok:true});
        return;
      }
      if(childData&&childData.type==="artifact-restore-controls"){
        post({type:"artifact-restore-controls"});
        return;
      }
      if(childData&&childData.type==="navigate"&&typeof childData.path==="string"){show(childData.path,childData.fragment);}
    }
  });
  post({type:"ready"});
})();`;

export function buildArtifactSandboxHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="${ARTIFACT_SANDBOX_CSP}">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Shared HTML artifact sandbox</title>
  <style>
    html,body,.artifact-document{width:100%;height:100%;margin:0;border:0;background:#fff}
    body{overflow:hidden}
    .artifact-document{display:block}
    @media(prefers-color-scheme:dark){html,body{background:#0b0e14}}
  </style>
</head>
<body>
  <script>${ARTIFACT_BRIDGE_SCRIPT.replace(/<\/script/gi, "<\\/script")}</script>
</body>
</html>`;
}
