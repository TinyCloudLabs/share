export const ARTIFACT_SANDBOX_PATH = "/artifact-sandbox.html";

export const ARTIFACT_SANDBOX_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'unsafe-inline'",
  "img-src data: blob:",
  "font-src data: blob:",
  "media-src data: blob:",
  "connect-src 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "navigate-to 'none'",
].join("; ");

export const ARTIFACT_SANDBOX_HTTP_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ["content-security-policy", "frame-ancestors 'self'"],
  ["x-frame-options", "SAMEORIGIN"],
  ["cache-control", "no-store"],
  ["referrer-policy", "no-referrer"],
  ["x-content-type-options", "nosniff"],
];

export interface ArtifactRenderRequest {
  readonly type: "render";
  readonly id: string;
  readonly nonce: string;
  readonly entry: string;
  readonly pages: Readonly<Record<string, string>>;
}

export const ARTIFACT_BRIDGE_SCRIPT = `(function(){
  "use strict";
  var nonce=decodeURIComponent(window.location.hash.slice(1));
  if(self.origin!=="null"||!/^[0-9a-f]{32}$/.test(nonce))return;
  var child=null;
  var pages=null;
  var activeId="";
  var activeFragment="";
  var childReady=false;
  var seenInitialLoad=false;
  function post(message){window.parent.postMessage(Object.assign({nonce:nonce},message),"*");}
  function destroyChild(){if(child){child.remove();child=null;}}
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
    child.addEventListener("load",function(){
      if(!seenInitialLoad){seenInitialLoad=true;return;}
      post({type:"result",id:activeId,ok:false,error:"navigation"});
      destroyChild();
    });
    child.srcdoc=pages[path];
    document.body.replaceChildren(child);
  }
  window.addEventListener("message",function(event){
    if(event.source===window.parent){
      var data=event.data;
      if(!data||data.type!=="render"||data.nonce!==nonce||typeof data.id!=="string"||typeof data.entry!=="string"||!data.pages||typeof data.pages!=="object")return;
      activeId=data.id;pages=data.pages;show(data.entry,"");return;
    }
    if(child&&event.source===child.contentWindow&&event.origin==="null"){
      var childData=event.data;
      if(childData&&childData.type==="artifact-ready"&&!childReady){
        childReady=true;
        if(activeFragment)child.contentWindow.postMessage({type:"artifact-fragment",fragment:activeFragment},"*");
        post({type:"result",id:activeId,ok:true});
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
