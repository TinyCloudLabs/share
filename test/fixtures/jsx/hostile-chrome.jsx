// Benign UI-redress self-check. The viewer's notice and bar must stay visible,
// reachable and clickable whatever an artifact draws or does. This fixture TRIES
// the usual tricks; the e2e test (test/e2e-jsx.mjs) asserts none of them reached
// the viewer chrome. It talks to nothing and only reports its own observations.
import { useEffect, useState } from "react";

export default function HostileChrome() {
  const [report, setReport] = useState(null);

  useEffect(() => {
    const results = {};
    // A full-viewport element with the largest z-index, fixed to the frame's viewport.
    const cover = document.createElement("div");
    cover.id = "cover";
    cover.style.cssText = "position:fixed;inset:0;width:100vw;height:100vh;z-index:2147483647;background:rgb(255,0,0);";
    // On the root element: a transformed body would otherwise become the fixed element's containing block.
    document.documentElement.append(cover);
    // Pointer-events games on the artifact's own document.
    document.documentElement.style.pointerEvents = "none";
    cover.style.pointerEvents = "auto";
    // Oversized layout that tries to push the page around.
    document.body.style.cssText += ";width:10000px;height:10000px;";
    // Fullscreen and Picture-in-Picture over the chrome.
    results.fullscreenEnabled = document.fullscreenEnabled;
    results.pictureInPictureEnabled = document.pictureInPictureEnabled;
    results.fullscreenRequest = "pending";
    try {
      Promise.resolve(document.documentElement.requestFullscreen()).then(
        () => { results.fullscreenRequest = "granted"; },
        (error) => { results.fullscreenRequest = `rejected:${error.name}`; },
      );
    } catch (error) {
      results.fullscreenRequest = `threw:${error.name}`;
    }
    // Focus stealing: autofocus, tabindex loops, and swallowed Tab/Escape/shortcut keys.
    const input = document.createElement("input");
    input.id = "thief";
    input.setAttribute("autofocus", "");
    input.tabIndex = 1;
    document.body.append(input);
    let steal = null;
    window.__startStealing = () => { if (steal === null) steal = setInterval(() => input.focus(), 10); };
    window.__startStealing();
    // The test stops the focus loop to look at where a revealed notice puts focus; the rest stays hostile.
    window.__stopStealing = () => { clearInterval(steal); steal = null; };
    // Everything an artifact could post at the viewer: to its parent (the bridge) and to the top window.
    window.__forgeMessages = () => {
      const nonce = decodeURIComponent(document.baseURI.split("#")[1] ?? "");
      for (const target of [window.parent, window.top]) {
        for (const message of [
          { type: "restore-controls" },
          { v: 1, type: "restore-controls" },
          { v: 1, type: "restore-controls", nonce },
          { v: 1, type: "dismiss", nonce },
          { v: 1, type: "ready", nonce },
        ]) target.postMessage(message, "*");
      }
    };
    for (const target of [window, document]) {
      target.addEventListener("keydown", (event) => {
        event.preventDefault();
        event.stopImmediatePropagation();
      }, true);
    }
    input.addEventListener("blur", () => { if (steal !== null) input.focus(); });
    setTimeout(() => setReport({ results }), 400);
    return () => clearInterval(steal);
  }, []);

  return (
    <main className="p-6">
      <h1 className="text-lg font-semibold">Hostile chrome check</h1>
      <pre id="report" data-done={report ? "yes" : "no"} className="mt-3 text-xs whitespace-pre-wrap">
        {report ? JSON.stringify(report, null, 2) : "running"}
      </pre>
    </main>
  );
}
