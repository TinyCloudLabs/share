// Benign viewer-privacy check. A shared artifact must not be able to tell its
// author who opened it or when, so every remote load below must be refused.
// The e2e test points BEACON at a loopback server and asserts it saw nothing.
import { useEffect, useState } from "react";

const BEACON = "__BEACON__";
const PROBES = "__PROBES__";

function watch(element, events) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (outcome) => {
      if (!settled) {
        settled = true;
        resolve(outcome);
      }
    };
    for (const name of events) element.addEventListener(name, () => finish(name));
    setTimeout(() => finish("silent"), 1200);
  });
}

const probes = {
  img: () => {
    const element = document.createElement("img");
    element.src = `${BEACON}/img`;
    document.body.append(element);
    return watch(element, ["load", "error"]);
  },
  imageConstructor: () => {
    const element = new Image();
    element.src = `${BEACON}/image-constructor`;
    return watch(element, ["load", "error"]);
  },
  video: () => {
    const element = document.createElement("video");
    element.src = `${BEACON}/video`;
    document.body.append(element);
    return watch(element, ["loadedmetadata", "error"]);
  },
  audio: () => {
    const element = document.createElement("audio");
    element.src = `${BEACON}/audio`;
    document.body.append(element);
    return watch(element, ["loadedmetadata", "error"]);
  },
  cssUrl: () => {
    const style = document.createElement("style");
    style.textContent = `body { background-image: url(${BEACON}/css-url); }`;
    document.head.append(style);
    return new Promise((resolve) => setTimeout(() => resolve("styled"), 800));
  },
  cssImport: () => {
    const style = document.createElement("style");
    style.textContent = `@import url(${BEACON}/css-import);`;
    document.head.append(style);
    return new Promise((resolve) => setTimeout(() => resolve("styled"), 800));
  },
  fontFace: () => {
    const style = document.createElement("style");
    style.textContent = `@font-face { font-family: Probe; src: url(${BEACON}/font); } body { font-family: Probe, sans-serif; }`;
    document.head.append(style);
    return document.fonts.load("16px Probe").then(
      () => "settled",
      () => "error",
    );
  },
  linkStylesheet: () => {
    const element = document.createElement("link");
    element.rel = "stylesheet";
    element.href = `${BEACON}/link-stylesheet`;
    document.head.append(element);
    return watch(element, ["load", "error"]);
  },
  linkPreconnect: () => {
    const element = document.createElement("link");
    element.rel = "preconnect";
    element.href = BEACON;
    document.head.append(element);
    return new Promise((resolve) => setTimeout(() => resolve("inserted"), 800));
  },
  linkDnsPrefetch: () => {
    const element = document.createElement("link");
    element.rel = "dns-prefetch";
    element.href = BEACON;
    document.head.append(element);
    return new Promise((resolve) => setTimeout(() => resolve("inserted"), 800));
  },
  linkPrefetch: () => {
    const element = document.createElement("link");
    element.rel = "prefetch";
    element.href = `${BEACON}/link-prefetch`;
    document.head.append(element);
    return watch(element, ["load", "error"]);
  },
  linkPrerender: () => {
    const element = document.createElement("link");
    element.rel = "prerender";
    element.href = `${BEACON}/link-prerender`;
    document.head.append(element);
    return new Promise((resolve) => setTimeout(() => resolve("inserted"), 800));
  },
  sendBeacon: () => Promise.resolve(String(navigator.sendBeacon(`${BEACON}/send-beacon`, "x"))),
  xhr: () =>
    new Promise((resolve) => {
      const request = new XMLHttpRequest();
      request.onerror = () => resolve("error");
      request.onload = () => resolve("load");
      try {
        request.open("GET", `${BEACON}/xhr`);
        request.send();
      } catch (error) {
        resolve(error.name);
      }
    }),
  webSocket: () =>
    new Promise((resolve) => {
      try {
        const socket = new WebSocket(`${BEACON.replace("http", "ws")}/websocket`);
        socket.onerror = () => resolve("error");
        socket.onopen = () => resolve("open");
        setTimeout(() => resolve("silent"), 1200);
      } catch (error) {
        resolve(error.name);
      }
    }),
  eventSource: () =>
    new Promise((resolve) => {
      const source = new EventSource(`${BEACON}/event-source`);
      source.onerror = () => resolve("error");
      source.onopen = () => resolve("open");
      setTimeout(() => resolve("silent"), 1200);
    }),
  // WebRTC: ICE gathering contacts the STUN server named here.
  webrtc: () =>
    new Promise((resolve) => {
      try {
        const peer = new RTCPeerConnection({ iceServers: [{ urls: `stun:${new URL(BEACON).host}` }] });
        peer.createDataChannel("probe");
        peer.onicecandidate = (event) => {
          if (event.candidate === null) resolve("gathered");
        };
        peer.createOffer().then((offer) => peer.setLocalDescription(offer)).catch((error) => resolve(error.name));
        setTimeout(() => resolve("silent"), 3500);
      } catch (error) {
        resolve(error.name);
      }
    }),
  // Navigating probes: the frame is closed by the bridge's watchdog or the
  // navigation is refused. Each runs alone (see test/e2e-jsx.mjs).
  iframe: () => {
    const element = document.createElement("iframe");
    element.src = `${BEACON}/iframe`;
    document.body.append(element);
    return watch(element, ["load", "error"]);
  },
  object: () => {
    const element = document.createElement("object");
    element.data = `${BEACON}/object`;
    document.body.append(element);
    return watch(element, ["load", "error"]);
  },
  embed: () => {
    const element = document.createElement("embed");
    element.src = `${BEACON}/embed`;
    document.body.append(element);
    return watch(element, ["load", "error"]);
  },
  metaRefresh: () => {
    const element = document.createElement("meta");
    element.httpEquiv = "refresh";
    element.content = `0;url=${BEACON}/meta-refresh`;
    document.head.append(element);
    return new Promise((resolve) => setTimeout(() => resolve("inserted"), 1500));
  },
  locationAssign: () => {
    window.location.href = `${BEACON}/location`;
    return new Promise((resolve) => setTimeout(() => resolve("assigned"), 1500));
  },
};

export default function Privacy() {
  const [report, setReport] = useState(null);

  useEffect(() => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      violations.push(`${event.violatedDirective} ${event.blockedURI.slice(0, 80)}`);
    });
    (async () => {
      const outcomes = {};
      for (const name of PROBES.split(",")) {
        outcomes[name] = await probes[name]();
      }
      setReport({ outcomes, violations: [...new Set(violations)] });
    })();
  }, []);

  return (
    <main className="p-6">
      <h1 className="text-lg font-semibold">Privacy check</h1>
      <pre id="report" data-done={report ? "yes" : "no"} className="mt-3 text-xs whitespace-pre-wrap">
        {report ? JSON.stringify(report, null, 2) : "running"}
      </pre>
    </main>
  );
}
