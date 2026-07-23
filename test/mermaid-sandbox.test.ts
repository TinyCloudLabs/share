/**
 * Mermaid opaque-origin sandbox (viewer spec §3.2-3.3): frame document
 * pinning + the parent-side postMessage protocol, driven against the REAL
 * createMermaidSandbox with the frame interior shimmed (jsdom does not
 * execute iframe documents; the frame side is exercised by pinning the
 * document builder's contents instead).
 */
import { describe, expect, it, vi } from "vitest";

import { readFileSync } from "node:fs";

import {
  MERMAID_BRIDGE_SCRIPT,
  MERMAID_SANDBOX_CSP,
  MERMAID_SANDBOX_HTTP_HEADERS,
  MERMAID_SANDBOX_PATH,
  buildMermaidSandboxHtml,
} from "../src/viewer/mermaid-frame.js";
import {
  MERMAID_SANDBOX_IFRAME_CLASS,
  createMermaidSandbox,
} from "../src/viewer/mermaid-sandbox.js";
import {
  MAX_SVG_NODES,
  renderMarkdownInto,
  sanitizeSvg,
} from "../src/viewer/render.js";
import { previewBodyOf, previewFrameOf } from "./preview-helpers.js";

// ------------------------------------------------------- frame document

describe("mermaid sandbox frame document (mermaid-frame.ts)", () => {
  it("pins the spec §3.2 CSP verbatim and embeds it as a meta tag", () => {
    expect(MERMAID_SANDBOX_CSP).toBe(
      "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:",
    );
    const html = buildMermaidSandboxHtml("/* lib */");
    expect(html).toContain(
      `<meta http-equiv="Content-Security-Policy" content="${MERMAID_SANDBOX_CSP}">`,
    );
    expect(html).toContain('<meta name="referrer" content="no-referrer">');
  });

  it("runs mermaid in strict mode INSIDE the sandbox and speaks the narrow protocol", () => {
    const html = buildMermaidSandboxHtml("/* lib */");
    expect(html).toContain('securityLevel: "strict"');
    expect(html).toContain('startOnLoad: false');
    // protocol markers: ready announcement + render/result messages
    expect(html).toContain('{ type: "ready", nonce: nonce }');
    expect(html).toContain('data.type !== "render"');
    expect(html).toContain('type: "result"');
    // and the self-defense guard ships in the served document
    expect(html).toContain('self.origin !== "null"');
  });

  it("escapes </script sequences in the inlined library", () => {
    const html = buildMermaidSandboxHtml('var s = "</script><img src=x>";');
    expect(html).not.toContain('"</script><img');
    expect(html).toContain('"<\\/script><img src=x>";');
  });

  it("pins the embedding-refusal HTTP headers and ships the production _headers rule", () => {
    // frame-ancestors cannot ride in a <meta> CSP: it must be an HTTP header,
    // set by the vite middleware in dev/preview and by the static host in prod.
    expect(MERMAID_SANDBOX_HTTP_HEADERS).toEqual([
      ["content-security-policy", "frame-ancestors 'self'"],
      ["x-frame-options", "SAMEORIGIN"],
      ["cache-control", "no-store"],
      ["referrer-policy", "no-referrer"],
      ["x-content-type-options", "nosniff"],
    ]);
    // cwd-relative: vitest runs from the project root (import.meta.url is
    // not a file: URL under the jsdom environment).
    const headersFile = readFileSync("public/_headers", "utf8");
    const sandboxRule = headersFile
      .split(/\n(?=\/)/) // per-path blocks start at a leading "/"
      .find((block) => block.includes(MERMAID_SANDBOX_PATH));
    expect(sandboxRule).toBeDefined();
    expect(sandboxRule).toContain("Content-Security-Policy: frame-ancestors 'self'");
    expect(sandboxRule).toContain("X-Frame-Options: SAMEORIGIN");
  });
});

// -------------------------------------------- frame bridge (EXECUTED, mocked env)

interface BridgeMessageEvent {
  source: unknown;
  data: unknown;
}

/**
 * Execute the REAL bridge script against a mock self/window/mermaid — jsdom
 * cannot run iframe documents, but the exported script can be run directly,
 * proving the guards behave (not merely that their source text exists).
 */
function runBridge(origin: string, hash: string) {
  const posted: Array<{ message: Record<string, unknown>; targetOrigin: unknown }> = [];
  const listeners: Array<(event: BridgeMessageEvent) => void> = [];
  const parent = {
    postMessage: (message: Record<string, unknown>, targetOrigin: unknown) => {
      posted.push({ message, targetOrigin });
    },
  };
  const mermaidCalls = { initialized: 0, rendered: [] as string[] };
  const mermaid = {
    initialize: () => {
      mermaidCalls.initialized += 1;
    },
    render: (_id: string, source: string) => {
      mermaidCalls.rendered.push(source);
      return Promise.resolve({ svg: "<svg><text>rendered</text></svg>" });
    },
  };
  const win = {
    location: { hash },
    parent,
    addEventListener: (_type: string, listener: (event: BridgeMessageEvent) => void) => {
      listeners.push(listener);
    },
  };
  new Function("self", "window", "mermaid", MERMAID_BRIDGE_SCRIPT)(
    { origin },
    win,
    mermaid,
  );
  const dispatch = (event: BridgeMessageEvent): void => {
    for (const listener of listeners) listener(event);
  };
  return { posted, listeners, parent, mermaid: mermaidCalls, dispatch };
}

const flushMicrotasks = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("mermaid bridge self-defense (executed)", () => {
  it("embedded WITHOUT a sandbox (concrete origin): fully inert — no mermaid init, no listener, only a refusal", () => {
    const bridge = runBridge("https://share.tinycloud.xyz", "#some-nonce");
    expect(bridge.mermaid.initialized).toBe(0);
    expect(bridge.listeners).toHaveLength(0); // never even listens
    expect(bridge.posted).toHaveLength(1);
    expect(bridge.posted[0]!.message["ok"]).toBe(false);
    expect(bridge.posted[0]!.message["error"]).toContain("not in an opaque-origin sandbox");
  });

  it("sandboxed but created without a handshake nonce: fully inert", () => {
    const bridge = runBridge("null", "");
    expect(bridge.mermaid.initialized).toBe(0);
    expect(bridge.listeners).toHaveLength(0);
    expect(bridge.posted).toHaveLength(0);
  });

  it("sandboxed + nonce: announces ready WITH the nonce and renders only nonce-carrying parent messages", async () => {
    const bridge = runBridge("null", "#the-nonce");
    expect(bridge.mermaid.initialized).toBe(1);
    expect(bridge.posted).toHaveLength(1);
    expect(bridge.posted[0]!.message).toEqual({ type: "ready", nonce: "the-nonce" });

    // wrong source (not window.parent): ignored
    bridge.dispatch({
      source: {},
      data: { type: "render", id: "a", nonce: "the-nonce", source: "graph TD; A" },
    });
    // right source, missing/wrong nonce: ignored
    bridge.dispatch({
      source: bridge.parent,
      data: { type: "render", id: "b", source: "graph TD; B" },
    });
    bridge.dispatch({
      source: bridge.parent,
      data: { type: "render", id: "c", nonce: "attacker-nonce", source: "graph TD; C" },
    });
    await flushMicrotasks();
    expect(bridge.mermaid.rendered).toHaveLength(0);
    expect(bridge.posted).toHaveLength(1); // still just the ready

    // right source + right nonce: renders, and the reply carries the nonce
    bridge.dispatch({
      source: bridge.parent,
      data: { type: "render", id: "d", nonce: "the-nonce", source: "graph TD; D" },
    });
    await flushMicrotasks();
    expect(bridge.mermaid.rendered).toEqual(["graph TD; D"]);
    expect(bridge.posted).toHaveLength(2);
    expect(bridge.posted[1]!.message).toEqual({
      type: "result",
      id: "d",
      nonce: "the-nonce",
      ok: true,
      svg: "<svg><text>rendered</text></svg>",
    });
  });
});

// --------------------------------------------------- parent-side protocol

/**
 * Dispatch a message event that appears to come from `source`, posting from
 * `origin` — "null" is what a real opaque-origin frame posts as.
 */
function dispatchFrom(source: Window | null, data: unknown, origin = "null"): void {
  window.dispatchEvent(
    new MessageEvent("message", { data, source: source as Window, origin }),
  );
}

function setupSandbox() {
  const sandbox = createMermaidSandbox(document);
  const iframes = document.querySelectorAll<HTMLIFrameElement>(
    `iframe.${MERMAID_SANDBOX_IFRAME_CLASS}`,
  );
  const iframe = iframes[iframes.length - 1];
  if (iframe === undefined) throw new Error("sandbox iframe not created");
  const frameWindow = iframe.contentWindow;
  if (frameWindow === null) throw new Error("jsdom gave no contentWindow");
  // The handshake nonce rides in the frame URL fragment, set at creation.
  const nonce = (iframe.getAttribute("src") ?? "").split("#")[1] ?? "";
  if (nonce.length === 0) throw new Error("sandbox iframe has no nonce fragment");
  const posted: Array<{ message: unknown; targetOrigin: unknown }> = [];
  vi.spyOn(frameWindow, "postMessage").mockImplementation(
    (message: unknown, targetOrigin?: unknown) => {
      posted.push({ message, targetOrigin });
    },
  );
  return { sandbox, iframe, frameWindow, nonce, posted };
}

describe("createMermaidSandbox (parent side)", () => {
  it("creates an opaque-origin iframe: sandbox=allow-scripts ONLY, app-served src with a fresh CSPRNG nonce fragment", () => {
    const { sandbox, iframe, nonce } = setupSandbox();
    try {
      expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
      expect(iframe.getAttribute("sandbox")).not.toContain("allow-same-origin");
      expect(iframe.getAttribute("src")).toBe(`${MERMAID_SANDBOX_PATH}#${nonce}`);
      expect(nonce).toMatch(/^[0-9a-f]{32}$/); // 128-bit hex handshake nonce
      expect(iframe.getAttribute("aria-hidden")).toBe("true");
      expect(document.body.contains(iframe)).toBe(true);
      // fresh per frame
      const second = createMermaidSandbox(document);
      const iframes = document.querySelectorAll<HTMLIFrameElement>(
        `iframe.${MERMAID_SANDBOX_IFRAME_CLASS}`,
      );
      const secondSrc = iframes[iframes.length - 1]?.getAttribute("src") ?? "";
      expect(secondSrc.split("#")[1]).not.toBe(nonce);
      second.destroy();
    } finally {
      sandbox.destroy();
    }
  });

  it("queues renders until the frame announces ready, then posts ONLY {type,id,nonce,source} with targetOrigin *", async () => {
    const { sandbox, frameWindow, nonce, posted } = setupSandbox();
    try {
      const pending = sandbox.render("graph TD; A-->B");
      expect(posted).toHaveLength(0); // not ready yet — nothing crosses

      dispatchFrom(frameWindow, { type: "ready", nonce });
      expect(posted).toHaveLength(1);
      const request = posted[0]!.message as Record<string, unknown>;
      expect(Object.keys(request).sort()).toEqual(["id", "nonce", "source", "type"]);
      expect(request["type"]).toBe("render");
      expect(request["nonce"]).toBe(nonce);
      expect(request["source"]).toBe("graph TD; A-->B");
      expect(posted[0]!.targetOrigin).toBe("*");

      dispatchFrom(frameWindow, {
        type: "result",
        id: request["id"],
        nonce,
        ok: true,
        svg: "<svg><text>ok</text></svg>",
      });
      await expect(pending).resolves.toBe("<svg><text>ok</text></svg>");
    } finally {
      sandbox.destroy();
    }
  });

  it("ignores ready/result messages whose source is not OUR frame", async () => {
    const { sandbox, frameWindow, nonce, posted } = setupSandbox();
    try {
      const pending = sandbox.render("graph TD; A-->B");
      // "ready" claimed by the parent window itself (e.g. hostile content
      // that somehow runs — defense in depth): must NOT unblock the queue.
      dispatchFrom(window, { type: "ready", nonce });
      expect(posted).toHaveLength(0);

      dispatchFrom(frameWindow, { type: "ready", nonce });
      const request = posted[0]!.message as Record<string, unknown>;
      // result forged from the wrong source: must stay pending
      dispatchFrom(window, {
        type: "result",
        id: request["id"],
        nonce,
        ok: true,
        svg: "<svg><script>window.__pwned=true</script></svg>",
      });
      let settled = false;
      void pending.then(() => (settled = true)).catch(() => (settled = true));
      await Promise.resolve();
      expect(settled).toBe(false);

      dispatchFrom(frameWindow, {
        type: "result",
        id: request["id"],
        nonce,
        ok: true,
        svg: "<svg/>",
      });
      await expect(pending).resolves.toBe("<svg/>");
    } finally {
      sandbox.destroy();
    }
  });

  it("ignores messages without the handshake nonce, even from OUR frame's window", async () => {
    const { sandbox, frameWindow, nonce, posted } = setupSandbox();
    try {
      const pending = sandbox.render("graph TD; A-->B");
      // ready without / with the wrong nonce: must NOT unblock the queue
      dispatchFrom(frameWindow, { type: "ready" });
      dispatchFrom(frameWindow, { type: "ready", nonce: "not-the-nonce" });
      expect(posted).toHaveLength(0);

      dispatchFrom(frameWindow, { type: "ready", nonce });
      const request = posted[0]!.message as Record<string, unknown>;
      // result without the nonce: must stay pending
      dispatchFrom(frameWindow, {
        type: "result",
        id: request["id"],
        ok: true,
        svg: "<svg/>",
      });
      let settled = false;
      void pending.then(() => (settled = true)).catch(() => (settled = true));
      await Promise.resolve();
      expect(settled).toBe(false);

      dispatchFrom(frameWindow, { type: "result", id: request["id"], nonce, ok: true, svg: "<svg/>" });
      await expect(pending).resolves.toBe("<svg/>");
    } finally {
      sandbox.destroy();
    }
  });

  it("ignores messages whose origin is not \"null\" (only an opaque-origin frame may answer)", async () => {
    const { sandbox, frameWindow, nonce, posted } = setupSandbox();
    try {
      const pending = sandbox.render("graph TD; A-->B");
      // a concrete origin means the poster is NOT our sandboxed frame —
      // e.g. the document loaded unsandboxed somewhere: ignore it.
      dispatchFrom(frameWindow, { type: "ready", nonce }, "https://share.tinycloud.xyz");
      expect(posted).toHaveLength(0);

      dispatchFrom(frameWindow, { type: "ready", nonce });
      const request = posted[0]!.message as Record<string, unknown>;
      dispatchFrom(
        frameWindow,
        { type: "result", id: request["id"], nonce, ok: true, svg: "<svg/>" },
        "https://share.tinycloud.xyz",
      );
      let settled = false;
      void pending.then(() => (settled = true)).catch(() => (settled = true));
      await Promise.resolve();
      expect(settled).toBe(false);

      dispatchFrom(frameWindow, { type: "result", id: request["id"], nonce, ok: true, svg: "<svg/>" });
      await expect(pending).resolves.toBe("<svg/>");
    } finally {
      sandbox.destroy();
    }
  });

  it("rejects a render the frame reports as failed", async () => {
    const { sandbox, frameWindow, nonce, posted } = setupSandbox();
    try {
      const pending = sandbox.render("not a diagram");
      dispatchFrom(frameWindow, { type: "ready", nonce });
      const request = posted[0]!.message as Record<string, unknown>;
      dispatchFrom(frameWindow, {
        type: "result",
        id: request["id"],
        nonce,
        ok: false,
        error: "parse error",
      });
      await expect(pending).rejects.toThrow(/parse error/);
    } finally {
      sandbox.destroy();
    }
  });

  it("destroy() removes the frame, rejects pending renders, and refuses new ones", async () => {
    const { sandbox, iframe } = setupSandbox();
    const pending = sandbox.render("graph TD; A-->B");
    sandbox.destroy();
    expect(document.body.contains(iframe)).toBe(false);
    await expect(pending).rejects.toThrow(/destroyed/);
    await expect(sandbox.render("graph TD; X-->Y")).rejects.toThrow(/destroyed/);
    sandbox.destroy(); // idempotent
  });
});

// ------------------------------------------- render.ts sandbox integration

function makeContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  return container;
}

const DIAGRAM_MD = ["```mermaid", "graph TD; A-->B", "```"].join("\n");

describe("render.ts mermaid pipeline (sandboxed)", () => {
  it("re-sanitizes sandbox SVG before insertion (hostile frame output never lands)", async () => {
    const container = makeContainer();
    await renderMarkdownInto(container, DIAGRAM_MD, "document", {
      mermaidSandbox: () => ({
        render: () =>
          Promise.resolve(
            '<svg xmlns="http://www.w3.org/2000/svg"><text>diagram</text>' +
              "<script>window.__pwned=true</script>" +
              '<foreignObject><iframe src="https://evil.example"></iframe></foreignObject></svg>',
          ),
        destroy: () => {},
      }),
    });
    const body = previewBodyOf(container);
    const host = body.querySelector(".viewer-mermaid");
    expect(host).not.toBeNull();
    expect(host?.querySelector("svg text")?.textContent).toBe("diagram");
    const srcdoc = previewFrameOf(container).srcdoc;
    expect(srcdoc).not.toContain("<script");
    expect(srcdoc).not.toContain("foreignObject");
    expect(srcdoc).not.toContain("evil.example");
    expect((window as { __pwned?: unknown }).__pwned).toBeUndefined();
  });

  it("enforces the MAX_SVG_NODES bound: an element bomb never joins the document", async () => {
    const bomb = `<svg xmlns="http://www.w3.org/2000/svg">${"<circle r='1'/>".repeat(
      MAX_SVG_NODES + 10,
    )}</svg>`;
    // sanity: the bomb survives sanitization (it is not executable), so the
    // node-count bound is the ONLY thing standing between it and the DOM
    expect(sanitizeSvg(bomb).length).toBeGreaterThan(0);
    const container = makeContainer();
    await renderMarkdownInto(container, DIAGRAM_MD, "document", {
      mermaidSandbox: () => ({
        render: () => Promise.resolve(bomb),
        destroy: () => {},
      }),
    });
    // fail closed: no svg host; the sanitized source stays visible as code
    // (inside the preview frame — the container itself holds only the frame)
    const body = previewBodyOf(container);
    expect(body.querySelector(".viewer-mermaid")).toBeNull();
    expect(body.querySelector("pre > code.language-mermaid")?.textContent).toContain(
      "graph TD; A-->B",
    );
  });

  it("a timed-out render DESTROYS the sandbox and leaves remaining diagrams as source", async () => {
    const destroyed: number[] = [];
    const container = makeContainer();
    await renderMarkdownInto(
      container,
      [DIAGRAM_MD, "", "```mermaid", "graph TD; C-->D", "```"].join("\n"),
      "document",
      {
        mermaidTimeoutMs: 20,
        mermaidSandbox: () => ({
          render: () => new Promise<string>(() => {}), // hangs forever
          destroy: () => destroyed.push(Date.now()),
        }),
      },
    );
    expect(destroyed.length).toBeGreaterThanOrEqual(1); // frame torn down
    const body = previewBodyOf(container);
    expect(body.querySelector(".viewer-mermaid")).toBeNull();
    expect(
      body.querySelectorAll("pre > code.language-mermaid"),
    ).toHaveLength(2); // both blocks stay as sanitized source
  });

  it("sandbox factory failure leaves every diagram as sanitized source (fail closed)", async () => {
    const container = makeContainer();
    await renderMarkdownInto(container, DIAGRAM_MD, "document", {
      mermaidSandbox: () => {
        throw new Error("no sandbox here");
      },
    });
    const body = previewBodyOf(container);
    expect(body.querySelector(".viewer-mermaid")).toBeNull();
    expect(body.querySelector("pre > code.language-mermaid")).not.toBeNull();
  });
});
