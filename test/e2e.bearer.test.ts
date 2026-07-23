/**
 * STAGE-4 END-TO-END: the whole bearer loop in-process.
 *
 *   CLI create (lib entry) — markdown WITH a mermaid diagram AND hostile
 *   payloads → seals content + envelope, puts BOTH in the in-process dev
 *   registry → /s/<cid>#k= link → viewer resolve (fetch, CID re-verify,
 *   decrypt, schema, signature, delegation binding, expiry, content fetch +
 *   CID re-verify + decrypt) → present (sanitized markdown; mermaid through
 *   the REAL opaque-origin sandbox module, its frame interior shimmed for
 *   jsdom) → assertions:
 *
 *   - the markdown renders; the mermaid diagram renders as SANITIZED svg;
 *   - the diagram SOURCE TEXT is the ONLY payload posted into the frame —
 *     no fragment key, session key, content key, envelope, or document text
 *     ever crosses the boundary;
 *   - the hostile <script> / javascript: link never executes or survives;
 *   - content-CID mismatch, missing content, tampered pointer, wrong key,
 *     and expiry each fail CLOSED (no content container at all).
 */
import {
  seal,
  toBase64Url,
  type ShareEnvelope,
} from "@tinycloud/share-envelope";
import { createBearerShare } from "@tinycloud/share-cli";
import { putBlob } from "@tinycloud/share-registry";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { beforeEach, describe, expect, it } from "vitest";

import {
  MERMAID_SANDBOX_IFRAME_CLASS,
  createMermaidSandbox,
} from "../src/viewer/mermaid-sandbox.js";
import { presentShare } from "../src/viewer/present.js";
import type { MermaidSandboxFactory } from "../src/viewer/render.js";
import { resolveShare, type ResolveResult } from "../src/viewer/resolve.js";
import { assertContentIsolated, previewFrameOf } from "./preview-helpers.js";

// ---------------------------------------------------------------- fixtures

const REGISTRY_BASE = "http://registry.local";

const DIAGRAM_SOURCE = "graph TD\n  NodeA[Start] --> NodeB[End]";

/** Markdown with a real diagram AND hostile payloads, per the stage-4 brief. */
const MARKDOWN = [
  "# Q3 Report",
  "",
  "Hello from the **bearer** share.",
  "",
  "```mermaid",
  DIAGRAM_SOURCE,
  "```",
  "",
  "<script>window.__pwned = true;</script>",
  "",
  "[malicious](javascript:window.__pwned=true)",
  "",
].join("\n");

let registry: DevRegistry;
let fetchFn: typeof fetch;

function handlerFetch(target: DevRegistry): typeof fetch {
  return async (input, init) => {
    const withDuplex =
      init?.body === undefined || init.body === null
        ? init
        : ({ ...init, duplex: "half" } as RequestInit);
    return target.handler(new Request(input, withDuplex));
  };
}

beforeEach(() => {
  registry = createDevRegistry();
  fetchFn = handlerFetch(registry);
  delete (window as { __pwned?: unknown }).__pwned;
});

function create() {
  return createBearerShare({
    content: new TextEncoder().encode(MARKDOWN),
    filename: "q3-report.md",
    registryBaseUrl: REGISTRY_BASE,
    senderName: "Adam",
    fetchFn,
  });
}

function resolve(
  url: string,
  extra: { now?: () => number } = {},
): Promise<ResolveResult> {
  return resolveShare(url, { registryBaseUrl: REGISTRY_BASE, fetchFn, ...extra });
}

function makeRoot(): HTMLElement {
  const root = document.createElement("div");
  document.body.append(root);
  return root;
}

// ------------------------------------------------------- frame-side shim

interface PostedMessage {
  message: unknown;
  targetOrigin: unknown;
}

/**
 * What the frame's bridge would return for the fixture diagram — INCLUDING
 * hostile extras, standing in for a compromised mermaid: the parent must
 * re-sanitize before insertion.
 */
function fakeMermaidSvg(): string {
  return (
    '<svg xmlns="http://www.w3.org/2000/svg" aria-roledescription="flowchart">' +
    '<g class="node"><text>Start</text><text>End</text></g>' +
    "<script>window.__pwned=true</script>" +
    '<circle r="1" onload="window.__pwned=true"/>' +
    '<a href="javascript:window.__pwned=true"><text>x</text></a>' +
    '<image href="https://evil.example/x.png"/>' +
    "</svg>"
  );
}

/**
 * Use the REAL createMermaidSandbox (real iframe, real postMessage protocol,
 * real source validation) and shim only the frame INTERIOR, which jsdom
 * cannot execute: every message posted into the frame is recorded, and
 * render requests are answered like the bridge would.
 */
function shimmedFrameFactory(posted: PostedMessage[]): MermaidSandboxFactory {
  return (doc: Document) => {
    const sandbox = createMermaidSandbox(doc);
    const iframes = doc.querySelectorAll<HTMLIFrameElement>(
      `iframe.${MERMAID_SANDBOX_IFRAME_CLASS}`,
    );
    const iframe = iframes[iframes.length - 1];
    if (iframe === undefined) throw new Error("sandbox iframe missing");
    const frameWindow = iframe.contentWindow;
    if (frameWindow === null) throw new Error("jsdom gave no contentWindow");
    const view = doc.defaultView;
    if (view === null) throw new Error("document has no window");
    // The real bridge reads the handshake nonce from the frame URL fragment
    // and echoes it on every reply; the shim does exactly the same.
    const nonce = (iframe.getAttribute("src") ?? "").split("#")[1] ?? "";
    if (nonce.length === 0) throw new Error("sandbox iframe has no nonce fragment");

    const respond = (message: unknown): void => {
      posted.push({ message, targetOrigin: "*" });
      const request = message as { type?: unknown; id?: unknown; source?: unknown };
      if (
        request.type !== "render" ||
        typeof request.id !== "string" ||
        typeof request.source !== "string"
      ) {
        return;
      }
      queueMicrotask(() => {
        view.dispatchEvent(
          new MessageEvent("message", {
            data: {
              type: "result",
              id: request.id,
              nonce,
              ok: true,
              svg: fakeMermaidSvg(),
            },
            source: frameWindow,
            origin: "null", // what a real opaque-origin frame posts as
          }),
        );
      });
    };
    Object.defineProperty(frameWindow, "postMessage", {
      value: (message: unknown) => respond(message),
      configurable: true,
    });
    // the bridge announces readiness once loaded
    view.dispatchEvent(
      new MessageEvent("message", {
        data: { type: "ready", nonce },
        source: frameWindow,
        origin: "null",
      }),
    );
    return sandbox;
  };
}

function assertNoExecutableContent(container: HTMLElement): void {
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("object, embed")).toBeNull();
  for (const node of Array.from(container.querySelectorAll("*"))) {
    for (const attr of Array.from(node.attributes)) {
      expect(
        attr.name.toLowerCase().startsWith("on"),
        `event handler attribute ${attr.name} survived`,
      ).toBe(false);
      if (["href", "src", "xlink:href", "action", "formaction"].includes(attr.name)) {
        const value = attr.value.toLowerCase().replace(/[\s -]/g, "");
        expect(value.startsWith("javascript:"), "javascript: URL survived").toBe(false);
      }
    }
  }
  expect((window as { __pwned?: unknown }).__pwned).toBeUndefined();
}

// -------------------------------------------------------------- happy path

describe("bearer e2e: create → share → open → render", () => {
  it("renders the shared markdown with a sandbox-rendered, re-sanitized mermaid diagram; hostile content never executes", async () => {
    const created = await create();
    expect(created.url).toMatch(/^https:\/\/share\.tinycloud\.xyz\/s\/bafkr[a-z2-7]+#k=/);

    const result = await resolve(created.url);
    expect(result.state).toBe("ok");
    if (result.state !== "ok") throw new Error("unreachable");
    expect(result.content).toBe(MARKDOWN);
    expect(result.senderVerified).toBe(false); // bearer sender: NEVER verified

    const posted: PostedMessage[] = [];
    const root = makeRoot();
    const container = await presentShare(root, result, {
      mermaidSandbox: shimmedFrameFactory(posted),
    });
    expect(container).not.toBeNull();

    // Markdown rendered — INSIDE the scriptless preview frame (§3.3): the
    // privileged content container holds exactly the iframe and nothing else.
    const body = assertContentIsolated(container as HTMLElement);
    expect(body.querySelector("h1")?.textContent).toBe("Q3 Report");
    expect(body.querySelector("strong")?.textContent).toBe("bearer");
    // Chrome stays in the privileged document: filename + unverified sender
    expect(root.textContent).toContain("q3-report.md");
    expect(root.textContent).toContain("shared by Adam (unverified)");
    const download = Array.from(root.querySelectorAll("button")).find(
      (button) => button.textContent === "Download original",
    );
    expect(download).toBeDefined();

    // Mermaid rendered through the sandbox path, re-sanitized, in the frame
    const svgHost = body.querySelector(".viewer-mermaid");
    expect(svgHost).not.toBeNull();
    expect(svgHost?.querySelector("svg")).not.toBeNull();
    expect(svgHost?.textContent).toContain("Start");
    expect(svgHost?.textContent).toContain("End");
    const srcdoc = previewFrameOf(container as HTMLElement).srcdoc;
    expect(srcdoc).not.toContain("evil.example");
    expect(srcdoc.toLowerCase()).not.toContain("onload");

    // Hostile payloads: never executed, never present
    assertNoExecutableContent(body);

    // ---------------- the boundary proof ----------------
    // Exactly one render request crossed into the frame, and its ONLY
    // payload is the diagram source text (plus the handshake nonce, which
    // carries no information about the share).
    expect(posted).toHaveLength(1);
    const request = posted[0]!.message as Record<string, unknown>;
    expect(Object.keys(request).sort()).toEqual(["id", "nonce", "source", "type"]);
    expect(request["type"]).toBe("render");
    expect((request["source"] as string).trim()).toBe(DIAGRAM_SOURCE);
    expect(posted[0]!.targetOrigin).toBe("*");

    // Nothing secret crossed: not the fragment key, not the session key,
    // not the content key, not the delegation, not the rest of the document.
    const crossed = JSON.stringify(posted);
    const fragmentKey = created.url.split("#k=")[1] ?? "";
    expect(fragmentKey.length).toBeGreaterThan(0);
    expect(crossed).not.toContain(fragmentKey);
    const target = created.envelope.authorizationTarget;
    if (target.kind !== "bearerKey") throw new Error("expected bearer target");
    expect(crossed).not.toContain(target.sessionJwk.d);
    expect(crossed).not.toContain(target.sessionJwk.x);
    expect(crossed).not.toContain(created.envelope.content?.key ?? "@@none@@");
    expect(crossed).not.toContain(created.envelope.delegation);
    expect(crossed).not.toContain("Hello from"); // non-diagram document text
    expect(crossed).not.toContain("<script>"); // hostile block stayed outside
    expect(crossed).not.toContain(created.envelopeCid);

    // ---------------- the preview-frame boundary (§3.3) ----------------
    // The frame's ENTIRE input is its srcdoc payload (no message channel
    // exists into a scriptless frame). It carries the sanitized document —
    // and none of the secrets: fragment key, bearer session key, content
    // key, delegation, envelope CID, content CID.
    expect(srcdoc).toContain("Q3 Report");
    expect(srcdoc).not.toContain(fragmentKey);
    expect(srcdoc).not.toContain(target.sessionJwk.d);
    expect(srcdoc).not.toContain(target.sessionJwk.x);
    expect(srcdoc).not.toContain(created.envelope.content?.key ?? "@@none@@");
    expect(srcdoc).not.toContain(created.envelope.delegation);
    expect(srcdoc).not.toContain(created.envelopeCid);
    expect(srcdoc).not.toContain(created.contentCid);
  });

  it("node-count breach in the assembled document → 'content too large', no frame, no content (fail closed)", async () => {
    const created = await create();
    const result = await resolve(created.url);
    expect(result.state).toBe("ok");

    const root = makeRoot();
    const container = await presentShare(root, result, {
      mermaidSandbox: shimmedFrameFactory([]),
      previewNodeBudget: 3, // tests-only override of MAX_PREVIEW_NODES
    });
    expect(container).not.toBeNull();
    // fail closed: no preview frame, no rendered content, an honest state
    expect(container?.querySelector("iframe")).toBeNull();
    expect(container?.textContent).toContain("too large to display");
    expect(root.textContent).not.toContain("Q3 Report");
  });
});

// -------------------------------------------------------------- fail closed

/** No content container may exist for a non-ok result (ui.ts invariant). */
async function expectFailClosed(result: ResolveResult): Promise<HTMLElement> {
  const root = makeRoot();
  const container = await presentShare(root, result);
  expect(container).toBeNull();
  expect(root.querySelector(".viewer-content")).toBeNull();
  return root;
}

describe("bearer e2e: fail-closed paths", () => {
  it("content-CID mismatch (tampered stored bytes) → content-integrity-failed, no render", async () => {
    const created = await create();
    const record = registry.store.get(created.contentCid);
    expect(record).toBeDefined();
    record!.bytes.set([record!.bytes[20]! ^ 0xff], 20); // flip one byte

    const result = await resolve(created.url);
    expect(result.state).toBe("content-integrity-failed");
    const root = await expectFailClosed(result);
    expect(root.textContent).toContain("integrity check");
  });

  it("content blob missing from the registry → content-fetch-failed, no render", async () => {
    const created = await create();
    registry.store.delete(created.contentCid);
    const result = await resolve(created.url);
    expect(result).toMatchObject({ state: "content-fetch-failed" });
    const root = await expectFailClosed(result);
    expect(root.textContent).toContain("Couldn't fetch the shared file");
  });

  it("tampered content pointer (re-aimed at another blob) → signature-invalid", async () => {
    const created = await create();
    // Mallory seals her own blob and re-points the envelope's SIGNED content
    // pointer at it, republishing under a new link. The sender signature
    // covers the pointer, so this dies at signature verification.
    const malloryKey = new Uint8Array(32).fill(3);
    const mallorySealed = await seal(
      new TextEncoder().encode("# Mallory was here"),
      malloryKey,
    );
    await putBlob(REGISTRY_BASE, mallorySealed.blob, new Date(Date.now() + 3_600_000), {
      fetchFn,
    });
    const tampered: ShareEnvelope = {
      ...created.envelope,
      content: { cid: mallorySealed.cid, key: toBase64Url(malloryKey) },
    };
    const envelopeKey = new Uint8Array(32).fill(5);
    const sealedTampered = await seal(
      new TextEncoder().encode(JSON.stringify(tampered)),
      envelopeKey,
    );
    await putBlob(REGISTRY_BASE, sealedTampered.blob, new Date(Date.now() + 3_600_000), {
      fetchFn,
    });
    const result = await resolve(
      `https://share.tinycloud.xyz/s/${sealedTampered.cid}#k=${toBase64Url(envelopeKey)}`,
    );
    expect(result.state).toBe("signature-invalid");
    await expectFailClosed(result);
  });

  it("wrong fragment key → decrypt-failed, no render", async () => {
    const created = await create();
    const wrongKey = toBase64Url(new Uint8Array(32).fill(9));
    const result = await resolve(
      `https://share.tinycloud.xyz/s/${created.envelopeCid}#k=${wrongKey}`,
    );
    expect(result.state).toBe("decrypt-failed");
    await expectFailClosed(result);
  });

  it("expired share → expired, no render (content never fetched)", async () => {
    const created = await create();
    let contentFetched = false;
    const spyFetch: typeof fetch = async (input, init) => {
      if (String(input).includes(created.contentCid)) contentFetched = true;
      return fetchFn(input, init);
    };
    const result = await resolveShare(created.url, {
      registryBaseUrl: REGISTRY_BASE,
      fetchFn: spyFetch,
      now: () => Date.parse(created.expiry) + 1,
    });
    expect(result.state).toBe("expired");
    expect(contentFetched).toBe(false); // fail closed BEFORE fetching content
    const root = await expectFailClosed(result);
    expect(root.textContent).toContain("expired");
  });
});
