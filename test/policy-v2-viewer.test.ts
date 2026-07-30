/**
 * Recipient-facing behaviour of the addressed (v2) viewer:
 *  - P0-3: raw exception text never reaches the recipient;
 *  - P0-4: the state announces itself and takes focus;
 *  - P0-5: opening a file keeps the folder navigation mounted and Back works.
 *
 * The node client is stubbed at the module boundary; everything below it is
 * the shipped code path.
 */
import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// jsdom 26 ships its own SubtleCrypto, which rejects ArrayBuffers from the
// module realm — the shipped digest helper cannot run under it. Use node's.
// Environment plumbing only; no app behaviour changes.
Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const { digestBytes } = await import("../src/email-share/node-verifier.js");

const stub = vi.hoisted(() => ({
  invokes: [] as Array<Record<string, unknown>>,
  establish: async (): Promise<{ resource: Record<string, unknown> }> => ({ resource: { kind: "exact", path: "notes/plan.md" } }),
  respond: async (_request: Record<string, unknown>): Promise<Response> => new Response(null, { status: 500 }),
}));

vi.mock("@tinycloud/share-app-compat", () => ({
  ShareRecipientClient: class {
    constructor(_options: unknown) {}
    establishPolicySession(): Promise<{ resource: Record<string, unknown> }> { return stub.establish(); }
    nativeInvoke(request: Record<string, unknown>): Promise<Response> {
      stub.invokes.push(request);
      return stub.respond(request);
    }
  },
}));

const { RECIPIENT_FAILURE, mountPolicyV2Viewer, recipientFailureKind } = await import("../src/viewer/policy-v2.js");

/**
 * The approved recipient-facing copy, written out as LITERALS (TC-305).
 *
 * These strings are deliberately not read from the implementation. Asserting
 * `status.textContent === EXPECTED_FAILURE_COPY.denied` is a tautology: editing the
 * shipped string edits the expectation with it, so a copy regression — jargon
 * creeping back in, the wrong message shown for a state, an unactionable
 * sentence — can never turn this suite red. Every assertion below compares
 * against the sentence a recipient is supposed to read. Exactly one test
 * compares the exported table to these literals; that is the single place a
 * deliberate copy change has to be re-approved.
 */
const EXPECTED_FAILURE_COPY = {
  denied: "You don't have access to this. Ask the sender to share it again.",
  conflict: "Someone else saved a change first. Reload to see the latest version.",
  malformed: "Something went wrong opening this. Ask the sender for a fresh link.",
  offline: "You appear to be offline. Reconnect and try again.",
} as const;

const EXPECTED_COPY_SUCCEEDED = "Link copied.";
const EXPECTED_COPY_FAILED = "Copy failed. Allow clipboard access and try again.";

const RAW_MESSAGES = [
  "native get denied",
  "native list denied",
  "KV_PRECONDITION_FAILED",
  "native response media type is invalid",
  "native response binding is invalid",
  "native response content binding is invalid",
];

function envelopeWith(actions: readonly string[]): Parameters<typeof mountPolicyV2Viewer>[1] {
  return { envelope: { actions } as never, shareCid: "bafkreisharecid", policy: {} };
}

function mount(actions: readonly string[], shareUrl?: string): HTMLElement {
  const root = document.createElement("div");
  root.tabIndex = -1;
  document.body.append(root);
  mountPolicyV2Viewer(root, envelopeWith(actions), {
    nodeOrigin: "https://node.example",
    trustedNode: {} as never,
    holderDid: "did:key:z6Mkholder",
    buildPresentation: async () => ({}) as never,
    ...(shareUrl === undefined ? {} : { shareUrl }),
  });
  return root;
}

function nativeJson(body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

async function listResponse(path: string, entries: readonly unknown[]): Promise<Response> {
  return nativeJson({ type: "TinyCloudShareInvokeResponse", version: 2, action: "tinycloud.kv/list", resource: path, entries, nextCursor: null });
}

async function getResponse(path: string, text: string): Promise<Response> {
  const bytes = Uint8Array.from(Buffer.from(text, "utf8"));
  return nativeJson({
    type: "TinyCloudShareInvokeResponse", version: 2, action: "tinycloud.kv/get", resource: path,
    mediaType: "text/markdown", content: Buffer.from(bytes).toString("base64url"), bodyDigest: await digestBytes(bytes), etag: null,
  });
}

async function artifactGetResponse(path: string, text: string, mediaType: string): Promise<Response> {
  const bytes = Uint8Array.from(Buffer.from(text, "utf8"));
  return nativeJson({
    type: "TinyCloudShareInvokeResponse", version: 2, action: "tinycloud.kv/get", resource: path,
    mediaType, content: Buffer.from(bytes).toString("base64url"), bodyDigest: await digestBytes(bytes), etag: null,
  });
}

function status(root: HTMLElement): HTMLElement {
  return root.querySelector<HTMLElement>(".viewer-policy-status")!;
}

function clickOpen(root: HTMLElement): void {
  root.querySelector<HTMLButtonElement>("button.viewer-primary-action")!.click();
}

function folderButtons(root: HTMLElement): HTMLButtonElement[] {
  return Array.from(root.querySelectorAll<HTMLButtonElement>(".viewer-folder-entry"));
}

beforeEach(() => {
  document.body.replaceChildren();
  document.body.classList.remove("artifact-active");
  localStorage.clear();
  stub.invokes.length = 0;
  stub.establish = async () => ({ resource: { kind: "exact", path: "notes/plan.md" } });
  stub.respond = async () => new Response(null, { status: 500 });
  window.history.replaceState(null, "", "/s/bafkreisharecid");
});

describe("addressed viewer — recipient never sees raw exception text (P0-3)", () => {
  it("maps a denied node response to the access message, not `native get denied`", async () => {
    stub.respond = async () => new Response("{}", { status: 403 });
    const root = mount(["read"]);
    clickOpen(root);
    await vi.waitFor(() => expect(status(root).textContent).toBe(EXPECTED_FAILURE_COPY.denied));
    for (const raw of RAW_MESSAGES) expect(root.textContent).not.toContain(raw);
    expect(status(root).getAttribute("role")).toBe("alert");
  });

  it("maps a malformed node payload to the generic message", async () => {
    stub.respond = async () => new Response("not json", { status: 200, headers: { "content-type": "text/plain" } });
    const root = mount(["read"]);
    clickOpen(root);
    await vi.waitFor(() => expect(status(root).textContent).toBe(EXPECTED_FAILURE_COPY.malformed));
    expect(root.textContent).not.toContain("media type is invalid");
  });

  it("maps a 412 to the conflict message and a dead connection to the offline message", async () => {
    stub.respond = async () => new Response("{}", { status: 412 });
    const conflict = mount(["read"]);
    clickOpen(conflict);
    await vi.waitFor(() => expect(status(conflict).textContent).toBe(EXPECTED_FAILURE_COPY.conflict));

    stub.establish = async () => { throw new TypeError("Failed to fetch"); };
    const offline = mount(["read"]);
    clickOpen(offline);
    await vi.waitFor(() => expect(status(offline).textContent).toBe(EXPECTED_FAILURE_COPY.offline));
  });

  it("classifies untagged failures conservatively and keeps the four messages jargon-free", () => {
    expect(recipientFailureKind(new Error("anything at all"))).toBe("malformed");
    expect(recipientFailureKind(new TypeError("Failed to fetch"))).toBe("offline");
    expect(recipientFailureKind(Object.assign(new Error("native list denied"), { kind: "denied" }))).toBe("denied");
    for (const message of Object.values(RECIPIENT_FAILURE)) {
      expect(message).not.toMatch(/native|delegation|capability|policy|envelope|KV|CID|registry/i);
    }
  });

  /**
   * The one place the shipped table is compared to the approved copy. Every
   * other assertion in this file uses the literals, so a copy edit lands here
   * and has to be made deliberately — instead of silently rewriting every
   * expectation at once (TC-305).
   */
  it("ships exactly the approved four messages and no fifth failure state", () => {
    expect(RECIPIENT_FAILURE).toEqual(EXPECTED_FAILURE_COPY);
  });
});

describe("addressed viewer — the state announces itself (P0-4)", () => {
  it("moves focus to the viewer root and keeps the document out of the live region (P2-5)", () => {
    const root = mount(["read"]);
    expect(document.activeElement).toBe(root);
    expect(root.querySelector(".viewer-content")?.hasAttribute("aria-live")).toBe(false);
    expect(status(root).getAttribute("aria-live")).toBe("polite");
  });

  it("keeps a failure announcement assertive and a progress announcement polite", async () => {
    stub.respond = async () => new Response("{}", { status: 403 });
    const root = mount(["read"]);
    clickOpen(root);
    expect(status(root).getAttribute("role")).toBe("status");
    await vi.waitFor(() => expect(status(root).getAttribute("role")).toBe("alert"));
  });
});

describe("addressed viewer — folder → file is no longer a trap (P0-5)", () => {
  beforeEach(() => {
    stub.establish = async () => ({ resource: { kind: "prefix", path: "notes/" } });
    stub.respond = async (request) => {
      const resource = request.resource as { readonly path: string };
      if (request.action === "list") {
        return resource.path === "notes/"
          ? listResponse("notes/", ["notes/plan.md", { path: "notes/sub/", kind: "folder" }])
          : listResponse(resource.path, [`${resource.path}deep.md`]);
      }
      return getResponse(resource.path, "# Plan\n\nbody text");
    };
  });

  it("renders the opened file beside the folder navigation instead of destroying it", async () => {
    const root = mount(["read", "list"]);
    clickOpen(root);
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));

    folderButtons(root).find((button) => button.dataset.path === "notes/plan.md")!.click();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(false));

    // the folder list survived the file open — the trap is gone
    expect(root.querySelector<HTMLElement>(".viewer-folder-panel")?.hidden).toBe(false);
    expect(folderButtons(root)).toHaveLength(2);
    const back = root.querySelector<HTMLButtonElement>(".viewer-file-back")!;
    expect(back.hidden).toBe(false);
    expect(back.textContent).toBe("← notes");
    expect(document.activeElement).toBe(back);
  });

  /**
   * TC-305: this used to hand-dispatch `new PopStateEvent("popstate", { state })`
   * with a state object the test authored itself, which proves only that the
   * listener reacts to a shape the test invented. It never exercised the
   * `recordView` -> browser-history-stack -> Back round trip, so a viewer that
   * pushed no entry, pushed the wrong state key, or pushed two entries per
   * navigation would still have passed. jsdom implements a real session history,
   * so drive `window.history.back()` and let the browser deliver the state the
   * viewer actually recorded.
   */
  it("pushes one history entry per navigation and restores the folder on real browser Back", async () => {
    const before = window.history.length;
    const root = mount(["read", "list"]);
    clickOpen(root);
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));
    // The root folder is recorded with replaceState, so it costs no entry.
    expect(window.history.length).toBe(before);

    folderButtons(root).find((button) => button.dataset.path === "notes/plan.md")!.click();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(false));
    expect((window.history.state as { tinycloudShareView?: { kind?: string } } | null)?.tinycloudShareView?.kind).toBe("file");
    // Exactly one entry per navigation: Back must not need pressing twice.
    expect(window.history.length).toBe(before + 1);
    // the recorded position never puts anything about the share in the URL
    expect(window.location.href).not.toContain("plan.md");
    expect(window.location.hash).toBe("");

    window.history.back();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(true));
    expect(folderButtons(root)).toHaveLength(2);
    expect((window.history.state as { tinycloudShareView?: { kind?: string; path?: string } } | null)?.tinycloudShareView).toEqual({ kind: "folder", path: "notes/" });
  });

  it("restores the folder the recipient came from after browsing two levels deep", async () => {
    const root = mount(["read", "list"]);
    clickOpen(root);
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));

    folderButtons(root).find((button) => button.dataset.path === "notes/sub/")!.click();
    await vi.waitFor(() => expect(folderButtons(root).map((button) => button.dataset.path)).toEqual(["notes/sub/deep.md"]));
    folderButtons(root)[0]!.click();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(false));

    window.history.back();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(true));
    await vi.waitFor(() => expect(folderButtons(root).map((button) => button.dataset.path)).toEqual(["notes/sub/deep.md"]));

    window.history.back();
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));
    expect(folderButtons(root).map((button) => button.dataset.path)).toEqual(["notes/plan.md", "notes/sub/"]);
  });

  it("opens a subfolder instead of printing a stub", async () => {
    const root = mount(["read", "list"]);
    clickOpen(root);
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));

    folderButtons(root).find((button) => button.dataset.path === "notes/sub/")!.click();
    await vi.waitFor(() => expect(folderButtons(root).map((button) => button.dataset.path)).toEqual(["notes/sub/deep.md"]));
    expect(root.textContent).not.toContain("Nested folders are not part of this share.");
  });

  it("reports a denied folder page without losing the folder the recipient is standing in", async () => {
    const root = mount(["read", "list"]);
    clickOpen(root);
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));

    stub.respond = async () => new Response("{}", { status: 403 });
    folderButtons(root).find((button) => button.dataset.path === "notes/sub/")!.click();
    await vi.waitFor(() => expect(status(root).textContent).toBe(EXPECTED_FAILURE_COPY.denied));
    expect(folderButtons(root)).toHaveLength(2);
  });
});

describe("addressed viewer — HTML artifact selection", () => {
  beforeEach(() => {
    stub.establish = async () => ({ resource: { kind: "prefix", path: "shares/artifact" } });
  });

  function mountArtifact(): HTMLElement {
    const root = document.createElement("div");
    root.tabIndex = -1;
    document.body.append(root);
    mountPolicyV2Viewer(root, {
      envelope: {
        actions: ["read", "list"],
        shareId: "artifact-share",
        resource: { kind: "prefix", path: "shares/artifact" },
        metadata: { artifact: "html" },
      } as never,
      shareCid: "bafkreisharecid",
      policy: {},
    }, {
      nodeOrigin: "https://node.example",
      trustedNode: {} as never,
      holderDid: "did:key:z6Mkholder",
      buildPresentation: async () => ({}) as never,
      shareUrl: "https://share.tinycloud.xyz/s/example#secret",
    });
    return root;
  }

  it("loads every artifact file through verified native invokes and switches to the sandbox", async () => {
    stub.respond = async (request) => {
      const resource = request.resource as { readonly path: string };
      if (request.action === "list") {
        return listResponse(resource.path, [
          "shares/artifact/index.html",
          "shares/artifact/styles/site.css",
          "shares/artifact/assets/cloud.svg",
        ]);
      }
      if (resource.path.endsWith("index.html")) {
        return artifactGetResponse(resource.path, '<link rel="stylesheet" href="styles/site.css"><h1>Artifact</h1><img src="assets/cloud.svg">', "text/html");
      }
      if (resource.path.endsWith("site.css")) return artifactGetResponse(resource.path, "h1{color:navy}", "text/css");
      return artifactGetResponse(resource.path, "<svg xmlns=\"http://www.w3.org/2000/svg\"/>", "image/svg+xml");
    };
    const root = mountArtifact();
    clickOpen(root);
    await vi.waitFor(() => expect(document.querySelector<HTMLIFrameElement>(".viewer-artifact-frame")).not.toBeNull());
    const frame = document.querySelector<HTMLIFrameElement>(".viewer-artifact-frame")!;
    const nonce = new URL(frame.src).hash.slice(1);
    const post = vi.spyOn(frame.contentWindow!, "postMessage");
    window.dispatchEvent(new MessageEvent("message", { source: frame.contentWindow, origin: "null", data: { type: "ready", nonce } }));
    await vi.waitFor(() => expect(post).toHaveBeenCalledOnce());
    const request = post.mock.calls[0]![0] as { id: string };
    window.dispatchEvent(new MessageEvent("message", { source: frame.contentWindow, origin: "null", data: { type: "result", nonce, id: request.id, ok: true } }));

    await vi.waitFor(() => expect(document.body.classList.contains("artifact-active")).toBe(true));
    expect(frame.hidden).toBe(false);
    expect(root.querySelector<HTMLElement>(".viewer-policy-v2")?.hidden).toBe(true);
    expect(document.querySelector(".artifact-chrome")?.textContent).toContain("Shared with TinyCloud");
    expect(document.body.textContent).not.toContain("#secret");
    expect(stub.invokes.map((request) => request.action)).toEqual(["list", "get", "get", "get"]);

    window.dispatchEvent(new MessageEvent("message", { source: frame.contentWindow, origin: "null", data: { type: "result", nonce, id: request.id, ok: false } }));
    await vi.waitFor(() => expect(document.body.classList.contains("artifact-active")).toBe(false));
    expect(document.querySelector(".viewer-artifact-frame")).toBeNull();
    expect(root.querySelector<HTMLElement>(".viewer-policy-v2")?.hidden).toBe(false);
    expect(status(root).textContent).toBe("This HTML artifact uses a browser feature that TinyCloud cannot safely run.");
  });

  it("shows a deliberate missing-resource state without developer details", async () => {
    stub.respond = async (request) => {
      const resource = request.resource as { readonly path: string };
      if (request.action === "list") return listResponse(resource.path, ["shares/artifact/index.html"]);
      return artifactGetResponse(resource.path, '<img src="missing.png">', "text/html");
    };
    const root = mountArtifact();
    clickOpen(root);
    await vi.waitFor(() => expect(status(root).textContent).toBe("This HTML artifact is missing a required file. Ask the sender to share the complete folder."));
    expect(root.textContent).not.toContain("missing.png");
    expect(document.querySelector(".viewer-artifact-frame")).toBeNull();
  });
});

/**
 * TC-305 / TC-297. The previous version of this section installed a
 * `navigator.clipboard.writeText` that always RESOLVED, so the assertion only
 * ever covered the branch that hands the URL straight to the Clipboard API and
 * touches no DOM at all. The leak TC-297 had to fix lived in the *other*
 * branch — the `execCommand("copy")` fallback taken when the Clipboard API is
 * missing or refuses — which attached a `<textarea>` holding the complete share
 * URL (key fragment included) to `document.body`. Forcing the happy path is why
 * a security test could sit at this exact spot and miss it.
 *
 * These tests take the denied path deliberately, and observe the document
 * *while* the synchronous copy is in flight, since that is the only window in
 * which the leaked node was ever attached.
 */
describe("addressed viewer — Copy link takes the Clipboard-API-denied path", () => {
  const SECRET = `https://share.tinycloud.xyz/s/bafkreisharecid#k=${"A".repeat(43)}`;

  /**
   * Every way a live document can hold a string: serialized markup (text nodes
   * and attributes), attribute values, and the `value` PROPERTY of form
   * controls — which never appears in `outerHTML` and is exactly where the
   * TC-297 leak lived.
   */
  function exposuresOf(secret: string, when: string): string[] {
    const found: string[] = [];
    if (document.documentElement.outerHTML.includes(secret)) found.push(`${when}: serialized document`);
    for (const node of Array.from(document.querySelectorAll("*"))) {
      for (const attribute of Array.from(node.attributes)) {
        if (attribute.value.includes(secret)) found.push(`${when}: <${node.localName} ${attribute.name}>`);
      }
      const live = (node as unknown as { readonly value?: unknown }).value;
      if (typeof live === "string" && live.includes(secret)) found.push(`${when}: <${node.localName}>.value`);
    }
    if ((document.documentElement.textContent ?? "").includes(secret)) found.push(`${when}: text node`);
    return found;
  }

  /**
   * jsdom implements neither the Clipboard API nor `execCommand`, so the
   * fallback's engine call has to be supplied. The stand-in does only what a
   * real engine does: observe the document at the moment of the copy, deliver
   * whatever a `copy` handler substitutes, and report success.
   */
  function installEngineClipboard(succeeds: boolean): { readonly delivered: string[]; readonly exposures: string[]; readonly execCommand: ReturnType<typeof vi.fn> } {
    const delivered: string[] = [];
    const exposures: string[] = [];
    const execCommand = vi.fn((command: string) => {
      if (command !== "copy") return false;
      exposures.push(...exposuresOf(SECRET, "during the copy"));
      if (!succeeds) return false;
      const event = new Event("copy", { bubbles: true, cancelable: true });
      Object.defineProperty(event, "clipboardData", {
        value: { setData: (type: string, value: string) => { if (type === "text/plain") delivered.push(value); } },
      });
      document.dispatchEvent(event);
      return true;
    });
    Object.defineProperty(document, "execCommand", { configurable: true, writable: true, value: execCommand });
    return { delivered, exposures, execCommand };
  }

  function denyClipboardApi(): ReturnType<typeof vi.fn> {
    const writeText = vi.fn(async () => { throw new DOMException("Write permission denied.", "NotAllowedError"); });
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    return writeText;
  }

  function copyButton(root: HTMLElement): HTMLButtonElement {
    return Array.from(root.querySelectorAll<HTMLButtonElement>("button")).find((button) => button.textContent === "Copy link")!;
  }

  function copyStatus(root: HTMLElement): HTMLElement {
    return root.querySelector<HTMLElement>(".viewer-policy-copy-status")!;
  }

  afterEach(() => {
    Reflect.deleteProperty(navigator, "clipboard");
    Reflect.deleteProperty(document, "execCommand");
  });

  it("still delivers the complete URL when the Clipboard API refuses, without ever attaching it to the document", async () => {
    const writeText = denyClipboardApi();
    const engine = installEngineClipboard(true);

    const root = mount(["read"], SECRET);
    expect(copyButton(root).disabled).toBe(false);
    copyButton(root).click();

    await vi.waitFor(() => expect(copyStatus(root).textContent).toBe(EXPECTED_COPY_SUCCEEDED));
    // The denied branch is the one under test — prove it was actually taken.
    expect(writeText).toHaveBeenCalledWith(SECRET);
    expect(engine.execCommand).toHaveBeenCalledWith("copy");
    // The recipient's clipboard receives the whole secret, fragment included.
    expect(engine.delivered).toEqual([SECRET]);
    // …and the document never held it, at any point.
    expect(engine.exposures).toEqual([]);
    expect(exposuresOf(SECRET, "after the copy")).toEqual([]);
  });

  it("takes the same DOM-free path when the Clipboard API is absent entirely", async () => {
    const engine = installEngineClipboard(true);

    const root = mount(["read"], SECRET);
    copyButton(root).click();

    await vi.waitFor(() => expect(engine.delivered).toEqual([SECRET]));
    expect(engine.exposures).toEqual([]);
    expect(exposuresOf(SECRET, "after the copy")).toEqual([]);
    expect(copyStatus(root).textContent).toBe(EXPECTED_COPY_SUCCEEDED);
  });

  it("leaves no decoy or selection behind after the fallback runs", async () => {
    const engine = installEngineClipboard(true);
    const root = mount(["read"], SECRET);
    // Whatever the recipient had selected before pressing Copy must come back.
    const marker = document.createElement("p");
    marker.textContent = "recipient selection";
    document.body.append(marker);
    const range = document.createRange();
    range.selectNodeContents(marker);
    document.getSelection()?.removeAllRanges();
    document.getSelection()?.addRange(range);
    const before = document.body.childElementCount;

    copyButton(root).click();
    await vi.waitFor(() => expect(engine.delivered).toEqual([SECRET]));

    expect(document.body.childElementCount).toBe(before); // the decoy node is gone
    expect(document.getSelection()?.rangeCount).toBe(1);
    expect(document.getSelection()?.getRangeAt(0).startContainer).toBe(marker);
  });

  it("tells the recipient what to do when both clipboard paths refuse, and still leaks nothing", async () => {
    denyClipboardApi();
    const engine = installEngineClipboard(false);

    const root = mount(["read"], SECRET);
    copyButton(root).click();

    await vi.waitFor(() => expect(copyStatus(root).textContent).toBe(EXPECTED_COPY_FAILED));
    expect(copyStatus(root).getAttribute("role")).toBe("alert");
    expect(engine.delivered).toEqual([]);
    expect(engine.exposures).toEqual([]);
    expect(exposuresOf(SECRET, "after the failed copy")).toEqual([]);
  });

  it("copies through the Clipboard API when it is available, and still never renders the URL", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const root = mount(["read"], SECRET);
    copyButton(root).click();
    await vi.waitFor(() => expect(copyStatus(root).textContent).toBe(EXPECTED_COPY_SUCCEEDED));
    expect(writeText).toHaveBeenCalledWith(SECRET);
    expect(exposuresOf(SECRET, "after the copy")).toEqual([]);
  });

  it("offers no copy control at all when the viewer was never given the launch URL", () => {
    const root = mount(["read"]);
    expect(copyButton(root).disabled).toBe(true);
  });
});
