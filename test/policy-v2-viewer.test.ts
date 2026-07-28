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

import { beforeEach, describe, expect, it, vi } from "vitest";

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

vi.mock("@tinycloud/share-sdk", () => ({
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
    await vi.waitFor(() => expect(status(root).textContent).toBe(RECIPIENT_FAILURE.denied));
    for (const raw of RAW_MESSAGES) expect(root.textContent).not.toContain(raw);
    expect(status(root).getAttribute("role")).toBe("alert");
  });

  it("maps a malformed node payload to the generic message", async () => {
    stub.respond = async () => new Response("not json", { status: 200, headers: { "content-type": "text/plain" } });
    const root = mount(["read"]);
    clickOpen(root);
    await vi.waitFor(() => expect(status(root).textContent).toBe(RECIPIENT_FAILURE.malformed));
    expect(root.textContent).not.toContain("media type is invalid");
  });

  it("maps a 412 to the conflict message and a dead connection to the offline message", async () => {
    stub.respond = async () => new Response("{}", { status: 412 });
    const conflict = mount(["read"]);
    clickOpen(conflict);
    await vi.waitFor(() => expect(status(conflict).textContent).toBe(RECIPIENT_FAILURE.conflict));

    stub.establish = async () => { throw new TypeError("Failed to fetch"); };
    const offline = mount(["read"]);
    clickOpen(offline);
    await vi.waitFor(() => expect(status(offline).textContent).toBe(RECIPIENT_FAILURE.offline));
  });

  it("classifies untagged failures conservatively and keeps the four messages jargon-free", () => {
    expect(recipientFailureKind(new Error("anything at all"))).toBe("malformed");
    expect(recipientFailureKind(new TypeError("Failed to fetch"))).toBe("offline");
    expect(recipientFailureKind(Object.assign(new Error("native list denied"), { kind: "denied" }))).toBe("denied");
    for (const message of Object.values(RECIPIENT_FAILURE)) {
      expect(message).not.toMatch(/native|delegation|capability|policy|envelope|KV|CID|registry/i);
    }
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

  it("pushes one history entry per navigation and restores the folder on Back", async () => {
    const root = mount(["read", "list"]);
    clickOpen(root);
    await vi.waitFor(() => expect(folderButtons(root)).toHaveLength(2));

    folderButtons(root).find((button) => button.dataset.path === "notes/plan.md")!.click();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(false));
    expect((window.history.state as { tinycloudShareView?: { kind?: string } } | null)?.tinycloudShareView?.kind).toBe("file");
    // the recorded position never puts anything about the share in the URL
    expect(window.location.href).not.toContain("plan.md");
    expect(window.location.hash).toBe("");

    window.dispatchEvent(new PopStateEvent("popstate", { state: { tinycloudShareView: { kind: "folder", path: "notes/" } } }));
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".viewer-file-panel")?.hidden).toBe(true));
    expect(folderButtons(root)).toHaveLength(2);
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
    await vi.waitFor(() => expect(status(root).textContent).toBe(RECIPIENT_FAILURE.denied));
    expect(folderButtons(root)).toHaveLength(2);
  });
});

describe("addressed viewer — Copy link", () => {
  const SECRET = `https://share.tinycloud.xyz/s/bafkreisharecid#k=${"A".repeat(43)}`;

  it("copies the complete in-memory URL and never renders it", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const root = mount(["read"], SECRET);
    const copy = Array.from(root.querySelectorAll<HTMLButtonElement>("button")).find((button) => button.textContent === "Copy link")!;
    expect(copy.disabled).toBe(false);
    copy.click();
    await vi.waitFor(() => expect(writeText).toHaveBeenCalledWith(SECRET));
    expect(root.textContent).not.toContain(SECRET);
    expect(Array.from(root.querySelectorAll("*")).every((node) => !Array.from(node.attributes).some((attribute) => attribute.value.includes(SECRET)))).toBe(true);
  });
});
