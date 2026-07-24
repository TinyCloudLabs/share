import { ShareRecipientClient, type PolicyChallenge, type PolicyPresentationMaterial } from "@tinycloud/share-sdk";
import type { TrustedNode } from "../email-share/protocol.js";
import { fromBase64Url, type ShareEnvelopeV2 } from "@tinycloud/share-envelope";
import { renderSafeContent } from "./content.js";
import { mountTextEditor, canEdit, type EditableDocument } from "./editor.js";
import { normalizeFolderPage, renderFolder } from "./folder.js";

export interface PolicyV2ViewerOptions {
  readonly nodeOrigin: string;
  readonly trustedNode: TrustedNode;
  readonly holderDid: string;
  readonly buildPresentation: (input: { readonly challenge: PolicyChallenge; readonly envelope: ShareEnvelopeV2; readonly policy: Record<string, unknown> }) => Promise<PolicyPresentationMaterial | Record<string, unknown>>;
  readonly fetchFn?: typeof fetch;
}

function text(doc: Document, tag: keyof HTMLElementTagNameMap, className: string, value: string): HTMLElement {
  const node = doc.createElement(tag); node.className = className; node.textContent = value; return node;
}

async function nativePayload(response: Response): Promise<{ readonly value: Record<string, unknown>; readonly bytes?: Uint8Array; readonly mediaType?: string; readonly etag?: string }> {
  const value = await response.json() as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("native response is invalid");
  const object = value as Record<string, unknown>;
  const bytes = typeof object.content === "string" ? fromBase64Url(object.content) : undefined;
  return { value: object, ...(bytes === undefined ? {} : { bytes }), ...(typeof object.mediaType === "string" ? { mediaType: object.mediaType } : {}), ...(typeof object.etag === "string" ? { etag: object.etag } : {}) };
}

export function mountPolicyV2Viewer(root: HTMLElement, input: { readonly envelope: ShareEnvelopeV2; readonly shareCid: string; readonly policy: Record<string, unknown> }, options: PolicyV2ViewerOptions): void {
  const doc = root.ownerDocument;
  root.replaceChildren();
  const shell = doc.createElement("main"); shell.className = "viewer-state viewer-policy-v2";
  shell.append(text(doc, "h1", "viewer-state-title", "Verify access to this share"), text(doc, "p", "viewer-state-detail", "The link is intact. The next step proves the recipient claim and binds every read, list, or edit request to the verified Node session."));
  const open = doc.createElement("button"); open.type = "button"; open.className = "viewer-primary-action"; open.textContent = "Verify and open";
  const status = text(doc, "p", "viewer-policy-status", ""); status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  const content = doc.createElement("section"); content.className = "viewer-content"; content.setAttribute("aria-live", "polite");
  shell.append(open, status, content); root.append(shell);
  open.addEventListener("click", () => {
    open.disabled = true; status.textContent = "Checking the signed policy challenge…";
    void (async () => {
      const client = new ShareRecipientClient({ nodeOrigin: options.nodeOrigin, trustedNode: options.trustedNode, holderDid: options.holderDid, envelope: input.envelope, shareCid: input.shareCid, buildPresentation: options.buildPresentation, ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }) });
      const session = await client.establishPolicySession();
      status.textContent = "Verified session established.";
      const actions = session.actions;
      const invoke = async (action: "list" | "get" | "put", resource: Record<string, unknown>): Promise<{ readonly response: Response; readonly payload: Awaited<ReturnType<typeof nativePayload>> }> => {
        const response = await client.nativeInvoke({ action, resource });
        if (!response.ok) throw new Error(`native ${action} denied`);
        return { response, payload: await nativePayload(response) };
      };
      if (actions.includes("list")) {
        const listed = await invoke("list", session.resource);
        const prefix = session.resource.kind === "prefix" ? session.resource.path : "";
        const renderPage = (page: ReturnType<typeof normalizeFolderPage>, path: string): void => renderFolder(content, page, path, 50, (nextPath) => { void invoke("list", { kind: "prefix", path: nextPath }).then(({ payload }) => renderPage(normalizeFolderPage(payload.value), nextPath)).catch(() => { content.textContent = "This folder could not be opened."; }); }, (cursor) => { if (cursor === undefined) return; void invoke("list", { kind: "prefix", path, cursor }).then(({ payload }) => renderPage(normalizeFolderPage(payload.value), path)).catch(() => { content.textContent = "The next folder page could not be loaded."; }); }, (parent) => { void invoke("list", { kind: "prefix", path: parent }).then(({ payload }) => renderPage(normalizeFolderPage(payload.value), parent)).catch(() => { content.textContent = "This folder could not be opened."; }); });
        renderPage(normalizeFolderPage(listed.payload.value), prefix);
        return;
      }
      const loaded = await invoke("get", session.resource);
      const bytes = loaded.payload.bytes ?? new Uint8Array(await loaded.response.arrayBuffer());
      const mediaType = loaded.payload.mediaType ?? loaded.response.headers.get("content-type") ?? "application/octet-stream";
      const etag = loaded.payload.etag ?? loaded.response.headers.get("etag") ?? "";
      await renderSafeContent(content, bytes, { mediaType, filename: input.envelope.metadata.filename ?? "shared-document", byteLength: bytes.byteLength });
      if (actions.includes("edit") && etag !== "" && canEdit(mediaType, actions)) {
        const editorRoot = doc.createElement("section"); editorRoot.className = "viewer-editor-panel"; content.append(editorRoot);
        const editable: EditableDocument = { bytes, etag, mediaType };
        mountTextEditor(editorRoot, editable, { save: async (next, ifMatch) => { const saved = await client.nativeInvoke({ action: "put", resource: session.resource, body: Array.from(next), bodyDigest: await crypto.subtle.digest("SHA-256", next.buffer.slice(next.byteOffset, next.byteOffset + next.byteLength) as ArrayBuffer).then((digest) => Array.from(new Uint8Array(digest))), ifMatch, contentType: mediaType }); if (saved.status === 412) throw Object.assign(new Error("KV_PRECONDITION_FAILED"), { status: 412 }); if (!saved.ok) throw new Error("save denied"); const payload = await nativePayload(saved); return { etag: payload.etag ?? saved.headers.get("etag") ?? "" }; }, reload: async () => { const fresh = await invoke("get", session.resource); const freshBytes = fresh.payload.bytes ?? new Uint8Array(await fresh.response.arrayBuffer()); return { bytes: freshBytes, etag: fresh.payload.etag ?? fresh.response.headers.get("etag") ?? "", mediaType: fresh.payload.mediaType ?? fresh.response.headers.get("content-type") ?? mediaType }; } });
      }
    })().catch((error) => { status.textContent = error instanceof Error ? error.message : "This share could not be opened."; open.disabled = false; });
  });
}
