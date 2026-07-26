import { ShareRecipientClient, type PolicyChallenge, type PolicyPresentationMaterial } from "@tinycloud/share-sdk";
import type { TrustedNode } from "../email-share/protocol.js";
import { fromBase64Url, toBase64Url, type ShareEnvelopeV2 } from "@tinycloud/share-envelope";
import { digestBytes } from "../email-share/node-verifier.js";
import { renderSafeContent } from "./content.js";
import { mountTextEditor, canEdit, type EditableDocument } from "./editor.js";
import { normalizeFolderPage, renderFolder } from "./folder.js";
import { copyWithFallback } from "../share/link-only.js";

export interface PolicyV2ViewerOptions {
  readonly nodeOrigin: string;
  readonly trustedNode: TrustedNode;
  readonly holderDid: string;
  readonly buildPresentation: (input: { readonly challenge: PolicyChallenge; readonly envelope: ShareEnvelopeV2; readonly policy: Record<string, unknown> }) => Promise<PolicyPresentationMaterial | Record<string, unknown>>;
  readonly fetchFn?: typeof fetch;
  /** Complete launch URL kept in memory for the recipient's explicit copy action. */
  readonly shareUrl?: string;
}

function text(doc: Document, tag: keyof HTMLElementTagNameMap, className: string, value: string): HTMLElement {
  const node = doc.createElement(tag); node.className = className; node.textContent = value; return node;
}

async function nativePayload(response: Response, expectedAction: "get" | "list" | "put", expectedResource: string, expectedBodyDigest?: string, expectedContentType?: string): Promise<{ readonly value: Record<string, unknown>; readonly bytes?: Uint8Array; readonly mediaType?: string; readonly etag?: string }> {
  const contentType = response.headers.get("content-type");
  if (contentType !== null && !/^application\/json(?:\s*;|$)/i.test(contentType)) throw new Error("native response media type is invalid");
  const value = await response.json() as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("native response is invalid");
  const object = value as Record<string, unknown>;
  const action = expectedAction === "get" ? "tinycloud.kv/get" : expectedAction === "list" ? "tinycloud.kv/list" : "tinycloud.kv/put";
  const allowed = expectedAction === "get"
    ? ["type", "version", "action", "resource", "mediaType", "content", "bodyDigest", "etag"]
    : expectedAction === "list"
      ? ["type", "version", "action", "resource", "entries", "nextCursor"]
      : ["type", "version", "action", "resource", "etag", "bodyDigest", "contentType"];
  if (Object.keys(object).some((key) => !allowed.includes(key))) throw new Error("native response has unknown fields");
  const required = expectedAction === "get"
    ? ["type", "version", "action", "resource", "mediaType", "content", "bodyDigest", "etag"]
    : expectedAction === "list"
      ? ["type", "version", "action", "resource", "entries", "nextCursor"]
      : ["type", "version", "action", "resource", "etag", "bodyDigest", "contentType"];
  if (required.some((key) => !Object.hasOwn(object, key)) || object.type !== "TinyCloudShareInvokeResponse" || object.version !== 2 || object.action !== action || object.resource !== expectedResource) throw new Error("native response binding is invalid");
  if (expectedAction === "list") {
    if (!Array.isArray(object.entries) || (object.nextCursor !== null && typeof object.nextCursor !== "string")) throw new Error("native response entries are invalid");
    return { value: { entries: object.entries, nextCursor: object.nextCursor } };
  }
  if (typeof object.bodyDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(object.bodyDigest)) throw new Error("native response digest is invalid");
  if (expectedAction === "get") {
    if (typeof object.mediaType !== "string" || object.mediaType.length === 0 || object.mediaType.length > 128 || /[\u0000-\u001f\u007f]/.test(object.mediaType) || typeof object.content !== "string" || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+(?:\s*;\s*[^\u0000-\u001f\u007f]{1,96})?$/.test(object.mediaType)) throw new Error("native response content is invalid");
    let bytes: Uint8Array;
    try { bytes = fromBase64Url(object.content); } catch { throw new Error("native response content is invalid"); }
    if (toBase64Url(bytes) !== object.content || bytes.length > 100 * 1024 * 1024 || object.bodyDigest !== await digestBytes(bytes) || (object.etag !== null && typeof object.etag !== "string")) throw new Error("native response content binding is invalid");
    return { value: object, bytes, mediaType: object.mediaType, ...(typeof object.etag === "string" ? { etag: object.etag } : {}) };
  }
  if (typeof object.etag !== "string" || typeof object.contentType !== "string" || (expectedBodyDigest !== undefined && object.bodyDigest !== expectedBodyDigest) || (expectedContentType !== undefined && object.contentType !== expectedContentType)) throw new Error("native response put fields are invalid");
  return { value: object, etag: object.etag };
}

export function mountPolicyV2Viewer(root: HTMLElement, input: { readonly envelope: ShareEnvelopeV2; readonly shareCid: string; readonly policy: Record<string, unknown> }, options: PolicyV2ViewerOptions): void {
  const doc = root.ownerDocument;
  root.replaceChildren();
  const shell = doc.createElement("main"); shell.className = "viewer-state viewer-policy-v2";
  shell.append(text(doc, "h1", "viewer-state-title", "Verify access to this share"), text(doc, "p", "viewer-state-detail", "The link is intact. The next step proves the recipient claim and binds every read, list, or edit request to the verified Node session."));
  const open = doc.createElement("button"); open.type = "button"; open.className = "viewer-primary-action"; open.textContent = "Verify and open";
  const status = text(doc, "p", "viewer-policy-status", ""); status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  const copyStatus = text(doc, "span", "viewer-policy-copy-status", ""); copyStatus.setAttribute("role", "status"); copyStatus.setAttribute("aria-live", "polite");
  const copy = doc.createElement("button"); copy.type = "button"; copy.className = "viewer-secondary-action"; copy.textContent = "Copy link";
  copy.disabled = options.shareUrl === undefined;
  if (options.shareUrl !== undefined) copy.addEventListener("click", () => { void copyWithFallback(options.shareUrl!).then(() => { copyStatus.textContent = "Link copied."; }).catch(() => { copyStatus.setAttribute("role", "alert"); copyStatus.textContent = "Copy failed. Allow clipboard access and try again."; }); });
  const content = doc.createElement("section"); content.className = "viewer-content"; content.setAttribute("aria-live", "polite");
  shell.append(open, copy, copyStatus, status, content); root.append(shell);
  open.addEventListener("click", () => {
    open.disabled = true; status.textContent = "Checking the signed policy challenge…";
    void (async () => {
      const client = new ShareRecipientClient({ nodeOrigin: options.nodeOrigin, trustedNode: options.trustedNode, holderDid: options.holderDid, envelope: input.envelope, shareCid: input.shareCid, buildPresentation: options.buildPresentation, ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }) });
      const session = await client.establishPolicySession();
      status.textContent = "Verified session established.";
      // The session response narrows the first operation, while the signed
      // envelope remains the authority for the complete allowed action set.
      const actions = input.envelope.actions;
      const invoke = async (action: "list" | "get" | "put", resource: Record<string, unknown>, extra: Record<string, unknown> = {}): Promise<{ readonly response: Response; readonly payload: Awaited<ReturnType<typeof nativePayload>> }> => {
        const response = await client.nativeInvoke({ action, resource, ...extra });
        if (!response.ok) throw new Error(`native ${action} denied`);
        const body = Array.isArray(extra.body) ? Uint8Array.from(extra.body as number[]) : undefined;
        const bodyDigest = body === undefined ? undefined : await digestBytes(body);
        return { response, payload: await nativePayload(response, action, typeof resource.path === "string" ? resource.path : "", bodyDigest, typeof extra.contentType === "string" ? extra.contentType : undefined) };
      };
      const renderLoadedFile = async (path: string, bytes: Uint8Array, mediaType: string, etag: string): Promise<void> => {
        await renderSafeContent(content, bytes, { mediaType, filename: path.split("/").at(-1) ?? "shared-document", byteLength: bytes.byteLength });
        if (!actions.includes("edit") || etag === "" || !canEdit(mediaType, actions)) return;
        const editorRoot = doc.createElement("section"); editorRoot.className = "viewer-editor-panel"; content.append(editorRoot);
        const editable: EditableDocument = { bytes, etag, mediaType };
        mountTextEditor(editorRoot, editable, { save: async (next, ifMatch) => { const bodyDigest = await digestBytes(next); const saved = await client.nativeInvoke({ action: "put", resource: { kind: "exact", path }, body: Array.from(next), bodyDigest: Array.from(fromBase64Url(bodyDigest)), ifMatch, contentType: mediaType }); if (saved.status === 412) throw Object.assign(new Error("KV_PRECONDITION_FAILED"), { status: 412 }); if (!saved.ok) throw new Error("save denied"); const payload = await nativePayload(saved, "put", path, bodyDigest, mediaType); return { etag: payload.etag ?? saved.headers.get("etag") ?? "" }; }, reload: async () => { const fresh = await invoke("get", { kind: "exact", path }); const freshBytes = fresh.payload.bytes ?? new Uint8Array(await fresh.response.arrayBuffer()); return { bytes: freshBytes, etag: fresh.payload.etag ?? fresh.response.headers.get("etag") ?? "", mediaType: fresh.payload.mediaType ?? fresh.response.headers.get("content-type") ?? mediaType }; } });
      };
      if (actions.includes("list")) {
        const listed = await invoke("list", session.resource);
        const prefix = session.resource.kind === "prefix" ? session.resource.path : "";
        const renderPage = (page: ReturnType<typeof normalizeFolderPage>, path: string): void => renderFolder(content, page, path, 50, (nextPath, kind) => { const operation = kind === "file" ? "get" as const : "list" as const; void invoke(operation, kind === "file" ? { kind: "exact", path: nextPath } : { kind: "prefix", path: nextPath }, { limit: kind === "file" ? undefined : 50 }).then(async ({ response, payload }) => { if (kind === "file") { const bytes = payload.bytes ?? new Uint8Array(); await renderLoadedFile(nextPath, bytes, payload.mediaType ?? response.headers.get("content-type") ?? "application/octet-stream", payload.etag ?? response.headers.get("etag") ?? ""); } else renderPage(normalizeFolderPage(payload.value), nextPath); }).catch(() => { content.textContent = "This shared entry could not be opened."; }); }, (cursor) => { if (cursor === undefined) return; void invoke("list", { kind: "prefix", path }, { cursor, limit: 50 }).then(({ payload }) => renderPage(normalizeFolderPage(payload.value), path)).catch(() => { content.textContent = "The next folder page could not be loaded."; }); }, (parent) => { void invoke("list", { kind: "prefix", path: parent }, { limit: 50 }).then(({ payload }) => renderPage(normalizeFolderPage(payload.value), parent)).catch(() => { content.textContent = "This folder could not be opened."; }); });
        renderPage(normalizeFolderPage(listed.payload.value), prefix);
        return;
      }
      const loaded = await invoke("get", session.resource);
      const bytes = loaded.payload.bytes ?? new Uint8Array(await loaded.response.arrayBuffer());
      const mediaType = loaded.payload.mediaType ?? loaded.response.headers.get("content-type") ?? "application/octet-stream";
      const etag = loaded.payload.etag ?? loaded.response.headers.get("etag") ?? "";
      await renderLoadedFile(session.resource.path, bytes, mediaType, etag);
    })().catch((error) => { status.textContent = error instanceof Error ? error.message : "This share could not be opened."; open.disabled = false; });
  });
}
