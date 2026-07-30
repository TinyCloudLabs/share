import { ShareRecipientClient, type PolicyChallenge, type PolicyPresentationMaterial } from "@tinycloud/share-app-compat";
import type { TrustedNode } from "../email-share/protocol.js";
import { fromBase64Url, toBase64Url, type ShareEnvelopeV2 } from "@tinycloud/share-envelope";
import { digestBytes } from "../email-share/node-verifier.js";
import { renderSafeContent } from "./content.js";
import { mountTextEditor, canEdit, type EditableDocument } from "./editor.js";
import { normalizeFolderPage, renderFolder } from "./folder.js";
import { copyWithFallback } from "../share/link-only.js";
import { focusViewerRoot } from "./focus.js";
import {
  ArtifactBundleError,
  MAX_ARTIFACT_FILES,
  canonicalArtifactPath,
  prepareHtmlArtifact,
  type ArtifactFile,
} from "../artifact/bundle.js";
import { createArtifactSandbox, type ArtifactSandbox } from "./artifact-sandbox.js";
import { mountArtifactChrome, type ArtifactChrome } from "./artifact-chrome.js";

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

/**
 * Recipient-facing failure vocabulary. The recipient NEVER sees `error.message`:
 * every throw below is tagged with one of these four kinds, and the raw text is
 * a developer detail that only reaches console.debug. An untagged throw (for
 * example from ShareRecipientClient) is classified conservatively.
 */
export type RecipientFailureKind = "denied" | "conflict" | "malformed" | "offline";

export const RECIPIENT_FAILURE: Record<RecipientFailureKind, string> = {
  denied: "You don't have access to this. Ask the sender to share it again.",
  conflict: "Someone else saved a change first. Reload to see the latest version.",
  malformed: "Something went wrong opening this. Ask the sender for a fresh link.",
  offline: "You appear to be offline. Reconnect and try again.",
};

export const ARTIFACT_FAILURE = {
  malformed: "This HTML artifact is malformed. Ask the sender to share a corrected bundle.",
  missing: "This HTML artifact is missing a required file. Ask the sender to share the complete folder.",
  unsupported: "This HTML artifact uses a browser feature that TinyCloud cannot safely run.",
  limit: "This HTML artifact is too large or complex to render safely.",
} as const;

function fail(kind: RecipientFailureKind, detail: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error(detail), { kind, ...extra });
}

export function recipientFailureKind(error: unknown): RecipientFailureKind {
  const tagged = (typeof error === "object" && error !== null ? (error as { readonly kind?: unknown }).kind : undefined);
  if (tagged === "denied" || tagged === "conflict" || tagged === "malformed" || tagged === "offline") return tagged;
  // A request that never reached the node rejects with TypeError and no
  // response; treat that (and an explicitly offline navigator) as offline.
  if (error instanceof TypeError) return "offline";
  if (typeof navigator === "object" && navigator !== null && navigator.onLine === false) return "offline";
  return "malformed";
}

export function recipientFailureMessage(error: unknown): string {
  return RECIPIENT_FAILURE[recipientFailureKind(error)];
}

export async function nativePayload(response: Response, expectedAction: "get" | "metadata" | "list" | "put", expectedResource: string, expectedBodyDigest?: string, expectedContentType?: string): Promise<{ readonly value: Record<string, unknown>; readonly bytes?: Uint8Array; readonly mediaType?: string; readonly metadata?: Record<string, string>; readonly etag?: string; readonly proof?: Record<string, unknown> }> {
  const contentType = response.headers.get("content-type");
  if (contentType !== null && !/^application\/json(?:\s*;|$)/i.test(contentType)) throw fail("malformed", "native response media type is invalid");
  const value = await response.json() as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw fail("malformed", "native response is invalid");
  const object = value as Record<string, unknown>;
  const action = expectedAction === "get" ? "tinycloud.kv/get" : expectedAction === "metadata" ? "tinycloud.kv/metadata" : expectedAction === "list" ? "tinycloud.kv/list" : "tinycloud.kv/put";
  const allowed = expectedAction === "get"
    ? ["type", "version", "action", "resource", "mediaType", "content", "bodyDigest", "etag", "proof"]
    : expectedAction === "metadata"
      ? ["type", "version", "action", "resource", "metadata", "etag", "proof"]
    : expectedAction === "list"
      ? ["type", "version", "action", "resource", "entries", "nextCursor"]
      : ["type", "version", "action", "resource", "etag", "bodyDigest", "contentType", "proof"];
  if (Object.keys(object).some((key) => !allowed.includes(key))) throw fail("malformed", "native response has unknown fields");
  const required = expectedAction === "get"
    ? ["type", "version", "action", "resource", "mediaType", "content", "bodyDigest", "etag"]
    : expectedAction === "metadata"
      ? ["type", "version", "action", "resource", "metadata", "etag"]
    : expectedAction === "list"
      ? ["type", "version", "action", "resource", "entries", "nextCursor"]
      : ["type", "version", "action", "resource", "etag", "bodyDigest", "contentType"];
  if (required.some((key) => !Object.hasOwn(object, key)) || object.type !== "TinyCloudShareInvokeResponse" || object.version !== 2 || object.action !== action || object.resource !== expectedResource) throw fail("malformed", "native response binding is invalid");
  if (expectedAction === "list") {
    if (!Array.isArray(object.entries) || (object.nextCursor !== null && typeof object.nextCursor !== "string")) throw fail("malformed", "native response entries are invalid");
    return { value: { entries: object.entries, nextCursor: object.nextCursor }, ...(isProof(object.proof) ? { proof: object.proof } : {}) };
  }
  if (expectedAction === "metadata") {
    if (typeof object.metadata !== "object" || object.metadata === null || Array.isArray(object.metadata) || Object.entries(object.metadata).some(([key, value]) => key.length === 0 || key.length > 128 || /[\u0000-\u001f\u007f]/.test(key) || typeof value !== "string" || value.length > 1024 || /[\u0000-\u001f\u007f]/.test(value)) || (object.etag !== null && typeof object.etag !== "string")) throw fail("malformed", "native response metadata is invalid");
    return { value: object, metadata: object.metadata as Record<string, string>, ...(typeof object.etag === "string" ? { etag: object.etag } : {}), ...(isProof(object.proof) ? { proof: object.proof } : {}) };
  }
  if (typeof object.bodyDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(object.bodyDigest)) throw fail("malformed", "native response digest is invalid");
  if (expectedAction === "get") {
    if (typeof object.mediaType !== "string" || object.mediaType.length === 0 || object.mediaType.length > 128 || /[\u0000-\u001f\u007f]/.test(object.mediaType) || typeof object.content !== "string" || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+(?:\s*;\s*[^\u0000-\u001f\u007f]{1,96})?$/.test(object.mediaType)) throw fail("malformed", "native response content is invalid");
    let bytes: Uint8Array;
    try { bytes = fromBase64Url(object.content); } catch { throw fail("malformed", "native response content is invalid"); }
    if (toBase64Url(bytes) !== object.content || bytes.length > 100 * 1024 * 1024 || object.bodyDigest !== await digestBytes(bytes) || (object.etag !== null && typeof object.etag !== "string")) throw fail("malformed", "native response content binding is invalid");
    return { value: object, bytes, mediaType: object.mediaType, ...(typeof object.etag === "string" ? { etag: object.etag } : {}), ...(isProof(object.proof) ? { proof: object.proof } : {}) };
  }
  if (typeof object.etag !== "string" || typeof object.contentType !== "string" || (expectedBodyDigest !== undefined && object.bodyDigest !== expectedBodyDigest) || (expectedContentType !== undefined && object.contentType !== expectedContentType)) throw fail("malformed", "native response put fields are invalid");
  return { value: object, etag: object.etag, ...(isProof(object.proof) ? { proof: object.proof } : {}) };
}

function isProof(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && typeof (value as Record<string, unknown>).alg === "string" && typeof (value as Record<string, unknown>).kid === "string" && typeof (value as Record<string, unknown>).signature === "string";
}

/** One recorded viewer position, restored on Back/Forward. */
type ShareView =
  | { readonly kind: "folder"; readonly path: string }
  | { readonly kind: "file"; readonly path: string; readonly parent: string };

const VIEW_STATE_KEY = "tinycloudShareView";

function readView(state: unknown): ShareView | undefined {
  if (typeof state !== "object" || state === null) return undefined;
  const view = (state as Record<string, unknown>)[VIEW_STATE_KEY];
  if (typeof view !== "object" || view === null) return undefined;
  const candidate = view as { readonly kind?: unknown; readonly path?: unknown; readonly parent?: unknown };
  if (typeof candidate.path !== "string") return undefined;
  if (candidate.kind === "folder") return { kind: "folder", path: candidate.path };
  if (candidate.kind === "file" && typeof candidate.parent === "string") return { kind: "file", path: candidate.path, parent: candidate.parent };
  return undefined;
}

/**
 * The address bar is deliberately key-free (email-share/url.ts scrubs `#k=`
 * before anything else runs), so a recorded position may never touch the URL.
 * `pathname` is what is already displayed; only the history STATE carries the
 * folder position, which keeps Back working without putting anything about the
 * share into history, referrers, or bookmarks.
 */
function recordView(history: History, location: Location, view: ShareView, replace = false): void {
  const state = { [VIEW_STATE_KEY]: view };
  if (replace) history.replaceState(state, "", location.pathname);
  else history.pushState(state, "", location.pathname);
}

function folderName(path: string): string {
  const name = path.replace(/\/+$/, "").split("/").at(-1);
  return name === undefined || name === "" ? "the shared folder" : name;
}

export function mountPolicyV2Viewer(root: HTMLElement, input: { readonly envelope: ShareEnvelopeV2; readonly shareCid: string; readonly policy: Record<string, unknown> }, options: PolicyV2ViewerOptions): void {
  const doc = root.ownerDocument;
  const view = doc.defaultView ?? window;
  root.replaceChildren();
  const shell = doc.createElement("main"); shell.className = "viewer-state viewer-policy-v2";
  shell.append(text(doc, "h1", "viewer-state-title", "Open this shared document"), text(doc, "p", "viewer-state-detail", "Confirm it's you, and this document will open."));
  const open = doc.createElement("button"); open.type = "button"; open.className = "viewer-primary-action"; open.textContent = "Verify and open";
  const status = text(doc, "p", "viewer-policy-status", ""); status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  const copyStatus = text(doc, "span", "viewer-policy-copy-status", ""); copyStatus.setAttribute("role", "status"); copyStatus.setAttribute("aria-live", "polite");
  const copy = doc.createElement("button"); copy.type = "button"; copy.className = "viewer-secondary-action"; copy.textContent = "Copy link";
  copy.disabled = options.shareUrl === undefined;
  if (options.shareUrl !== undefined) copy.addEventListener("click", () => { void copyWithFallback(options.shareUrl!).then(() => { copyStatus.removeAttribute("role"); copyStatus.textContent = "Link copied."; }).catch(() => { copyStatus.setAttribute("role", "alert"); copyStatus.textContent = "Copy failed. Allow clipboard access and try again."; }); });
  // The folder navigation and the opened file are SIBLINGS: opening a file must
  // never destroy the list the recipient came from (P0-5).
  const folderPanel = doc.createElement("nav"); folderPanel.className = "viewer-folder-panel"; folderPanel.hidden = true;
  const filePanel = doc.createElement("section"); filePanel.className = "viewer-file-panel"; filePanel.hidden = true;
  const fileBack = doc.createElement("button"); fileBack.type = "button"; fileBack.className = "viewer-secondary-action viewer-file-back"; fileBack.hidden = true;
  // No aria-live here: the shared document is not a status update, and marking
  // it live makes a screen reader read the whole file as one announcement.
  const content = doc.createElement("section"); content.className = "viewer-content";
  filePanel.append(fileBack, content);
  shell.append(open, copy, copyStatus, status, folderPanel, filePanel); root.append(shell);
  focusViewerRoot(root);

  let restore: ((position: ShareView) => void) | undefined;
  view.addEventListener("popstate", (event) => {
    const position = readView((event as PopStateEvent).state);
    if (position === undefined || restore === undefined) return;
    restore(position);
  });

  const showFailure = (error: unknown): void => {
    // Log only the bounded category. Raw exceptions can contain resource
    // paths, recipient details, or transport URLs and must not cross this
    // privacy boundary.
    console.debug("tinycloud share: recipient request failed", {
      kind: error instanceof ArtifactBundleError ? `artifact-${error.kind}` : recipientFailureKind(error),
    });
    status.setAttribute("role", "alert");
    status.textContent = error instanceof ArtifactBundleError ? ARTIFACT_FAILURE[error.kind] : recipientFailureMessage(error);
  };
  const showProgress = (message: string): void => {
    status.setAttribute("role", "status");
    status.textContent = message;
  };

  open.addEventListener("click", () => {
    open.disabled = true; showProgress("Checking…");
    void (async () => {
      const client = new ShareRecipientClient({ nodeOrigin: options.nodeOrigin, trustedNode: options.trustedNode, holderDid: options.holderDid, envelope: input.envelope, shareCid: input.shareCid, buildPresentation: options.buildPresentation, ...(options.fetchFn === undefined ? {} : { fetchFn: options.fetchFn }) });
      const session = await client.establishPolicySession();
      showProgress("Opening…");
      // The session response narrows the first operation, while the signed
      // envelope remains the authority for the complete allowed action set.
      const actions = input.envelope.actions;
      const invoke = async (action: "list" | "metadata" | "get" | "put", resource: Record<string, unknown>, extra: Record<string, unknown> = {}): Promise<{ readonly response: Response; readonly payload: Awaited<ReturnType<typeof nativePayload>> }> => {
        const response = await client.nativeInvoke({ action, resource, ...extra });
        if (!response.ok) throw fail(response.status === 412 ? "conflict" : "denied", `native ${action} denied`, { status: response.status });
        const body = Array.isArray(extra.body) ? Uint8Array.from(extra.body as number[]) : undefined;
        const bodyDigest = body === undefined ? undefined : await digestBytes(body);
        return { response, payload: await nativePayload(response, action, typeof resource.path === "string" ? resource.path : "", bodyDigest, typeof extra.contentType === "string" ? extra.contentType : undefined) };
      };
      if (input.envelope.metadata?.artifact === "html") {
        if (session.resource.kind !== "prefix" || input.envelope.resource.kind !== "prefix" || !actions.includes("read") || !actions.includes("list")) {
          throw new ArtifactBundleError("malformed", "artifact authority is not a readable prefix");
        }
        const rootPrefix = session.resource.path.replace(/\/+$/, "");
        if (rootPrefix.length === 0 || rootPrefix !== input.envelope.resource.path.replace(/\/+$/, "")) {
          throw new ArtifactBundleError("malformed", "artifact session resource does not match its envelope");
        }
        const prefix = `${rootPrefix}/`;
        const listedPaths = new Map<string, string>();
        const cursors = new Set<string>();
        let cursor: string | undefined;
        do {
          const { payload } = await invoke("list", { kind: "prefix", path: rootPrefix }, { limit: MAX_ARTIFACT_FILES, ...(cursor === undefined ? {} : { cursor }) });
          const page = normalizeFolderPage(payload.value);
          for (const entry of page.entries) {
            if (entry.kind === "folder") continue;
            if (!entry.path.startsWith(prefix)) throw new ArtifactBundleError("malformed", "artifact listing escaped its prefix");
            const relative = canonicalArtifactPath(entry.path.slice(prefix.length));
            const collisionKey = relative.toLowerCase();
            if (listedPaths.has(collisionKey)) throw new ArtifactBundleError("malformed", "artifact listing contains colliding paths");
            listedPaths.set(collisionKey, relative);
            if (listedPaths.size > MAX_ARTIFACT_FILES) throw new ArtifactBundleError("limit", "artifact file count exceeds its limit");
          }
          cursor = page.nextCursor;
          if (cursor !== undefined && (cursor.length === 0 || cursors.has(cursor))) {
            throw new ArtifactBundleError("malformed", "artifact listing cursor is invalid");
          }
          if (cursor !== undefined) cursors.add(cursor);
        } while (cursor !== undefined);
        const files: ArtifactFile[] = [];
        for (const relative of listedPaths.values()) {
          const path = `${prefix}${relative}`;
          const { response, payload } = await invoke("get", { kind: "exact", path });
          files.push({
            path: relative,
            bytes: payload.bytes ?? new Uint8Array(),
            mediaType: payload.mediaType ?? response.headers.get("content-type") ?? "application/octet-stream",
          });
        }
        const artifact = await prepareHtmlArtifact(files);
        let chrome: ArtifactChrome | undefined;
        let sandbox: ArtifactSandbox;
        const runtimeFailure = (): void => {
          sandbox.destroy();
          chrome?.destroy();
          doc.body.classList.remove("artifact-active");
          shell.hidden = false;
          status.setAttribute("role", "alert");
          status.textContent = ARTIFACT_FAILURE.unsupported;
          open.disabled = false;
        };
        sandbox = createArtifactSandbox(doc, { onFailure: runtimeFailure });
        try {
          await sandbox.render(artifact);
          shell.hidden = true;
          sandbox.iframe.hidden = false;
          doc.body.classList.add("artifact-active");
          chrome = await mountArtifactChrome(doc, {
            shareId: input.envelope.shareId,
            ...(options.shareUrl === undefined ? {} : { shareUrl: options.shareUrl }),
          });
          showProgress("");
          return;
        } catch (error) {
          sandbox.destroy();
          throw error instanceof ArtifactBundleError ? error : new ArtifactBundleError("malformed", "artifact sandbox failed");
        }
      }
      const renderLoadedFile = async (path: string, bytes: Uint8Array, mediaType: string, etag: string): Promise<void> => {
        await renderSafeContent(content, bytes, { mediaType, filename: path.split("/").at(-1) ?? "shared-document", byteLength: bytes.byteLength });
        if (!actions.includes("edit") || etag === "" || !canEdit(mediaType, actions)) return;
        const editorRoot = doc.createElement("section"); editorRoot.className = "viewer-editor-panel"; content.append(editorRoot);
        const editable: EditableDocument = { bytes, etag, mediaType };
        mountTextEditor(editorRoot, editable, { save: async (next, ifMatch) => { const bodyDigest = await digestBytes(next); const saved = await client.nativeInvoke({ action: "put", resource: { kind: "exact", path }, body: Array.from(next), bodyDigest: Array.from(fromBase64Url(bodyDigest)), ifMatch, contentType: mediaType }); if (saved.status === 412) throw fail("conflict", "KV_PRECONDITION_FAILED", { status: 412 }); if (!saved.ok) throw fail("denied", "save denied", { status: saved.status }); const payload = await nativePayload(saved, "put", path, bodyDigest, mediaType); return { etag: payload.etag ?? saved.headers.get("etag") ?? "" }; }, reload: async () => { const fresh = await invoke("get", { kind: "exact", path }); const freshBytes = fresh.payload.bytes ?? new Uint8Array(await fresh.response.arrayBuffer()); return { bytes: freshBytes, etag: fresh.payload.etag ?? fresh.response.headers.get("etag") ?? "", mediaType: fresh.payload.mediaType ?? fresh.response.headers.get("content-type") ?? mediaType }; } });
      };
      if (actions.includes("list")) {
        const rootPrefix = session.resource.kind === "prefix" ? session.resource.path : "";
        let currentFolder = rootPrefix;
        const hideFile = (): void => { fileBack.hidden = true; filePanel.hidden = true; content.replaceChildren(); };
        const loadFolder = async (path: string, record = true, extra: Record<string, unknown> = {}): Promise<void> => {
          const { payload } = await invoke("list", { kind: "prefix", path }, { limit: 50, ...extra });
          currentFolder = path;
          hideFile();
          folderPanel.hidden = false;
          renderFolder(folderPanel, normalizeFolderPage(payload.value), path, 50, navigate, nextPage, goToParent);
          showProgress("");
          if (record) recordView(view.history, view.location, { kind: "folder", path });
        };
        const loadFile = async (path: string, parent: string, record = true): Promise<void> => {
          const { response, payload } = await invoke("get", { kind: "exact", path });
          const bytes = payload.bytes ?? new Uint8Array();
          fileBack.textContent = `← ${folderName(parent)}`;
          fileBack.hidden = false;
          filePanel.hidden = false;
          await renderLoadedFile(path, bytes, payload.mediaType ?? response.headers.get("content-type") ?? "application/octet-stream", payload.etag ?? response.headers.get("etag") ?? "");
          showProgress("");
          if (record) recordView(view.history, view.location, { kind: "file", path, parent });
          fileBack.focus();
        };
        function navigate(nextPath: string, kind: "file" | "folder"): void {
          if (kind === "folder") { void loadFolder(nextPath).catch(showFailure); return; }
          void loadFile(nextPath, currentFolder).catch(showFailure);
        }
        function nextPage(cursor: string | undefined): void {
          if (cursor === undefined) return;
          void loadFolder(currentFolder, true, { cursor }).catch(showFailure);
        }
        function goToParent(parent: string): void { void loadFolder(parent).catch(showFailure); }
        restore = (position): void => {
          if (position.kind === "file") { void loadFile(position.path, position.parent, false).catch(showFailure); return; }
          void loadFolder(position.path, false).catch(showFailure);
        };
        fileBack.addEventListener("click", () => { view.history.back(); });
        await loadFolder(rootPrefix, false);
        recordView(view.history, view.location, { kind: "folder", path: rootPrefix }, true);
        return;
      }
      const metadataResult = await invoke("metadata", session.resource);
      const loaded = await invoke("get", session.resource);
      const bytes = loaded.payload.bytes ?? new Uint8Array(await loaded.response.arrayBuffer());
      const mediaType = loaded.payload.mediaType ?? metadataResult.payload.metadata?.["content-type"] ?? loaded.response.headers.get("content-type") ?? "application/octet-stream";
      const etag = loaded.payload.etag ?? metadataResult.payload.etag ?? loaded.response.headers.get("etag") ?? "";
      filePanel.hidden = false;
      await renderLoadedFile(session.resource.path, bytes, mediaType, etag);
      showProgress("");
    })().catch((error) => { showFailure(error); open.disabled = false; });
  });
}
