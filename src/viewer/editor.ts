export interface EditableDocument { readonly bytes: Uint8Array; readonly etag: string; readonly mediaType: string; }
export interface EditorSaveClient { save(bytes: Uint8Array, ifMatch: string): Promise<{ readonly etag: string }>; reload(): Promise<EditableDocument>; }
export type EditorState = "clean" | "dirty" | "saving" | "saved" | "conflict";

function isPreconditionConflict(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const value = error as { readonly code?: unknown; readonly status?: unknown; readonly response?: { readonly status?: unknown } };
  return value.code === "KV_PRECONDITION_FAILED" || value.code === "KV_CONFLICT" || value.status === 412 || value.response?.status === 412;
}

export class ShareEditor {
  private state: EditorState = "clean";
  private draft: Uint8Array;
  private etag: string;
  constructor(input: EditableDocument, private readonly client: EditorSaveClient) { this.draft = input.bytes.slice(); this.etag = input.etag; }
  get currentState(): EditorState { return this.state; }
  get value(): Uint8Array { return this.draft.slice(); }
  setDraft(bytes: Uint8Array): void { this.draft = bytes.slice(); this.state = "dirty"; }
  async save(): Promise<void> {
    this.state = "saving";
    try { const result = await this.client.save(this.draft.slice(), this.etag); this.etag = result.etag; this.state = "saved"; }
    catch (error) { this.state = isPreconditionConflict(error) ? "conflict" : "dirty"; throw error; }
  }
  async reload(): Promise<void> { const fresh = await this.client.reload(); this.draft = fresh.bytes.slice(); this.etag = fresh.etag; this.state = "clean"; }
}

export function canEdit(mediaType: string, actions: readonly string[]): boolean {
  const normalized = mediaType.split(";", 1)[0]?.toLowerCase() ?? "";
  return actions.includes("edit") && (normalized === "text/markdown" || normalized === "text/plain" || normalized === "text/csv" || normalized === "application/json");
}

export function mountTextEditor(root: HTMLElement, initial: EditableDocument, client: EditorSaveClient, copyText: (value: string) => Promise<void> = async (value) => { await navigator.clipboard.writeText(value); }): ShareEditor | null {
  if (!canEdit(initial.mediaType, ["edit"])) return null;
  let source: string;
  try { source = new TextDecoder("utf-8", { fatal: true }).decode(initial.bytes); } catch { return null; }
  const editor = new ShareEditor(initial, client); const doc = root.ownerDocument; root.replaceChildren();
  const heading = doc.createElement("h2"); heading.textContent = "Edit shared text";
  const area = doc.createElement("textarea"); area.className = "viewer-editor"; area.value = source; area.setAttribute("aria-label", "Shared text draft");
  const save = doc.createElement("button"); save.type = "button"; save.className = "viewer-primary-action viewer-editor-save"; save.textContent = "Save changes";
  const status = doc.createElement("p"); status.className = "viewer-editor-status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  const conflict = doc.createElement("div"); conflict.className = "viewer-editor-conflict"; conflict.hidden = true; const reload = doc.createElement("button"); reload.type = "button"; reload.className = "viewer-secondary-action"; reload.textContent = "Reload current version"; const copy = doc.createElement("button"); copy.type = "button"; copy.className = "viewer-secondary-action"; copy.textContent = "Copy my draft"; const conflictTitle = doc.createElement("strong"); conflict.append(conflictTitle, reload, copy); root.append(heading, area, save, status, conflict);
  area.addEventListener("input", () => editor.setDraft(new TextEncoder().encode(area.value)));
  save.addEventListener("click", () => { save.disabled = true; void editor.save().then(() => { status.textContent = "Saved."; }).catch((error) => { if (isPreconditionConflict(error)) { status.textContent = "This share changed elsewhere. Your draft is still here."; conflict.hidden = false; conflictTitle.textContent = "Save conflict — choose what to do next."; } else { status.textContent = "The save failed. Your draft is still here; no retry was made."; } }).finally(() => { save.disabled = false; }); });
  reload.addEventListener("click", () => { void editor.reload().then(() => { try { area.value = new TextDecoder("utf-8", { fatal: true }).decode(editor.value); } catch { status.textContent = "The current version is not editable text."; return; } conflict.hidden = true; status.textContent = "Reloaded current version."; }).catch(() => { status.textContent = "Reload failed. Your draft is still here."; }); });
  copy.addEventListener("click", () => { void copyText(area.value).then(() => { status.textContent = "Draft copied."; }).catch(() => { status.textContent = "Copy failed. Your draft is still here; select it manually."; }); });
  return editor;
}
