export interface FolderEntry { readonly path: string; readonly kind: "file" | "folder"; }

export function directChildren(entries: readonly FolderEntry[], prefix: string): readonly FolderEntry[] {
  const normalized = prefix === "" || prefix.endsWith("/") ? prefix : `${prefix}/`;
  const children = new Map<string, FolderEntry>();
  for (const entry of entries) {
    if (!entry.path.startsWith(normalized) || entry.path === normalized) continue;
    const rest = entry.path.slice(normalized.length);
    const slash = rest.indexOf("/");
    const child = slash === -1 ? rest : rest.slice(0, slash);
    if (child.length === 0) continue;
    const path = `${normalized}${child}`;
    children.set(path, { path, kind: slash === -1 ? entry.kind : "folder" });
  }
  return [...children.values()].sort((a, b) => a.path.localeCompare(b.path));
}

export interface FolderPage {
  readonly entries: readonly FolderEntry[];
  readonly nextCursor?: string;
}

/** Canonical native `/invoke` list response, kept at the viewer boundary. */
export interface NativeFolderPage {
  readonly paths: readonly (string | { readonly path: string; readonly kind?: "file" | "folder" })[];
  readonly nextCursor?: string | null;
}

export function normalizeFolderPage(value: unknown): FolderPage {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("folder response is invalid");
  const record = value as Record<string, unknown>;
  const raw = Array.isArray(record.entries) ? record.entries : Array.isArray(record.paths) ? record.paths : undefined;
  if (raw === undefined) throw new Error("folder response is invalid");
  const entries = raw.map((entry): FolderEntry => {
    if (typeof entry === "string") return { path: entry, kind: "file" };
    if (typeof entry !== "object" || entry === null || Array.isArray(entry) || typeof (entry as Record<string, unknown>).path !== "string") throw new Error("folder entry is invalid");
    const item = entry as Record<string, unknown>;
    return { path: item.path as string, kind: item.kind === "folder" ? "folder" : "file" };
  });
  return { entries, ...(typeof record.nextCursor === "string" ? { nextCursor: record.nextCursor } : {}) };
}

export function renderFolder(container: HTMLElement, page: readonly FolderEntry[] | FolderPage, prefix: string, pageSize = 50, onNavigate?: (path: string) => void, onPage?: (cursor: string | undefined) => void, onBack?: (path: string) => void): void {
  const doc = container.ownerDocument; const isPage = !Array.isArray(page); const entries: readonly FolderEntry[] = isPage ? (page as FolderPage).entries : (page as readonly FolderEntry[]); const children = (isPage ? entries : directChildren(entries, prefix)).slice(0, pageSize); container.replaceChildren();
  const nav = doc.createElement("nav"); nav.className = "viewer-folder"; nav.setAttribute("aria-label", "Shared folder");
  if (prefix !== "") { const back = doc.createElement("button"); back.type = "button"; back.className = "viewer-secondary-action viewer-folder-back"; back.textContent = "Back"; const parent = prefix.replace(/\/$/, "").split("/").slice(0, -1).join("/"); back.addEventListener("click", () => onBack?.(parent.length === 0 ? "" : `${parent}/`)); nav.append(back); }
  const crumb = doc.createElement("p"); crumb.className = "viewer-breadcrumb"; crumb.textContent = prefix === "" ? "Shared folder" : `Shared folder / ${prefix.replace(/\/$/, "")}`; nav.append(crumb);
  const list = doc.createElement("ul"); list.className = "viewer-folder-list"; for (const child of children) { const item = doc.createElement("li"); const button = doc.createElement("button"); button.type = "button"; button.className = "viewer-folder-entry"; button.dataset.path = child.path; button.textContent = child.kind === "folder" ? `▸ ${child.path.split("/").at(-1) ?? child.path}` : child.path.split("/").at(-1) ?? child.path; button.addEventListener("click", () => onNavigate?.(child.kind === "folder" ? `${child.path}/` : child.path)); item.append(button); list.append(item); } nav.append(list);
  const nextCursor = isPage ? (page as FolderPage).nextCursor : undefined;
  if (nextCursor !== undefined) { const next = doc.createElement("button"); next.type = "button"; next.className = "viewer-secondary-action viewer-folder-next"; next.textContent = "Next page"; next.addEventListener("click", () => onPage?.(nextCursor)); nav.append(next); }
  container.append(nav);
}
