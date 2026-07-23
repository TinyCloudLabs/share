import {
  MAX_CONTENT_BYTES,
  createBearerShare,
  type CreateBearerShareResult,
} from "@tinycloud/share-cli";
import {
  CidMismatchError,
  RegistryHttpError,
} from "@tinycloud/share-registry";

const LINK_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const AUTHENTICATED_REGISTRY_PATH = "/api/share/link-only/registry";

export type CreateShare = (options: {
  readonly content: Uint8Array;
  readonly filename: string;
  readonly registryBaseUrl: string;
  readonly expiresAt: Date;
  readonly viewerOrigin: string;
  readonly fetchFn: typeof globalThis.fetch;
}) => Promise<CreateBearerShareResult>;

export type LinkOnlyFailureKind =
  | "authentication"
  | "file"
  | "storage"
  | "encryption";

export class LinkOnlyShareError extends Error {
  constructor(
    readonly kind: LinkOnlyFailureKind,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "LinkOnlyShareError";
  }
}

export interface CreateLinkOnlyShareOptions {
  readonly origin: string;
  readonly now?: () => number;
  readonly createShare?: CreateShare;
  readonly fetchFn?: typeof globalThis.fetch;
}

export interface LinkOnlyMountOptions extends CreateLinkOnlyShareOptions {
  readonly openKeyAddress: string;
  readonly copyText?: (value: string) => Promise<void>;
}

function element<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  className: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formattedSize(size: number): string {
  if (size < 1024) return `${size} B`;
  return `${(size / 1024).toFixed(1)} KB`;
}

function readFileBytes(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      if (!(reader.result instanceof ArrayBuffer)) {
        reject(new Error("file did not produce bytes"));
        return;
      }
      resolve(new Uint8Array(reader.result));
    });
    reader.addEventListener("error", () => {
      reject(reader.error ?? new Error("file could not be read"));
    });
    reader.readAsArrayBuffer(file);
  });
}

async function validateFile(file: File): Promise<Uint8Array> {
  if (file.size === 0) {
    throw new LinkOnlyShareError("file", "Choose a non-empty text or Markdown file.");
  }
  if (file.size > MAX_CONTENT_BYTES) {
    throw new LinkOnlyShareError("file", "Choose a text or Markdown file smaller than 64 KB.");
  }
  if (!/\.(?:md|markdown|txt)$/i.test(file.name)) {
    throw new LinkOnlyShareError("file", "Choose a .txt, .md, or .markdown file.");
  }
  let bytes: Uint8Array;
  try {
    bytes = await readFileBytes(file);
  } catch (error) {
    throw new LinkOnlyShareError(
      "file",
      "This file could not be read. Choose it again and retry.",
      { cause: error },
    );
  }
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new LinkOnlyShareError(
      "file",
      "This file is not valid UTF-8 text. Choose a text or Markdown file.",
      { cause: error },
    );
  }
  return bytes;
}

function authenticatedFetch(
  fetchFn: typeof globalThis.fetch,
): typeof globalThis.fetch {
  return async (input, init) => {
    let response: Response;
    try {
      response = await fetchFn(input, {
        ...init,
        credentials: "include",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    } catch (error) {
      throw new LinkOnlyShareError(
        "storage",
        "The encrypted file could not reach TinyCloud storage. Check your connection and try again.",
        { cause: error },
      );
    }
    if (response.status === 401 || response.status === 403) {
      throw new LinkOnlyShareError(
        "authentication",
        "Your OpenKey session expired. Reload this page and sign in again.",
      );
    }
    return response;
  };
}

export async function createLinkOnlyShare(
  file: File,
  options: CreateLinkOnlyShareOptions,
): Promise<CreateBearerShareResult> {
  const content = await validateFile(file);
  const now = options.now?.() ?? Date.now();
  const create = options.createShare ?? createBearerShare;
  const fetchFn = authenticatedFetch(options.fetchFn ?? globalThis.fetch);
  try {
    return await create({
      content,
      filename: file.name,
      registryBaseUrl: `${options.origin}${AUTHENTICATED_REGISTRY_PATH}`,
      expiresAt: new Date(now + LINK_LIFETIME_MS),
      viewerOrigin: options.origin,
      fetchFn,
    });
  } catch (error) {
    if (error instanceof LinkOnlyShareError) throw error;
    if (error instanceof RegistryHttpError || error instanceof CidMismatchError) {
      throw new LinkOnlyShareError(
        "storage",
        "TinyCloud storage did not accept the encrypted file. Try again in a moment.",
        { cause: error },
      );
    }
    throw new LinkOnlyShareError(
      "encryption",
      "This browser could not encrypt the file. Nothing was uploaded; try again in a current browser.",
      { cause: error },
    );
  }
}

export async function copyWithFallback(value: string): Promise<void> {
  if (navigator.clipboard?.writeText !== undefined) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Clipboard permissions vary across browsers and embedded contexts.
      // Fall through to the selection-based copy path.
    }
  }
  const field = document.createElement("textarea");
  field.value = value;
  field.readOnly = true;
  field.setAttribute("aria-hidden", "true");
  Object.assign(field.style, {
    position: "fixed",
    inset: "0 auto auto -9999px",
    opacity: "0",
    pointerEvents: "none",
  });
  document.body.append(field);
  try {
    field.focus();
    field.select();
    field.setSelectionRange(0, field.value.length);
    if (!document.execCommand("copy")) throw new Error("clipboard unavailable");
  } finally {
    field.remove();
  }
}

function errorCopy(error: unknown): { kind: LinkOnlyFailureKind; message: string } {
  if (error instanceof LinkOnlyShareError) {
    return { kind: error.kind, message: error.message };
  }
  return {
    kind: "encryption",
    message: "The share could not be created. Nothing was sent; try again.",
  };
}

export function mountLinkOnlyShare(
  root: HTMLElement,
  options: LinkOnlyMountOptions,
): void {
  const doc = root.ownerDocument;
  const copyText = options.copyText ?? copyWithFallback;
  root.removeAttribute("aria-busy");
  root.replaceChildren();

  const shell = element(doc, "main", "sender-shell");
  const header = element(doc, "header", "sender-header");
  header.append(
    element(
      doc,
      "p",
      "sender-kicker",
      `OpenKey connected · ${options.openKeyAddress.slice(0, 6)}…${options.openKeyAddress.slice(-4)}`,
    ),
    element(doc, "h1", "sender-title", "Share one file."),
    element(
      doc,
      "p",
      "sender-lede",
      "Your browser encrypts the file, then creates a private link. Anyone with the complete link can open it.",
    ),
  );

  const form = element(doc, "form", "sender-form link-only-form");
  form.noValidate = true;
  const progress = element(doc, "ol", "share-progress");
  progress.setAttribute("aria-label", "Sharing steps");
  for (const [number, label, state] of [
    ["01", "Signed in", "complete"],
    ["02", "Choose file", "current"],
    ["03", "Copy link", "upcoming"],
  ] as const) {
    const item = element(doc, "li", "");
    item.dataset.state = state;
    item.append(element(doc, "span", "", number), doc.createTextNode(label));
    progress.append(item);
  }

  const fileLabel = element(doc, "label", "upload-field");
  const fileTitle = element(doc, "strong", "upload-title", "Choose one file");
  const fileHelp = element(
    doc,
    "span",
    "upload-help",
    "Text or Markdown · smaller than 64 KB",
  );
  const fileInput = element(doc, "input", "upload-input");
  fileInput.type = "file";
  fileInput.name = "document";
  fileInput.accept = ".md,.markdown,.txt,text/markdown,text/plain";
  fileInput.required = true;
  const fileMeta = element(doc, "span", "upload-meta", "No file selected");
  fileLabel.append(fileTitle, fileHelp, fileInput, fileMeta);

  const possessionNote = element(
    doc,
    "p",
    "scope-note possession-note",
    "Keep the complete link private. It includes the key needed to decrypt this read-only copy and expires in 7 days.",
  );

  const notifyRow = element(doc, "div", "notify-row");
  const notify = element(doc, "input", "notify-checkbox");
  notify.id = "notify-by-email";
  notify.type = "checkbox";
  notify.name = "notify-by-email";
  notify.checked = false;
  notify.disabled = true;
  notify.setAttribute("aria-describedby", "notify-by-email-help");
  const notifyCopy = element(doc, "div", "notify-copy");
  const notifyLabel = element(doc, "label", "notify-label", "Notify by email");
  notifyLabel.htmlFor = notify.id;
  const notifyHelp = element(
    doc,
    "p",
    "notify-help",
    "Coming soon. Create and send the link yourself for now.",
  );
  notifyHelp.id = "notify-by-email-help";
  notifyCopy.append(notifyLabel, notifyHelp);
  notifyRow.append(notify, notifyCopy);

  const submit = element(
    doc,
    "button",
    "button button-primary create-link-button",
    "Create private link",
  );
  submit.type = "submit";
  const status = element(doc, "div", "sender-status");
  status.dataset.linkStatus = "true";
  status.setAttribute("aria-live", "polite");
  status.setAttribute("aria-atomic", "true");
  form.append(progress, fileLabel, possessionNote, notifyRow, submit, status);
  shell.append(header, form);
  root.append(shell);

  const reset = (): void => {
    form.reset();
    notify.checked = false;
    fileLabel.hidden = false;
    possessionNote.hidden = false;
    notifyRow.hidden = false;
    submit.hidden = false;
    fileLabel.dataset.selected = "false";
    fileMeta.textContent = "No file selected";
    status.replaceChildren();
    delete status.dataset.state;
    submit.disabled = false;
    progress.children[1]?.setAttribute("data-state", "current");
    progress.children[2]?.setAttribute("data-state", "upcoming");
    fileInput.focus();
  };

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    fileLabel.dataset.selected = String(file !== undefined);
    fileMeta.textContent =
      file === undefined
        ? "No file selected"
        : `${file.name} · ${formattedSize(file.size)}`;
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      const file = fileInput.files?.[0];
      if (file === undefined) {
        status.dataset.state = "error-file";
        status.setAttribute("role", "alert");
        status.replaceChildren(
          element(doc, "strong", "sender-status-title", "Choose a file"),
          element(
            doc,
            "span",
            "sender-status-detail",
            "Select one text or Markdown file before creating a link.",
          ),
        );
        return;
      }
      submit.disabled = true;
      status.removeAttribute("role");
      status.dataset.state = "encrypting";
      status.replaceChildren(
        element(doc, "strong", "sender-status-title", "Encrypting in this browser"),
        element(
          doc,
          "span",
          "sender-status-detail",
          "The file and its decryption key stay private while TinyCloud stores only encrypted bytes.",
        ),
      );
      try {
        const result = await createLinkOnlyShare(file, options);
        progress.children[1]?.setAttribute("data-state", "complete");
        progress.children[2]?.setAttribute("data-state", "current");
        fileLabel.hidden = true;
        possessionNote.hidden = true;
        notifyRow.hidden = true;
        submit.hidden = true;
        status.dataset.state = "created";
        status.removeAttribute("role");
        status.replaceChildren();
        const title = element(
          doc,
          "strong",
          "sender-status-title result-title",
          "Your private link is ready",
        );
        const detail = element(
          doc,
          "span",
          "sender-status-detail",
          "Send the complete link through a channel you trust. No email notification was sent.",
        );
        const linkLabel = element(doc, "label", "result-link-label", "Share link");
        const link = element(doc, "textarea", "share-result-link");
        link.id = "generated-share-link";
        link.readOnly = true;
        link.rows = 3;
        link.value = result.url;
        linkLabel.htmlFor = link.id;
        linkLabel.append(link);
        const actions = element(doc, "div", "result-actions");
        const copy = element(doc, "button", "button button-primary", "Copy link");
        copy.type = "button";
        const another = element(
          doc,
          "button",
          "button button-secondary",
          "Share another file",
        );
        another.type = "button";
        const copyStatus = element(doc, "span", "copy-status");
        copyStatus.setAttribute("role", "status");
        copyStatus.setAttribute("aria-live", "polite");
        copy.addEventListener("click", () => {
          copy.disabled = true;
          void copyText(result.url)
            .then(() => {
              copy.textContent = "Copied";
              copyStatus.textContent = "Link copied to clipboard.";
            })
            .catch(() => {
              copy.textContent = "Copy link";
              copyStatus.setAttribute("role", "alert");
              copyStatus.textContent =
                "Copy failed. Select the link above and copy it manually.";
              link.focus();
              link.select();
            })
            .finally(() => {
              copy.disabled = false;
            });
        });
        another.addEventListener("click", reset);
        actions.append(copy, another);
        status.append(title, detail, linkLabel, actions, copyStatus);
        copy.focus();
      } catch (error) {
        const failure = errorCopy(error);
        status.dataset.state = `error-${failure.kind}`;
        status.setAttribute("role", "alert");
        status.replaceChildren(
          element(
            doc,
            "strong",
            "sender-status-title",
            failure.kind === "authentication"
              ? "Sign in again"
              : failure.kind === "file"
                ? "Check this file"
                : failure.kind === "storage"
                  ? "Upload failed"
                  : "Encryption failed",
          ),
          element(doc, "span", "sender-status-detail", failure.message),
        );
      } finally {
        submit.disabled = false;
      }
    })();
  });
}
