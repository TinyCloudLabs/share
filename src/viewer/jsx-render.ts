/**
 * Viewer glue for one JSX artifact: load the verified library files, run the
 * source in the sandbox, and turn every failure into a house-style panel.
 *
 * Loaded lazily (content.ts imports it only for a bearer-delivered JSX file),
 * so the sandbox controller, loader, manifest and panel styles stay out of the
 * viewer's root chunk. Every string a frame sends back is shown with
 * `textContent`; nothing here parses, evaluates or injects artifact content.
 */
import "./jsx-panel.css";
import { JSX_LIBRARY_SET } from "../artifact/jsx-runtime/files.js";
import { JsxModuleIntegrityError, loadJsxModules } from "./jsx-modules.js";
import { JsxRenderError, createJsxSandbox, type JsxSandbox } from "./jsx-sandbox.js";
import type { JsxManifest } from "../artifact/jsx-runtime/files.js";

export const JSX_NOTICE =
  "This app comes from the sender and runs in an isolated frame. It can't read this link or your session, load anything from the internet, or make requests. It can still reveal your IP address to the sender, for example through WebRTC.";

export interface RenderJsxOptions {
  readonly filename: string;
  /** The verified source bytes, for the panel's "Download source" link. */
  readonly bytes: Uint8Array;
  /** Registers the teardown to run when the container's content is replaced. */
  readonly onCleanup: (cleanup: () => void) => void;
  /** Defaults to the build's manifest; tests inject one. */
  readonly manifest?: JsxManifest;
  readonly fetch?: typeof fetch;
  readonly onRestoreControls?: () => void;
  readonly frameClassName?: string;
}

interface PanelCopy {
  readonly title: string;
  readonly detail: readonly string[];
  readonly message?: string;
  readonly line?: number;
}

function libraryList(): string {
  return JSX_LIBRARY_SET.join(", ");
}

function copyFor(error: unknown): PanelCopy {
  if (error instanceof JsxModuleIntegrityError) {
    return { title: "This app wasn't started", detail: ["A library it needs couldn't be verified, so nothing was run. Download the file to open it elsewhere."] };
  }
  if (error instanceof JsxRenderError) {
    switch (error.phase) {
      case "compile":
        return { title: "This file has a syntax error", detail: ["Fix it and publish a new version, or download the file."], message: error.message, ...(error.line === undefined ? {} : { line: error.line }) };
      case "import": {
        const name = error.moduleName ?? "That module";
        return { title: `${name} isn't available`, detail: [`It isn't in the TinyCloud library set. Available: ${libraryList()}.`, "Bundle it into the file or publish a self-contained HTML page."] };
      }
      case "runtime":
        return { title: "This app stopped because of an error", detail: ["It ran into a problem while running. Download the file to look at it."], message: error.message };
      case "start":
        return { title: "This app didn't start", detail: ["It took too long to start. Download the file to open it elsewhere."] };
      case "limit":
        return { title: "This file is too large to run here", detail: ["Download it to open it elsewhere."] };
    }
  }
  return { title: "This app wasn't started", detail: ["We couldn't run it here. Download the file to open it elsewhere."] };
}

function buildPanel(doc: Document, copy: PanelCopy, options: RenderJsxOptions): { panel: HTMLElement; revoke: () => void } {
  const panel = doc.createElement("section");
  panel.className = "viewer-jsx-panel";
  panel.setAttribute("role", "alert");
  const title = doc.createElement("h2");
  title.className = "viewer-jsx-panel-title";
  title.textContent = copy.title;
  panel.append(title);
  for (const text of copy.detail) {
    const detail = doc.createElement("p");
    detail.className = "viewer-jsx-panel-detail";
    detail.textContent = text;
    panel.append(detail);
  }
  if (copy.line !== undefined) {
    const line = doc.createElement("p");
    line.className = "viewer-jsx-panel-line";
    line.textContent = `Line ${copy.line}`;
    panel.append(line);
  }
  if (copy.message !== undefined) {
    const message = doc.createElement("pre");
    message.className = "viewer-jsx-panel-message";
    message.textContent = copy.message;
    panel.append(message);
  }
  const href = URL.createObjectURL(new Blob([new Uint8Array(options.bytes).buffer as ArrayBuffer], { type: "text/plain;charset=utf-8" }));
  const download = doc.createElement("a");
  download.className = "viewer-jsx-panel-download";
  download.href = href;
  download.download = options.filename;
  download.textContent = "Download source";
  panel.append(download);
  return { panel, revoke: () => URL.revokeObjectURL(href) };
}

/**
 * Runs the artifact inside `container`. Always resolves: a failure is shown as
 * a panel (the container keeps no frame), so the caller's footer download and
 * the panel's link remain the fallback.
 */
export async function renderJsxPage(container: HTMLElement, source: string, options: RenderJsxOptions): Promise<void> {
  const doc = container.ownerDocument;
  const notice = doc.createElement("p");
  notice.className = "viewer-html-notice";
  notice.textContent = JSX_NOTICE;
  container.append(notice);

  let revokePanel: (() => void) | undefined;
  let sandbox: JsxSandbox | undefined;
  options.onCleanup(() => {
    sandbox?.destroy();
    revokePanel?.();
  });
  const showPanel = (error: unknown): void => {
    sandbox?.destroy();
    sandbox = undefined;
    const { panel, revoke } = buildPanel(doc, copyFor(error), options);
    revokePanel?.();
    revokePanel = revoke;
    container.replaceChildren(notice, panel);
  };

  try {
    // Dynamic: the manifest module is a build-time virtual module that tests replace.
    const manifest = options.manifest ?? (await import("./jsx-manifest.js")).manifest;
    const modules = await loadJsxModules(manifest, source, options.fetch === undefined ? {} : { fetch: options.fetch });
    sandbox = createJsxSandbox(doc, {
      mount: container,
      ...(options.frameClassName === undefined ? {} : { className: options.frameClassName }),
      title: `Shared app: ${options.filename}`,
      onFailure: showPanel,
      ...(options.onRestoreControls === undefined ? {} : { onRestoreControls: options.onRestoreControls }),
    });
    sandbox.iframe.hidden = false;
    await sandbox.render(source, modules);
  } catch (error) {
    showPanel(error);
  }
}
