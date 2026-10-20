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
import type { ArtifactNotice } from "./artifact-notice.js";
import type { JsxTheme } from "./jsx-frame.js";
import { JsxRenderError, createJsxSandbox, type JsxSandbox } from "./jsx-sandbox.js";
import type { JsxManifest } from "../artifact/jsx-runtime/files.js";

/**
 * The runner entry: source text or UTF-8 bytes plus options. Callers adapt
 * whatever they hold (a share descriptor, a file from the user's space) to
 * this; nothing here knows about shares.
 */
export interface RenderJsxOptions {
  /** Names the artifact in the frame title and the panel's "Download source" link. */
  readonly filename: string;
  readonly theme?: JsxTheme;
  /** Replaces the default frame title. */
  readonly title?: string;
  /**
   * Library file texts already loaded AND verified by the caller (loadJsxModules).
   * When absent they are loaded and verified here.
   */
  readonly modules?: Readonly<Record<string, string>>;
  /** Registers the teardown to run when the container's content is replaced. */
  readonly onCleanup: (cleanup: () => void) => void;
  /** Defaults to the build's manifest; tests inject one. */
  readonly manifest?: JsxManifest;
  readonly fetch?: typeof fetch;
  /** The viewer-chrome notice (artifact-notice.ts), kept above the frame or panel. */
  readonly notice?: ArtifactNotice;
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

class JsxSourceError extends Error {}

function copyFor(error: unknown): PanelCopy {
  if (error instanceof JsxModuleIntegrityError) {
    // Fails closed: the library files and the viewer disagree, which is what a deploy in progress looks like.
    return { title: "This artifact viewer is updating", detail: ["Try again in a minute. Nothing was run."] };
  }
  if (error instanceof JsxSourceError) {
    return { title: "This file isn't text", detail: ["It isn't valid UTF-8, so it can't be run. Download it to open it elsewhere."] };
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

function buildPanel(doc: Document, copy: PanelCopy, options: RenderJsxOptions, bytes: Uint8Array): { panel: HTMLElement; revoke: () => void } {
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
  const href = URL.createObjectURL(new Blob([new Uint8Array(bytes).buffer as ArrayBuffer], { type: "text/plain;charset=utf-8" }));
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
export async function renderJsxPage(container: HTMLElement, input: string | Uint8Array, options: RenderJsxOptions): Promise<void> {
  const doc = container.ownerDocument;
  const { notice } = options;
  if (notice !== undefined) container.append(notice.element);
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;

  let revokePanel: (() => void) | undefined;
  let sandbox: JsxSandbox | undefined;
  options.onCleanup(() => {
    sandbox?.destroy();
    revokePanel?.();
  });
  const showPanel = (error: unknown): void => {
    sandbox?.destroy();
    sandbox = undefined;
    const { panel, revoke } = buildPanel(doc, copyFor(error), options, bytes);
    revokePanel?.();
    revokePanel = revoke;
    container.replaceChildren(...(notice === undefined ? [panel] : [notice.element, panel]));
  };

  try {
    let source: string;
    if (typeof input === "string") source = input;
    else {
      try { source = new TextDecoder("utf-8", { fatal: true }).decode(input); } catch { throw new JsxSourceError("not UTF-8"); }
    }
    // Dynamic: the manifest module is a build-time virtual module that tests replace.
    const modules = options.modules ?? await loadJsxModules(options.manifest ?? (await import("./jsx-manifest.js")).manifest, source, options.fetch === undefined ? {} : { fetch: options.fetch });
    sandbox = createJsxSandbox(doc, {
      mount: container,
      ...(options.frameClassName === undefined ? {} : { className: options.frameClassName }),
      title: options.title ?? `Shared app: ${options.filename}`,
      onFailure: showPanel,
      ...(options.onRestoreControls === undefined ? {} : { onRestoreControls: options.onRestoreControls }),
    });
    sandbox.iframe.hidden = false;
    await sandbox.render(source, modules, options.theme);
  } catch (error) {
    showPanel(error);
  }
}
