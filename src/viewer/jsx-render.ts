/**
 * Viewer glue for one JSX artifact: load the verified library files, run the
 * source in the sandbox, show a loading state until the first render, and turn
 * every failure into a house-style panel.
 *
 * Loaded lazily (content.ts imports it only for a bearer-delivered JSX file),
 * so the sandbox controller, loader, manifest and panel styles stay out of the
 * viewer's root chunk. Every string a frame sends back is shown with
 * `textContent`; nothing here parses, evaluates or injects artifact content.
 */
import "./artifact-tokens.css";
import "./jsx-panel.css";
import { JSX_LIBRARY_SET } from "../artifact/jsx-runtime/files.js";
import { JsxModuleIntegrityError, loadJsxModules } from "./jsx-modules.js";
import type { ArtifactNotice } from "./artifact-notice.js";
import { JSX_MAX_SOURCE_CHARS, JSX_START_TIMEOUT_MS, type JsxTheme } from "./jsx-frame.js";
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
  /** After this long without the first render, the loading cover says so and offers Try again. */
  readonly slowAfterMs?: number;
}

interface PanelCopy {
  readonly title: string;
  readonly detail: readonly string[];
  readonly message?: string;
  readonly line?: number;
  /** Offers "Try again", which starts the whole load again. */
  readonly retry?: boolean;
}

/** Shown in the loading cover and, once the start timeout has passed, as the panel. */
const SLOW_TITLE = "This page is taking a long time to start";
const SLOW_DETAIL = "It may be a slow connection. Try again, or download the file to open it elsewhere.";

function libraryList(): string {
  return JSX_LIBRARY_SET.join(", ");
}

class JsxSourceError extends Error {}

/** Recipient-facing copy: the person reading it is not the author. */
function copyFor(error: unknown): PanelCopy {
  if (error instanceof JsxModuleIntegrityError) {
    // Fails closed: the library files and the viewer disagree, which is what a deploy in progress looks like.
    return { title: "This artifact viewer is updating", detail: ["Try again in a minute."], retry: true };
  }
  if (error instanceof JsxSourceError) {
    return { title: "This file isn't text", detail: ["It isn't valid UTF-8, so it can't be run. Download it to open it elsewhere."] };
  }
  if (error instanceof JsxRenderError) {
    switch (error.phase) {
      case "compile":
        return { title: "This file has a syntax error", detail: ["Ask the sender to share it again once it's fixed, or download the file."], message: error.message, ...(error.line === undefined ? {} : { line: error.line }) };
      case "import": {
        // The name comes from the file: it is shown as quoted text in the box, never as part of the title.
        return { title: "This page needs a library that isn't available", detail: [`It isn't in the TinyCloud library set. Available: ${libraryList()}.`, "Ask the sender to share a version that includes it."], message: `Import from the file: ${error.moduleName ?? "unknown"}` };
      }
      case "runtime":
        return { title: "This page stopped because of an error", detail: ["Ask the sender to share it again, or download the file to look at it."], message: error.message };
      case "start":
        return { title: SLOW_TITLE, detail: [SLOW_DETAIL], retry: true };
      case "limit":
        return { title: "This file is too large to run here", detail: ["Download it to open it elsewhere."] };
    }
  }
  return { title: "This page wasn't started", detail: ["We couldn't run it here. Download the file to open it elsewhere."], retry: true };
}

function actionButton(doc: Document, label: string, primary: boolean, onClick: () => void): HTMLButtonElement {
  const button = doc.createElement("button");
  button.type = "button";
  button.className = primary ? "viewer-jsx-action viewer-jsx-action--primary" : "viewer-jsx-action";
  button.textContent = label;
  button.addEventListener("click", onClick);
  return button;
}

function sourceLink(doc: Document, options: RenderJsxOptions, bytes: Uint8Array): { link: HTMLAnchorElement; revoke: () => void } {
  const href = URL.createObjectURL(new Blob([new Uint8Array(bytes).buffer as ArrayBuffer], { type: "text/plain;charset=utf-8" }));
  const link = doc.createElement("a");
  link.className = "viewer-jsx-action";
  link.href = href;
  link.download = options.filename;
  link.textContent = "Download source";
  return { link, revoke: () => URL.revokeObjectURL(href) };
}

function buildPanel(doc: Document, copy: PanelCopy, options: RenderJsxOptions, bytes: Uint8Array, retry: () => void): { panel: HTMLElement; revoke: () => void } {
  const panel = doc.createElement("section");
  panel.className = "viewer-jsx-panel";
  panel.dataset["theme"] = "system";
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
  const actions = doc.createElement("div");
  actions.className = "viewer-jsx-panel-actions";
  if (copy.retry === true) actions.append(actionButton(doc, "Try again", true, retry));
  const { link, revoke } = sourceLink(doc, options, bytes);
  actions.append(link);
  panel.append(actions);
  return { panel, revoke };
}

interface LoadingCover {
  readonly element: HTMLElement;
  /** Switches the cover to its "taking a long time" wording, with Try again. */
  slow(): void;
}

/** The viewer's own cover over the frame until it reports ready. A skeleton and one status line. */
function buildLoadingCover(doc: Document, retry: () => void): LoadingCover {
  const element = doc.createElement("div");
  element.className = "viewer-jsx-loading";
  element.dataset["theme"] = "system";
  element.dataset["state"] = "loading";
  element.setAttribute("role", "status");
  const skeleton = doc.createElement("div");
  skeleton.className = "viewer-jsx-skeleton";
  skeleton.setAttribute("aria-hidden", "true");
  for (let bar = 0; bar < 3; bar += 1) {
    const piece = doc.createElement("div");
    piece.className = "viewer-jsx-skeleton-bar";
    skeleton.append(piece);
  }
  const text = doc.createElement("p");
  text.className = "viewer-jsx-loading-text";
  text.textContent = "Loading the page…";
  element.append(skeleton, text);
  return {
    element,
    slow(): void {
      element.dataset["state"] = "slow";
      text.textContent = SLOW_TITLE;
      const detail = doc.createElement("p");
      detail.className = "viewer-jsx-loading-detail";
      detail.textContent = SLOW_DETAIL;
      element.append(detail, actionButton(doc, "Try again", true, retry));
    },
  };
}

/**
 * Runs the artifact inside `container`. Always resolves: a failure is shown as
 * a panel (the container keeps no frame), so the caller's footer download and
 * the panel's link remain the fallback. Until the first render the frame is
 * covered by a loading state; after the start timeout the cover and then the
 * panel offer Try again.
 */
export async function renderJsxPage(container: HTMLElement, input: string | Uint8Array, options: RenderJsxOptions): Promise<void> {
  const doc = container.ownerDocument;
  const { notice } = options;
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;

  let revokePanel: (() => void) | undefined;
  let sandbox: JsxSandbox | undefined;
  let slowTimer: ReturnType<typeof setTimeout> | undefined;
  let attempt = 0;
  const teardown = (): void => {
    clearTimeout(slowTimer);
    slowTimer = undefined;
    sandbox?.destroy();
    sandbox = undefined;
    revokePanel?.();
    revokePanel = undefined;
  };
  // Replacing the container's content ends this render for good, including one still loading.
  options.onCleanup(() => { attempt += 1; teardown(); });

  const chrome = (...rest: HTMLElement[]): HTMLElement[] => (notice === undefined ? rest : [notice.element, ...rest]);
  const showPanel = (error: unknown, mine: number): void => {
    if (mine !== attempt) return;
    teardown();
    const { panel, revoke } = buildPanel(doc, copyFor(error), options, bytes, retry);
    revokePanel = revoke;
    container.replaceChildren(...chrome(panel));
  };
  const retry = (): void => {
    teardown();
    void run();
  };

  async function run(): Promise<void> {
    const mine = ++attempt;
    const stage = doc.createElement("div");
    stage.className = "viewer-jsx-stage";
    stage.dataset["state"] = "loading";
    const cover = buildLoadingCover(doc, retry);
    // Covered from the first moment: library files can take seconds, long before a frame exists.
    stage.append(cover.element);
    container.replaceChildren(...chrome(stage));
    slowTimer = setTimeout(() => { if (mine === attempt) cover.slow(); }, options.slowAfterMs ?? JSX_START_TIMEOUT_MS);
    try {
      let source: string;
      if (typeof input === "string") source = input;
      else {
        try { source = new TextDecoder("utf-8", { fatal: true }).decode(input); } catch { throw new JsxSourceError("not UTF-8"); }
      }
      // Before anything scans or sends it: a hostile source must not cost the viewer time.
      if (source.length > JSX_MAX_SOURCE_CHARS) throw new JsxRenderError("limit", "This file is too large to run here.");
      // Dynamic: the manifest module is a build-time virtual module that tests replace.
      const modules = options.modules ?? await loadJsxModules(options.manifest ?? (await import("./jsx-manifest.js")).manifest, source, options.fetch === undefined ? {} : { fetch: options.fetch });
      if (mine !== attempt) return;
      sandbox = createJsxSandbox(doc, {
        mount: stage,
        ...(options.frameClassName === undefined ? {} : { className: options.frameClassName }),
        title: options.title ?? `Shared app: ${options.filename}`,
        onFailure: (error) => showPanel(error, mine),
        ...(options.onRestoreControls === undefined ? {} : { onRestoreControls: options.onRestoreControls }),
      });
      // Visible underneath the cover: the page needs real layout to measure (diagrams, charts).
      sandbox.iframe.hidden = false;
      await sandbox.render(source, modules, options.theme);
      if (mine !== attempt) return;
      clearTimeout(slowTimer);
      cover.element.remove();
      delete stage.dataset["state"];
    } catch (error) {
      showPanel(error, mine);
    }
  }
  await run();
}
