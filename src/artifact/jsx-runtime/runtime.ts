/**
 * The in-frame JSX runtime. Built into the `runtime` module file (build.ts) and
 * executed ONLY inside the opaque-origin child frame, never in the viewer.
 *
 * Untrusted source is compiled here with sucrase (jsx + typescript + imports),
 * evaluated with `new Function("require", "module", "exports", code)` through a
 * require shim that answers only the specifiers the bridge inlined, and the
 * default export is mounted under an ErrorBoundary. The frame's CSP already
 * allows `'unsafe-eval'` and refuses every network request, so eval adds no
 * capability here. Nothing in this file is reachable from the viewer realm.
 */
import { transform } from "sucrase";
import { Component, createElement, useEffect, type ReactNode } from "react";
import { createRoot } from "react-dom/client";

export type JsxErrorPhase = "compile" | "import" | "runtime";

export interface BootInput {
  readonly source: string;
  readonly theme: string;
}

export interface BootHost {
  has(specifier: string): boolean;
  require(specifier: string): unknown;
  /** Posts `{v:1,...}` to the bridge. */
  post(message: Record<string, unknown>): void;
}

/** Messages are capped here and again by the bridge and the viewer. */
const MAX_MESSAGE = 2048;

class ImportError extends Error {
  readonly moduleName: string;
  constructor(moduleName: string) {
    super(`Cannot find module "${moduleName.slice(0, 200)}"`);
    this.moduleName = moduleName;
  }
}

function describe(error: unknown): string {
  // sucrase prefixes its parse errors with the internal file name; the line is reported separately.
  const text = error instanceof Error ? `${error.name}: ${error.message.replace(/^Error transforming artifact\.tsx: /, "")}` : String(error);
  return text.length > MAX_MESSAGE ? text.slice(0, MAX_MESSAGE) : text;
}

function lineOf(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null || !("loc" in error)) return undefined;
  const loc = error.loc;
  if (typeof loc !== "object" || loc === null || !("line" in loc)) return undefined;
  return typeof loc.line === "number" && Number.isInteger(loc.line) && loc.line > 0 ? loc.line : undefined;
}

/**
 * Compile `source`. Throws the sucrase parse error (its `loc.line` is 1-based).
 * Exported so the compile contract can be tested without a DOM.
 */
export function compileSource(source: string): string {
  return transform(source, {
    transforms: ["jsx", "typescript", "imports"],
    jsxRuntime: "automatic",
    production: true,
    filePath: "artifact.tsx",
  }).code;
}

export function boot(input: BootInput, host: BootHost): void {
  let started = false;
  const fail = (phase: JsxErrorPhase, error: unknown, moduleName?: string): void => {
    const line = phase === "compile" ? lineOf(error) : undefined;
    host.post({
      type: "error",
      phase,
      message: describe(error),
      ...(line === undefined ? {} : { line }),
      ...(moduleName === undefined ? {} : { module: moduleName.slice(0, 200) }),
    });
  };

  document.documentElement.dataset["theme"] = input.theme === "light" || input.theme === "dark" ? input.theme : "system";

  // Uncaught errors that happen before the first commit are start-up failures;
  // later ones belong to the running app and are not forwarded.
  window.addEventListener("error", (event) => {
    if (!started) fail("runtime", event.error ?? event.message);
  });
  window.addEventListener("unhandledrejection", (event) => {
    if (!started) fail("runtime", event.reason);
  });
  // Keyboard focus inside the frame never reaches the viewer, so the recall shortcut is
  // forwarded as a bare signal that only reveals the chrome and moves focus to it. The
  // listener is registered first and in the capture phase, so no later listener the
  // artifact adds on window can run before it or stop the event first.
  window.addEventListener("keydown", (event) => {
    if (event.altKey && event.shiftKey && event.key.toLowerCase() === "c") host.post({ type: "restore-controls" });
  }, true);

  // Tailwind's browser runtime watches the document and builds CSS for the
  // classes the artifact uses. It is always present; a missing file is not fatal.
  if (host.has("@tailwindcss/browser")) {
    try {
      host.require("@tailwindcss/browser");
    } catch (error) {
      console.warn("tailwind failed to start", error);
    }
  }

  let code: string;
  try {
    code = compileSource(input.source);
  } catch (error) {
    fail("compile", error);
    return;
  }

  const requireShim = (specifier: unknown): unknown => {
    if (typeof specifier !== "string" || !host.has(specifier)) throw new ImportError(String(specifier));
    return host.require(specifier);
  };
  const module: { exports: Record<string, unknown> } = { exports: {} };
  try {
    new Function("require", "module", "exports", code)(requireShim, module, module.exports);
  } catch (error) {
    if (error instanceof ImportError) fail("import", error, error.moduleName);
    else fail("runtime", error);
    return;
  }

  const entry = module.exports["default"];
  if (typeof entry !== "function" && (typeof entry !== "object" || entry === null)) {
    fail("runtime", new Error("The file must export a React component as its default export, e.g. `export default function App() { … }`."));
    return;
  }

  class ErrorBoundary extends Component<{ children?: ReactNode }, { failed: boolean }> {
    override state = { failed: false };
    static getDerivedStateFromError(): { failed: boolean } {
      return { failed: true };
    }
    override componentDidCatch(error: unknown): void {
      fail("runtime", error);
    }
    override render(): ReactNode {
      return this.state.failed ? null : this.props.children;
    }
  }

  // Mounted after the app so its effect runs once the whole tree has committed.
  function ReadySignal(): null {
    useEffect(() => {
      started = true;
      host.post({ type: "ready" });
    }, []);
    return null;
  }

  const rootElement = document.getElementById("root");
  if (rootElement === null) {
    fail("runtime", new Error("The frame has no mount point."));
    return;
  }
  try {
    createRoot(rootElement, {
      onUncaughtError: (error: unknown) => fail("runtime", error),
    }).render(createElement(ErrorBoundary, null, createElement(entry as never), createElement(ReadySignal)));
  } catch (error) {
    fail("runtime", error);
  }
}

// The require shim looks this up by specifier: `__TC_REQUIRE__("@tc/runtime").boot`.
export default { boot };
