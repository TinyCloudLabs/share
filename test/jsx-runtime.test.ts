import { describe, expect, it } from "vitest";

import { boot, compileSource, type BootHost } from "../src/artifact/jsx-runtime/runtime.js";

describe("in-frame compile", () => {
  it("transforms JSX, TypeScript and ES imports with the automatic runtime", () => {
    const code = compileSource('import { useState } from "react";\nexport default function App({ n }: { n: number }) { const [a] = useState<number>(n); return <b>{a}</b>; }');
    expect(code).toMatch(/require\(["']react["']\)/);
    expect(code).toContain("react/jsx-runtime");
    expect(code).not.toContain(": number");
  });

  it("reports the 1-based line of a syntax error", () => {
    let caught: unknown;
    try { compileSource("export default function A() {\n  return (\n    <ul>\n      {[1].map((n) => <li>{n}</li>}\n    </ul>\n  );\n}"); } catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as { loc: { line: number } }).loc.line).toBe(4);
  });
});

function recordingHost(modules: Record<string, unknown>): { host: BootHost; messages: Array<Record<string, unknown>> } {
  const messages: Array<Record<string, unknown>> = [];
  return {
    messages,
    host: {
      has: (specifier) => Object.hasOwn(modules, specifier),
      require: (specifier) => modules[specifier],
      post: (message) => { messages.push(message); },
    },
  };
}

describe("in-frame boot", () => {
  async function runtimeModules(): Promise<Record<string, unknown>> {
    const react = await import("react");
    const jsx = await import("react/jsx-runtime");
    return { "react": react, "react/jsx-runtime": jsx };
  }

  it("mounts the default export and reports ready", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: "export default function App() { return <p id=\"hello\">Hi</p>; }", theme: "dark" }, host);
    await expect.poll(() => messages.map((message) => message["type"])).toContain("ready");
    expect(document.getElementById("hello")?.textContent).toBe("Hi");
    expect(document.documentElement.dataset["theme"]).toBe("dark");
  });

  it("reports compile errors with a line and nothing else running", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: "export default function A() {\n  return <div>;\n}", theme: "system" }, host);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({ type: "error", phase: "compile", line: expect.any(Number) });
    expect(String(messages[0]!["message"])).not.toContain("Error transforming artifact");
    expect(document.getElementById("root")?.childElementCount).toBe(0);
  });

  it("rejects an import the bridge did not inline, naming the module", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: 'import confetti from "canvas-confetti";\nexport default () => <i>{String(confetti)}</i>;', theme: "system" }, host);
    expect(messages).toEqual([{ type: "error", phase: "import", message: 'Error: Cannot find module "canvas-confetti"', module: "canvas-confetti" }]);
  });

  it("does not expose prototype names as modules", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: 'import x from "constructor"; export default () => <i>{String(x)}</i>;', theme: "system" }, host);
    expect(messages[0]).toMatchObject({ phase: "import", module: "constructor" });
  });

  it("reports a render error from the ErrorBoundary as a runtime error", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: 'export default function A() { throw new Error("boom"); }', theme: "system" }, host);
    await expect.poll(() => messages.some((message) => message["phase"] === "runtime")).toBe(true);
    expect(messages.some((message) => message["type"] === "ready")).toBe(false);
    expect(String(messages.find((message) => message["phase"] === "runtime")!["message"])).toContain("boom");
  });

  it("requires a default export that is a component", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: "export const App = () => null;", theme: "system" }, host);
    expect(messages[0]).toMatchObject({ type: "error", phase: "runtime" });
  });

  it("forwards only the recall shortcut as a bare signal", async () => {
    document.body.innerHTML = '<div id="root"></div>';
    const { host, messages } = recordingHost(await runtimeModules());
    boot({ source: "export default () => null;", theme: "system" }, host);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "C", altKey: true, shiftKey: true }));
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c" }));
    expect(messages.filter((message) => message["type"] === "restore-controls")).toEqual([{ type: "restore-controls" }]);
  });
});
