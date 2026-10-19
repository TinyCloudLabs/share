import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AGENT_PROMPT, PRODUCT, renderLandingTemplate } from "../src/landing/brand.ts";

const EXPECTED_PROMPT =
  "Share this with TinyCloud, and ask me who should be able to open it: https://agents.tinycloud.xyz/share";

const rendered = renderLandingTemplate(readFileSync(join(process.cwd(), "index.html"), "utf8"));

describe("landing template", () => {
  it("renders every token and never leaks review notes", () => {
    expect(rendered).not.toMatch(/\{\{|\}\}|\{PRODUCT\}|\{DOMAIN\}/);
    expect(rendered).not.toMatch(/\[(Backed|Track)\b/);
    expect(rendered).toContain(`<title>${PRODUCT} — Share what your agent makes.</title>`);
    expect(rendered).toContain("<span>TinyCloud <b>Sharing</b></span>");
  });

  it("rejects an unknown token instead of rendering it", () => {
    expect(() => renderLandingTemplate("<p>{{NOPE}}</p>")).toThrow(/NOPE/);
  });

  it("keeps the agent prompt exactly as specified", () => {
    expect(AGENT_PROMPT).toBe(EXPECTED_PROMPT);
  });
});

describe("agent prompt copy button", () => {
  const writeText = vi.fn<(text: string) => Promise<void>>();

  beforeEach(async () => {
    vi.resetModules();
    vi.useFakeTimers();
    writeText.mockReset().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    document.body.innerHTML = /<body[^>]*>([\s\S]*)<\/body>/.exec(rendered)![1]!;
    // Dynamic import is intentional: main.ts wires listeners on load, so it is re-evaluated per test after the DOM is set up.
    await import("../src/landing/main.ts");
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows the exact prompt in the box", () => {
    expect(document.querySelector("#agent-prompt")!.textContent).toBe(EXPECTED_PROMPT);
  });

  it("puts exactly the prompt on the clipboard, shows a copied state, then resets", async () => {
    const button = document.querySelector<HTMLButtonElement>("#copy-prompt")!;
    button.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(writeText).toHaveBeenCalledExactlyOnceWith(EXPECTED_PROMPT);
    expect(button.textContent).toBe("Copied");
    expect(button.dataset.state).toBe("copied");
    expect(document.querySelector("#copy-status")!.textContent).toBe("Copied to clipboard");

    await vi.advanceTimersByTimeAsync(2000);
    expect(button.textContent).toBe("Copy");
    expect(button.dataset.state).toBeUndefined();
    expect(document.querySelector("#copy-status")!.textContent).toBe("");
  });
});
