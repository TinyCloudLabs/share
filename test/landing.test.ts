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

  it("states the supported surfaces under the copy box", () => {
    const note = /<p class="agent-note">([\s\S]*?)<\/p>/.exec(rendered)![1]!.replace(/\s+/g, " ").trim();
    expect(note).toBe(
      "Works with coding agents like Claude Code, Codex and OpenCode. Chat apps through the TinyCloud MCP are next.",
    );
  });

  it("offers a secondary sign-in under the note that targets the same place as the bottom CTA", () => {
    const hero = /<p class="agent-signin">([\s\S]*?)<\/p>/.exec(rendered)![1]!;
    const heroLink = /<a class="agent-signin-link" href="([^"]+)">Sign in<\/a>/.exec(hero)![1];
    const bottomLink = /<a class="signin-link" href="([^"]+)">Sign in<\/a>/.exec(rendered)![1];
    expect(heroLink).toBeTruthy();
    expect(heroLink).toBe(bottomLink);
  });

  it("opens every web agent with exactly the prompt filled in", () => {
    const doc = new DOMParser().parseFromString(rendered, "text/html");
    const prompts = [...doc.querySelectorAll<HTMLAnchorElement>("a.agent-link[href^='https:']")].map((link) => {
      const url = new URL(link.href);
      return url.searchParams.get("q") ?? url.searchParams.get("text");
    });
    expect(prompts).toHaveLength(6);
    for (const prompt of prompts) expect(prompt).toBe(EXPECTED_PROMPT);
  });

  it("opens app-scheme agents (OpenClaw, Hermes) in place, not in a new blank tab", () => {
    const doc = new DOMParser().parseFromString(rendered, "text/html");
    const appLinks = [...doc.querySelectorAll<HTMLAnchorElement>("a.agent-link")].filter(
      (link) => !link.getAttribute("href")!.startsWith("https:"),
    );
    expect(appLinks.map((link) => link.dataset.agent)).toEqual(["openclaw", "hermes"]);
    for (const link of appLinks) expect(link.hasAttribute("target")).toBe(false);
  });

  it("describes the page with the hero subtitle", () => {
    const description = /<meta\s+name="description"\s+content="([^"]+)"/.exec(rendered)![1];
    const subtitle = /<p class="hero-intro">([\s\S]*?)<\/p>/.exec(rendered)![1]!.replace(/\s+/g, " ").trim();
    expect(description).toBe(subtitle);
  });
});

describe("agent prompt copy button", () => {
  const writeText = vi.fn<(text: string) => Promise<void>>();

  beforeEach(async () => {
    vi.resetModules();
    vi.useFakeTimers();
    writeText.mockReset().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    // jsdom has no matchMedia; main.ts reads the reduced-motion preference on load.
    window.matchMedia = vi.fn(() => ({ matches: false })) as unknown as typeof window.matchMedia;
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

  it("copies the prompt and says so when an agent tile is clicked", async () => {
    const chatgpt = document.querySelector<HTMLAnchorElement>('[data-agent="chatgpt"]')!;
    chatgpt.addEventListener("click", (event) => event.preventDefault());
    chatgpt.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(writeText).toHaveBeenCalledExactlyOnceWith(EXPECTED_PROMPT);
    expect(document.querySelector("#agent-status")!.textContent).toBe("Opening ChatGPT. The prompt is copied too.");
  });
});
