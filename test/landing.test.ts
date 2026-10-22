import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mountPrivacyVariant } from "../src/landing/preview-variant.ts";
import { AGENT_PROMPT, AGENT_TARGETS, PRIVACY_CLAUSE, PRODUCT, renderLandingTemplate, SKILL_URL } from "../src/landing/brand.ts";

const EXPECTED_PROMPT = "Read https://agents.tinycloud.xyz/share and follow it.";

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

  it("renders the copy button hidden and the prompt selectable, so the page works without script", () => {
    const doc = new DOMParser().parseFromString(rendered, "text/html");
    expect(doc.querySelector<HTMLButtonElement>("#copy-prompt")!.hidden).toBe(true);
    expect(doc.querySelector("#agent-prompt")!.textContent).toBe(EXPECTED_PROMPT);
  });

  it("renders every agent link statically, each carrying the exact prompt (or the skill URL for Hermes)", () => {
    const doc = new DOMParser().parseFromString(rendered, "text/html");
    const links = [...doc.querySelectorAll<HTMLAnchorElement>("nav.agent-links a[data-agent]")];
    expect(links.map((link) => link.dataset.agent)).toEqual(AGENT_TARGETS.map((agent) => agent.id));
    for (const link of links) {
      expect(link.getAttribute("target")).toBe("_blank");
      expect(link.getAttribute("rel")).toBe("noopener");
      const url = new URL(link.getAttribute("href")!);
      const carried = link.dataset.agent === "hermes" ? SKILL_URL : AGENT_PROMPT;
      expect([...url.searchParams.values()]).toContain(carried);
    }
  });

  it("renders the default privacy sentence", () => {
    const doc = new DOMParser().parseFromString(rendered, "text/html");
    expect(doc.querySelector("#privacy-clause")!.textContent).toBe(PRIVACY_CLAUSE);
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

  it("copies the prompt and shows the agent's message when an agent link is clicked", async () => {
    const link = document.querySelector<HTMLAnchorElement>('a[data-agent="gemini"]')!;
    link.addEventListener("click", (event) => event.preventDefault());
    link.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(writeText).toHaveBeenCalledExactlyOnceWith(EXPECTED_PROMPT);
    expect(document.querySelector("#copy-status")!.textContent).toBe("Copied. Paste it into Gemini.");
  });

  it("tells the reader to copy by hand when the clipboard is unavailable", async () => {
    writeText.mockRejectedValue(new Error("denied"));
    document.execCommand = vi.fn(() => false);
    const link = document.querySelector<HTMLAnchorElement>('a[data-agent="claude"]')!;
    link.addEventListener("click", (event) => event.preventDefault());
    link.click();
    await vi.advanceTimersByTimeAsync(0);

    expect(document.querySelector("#copy-status")!.textContent).toBe("Copy the prompt, then paste it into your agent.");
  });

  it("reveals the copy button once script runs", () => {
    expect(document.querySelector<HTMLButtonElement>("#copy-prompt")!.hidden).toBe(false);
  });
});

describe("preview privacy wording switch", () => {
  beforeEach(() => {
    document.body.innerHTML = /<body[^>]*>([\s\S]*)<\/body>/.exec(rendered)![1]!;
  });

  it("shows the alternative with ?v=b and the default otherwise", () => {
    mountPrivacyVariant(document, "?v=b");
    expect(document.querySelector("#privacy-clause")!.textContent).toBe("a link that no one else can open, not even TinyCloud");
    document.body.innerHTML = /<body[^>]*>([\s\S]*)<\/body>/.exec(rendered)![1]!;
    mountPrivacyVariant(document, "?v=a");
    expect(document.querySelector("#privacy-clause")!.textContent).toBe(PRIVACY_CLAUSE);
  });

  it("is not loaded by the landing script unless the preview flag is set", async () => {
    vi.resetModules();
    window.matchMedia = vi.fn(() => ({ matches: true })) as unknown as typeof window.matchMedia;
    window.history.replaceState(null, "", "/?v=b");
    await import("../src/landing/main.ts");
    await Promise.resolve();
    expect(document.querySelector("#privacy-clause")!.textContent).toBe(PRIVACY_CLAUSE);
    expect(document.querySelector(".preview-variant")).toBeNull();
    window.history.replaceState(null, "", "/");
  });
});
