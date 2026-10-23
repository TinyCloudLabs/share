import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { renderLandingTemplate } from "../src/landing/brand.ts";
import { CYCLES, HOLD_MS, SHARE_TARGETS, startShareTargetRotation, TYPE_MS } from "../src/landing/share-targets.ts";

const rendered = renderLandingTemplate(readFileSync(join(process.cwd(), "index.html"), "utf8"));

function mountHero(reduced: boolean): HTMLElement {
  document.body.innerHTML = new DOMParser().parseFromString(rendered, "text/html").body.innerHTML;
  window.matchMedia = vi.fn().mockImplementation(() => ({
    matches: reduced,
    media: "",
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
  return document.querySelector<HTMLElement>(".share-target")!;
}

function shown(): string | null {
  return document.querySelector(".share-target-text")!.textContent;
}

describe("share target phrases", () => {
  it("lists at least three phrases, none about links", () => {
    expect(SHARE_TARGETS.length).toBeGreaterThanOrEqual(3);
    expect(SHARE_TARGETS.filter((phrase) => phrase.includes("link"))).toEqual([]);
  });

  it("renders the first phrase statically at the end of the headline", () => {
    mountHero(false);
    expect(shown()).toBe(SHARE_TARGETS[0]);
    expect(document.querySelector("h1")!.textContent!.replace(/\s+/g, " ").trim()).toBe(
      `Share what your agent makes with ${SHARE_TARGETS[0]}`,
    );
    expect(document.querySelectorAll("h1 br")).toHaveLength(2);
  });

  it("gives screen readers the whole sentence once and hides the typed part", () => {
    mountHero(false);
    const h1 = document.querySelector("h1")!;
    const label = h1.getAttribute("aria-label")!;
    expect(label.startsWith("Share what your agent makes with ")).toBe(true);
    expect(label.endsWith(".")).toBe(true);
    for (const phrase of SHARE_TARGETS) expect(label).toContain(phrase);
    expect(h1.querySelector(".share-target")!.getAttribute("aria-hidden")).toBe("true");
  });
});

describe("share target rotation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = "";
  });

  it("types every phrase in turn for CYCLES passes, then settles on the first and stops", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);
    expect(shown()).toBe("");
    expect(wrapper.querySelector(".share-target-cursor")?.getAttribute("aria-hidden")).toBe("true");

    // A phrase is complete when the text stops growing: it is then deleted, or typing stops.
    const completed: string[] = [];
    let previous = "";
    let growing = false;
    for (let tick = 0; tick < 100_000 && vi.getTimerCount() > 0; tick++) {
      vi.advanceTimersByTime(10);
      const now = shown() ?? "";
      if (now.length > previous.length) growing = true;
      if (now.length < previous.length && growing) {
        completed.push(previous);
        growing = false;
      }
      previous = now;
    }
    if (growing) completed.push(previous);

    const passes = Array.from({ length: CYCLES }, () => SHARE_TARGETS).flat();
    expect(completed).toEqual([...passes, SHARE_TARGETS[0]]);
    expect(shown()).toBe(SHARE_TARGETS[0]);
    expect(wrapper.querySelector(".share-target-cursor")).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("never starts a timer and makes no DOM changes when reduced motion is requested", () => {
    const wrapper = mountHero(true);
    const before = document.querySelector("h1")!.innerHTML;
    startShareTargetRotation(wrapper);

    expect(vi.getTimerCount()).toBe(0);
    expect(document.querySelector("h1")!.innerHTML).toBe(before);
  });

  it("holds the typed text while hovered and resumes on leave", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);
    vi.advanceTimersByTime(TYPE_MS * 3);
    const held = shown();

    wrapper.dispatchEvent(new Event("pointerenter"));
    vi.advanceTimersByTime(HOLD_MS * 4);
    expect(shown()).toBe(held);

    wrapper.dispatchEvent(new Event("pointerleave"));
    vi.advanceTimersByTime(TYPE_MS * 2);
    expect(shown()).not.toBe(held);
  });

  it("holds the typed text while focus is inside and resumes on focus-out", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);
    vi.advanceTimersByTime(TYPE_MS * 3);
    const held = shown();

    wrapper.dispatchEvent(new Event("focusin"));
    vi.advanceTimersByTime(HOLD_MS * 4);
    expect(shown()).toBe(held);

    wrapper.dispatchEvent(new Event("focusout"));
    vi.advanceTimersByTime(TYPE_MS * 2);
    expect(shown()).not.toBe(held);
  });

  it("clears its timer when the returned stop function is called", () => {
    const wrapper = mountHero(false);
    const stop = startShareTargetRotation(wrapper);

    expect(vi.getTimerCount()).toBe(1);
    stop();
    expect(vi.getTimerCount()).toBe(0);
  });
});
