import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { renderLandingTemplate } from "../src/landing/brand.ts";
import {
  longestShareTarget,
  ROTATE_EVERY_MS,
  ROTATE_STOP_AFTER_MS,
  SHARE_TARGETS,
  startShareTargetRotation,
} from "../src/landing/share-targets.ts";

const rendered = renderLandingTemplate(readFileSync(join(process.cwd(), "index.html"), "utf8"));

/** Phrases listed under README "Landing page: recipient kinds", in order. */
function readmePhrases(): string[] {
  const readme = readFileSync(join(process.cwd(), "README.md"), "utf8");
  const section = /## Landing page: recipient kinds\n([\s\S]*?)(?=\n## |$)/.exec(readme)?.[1] ?? "";
  return [...section.matchAll(/^- (.+?) \((?:live|not live yet)\)$/gm)].map((match) => match[1]!);
}

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
  it("are the README list, in the README order", () => {
    const listed = readmePhrases();
    expect(listed.length).toBeGreaterThan(0);
    expect(SHARE_TARGETS).toEqual(listed);
  });

  it("renders the first phrase statically, so the page reads without JavaScript", () => {
    mountHero(false);
    expect(shown()).toBe(SHARE_TARGETS[0]);
  });

  it("renders the longest phrase as the width/height reservation, and no extra copyable node", () => {
    const target = new DOMParser().parseFromString(rendered, "text/html").querySelector<HTMLElement>(".share-target");
    expect(target?.dataset.longest).toBe(longestShareTarget());
    expect(longestShareTarget().length).toBe(Math.max(...SHARE_TARGETS.map((phrase) => phrase.length)));
    mountHero(false);
    expect(document.querySelector(".hero-phrase")!.textContent!.trim()).toBe(SHARE_TARGETS[0]);
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

  it("shows every phrase in order, then stops on the first", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);

    const seen: (string | null)[] = [shown()];
    for (let step = 0; step < ROTATE_STOP_AFTER_MS / ROTATE_EVERY_MS; step++) {
      vi.advanceTimersByTime(ROTATE_EVERY_MS);
      seen.push(shown());
    }

    expect(seen.slice(0, SHARE_TARGETS.length)).toEqual([...SHARE_TARGETS]);
    expect(shown()).toBe(SHARE_TARGETS[0]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("never starts a timer when reduced motion is requested", () => {
    const wrapper = mountHero(true);
    startShareTargetRotation(wrapper);

    vi.advanceTimersByTime(ROTATE_STOP_AFTER_MS * 2);
    expect(shown()).toBe(SHARE_TARGETS[0]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("makes no DOM changes under reduced motion", () => {
    const wrapper = mountHero(true);
    const before = document.querySelector(".hero-phrase")!.innerHTML;
    startShareTargetRotation(wrapper);
    expect(document.querySelector(".hero-phrase")!.innerHTML).toBe(before);
  });

  it("holds the current phrase while hovered and resumes on leave", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);

    wrapper.dispatchEvent(new Event("pointerenter"));
    vi.advanceTimersByTime(ROTATE_EVERY_MS);
    expect(shown()).toBe(SHARE_TARGETS[0]);

    wrapper.dispatchEvent(new Event("pointerleave"));
    vi.advanceTimersByTime(ROTATE_EVERY_MS);
    expect(shown()).toBe(SHARE_TARGETS[1]);
  });

  it("holds the current phrase while focus is inside and resumes on focus-out", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);

    wrapper.dispatchEvent(new Event("focusin"));
    vi.advanceTimersByTime(ROTATE_EVERY_MS);
    expect(shown()).toBe(SHARE_TARGETS[0]);

    wrapper.dispatchEvent(new Event("focusout"));
    vi.advanceTimersByTime(ROTATE_EVERY_MS);
    expect(shown()).toBe(SHARE_TARGETS[1]);
  });

  it("clears its timer when the returned stop function is called", () => {
    const wrapper = mountHero(false);
    const stop = startShareTargetRotation(wrapper);

    expect(vi.getTimerCount()).toBe(1);
    stop();
    expect(vi.getTimerCount()).toBe(0);
  });
});
