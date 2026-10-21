import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { renderLandingTemplate } from "../src/landing/brand.ts";
import {
  ROTATE_EVERY_MS,
  ROTATE_STOP_AFTER_MS,
  SHARE_TARGETS,
  startShareTargetRotation,
} from "../src/landing/share-targets.ts";

const rendered = renderLandingTemplate(readFileSync(join(process.cwd(), "index.html"), "utf8"));

const PLANNED_NOT_LIVE = ["your family", "your team", "your friend group", "your group chat"];

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
  it("lists at least three live phrases, none about links", () => {
    expect(SHARE_TARGETS.length).toBeGreaterThanOrEqual(3);
    expect(SHARE_TARGETS.filter((phrase) => phrase.includes("link"))).toEqual([]);
  });

  it("keeps planned-but-not-live recipient kinds out of the array", () => {
    for (const planned of PLANNED_NOT_LIVE) expect(SHARE_TARGETS).not.toContain(planned);
  });

  it("renders the first phrase statically in the hero sentence", () => {
    mountHero(false);
    expect(shown()).toBe(SHARE_TARGETS[0]);
    expect(document.querySelector(".hero-share-line")!.textContent).toContain(SHARE_TARGETS[0]!);
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

  it("cycles through every phrase, then stops and settles on the first", () => {
    const wrapper = mountHero(false);
    startShareTargetRotation(wrapper);

    const seen = new Set<string | null>([shown()]);
    for (let step = 0; step < ROTATE_STOP_AFTER_MS / ROTATE_EVERY_MS; step++) {
      vi.advanceTimersByTime(ROTATE_EVERY_MS);
      seen.add(shown());
    }

    expect([...seen].sort()).toEqual([...SHARE_TARGETS].sort());
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
