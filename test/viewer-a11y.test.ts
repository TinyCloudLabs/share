import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const css = readFileSync(
  resolve(process.cwd(), "src/viewer/viewer.css"),
  "utf8",
);

function rgb(hex: string): readonly [number, number, number] {
  const match = hex.match(/^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i);
  if (match === null) throw new Error(`expected six-digit color: ${hex}`);
  return [
    Number.parseInt(match[1]!, 16),
    Number.parseInt(match[2]!, 16),
    Number.parseInt(match[3]!, 16),
  ];
}

function luminance(hex: string): number {
  const channels = rgb(hex).map((channel) => {
    const value = channel / 255;
    return value <= 0.04045
      ? value / 12.92
      : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!;
}

function contrast(left: string, right: string): number {
  const a = luminance(left);
  const b = luminance(right);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function token(block: string, name: string): string {
  const value = block.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`))?.[1];
  if (value === undefined) throw new Error(`missing --${name}`);
  return value;
}

describe("viewer WCAG color tokens", () => {
  it("keeps small text and focus indicators above their AA contrast floors", () => {
    const light = css.match(/:root\s*{([^}]*)}/s)?.[1];
    const dark = css.match(/prefers-color-scheme:\s*dark[\s\S]*?:root\s*{([^}]*)}/)?.[1];
    if (light === undefined || dark === undefined) throw new Error("missing theme blocks");

    for (const theme of [light, dark]) {
      const background = token(theme, "bg");
      expect(contrast(token(theme, "ink-faint"), background)).toBeGreaterThanOrEqual(4.5);
      expect(contrast(token(theme, "focus-ring"), background)).toBeGreaterThanOrEqual(3);
    }
    expect(css).toContain("outline: 3px solid var(--focus-ring)");
  });
});
