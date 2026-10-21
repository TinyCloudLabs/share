import { describe, expect, it } from "vitest";

import { possessive } from "../src/apps/possessive.ts";

describe("possessive", () => {
  it("adds 's to a name, and only an apostrophe to a name that already ends in s", () => {
    expect(possessive("Health Log")).toBe("Health Log's");
    expect(possessive("Recipes")).toBe("Recipes'");
    expect(possessive("recipes")).toBe("recipes'");
  });
});
