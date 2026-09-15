import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Share SDK merge gates", () => {
  it("runs the production build and origin contract after the core checks", () => {
    const workflow = readFileSync(".github/workflows/share-sdk.yml", "utf8");
    const commands = [
      "npm ci",
      "npm run typecheck",
      "npm test",
      "npm run build:deploy",
      "npm run test:e2e:production-origin-contract",
    ];
    const positions = commands.map((command) => workflow.indexOf(`- run: ${command}`));

    expect(positions.every((position) => position >= 0)).toBe(true);
    expect(positions).toEqual([...positions].sort((left, right) => left - right));
  });
});
