import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const html = readFileSync(resolve(import.meta.dirname, "../share/index.html"), "utf8");
const llms = readFileSync(resolve(import.meta.dirname, "../public/llms.txt"), "utf8");

describe("recipient CLI guidance", () => {
  it("separates bearer CLI receive from addressed browser claim and names the planned agent path", () => {
    for (const copy of [html, llms]) {
      expect(copy).toContain("CLAIM_REQUIRED");
      expect(copy).toContain("completeEmailProof");
      expect(copy).toContain("HolderSigner");
      expect(copy).toContain("recipient agent's session key");
      expect(copy).toContain("not yet published and wired");
      expect(copy).toContain("Share browser");
    }
    expect(html).toContain("For a bearer link, an agent can use the installed CLI");
    expect(llms).toContain("This CLI receive command is for bearer links only");
  });

  it("uses the tinycloud executable in published share examples", () => {
    expect(llms).not.toMatch(/\btc share\b/);
    expect(llms).toContain("tinycloud share publish");
    expect(llms).toContain("tinycloud share show");
    expect(llms).toContain("tinycloud share revoke");
    expect(llms).toContain("tinycloud share receive");
  });
});
