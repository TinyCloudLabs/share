import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const html = readFileSync(resolve(import.meta.dirname, "../share/index.html"), "utf8");
const llms = readFileSync(resolve(import.meta.dirname, "../public/llms.txt"), "utf8");

describe("recipient CLI guidance", () => {
  it("separates bearer CLI receive from addressed browser claim and names the planned agent path", () => {
    for (const copy of [html, llms]) {
      expect(copy).toContain("CLAIM_REQUIRED");
      expect(copy).toContain("Share browser");
    }
    expect(html).toContain("For a link anyone holding it can open, your agent can read the shared content using the TinyCloud CLI.");
    expect(html).toContain("For a link addressed to your email, open it in the Share browser and enter the one-time code");
    expect(html).not.toContain("TC-1757");
    expect(html).not.toContain("completeEmailProof");
    expect(html).not.toContain("HolderSigner");
    expect(html).not.toContain("Until then");
    expect(llms).toContain("This CLI receive command is for bearer links only");
    expect(llms).not.toContain("TC-1757's");
    expect(llms).toContain("TC-1757 proof flow");
    expect(llms).toContain("not yet published and wired");
    expect(llms).toContain("`completeEmailProof`");
    expect(llms).toContain("`HolderSigner` backed by the recipient agent's session key");
    expect(html).toMatch(/<\/div>\s*<aside class="sender-form share-instructions"/);
  });

  it("uses the tinycloud executable in published share examples", () => {
    expect(llms).not.toMatch(/\btc share\b/);
    expect(llms).toContain("tinycloud share publish");
    expect(llms).toContain("tinycloud share show");
    expect(llms).toContain("tinycloud share revoke");
    expect(llms).toContain("tinycloud share receive");
  });
});
