import { describe, expect, it } from "vitest";

import { createPreviewFrame } from "../src/viewer/preview-frame.js";
import { markdownToSanitizedHtml } from "../src/viewer/render.js";

/** Render markdown through the real pipeline and return the parsed tree. */
async function rendered(markdown: string): Promise<HTMLElement> {
  const root = document.createElement("div");
  root.innerHTML = await markdownToSanitizedHtml(markdown);
  return root;
}

describe("external links open in a new tab", () => {
  it.each([
    ["https", "[docs](https://example.com/guide)", "https://example.com/guide"],
    ["http", "[docs](http://example.com/guide)", "http://example.com/guide"],
  ])("%s link keeps its destination and opens in a new tab", async (_scheme, markdown, href) => {
    const link = (await rendered(markdown)).querySelector("a");
    expect(link).not.toBeNull();
    expect(link?.getAttribute("href")).toBe(href);
    expect(link?.getAttribute("target")).toBe("_blank");
    expect(link?.getAttribute("rel")).toBe("noopener noreferrer");
    expect(link?.textContent).toBe("docs");
  });

  it("title names the destination host, not the full URL", async () => {
    const link = (await rendered("[x](https://Example.COM:8443/a/b?q=1)")).querySelector("a");
    expect(link?.getAttribute("title")).toBe("example.com:8443");
  });

  it("mailto link opens in a new tab and titles the address", async () => {
    const link = (await rendered("[mail](mailto:team@example.com)")).querySelector("a");
    expect(link?.getAttribute("href")).toBe("mailto:team@example.com");
    expect(link?.getAttribute("target")).toBe("_blank");
    expect(link?.getAttribute("rel")).toBe("noopener noreferrer");
    expect(link?.getAttribute("title")).toBe("Email team@example.com");
  });
});

describe("destinations that cannot open stay as inert text", () => {
  it.each([
    ["javascript:", "[x](javascript:alert(1))"],
    ["data:", "[x](data:text/html,<script>alert(1)</script>)"],
    ["vbscript:", "[x](vbscript:msgbox(1))"],
    ["file:", "[x](file:///etc/passwd)"],
    ["blob:", "[x](blob:https://example.com/3f2a)"],
  ])("%s destination is dropped", async (_scheme, markdown) => {
    const root = await rendered(markdown);
    expect(root.querySelector("a")).toBeNull();
    expect(root.querySelector("span.viewer-inert-link")?.textContent).toBe("x");
    expect(root.querySelector("span.viewer-inert-link")?.hasAttribute("href")).toBe(false);
  });

  it.each([
    ["tab inside the scheme", "[x](jav&#x09;ascript:alert(1))"],
    ["entity-encoded scheme", "[x](&#106;avascript:alert(1))"],
    ["mixed case", "[x](JaVaScRiPt:alert(1))"],
    ["leading whitespace before scheme", "[x](&#32;javascript:alert(1))"],
  ])("obfuscated javascript: (%s) is dropped", async (_label, markdown) => {
    const root = await rendered(markdown);
    expect(root.querySelector("a")).toBeNull();
    expect(root.innerHTML).not.toMatch(/javascript:/i);
  });

  it("protocol-relative destination is dropped", async () => {
    const root = await rendered("[x](//evil.example/a)");
    expect(root.querySelector("a")).toBeNull();
    expect(root.querySelector("span.viewer-inert-link")?.textContent).toBe("x");
  });

  it.each([
    ["same-document anchor", "[x](#section-2)"],
    ["relative file", "[x](./notes.md)"],
    ["root-relative path", "[x](/share/abc)"],
    ["bare relative path", "[x](notes.md)"],
  ])("%s becomes inert text and never navigates the frame", async (_label, markdown) => {
    const root = await rendered(markdown);
    expect(root.querySelector("a")).toBeNull();
    expect(root.querySelector("span.viewer-inert-link")?.textContent).toBe("x");
    expect(root.querySelector("span.viewer-inert-link")?.hasAttribute("href")).toBe(false);
  });
});

describe("preview frame sandbox", () => {
  it("grants only popup tokens, never scripts, same-origin, top navigation or forms", () => {
    const frame = createPreviewFrame(document, "<p>x</p>", 0);
    const tokens = (frame.getAttribute("sandbox") ?? "").split(" ").filter(Boolean).sort();
    expect(tokens).toEqual(["allow-popups", "allow-popups-to-escape-sandbox"]);
  });
});
