import { beforeEach, describe, expect, it, vi } from "vitest";

import { ARTIFACT_SANDBOX_HTTP_CSP } from "../src/viewer/artifact-frame.js";
import { NativeBearerError, classifyBearerFailure, receiveNativeBearer } from "../src/viewer/native-bearer.js";
import { PREVIEW_FRAME_CSP, buildPreviewDocument } from "../src/viewer/preview-frame.js";
import { BLOCKED_IMAGE_NOTICE, markdownToSanitizedHtml } from "../src/viewer/render.js";
import { renderShareUnavailable } from "../src/viewer/ui.js";

const URL_OF_LINK = "https://share.tinycloud.xyz/viewer#tc1=tc1%3Atoken";

describe("bearer failures reach the right screen", () => {
  it("classifies what the owner node and SDK say", () => {
    expect(classifyBearerFailure({ message: "Failed to register delegation: 401 - delegation-revoked: bafy123" })).toBe("revoked");
    expect(classifyBearerFailure({ message: "Failed to fetch shared data: 401 - Invalid invocation: delegation-ancestor-revoked: ancestor=bafyA invoked=bafyB" })).toBe("revoked");
    expect(classifyBearerFailure({ message: "Share link has expired", code: "AUTH_EXPIRED" })).toBe("expired");
    expect(classifyBearerFailure({ message: "Failed to fetch shared data: 503 - upstream down" })).toBe("unavailable");
    expect(classifyBearerFailure({ message: "Failed to fetch" })).toBe("unavailable");
    expect(classifyBearerFailure({ message: "Failed to fetch shared data: 401 - Unauthorized Action: space/kv/key" })).toBe("unverified");
  });

  it("throws a typed error carrying the reason, and reads the expiry from the link itself", async () => {
    const delegation = { cid: "x", expiry: "2026-10-12T08:00:00.000Z" };
    const token = `tc1:${btoa(JSON.stringify({ version: 1, delegation })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
    const link = `https://share.tinycloud.xyz/viewer#tc1=${encodeURIComponent(token)}`;
    const expired = await receiveNativeBearer(link, async () => ({ ok: false, error: { code: "AUTH_EXPIRED", message: "Share link has expired" } })).catch((error: unknown) => error);
    expect(expired).toBeInstanceOf(NativeBearerError);
    expect(expired).toMatchObject({ reason: "expired", expiresAt: "2026-10-12T08:00:00.000Z" });
    const revoked = await receiveNativeBearer(URL_OF_LINK, async () => { throw new Error("401 - delegation-revoked: bafy"); }).catch((error: unknown) => error);
    expect(revoked).toMatchObject({ reason: "revoked" });
    expect((revoked as NativeBearerError).expiresAt).toBeUndefined();
  });
});

describe("revoked, expired and unavailable screens", () => {
  beforeEach(() => document.body.replaceChildren());
  const open = (): HTMLElement => {
    const root = document.createElement("div");
    root.id = "viewer";
    document.body.append(root);
    // A previous verified share left the full-page layout on.
    document.body.classList.add("viewer-fullpage");
    root.append(Object.assign(document.createElement("main"), { className: "viewer-content", textContent: "SECRET BODY" }));
    return root;
  };

  it("says what happened, shows no content, and leaves the full-page layout", () => {
    const root = open();
    renderShareUnavailable(root, "revoked");
    expect(root.querySelector("h1")?.textContent).toBe("This share was revoked by its sender");
    expect(root.querySelector(".viewer-state")?.getAttribute("role")).toBe("alert");
    expect(root.textContent).not.toContain("SECRET BODY");
    expect(root.querySelector("iframe, .viewer-content, .artifact-chrome")).toBeNull();
    expect(document.body.classList.contains("viewer-fullpage")).toBe(false);
    expect(document.activeElement).toBe(root);
  });

  it("names the expiry date when the link carries one, and not a made-up one when it does not", () => {
    const root = open();
    renderShareUnavailable(root, "expired", "2026-10-12T08:00:00.000Z");
    expect(root.querySelector("h1")?.textContent).toMatch(/^This share expired on .*2026/);
    renderShareUnavailable(root, "expired");
    expect(root.querySelector("h1")?.textContent).toBe("This share has expired");
  });

  it("offers a retry only for a temporary outage, and runs the caller's retry (the page is never reloaded)", () => {
    const root = open();
    const retry = vi.fn();
    renderShareUnavailable(root, "unavailable", undefined, retry);
    expect(root.querySelector("h1")?.textContent).toBe("TinyCloud is temporarily unavailable");
    root.querySelector<HTMLButtonElement>("button.viewer-state-action")!.click();
    expect(retry).toHaveBeenCalledOnce();
    renderShareUnavailable(root, "unavailable");
    expect(root.querySelector("button")).toBeNull();
    renderShareUnavailable(root, "revoked", undefined, retry);
    expect(root.querySelector("button")).toBeNull();
  });
});

describe("viewer privacy: a shared artifact makes no request", () => {
  it("replaces every non-inline image with text and shows the URL as text only", async () => {
    const html = await markdownToSanitizedHtml([
      "![tracker](https://tracker.example/pixel.png?u=1)",
      "![local](/relative.png)",
      "[![badge](https://tracker.example/badge.svg)](https://tracker.example/click)",
      "![inline](data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7)",
    ].join("\n\n"));
    const doc = new DOMParser().parseFromString(html, "text/html");
    expect(doc.querySelectorAll("img")).toHaveLength(1);
    expect(doc.querySelector("img")?.getAttribute("src")).toMatch(/^data:image\/gif/);
    const blocked = Array.from(doc.querySelectorAll(".viewer-blocked-image"));
    expect(blocked.map((node) => node.firstChild?.textContent)).toEqual([BLOCKED_IMAGE_NOTICE, BLOCKED_IMAGE_NOTICE, BLOCKED_IMAGE_NOTICE]);
    expect(blocked[0]?.querySelector("code")?.textContent).toBe("https://tracker.example/pixel.png?u=1");
    expect(blocked.some((node) => node.querySelector("img, a, source"))).toBe(false);
    // The only link left is the author's own text link wrapping the placeholder; it loads nothing.
    expect(html).not.toMatch(/<img[^>]+src="https?:/);
  });

  it("never lets raw HTML bring an image, stylesheet, video or prefetch into a document", async () => {
    const html = await markdownToSanitizedHtml('<img src="https://t.example/a.png"><link rel="stylesheet" href="https://t.example/a.css"><link rel="prefetch" href="https://t.example/p"><video src="https://t.example/v.mp4"></video>\n\ntext');
    expect(html).not.toMatch(/t\.example/);
    expect(html).not.toMatch(/<(?:img|link|video|style|script|iframe)\b/i);
  });

  it("makes scrollers keyboard reachable and names task-list checkboxes", async () => {
    const html = await markdownToSanitizedHtml("```\nlong code\n```\n\n| a | b |\n| - | - |\n| 1 | 2 |\n\n- [x] done\n- [ ] todo");
    const doc = new DOMParser().parseFromString(html, "text/html");
    expect(doc.querySelector("pre")?.getAttribute("tabindex")).toBe("0");
    expect(doc.querySelector("table")?.getAttribute("tabindex")).toBe("0");
    expect(Array.from(doc.querySelectorAll("input[type=checkbox]"), (node) => node.getAttribute("aria-label"))).toEqual(["Completed task", "Incomplete task"]);
  });

  it("pins both frames to inline-only resources", () => {
    expect(PREVIEW_FRAME_CSP).toBe("default-src 'none'; img-src data: blob:; font-src data: blob:; style-src 'unsafe-inline'");
    const document = buildPreviewDocument("<p>x</p>", 1);
    expect(document).toContain(`content="${PREVIEW_FRAME_CSP}"`);
    // Tokens, base and prose are inlined: no stylesheet, font, script or import can be fetched.
    expect(document).not.toMatch(/<link\b|<script\b|@import|url\(\s*["']?https?:|@font-face/i);
    expect(document).not.toMatch(/Inter\b/);
    expect(document).toContain("data-theme=\"system\"");
    expect(document).toContain("tc-prose");
    for (const csp of [PREVIEW_FRAME_CSP, ARTIFACT_SANDBOX_HTTP_CSP]) {
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("img-src data: blob:");
      expect(csp).not.toMatch(/(?:img|font|style|connect|media|script)-src[^;]*(?:'self'|https?:|\*)/);
    }
    expect(ARTIFACT_SANDBOX_HTTP_CSP).toContain("connect-src 'none'");
    expect(ARTIFACT_SANDBOX_HTTP_CSP).toContain("font-src data: blob:");
  });
});
