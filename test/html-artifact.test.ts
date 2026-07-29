import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ArtifactBundleError,
  artifactMediaType,
  canonicalArtifactPath,
  detectHtmlArtifact,
  prepareHtmlArtifact,
  resolveArtifactReference,
  type ArtifactFile,
} from "../src/artifact/bundle.js";
import {
  ARTIFACT_SANDBOX_CSP,
  ARTIFACT_SANDBOX_HTTP_HEADERS,
  ARTIFACT_SANDBOX_PATH,
  buildArtifactSandboxHtml,
} from "../src/viewer/artifact-frame.js";
import { createArtifactSandbox } from "../src/viewer/artifact-sandbox.js";
import { mountArtifactChrome } from "../src/viewer/artifact-chrome.js";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

function utf8(path: string, value: string, mediaType?: string): ArtifactFile {
  return { path, bytes: new TextEncoder().encode(value), ...(mediaType === undefined ? {} : { mediaType }) };
}

function fixtureFiles(): ArtifactFile[] {
  const base = "examples/html-artifact/";
  return [
    utf8("index.html", readFileSync(`${base}index.html`, "utf8"), "text/html"),
    utf8("styles/site.css", readFileSync(`${base}styles/site.css`, "utf8"), "text/css"),
    utf8("scripts/app.js", readFileSync(`${base}scripts/app.js`, "utf8"), "text/javascript"),
    utf8("assets/cloud.svg", readFileSync(`${base}assets/cloud.svg`, "utf8"), "image/svg+xml"),
  ];
}

describe("HTML artifact bundle paths and detection", () => {
  it("detects exactly one canonical root index while ordinary folders stay compatible", () => {
    expect(detectHtmlArtifact(["index.html", "styles/site.css"])).toEqual({ kind: "html", entry: "index.html" });
    expect(detectHtmlArtifact(["site/index.html", "styles/site.css"])).toEqual({ kind: "folder", reason: "missing-root-index" });
    expect(() => detectHtmlArtifact(["index.html", "INDEX.HTML"])).toThrow(ArtifactBundleError);
  });

  it.each(["../secret", "/absolute", "a\\b", "a/%2e%2e/b", "a//b", "a/./b"])(
    "rejects unsafe canonical path %s",
    (path) => expect(() => canonicalArtifactPath(path)).toThrow(ArtifactBundleError),
  );

  it("resolves nested relatives and ignores lookup query/hash suffixes without allowing escape", () => {
    expect(resolveArtifactReference("pages/about/index.html", "../../assets/cloud.svg?v=2#mark")).toEqual({
      path: "assets/cloud.svg",
      fragment: "#mark",
      fragmentOnly: false,
    });
    expect(() => resolveArtifactReference("index.html", "../secret.txt")).toThrow(ArtifactBundleError);
    expect(() => resolveArtifactReference("index.html", "https://example.com/a.png")).toThrow(ArtifactBundleError);
    expect(artifactMediaType("assets/type.woff2")).toBe("font/woff2");
  });
});

describe("HTML artifact resource preparation", () => {
  it("rewrites the realistic fixture into a self-contained page with classic script intact", async () => {
    const artifact = await prepareHtmlArtifact(fixtureFiles());
    const page = artifact.pages["index.html"]!;
    expect(artifact).toMatchObject({ entry: "index.html", fileCount: 4 });
    expect(page).toContain("data:image/svg+xml;base64,");
    expect(page).toContain("<style>");
    expect(page).toContain("Send a signal");
    expect(page).toContain("Sandbox isolation confirmed.");
    expect(page).not.toContain('src="scripts/app.js"');
    expect(page).not.toContain('href="styles/site.css');
    expect(page).not.toContain("https://");
    expect(page).toContain("connect-src 'none'");
    expect(page).toContain("window.parent.postMessage");
  });

  it("supports bounded CSS imports, URLs, srcset, and internal HTML navigation", async () => {
    const artifact = await prepareHtmlArtifact([
      utf8("index.html", '<link rel="stylesheet" href="css/a.css"><img style="background:url(img/a.png)" srcset="img/a.png 1x, img/b.png?x=1 2x"><a href="pages/about.html#team">About</a>'),
      utf8("css/a.css", '@import url(./b.css) screen; body{background:url("../img/a.png#x")}'),
      utf8("css/b.css", "p{color:navy}"),
      { path: "img/a.png", bytes: new Uint8Array([1]), mediaType: "image/png" },
      { path: "img/b.png", bytes: new Uint8Array([2]), mediaType: "image/png" },
      utf8("pages/about.html", "<h1 id=team>Team</h1>"),
    ]);
    const page = artifact.pages["index.html"]!;
    expect(page).toContain("@media screen");
    expect(page.match(/data:image\/png;base64,/g)).toHaveLength(4);
    expect(page).toContain('data-tc-artifact-path="pages/about.html"');
    expect(page).toContain('data-tc-artifact-fragment="#team"');
    expect(artifact.pages["pages/about.html"]).toContain("Team");
  });

  it.each([
    [fixtureFiles().filter((file) => file.path !== "assets/cloud.svg"), "missing"],
    [[utf8("index.html", '<img src="https://tracker.example/pixel">')], "unsupported"],
    [[utf8("index.html", '<button onclick="alert(1)">Hi</button>')], "unsupported"],
    [[utf8("index.html", '<script>fetch("/private")</script>')], "unsupported"],
    [[utf8("index.html", '<script type="module">export default 1</script>')], "unsupported"],
    [[utf8("index.html", '<form action="/send"></form>')], "unsupported"],
    [[utf8("index.html", '<link rel="stylesheet" href="a.css">'), utf8("a.css", '@import "b.css";'), utf8("b.css", '@import "a.css";')], "unsupported"],
  ] as const)("fails closed for missing, external, dynamic, module, form, or cyclic input", async (files, kind) => {
    await expect(prepareHtmlArtifact(files)).rejects.toMatchObject({ kind });
  });

  it("fails closed at file-count and rendered-resource limits", async () => {
    const tooMany = Array.from({ length: 1_001 }, (_, index) => utf8(index === 0 ? "index.html" : `files/${index}.txt`, "x"));
    await expect(prepareHtmlArtifact(tooMany)).rejects.toMatchObject({ kind: "limit" });
    await expect(prepareHtmlArtifact([
      utf8("index.html", '<img src="large.png">'),
      { path: "large.png", bytes: new Uint8Array(10 * 1024 * 1024 + 1), mediaType: "image/png" },
    ])).rejects.toMatchObject({ kind: "limit" });
  });
});

describe("artifact sandbox boundary", () => {
  it("ships an opaque-origin, network-denying CSP and production frame headers", () => {
    expect(ARTIFACT_SANDBOX_CSP).toContain("connect-src 'none'");
    expect(ARTIFACT_SANDBOX_CSP).toContain("form-action 'none'");
    expect(ARTIFACT_SANDBOX_CSP).toContain("navigate-to 'none'");
    expect(ARTIFACT_SANDBOX_CSP).toContain("frame-src 'none'");
    expect(buildArtifactSandboxHtml()).toContain(`content="${ARTIFACT_SANDBOX_CSP}"`);
    expect(ARTIFACT_SANDBOX_HTTP_HEADERS).toContainEqual(["content-security-policy", "frame-ancestors 'self'"]);
    const headers = readFileSync("public/_headers", "utf8");
    expect(headers).toContain(ARTIFACT_SANDBOX_PATH);
    expect(headers).toContain("X-Frame-Options: SAMEORIGIN");
  });

  it("uses allow-scripts without allow-same-origin and accepts only nonce-bound frame messages", async () => {
    const sandbox = createArtifactSandbox(document);
    expect(sandbox.iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(sandbox.iframe.getAttribute("sandbox")).not.toContain("allow-same-origin");
    const nonce = new URL(sandbox.iframe.src).hash.slice(1);
    const post = vi.spyOn(sandbox.iframe.contentWindow!, "postMessage");
    const render = sandbox.render(await prepareHtmlArtifact([utf8("index.html", "<h1>Safe</h1>")]));
    window.dispatchEvent(new MessageEvent("message", {
      source: sandbox.iframe.contentWindow,
      origin: "null",
      data: { type: "ready", nonce: "wrong" },
    }));
    expect(post).not.toHaveBeenCalled();
    window.dispatchEvent(new MessageEvent("message", {
      source: sandbox.iframe.contentWindow,
      origin: "null",
      data: { type: "ready", nonce },
    }));
    expect(post).toHaveBeenCalledTimes(1);
    const request = post.mock.calls[0]![0] as { id: string };
    window.dispatchEvent(new MessageEvent("message", {
      source: sandbox.iframe.contentWindow,
      origin: "null",
      data: { type: "result", nonce, id: request.id, ok: true },
    }));
    await expect(render).resolves.toBeUndefined();
    sandbox.destroy();
  });
});

describe("TinyCloud artifact chrome", () => {
  beforeEach(() => {
    document.body.replaceChildren();
    localStorage.clear();
    window.history.replaceState(null, "", "/s/example");
  });
  afterEach(() => vi.restoreAllMocks());

  it("collapses, reopens, permanently hides, and restores accessibly without rendering the URL", async () => {
    const url = "https://share.tinycloud.xyz/s/example#private-fragment";
    await mountArtifactChrome(document, { shareId: "share-a", shareUrl: url });
    const root = document.querySelector<HTMLElement>(".artifact-chrome")!;
    const panel = root.querySelector<HTMLElement>(".artifact-chrome-panel")!;
    const cloud = root.querySelector<HTMLButtonElement>(".artifact-chrome-cloud")!;
    expect(root.textContent).toContain("Shared with TinyCloud");
    expect(root.textContent).not.toContain(url);
    expect(cloud.getAttribute("aria-label")).toBe("Open TinyCloud sharing controls");

    root.querySelector<HTMLButtonElement>(".artifact-chrome-button")!.click();
    expect(panel.hidden).toBe(true);
    expect(cloud.hidden).toBe(false);
    cloud.click();
    expect(panel.hidden).toBe(false);

    root.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    expect(root.hidden).toBe(true);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", altKey: true, shiftKey: true }));
    expect(root.hidden).toBe(false);
    expect(panel.hidden).toBe(false);
    expect(document.activeElement).toBe(root.querySelector<HTMLButtonElement>(".artifact-chrome-button"));
  });

  it("prefers Web Share and keeps status announcements outside the collapsible panel", async () => {
    const share = vi.fn().mockResolvedValue(undefined);
    await mountArtifactChrome(document, {
      shareId: "share-b",
      shareUrl: "https://share.tinycloud.xyz/s/example#secret",
      navigator: { clipboard: navigator.clipboard, share },
    });
    const root = document.querySelector<HTMLElement>(".artifact-chrome")!;
    root.querySelectorAll<HTMLButtonElement>(".artifact-chrome-button")[1]!.click();
    await vi.waitFor(() => expect(share).toHaveBeenCalledOnce());
    expect(root.querySelector(".artifact-chrome-status")?.parentElement).toBe(root);
  });

  it("keeps the controls usable when browser storage is unavailable", async () => {
    const unavailable = {
      get length() { throw new DOMException("denied", "SecurityError"); },
      clear() { throw new DOMException("denied", "SecurityError"); },
      getItem() { throw new DOMException("denied", "SecurityError"); },
      key() { throw new DOMException("denied", "SecurityError"); },
      removeItem() { throw new DOMException("denied", "SecurityError"); },
      setItem() { throw new DOMException("denied", "SecurityError"); },
    } as unknown as Storage;
    await expect(mountArtifactChrome(document, { shareId: "share-c", storage: unavailable })).resolves.toBeDefined();
    const root = document.querySelector<HTMLElement>(".artifact-chrome")!;
    root.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    expect(root.hidden).toBe(true);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", altKey: true, shiftKey: true }));
    expect(root.hidden).toBe(false);
  });
});
