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
  ARTIFACT_SANDBOX_HTTP_CSP,
  ARTIFACT_SANDBOX_HTTP_HEADERS,
  ARTIFACT_SANDBOX_PATH,
  buildArtifactSandboxHtml,
} from "../src/viewer/artifact-frame.js";
import { SANDBOX_PERMISSIONS_POLICY } from "../src/viewer/sandbox-permissions.js";
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

  it("allows benign local classic-script helpers named open", async () => {
    const artifact = await prepareHtmlArtifact([
      utf8("index.html", "<script>function open(){ return 1; } open();</script>"),
    ]);
    const page = artifact.pages["index.html"]!;
    expect(page).toContain("function open()");
    expect(page).toContain("open();");
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

  it("preserves stylesheet media guards when inlining linked and embedded CSS", async () => {
    const artifact = await prepareHtmlArtifact([
      utf8("index.html", '<link rel="stylesheet" href="css/a.css" media="print"><style media="screen">body{color:teal}</style>'),
      utf8("css/a.css", "body{background:papayawhip}"),
    ]);
    const page = artifact.pages["index.html"]!;
    expect(page).toContain("@media print");
    expect(page).toContain("@media screen");
  });

  it.each([
    [fixtureFiles().filter((file) => file.path !== "assets/cloud.svg"), "missing"],
    [[utf8("index.html", '<img src="https://tracker.example/pixel">')], "unsupported"],
    [[utf8("index.html", '<link rel="preload" href="bundle.js">')], "unsupported"],
    [[utf8("index.html", '<script>window.open("https://example.com")</script>')], "unsupported"],
    [[utf8("index.html", '<link rel="stylesheet" href="a.css" media="screen}</style><script>bad()</script>">'), utf8("a.css", "body{color:red}")], "unsupported"],
    [[utf8("index.html", '<style media="print}</style><script>bad()</script>">body{color:red}</style>')], "unsupported"],
    [[utf8("index.html", '<button onclick="alert(1)">Hi</button>')], "unsupported"],
    [[utf8("index.html", '<script>fetch("/private")</script>')], "unsupported"],
    [[utf8("index.html", '<script>location.href="/private"</script>')], "unsupported"],
    [[utf8("index.html", '<script type="module">export default 1</script>')], "unsupported"],
    [[utf8("index.html", '<form action="/send"></form>')], "unsupported"],
    [[utf8("index.html", '<link rel="stylesheet" href="a.css">'), utf8("a.css", '@import "b.css";'), utf8("b.css", '@import "a.css";')], "unsupported"],
  ] as const)("fails closed for missing, external, rel/media, dynamic, module, form, or cyclic input", async (files, kind) => {
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
  it("ships an opaque-origin, connection-refusing CSP and production frame headers", () => {
    expect(ARTIFACT_SANDBOX_CSP).toContain("connect-src 'none'");
    expect(ARTIFACT_SANDBOX_CSP).toContain("form-action 'none'");
    expect(ARTIFACT_SANDBOX_CSP).toContain("frame-src 'none'");
    expect(ARTIFACT_SANDBOX_CSP).not.toContain("navigate-to");
    expect(buildArtifactSandboxHtml()).toContain(`content="${ARTIFACT_SANDBOX_CSP}"`);
    // Nothing in the viewer listens for a restore message, so the bridge no longer relays one.
    expect(buildArtifactSandboxHtml()).not.toContain("artifact-restore-controls");
    // Dev/preview (Vite) and production (public/_headers) must serve the same
    // complete frame policy, with the site-wide policy detached first.
    expect(ARTIFACT_SANDBOX_HTTP_HEADERS).toContainEqual(["content-security-policy", ARTIFACT_SANDBOX_HTTP_CSP]);
    // Fullscreen and Picture-in-Picture stay off for the artifact frames, as for JSX.
    expect(ARTIFACT_SANDBOX_HTTP_HEADERS).toContainEqual(["permissions-policy", SANDBOX_PERMISSIONS_POLICY]);
    expect(SANDBOX_PERMISSIONS_POLICY).toMatch(/fullscreen=\(\).*picture-in-picture=\(\)/);
    const headers = readFileSync("public/_headers", "utf8");
    for (const route of ["/artifact-sandbox", ARTIFACT_SANDBOX_PATH]) {
      expect(headers).toContain(`\n${route}\n  ! Content-Security-Policy\n  Content-Security-Policy: ${ARTIFACT_SANDBOX_HTTP_CSP}\n  Permissions-Policy: ${SANDBOX_PERMISSIONS_POLICY}\n  X-Frame-Options: SAMEORIGIN\n`);
    }
  });

  it("uses allow-scripts without allow-same-origin and accepts only nonce-bound frame messages", async () => {
    const sandbox = createArtifactSandbox(document);
    expect(sandbox.iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(sandbox.iframe.getAttribute("sandbox")).not.toContain("allow-same-origin");
    // No permissions are delegated to the artifact frame (fullscreen, Picture-in-Picture, camera, ...).
    expect(sandbox.iframe.getAttribute("allow")).toBe("");
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
  const base = {
    title: "report.md",
    provenance: "Sender unverified",
    expiry: { text: "Jan 1, 2030", datetime: "2030-01-01T00:00:00.000Z" },
  };
  beforeEach(() => {
    document.body.replaceChildren();
    localStorage.clear();
    window.history.replaceState(null, "", "/viewer");
  });
  afterEach(() => vi.restoreAllMocks());

  it("hides to a recall pill, restores by pill and chord, and remembers per share", async () => {
    const chrome = await mountArtifactChrome(document, { ...base, shareId: "share-a", actions: [] });
    const bar = document.querySelector<HTMLElement>(".artifact-chrome")!;
    const pill = document.querySelector<HTMLButtonElement>(".artifact-chrome-pill")!;
    expect(bar.textContent).toContain("report.md");
    expect(bar.textContent).toContain("Expires Jan 1, 2030");
    expect(bar.textContent).not.toContain("Hide permanently");
    expect(pill.hidden).toBe(true);

    bar.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    expect(bar.hidden).toBe(true);
    expect(pill.hidden).toBe(false);
    expect(document.activeElement).toBe(pill);
    expect(document.querySelector(".artifact-chrome-status")?.textContent).toContain("Alt+Shift+C");

    window.dispatchEvent(new KeyboardEvent("keydown", { key: "C", altKey: true, shiftKey: true }));
    expect(bar.hidden).toBe(false);
    expect(pill.hidden).toBe(true);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", altKey: true }));
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", shiftKey: true }));
    expect(bar.hidden).toBe(false);

    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", altKey: true, shiftKey: true }));
    expect(bar.hidden).toBe(true);
    chrome.destroy();
    // Hidden state survives a reload of the same share, not of another one.
    await mountArtifactChrome(document, { ...base, shareId: "share-a", actions: [] });
    expect(document.querySelector<HTMLElement>(".artifact-chrome")!.hidden).toBe(true);
    expect(document.querySelector<HTMLElement>(".artifact-chrome-pill")!.hidden).toBe(false);
    document.querySelector<HTMLButtonElement>(".artifact-chrome-pill")!.click();
    expect(document.querySelector<HTMLElement>(".artifact-chrome")!.hidden).toBe(false);
    expect(localStorage.length).toBe(0);
  });

  it("has no message channel: no window message, from any source, shows or hides the bar", async () => {
    const sandbox = createArtifactSandbox(document);
    await mountArtifactChrome(document, { ...base, shareId: "share-e", actions: [] });
    const bar = document.querySelector<HTMLElement>(".artifact-chrome")!;
    const send = (source: MessageEventSource | null, data: unknown): void => { window.dispatchEvent(new MessageEvent("message", { source, origin: "null", data })); };
    const messages = [{ type: "artifact-restore-controls" }, { type: "artifact-hide-controls" }, { type: "artifact-toggle-controls" }, { type: "cap/read" }, "artifact-restore-controls", null, 42];
    for (const data of messages) for (const source of [sandbox.iframe.contentWindow, window, null]) { send(source, data); expect(bar.hidden, JSON.stringify(data)).toBe(false); }
    bar.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    expect(bar.hidden).toBe(true);
    for (const data of messages) for (const source of [sandbox.iframe.contentWindow, window, null]) { send(source, data); expect(bar.hidden, JSON.stringify(data)).toBe(true); }
    sandbox.destroy();
  });

  it("shows Copy and Download results where a sighted user can see them, and announces them too", async () => {
    const copy = vi.fn().mockResolvedValue(undefined);
    const fail = vi.fn().mockRejectedValue(new Error("denied"));
    await mountArtifactChrome(document, {
      ...base,
      shareId: "share-b",
      actions: [
        { label: "Copy link", icon: "link", doneLabel: "Copied", doneMessage: "Link copied", hint: "Keep this link: this page can't reopen the file by itself", run: copy },
        { label: "Copy text", icon: "copy", failMessage: "Couldn't copy the text. Allow clipboard access and try again.", run: fail },
        { label: "Download", icon: "download", run: fail },
        { label: "Share on", icon: "share", disabledReason: "The owner hasn't allowed passing this on yet" },
      ],
    });
    const bar = document.querySelector<HTMLElement>(".artifact-chrome")!;
    const toast = document.querySelector<HTMLElement>(".artifact-chrome-toast")!;
    const [copyLink, copyText, download, shareOn] = Array.from(bar.querySelectorAll<HTMLButtonElement>(".artifact-chrome-button"));
    // The toast exists before it speaks (a live region must), and is not the clipped status span.
    expect(toast.textContent).toBe("");
    expect(toast.classList.contains("artifact-chrome-status")).toBe(false);
    expect(bar.contains(toast)).toBe(false);

    copyLink!.click();
    await vi.waitFor(() => expect(toast.textContent).toBe("Link copied"));
    expect(toast.getAttribute("role")).toBe("status");
    expect(copyLink!.textContent).toContain("Copied");
    expect(document.getElementById(copyLink!.getAttribute("aria-describedby")!)?.textContent).toContain("can't reopen the file by itself");
    expect(copyLink!.title).toContain("Keep this link");

    copyText!.click();
    await vi.waitFor(() => expect(toast.getAttribute("role")).toBe("alert"));
    expect(toast.textContent).toBe("Couldn't copy the text. Allow clipboard access and try again.");
    download!.click();
    await vi.waitFor(() => expect(toast.textContent).toContain("Download failed"));
    expect(toast.textContent).not.toMatch(/clipboard/i);

    expect(shareOn!.disabled).toBe(true);
    expect(document.getElementById(shareOn!.getAttribute("aria-describedby")!)?.textContent).toBe("The owner hasn't allowed passing this on yet");
  });

  it("clears the toast on its own, longer for a refusal than for success", async () => {
    vi.useFakeTimers();
    try {
      await mountArtifactChrome(document, { ...base, shareId: "share-t", actions: [{ label: "Copy link", icon: "link", doneMessage: "Link copied", run: () => undefined }, { label: "Copy text", icon: "copy", run: () => { throw new Error("denied"); } }] });
      const toast = document.querySelector<HTMLElement>(".artifact-chrome-toast")!;
      const [ok, no] = Array.from(document.querySelectorAll<HTMLButtonElement>(".artifact-chrome-button"));
      ok!.click();
      await vi.advanceTimersByTimeAsync(10);
      expect(toast.textContent).toBe("Link copied");
      await vi.advanceTimersByTimeAsync(4_100);
      expect(toast.textContent).toBe("");
      no!.click();
      await vi.advanceTimersByTimeAsync(10);
      expect(toast.textContent).toContain("failed");
      await vi.advanceTimersByTimeAsync(4_100);
      expect(toast.textContent).toContain("failed");
      await vi.advanceTimersByTimeAsync(4_100);
      expect(toast.textContent).toBe("");
    } finally { vi.useRealTimers(); }
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
    await expect(mountArtifactChrome(document, { ...base, shareId: "share-c", actions: [], storage: unavailable })).resolves.toBeDefined();
    const bar = document.querySelector<HTMLElement>(".artifact-chrome")!;
    bar.querySelector<HTMLButtonElement>(".artifact-chrome-hide")!.click();
    expect(bar.hidden).toBe(true);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "c", altKey: true, shiftKey: true }));
    expect(bar.hidden).toBe(false);
  });
});
