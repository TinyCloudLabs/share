/**
 * Defence in depth, inside the sandbox frame: refuse the elements and attributes that make the BROWSER
 * ask for a URL on the page's behalf.
 *
 * Why. The frame's CSP stops every content and script request (connect-src, img-src, ... all `'none'`, `data:` and
 * `blob:` only), but no CSP directive governs a few browser-initiated requests: `<link rel=prerender>` /
 * `prefetch` send a GET with whatever query the page chose, `<link rel=preconnect>` opens a connection,
 * `<link rel=dns-prefetch>` resolves a name, `<a ping>` posts to a URL, WebRTC sends STUN packets. For a page a
 * stranger shared that leaks little (the author already has what the page knows). For an installed app it can
 * carry the person's own data, read through the app's grants, to a host the app's author chose.
 *
 * What this does (best effort; it cannot be a boundary, because the page's code runs in the same realm):
 *  - a URL is SAFE only if it is empty, `#...`, `data:` or `blob:`. Anything else (including a relative URL, which
 *    would resolve to the user-content host) is not;
 *  - `vetElement(tag, attributes, text)` is the one rule set. A `<base>`, `<iframe>`, `<frame>`, `<object>`,
 *    `<embed>`, `<portal>`, `<applet>` or `<script>` is never allowed; a `<meta>` with `http-equiv` or a `url=` is
 *    not; any element with a `src`, `srcset`, `poster`, `data`, `action`, `formaction`, `ping`, `manifest`,
 *    `background`, `cite`, `codebase`, `archive`, `longdesc`, `imagesrcset` or `xlink:href` that is not safe is not
 *    (so `<link>`, `<img>`, `<source>`, `<video>`, `<audio>`, `<track>`, `<form>`, `<a ping>`, `<input type=image>`
 *    are allowed only with safe URLs); `href` is vetted on `<link>`, `<base>`, SVG `<image>`/`<use>`/`<feImage>`
 *    (a plain `<a href>` is a click the person makes); inline `style` and `<style>` text may not name a URL,
 *    `@import` or `image-set()` target that is not safe;
 *  - the React element functions (`guardedElementFunctions`, used by the frame's `react` module) return `null`
 *    for an element that fails, so the page never renders it;
 *  - `installDomGuard` patches every DOM path known to put a node into a tree or a value on an attribute: the node
 *    insertion methods (`Node`, `ChildNode` on `Element`/`CharacterData`/`DocumentType`, `ParentNode` on
 *    `Element`/`Document`/`DocumentFragment`, `insertAdjacentElement`, `Range.insertNode`/`surroundContents`), every HTML
 *    string sink (innerHTML/outerHTML, `insertAdjacentHTML`, `setHTML`/`setHTMLUnsafe`, `Document.parseHTMLUnsafe`,
 *    `createContextualFragment`, `execCommand('insertHTML')`; `document.write` is refused), and every attribute
 *    sink (`setAttribute(NS)`, `setAttributeNode(NS)`, `NamedNodeMap.setNamedItem(NS)`, `Attr.value/nodeValue/textContent`,
 *    the reflected URL properties). Elements are vetted before they land; a subtree is swept INCLUDING `<template>`
 *    content and shadow roots, and a `<template shadowrootmode>` (declarative shadow DOM) is refused. A
 *    MutationObserver removes whatever still gets in;
 *  - `RTCPeerConnection` is removed.
 * Best effort: these paths are known closed, and code in the same realm may find others (a MutationObserver runs
 * after the browser has already started a prerender or preconnect). The page says so; the measured leaks are in
 * docs/tiny-app-runner.md.
 */

const SAFE_URL = /^(?:#|data:|blob:)/i;
const CONTROL = /[\u0000-\u0020\u007f-\u009f]/g;

/** True for an empty URL, a fragment, `data:` or `blob:` (after the browser's own whitespace stripping). */
export function isSafeUrl(value: string): boolean {
  const url = value.replace(CONTROL, "");
  return url === "" || SAFE_URL.test(url);
}

const URL_ATTRIBUTES: ReadonlySet<string> = new Set(["src", "poster", "data", "action", "formaction", "ping", "manifest", "background", "cite", "codebase", "archive", "longdesc", "xlink:href", "profile", "usemap"]);
const SRCSET_ATTRIBUTES: ReadonlySet<string> = new Set(["srcset", "imagesrcset"]);
/** Elements whose `href` is fetched by the browser without a click. */
const HREF_FETCHED: ReadonlySet<string> = new Set(["link", "base", "image", "use", "feimage", "script", "area"]);
const NEVER: ReadonlySet<string> = new Set(["base", "iframe", "frame", "frameset", "object", "embed", "portal", "applet", "script"]);

/** Every attribute that vetElement reads, lower case: the MutationObserver watches exactly these. */
export const WATCHED_ATTRIBUTES: readonly string[] = [...URL_ATTRIBUTES, ...SRCSET_ATTRIBUTES, "href", "rel", "http-equiv", "content", "style", "type", "shadowrootmode", "shadowroot"];

/** The URLs of a srcset, as the HTML parser reads it: a URL is a run of non-space characters (a data: URL may hold commas). */
function srcsetUrls(value: string): string[] {
  const urls: string[] = [];
  let index = 0;
  while (index < value.length) {
    while (index < value.length && /[\s,]/.test(value.charAt(index))) index += 1;
    const start = index;
    while (index < value.length && !/\s/.test(value.charAt(index))) index += 1;
    let url = value.slice(start, index);
    if (url === "") break;
    if (url.endsWith(",")) url = url.replace(/,+$/, "");
    else while (index < value.length && value.charAt(index) !== ",") index += 1; // the descriptor
    if (url !== "") urls.push(url);
  }
  return urls;
}

/** The first URL in CSS text that is not safe, or undefined. Covers `url()`, `@import`, `image-set()` and `src()` strings. */
export function unsafeCssUrl(css: string): string | undefined {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, " ");
  for (const match of text.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)/gi)) {
    const url = match[1] ?? match[2] ?? match[3] ?? "";
    if (!isSafeUrl(url)) return url;
  }
  for (const match of text.matchAll(/@import\s+(?:url\(\s*)?(?:"([^"]*)"|'([^']*)')/gi)) {
    const url = match[1] ?? match[2] ?? "";
    if (!isSafeUrl(url)) return url;
  }
  for (const match of text.matchAll(/(?:-webkit-)?(?:image-set|cross-fade|image|src)\(([^)]*)\)/gi)) {
    for (const quoted of (match[1] ?? "").matchAll(/"([^"]*)"|'([^']*)'/g)) {
      const url = quoted[1] ?? quoted[2] ?? "";
      if (!isSafeUrl(url)) return url;
    }
  }
  return undefined;
}

export type AttributeList = Iterable<readonly [string, string]>;

/**
 * Why an element is refused, or undefined when it is fine. `attributes` are lower-case names with string values;
 * `text` is a `<style>` element's text.
 */
export function vetElement(tag: string, attributes: AttributeList, text = ""): string | undefined {
  const name = tag.toLowerCase();
  if (NEVER.has(name)) return `<${name}> is not allowed`;
  const attrs = new Map<string, string>();
  for (const [key, value] of attributes) attrs.set(key.toLowerCase(), value);
  if (name === "template" && (attrs.has("shadowrootmode") || attrs.has("shadowroot"))) return "<template shadowrootmode> is not allowed";
  if (name === "meta") {
    if (attrs.has("http-equiv")) return "<meta http-equiv> is not allowed";
    if (/url\s*=/i.test(attrs.get("content") ?? "")) return "<meta content=url=…> is not allowed";
  }
  for (const [key, value] of attrs) {
    if (URL_ATTRIBUTES.has(key) && !isSafeUrl(value)) return `<${name} ${key}="${value.slice(0, 80)}"> is not allowed`;
    if (SRCSET_ATTRIBUTES.has(key) && srcsetUrls(value).some((url) => !isSafeUrl(url))) return `<${name} ${key}> names a URL that is not allowed`;
    if (key === "href" && HREF_FETCHED.has(name) && !isSafeUrl(value)) return `<${name} href="${value.slice(0, 80)}"> is not allowed`;
    if (key === "style") { const bad = unsafeCssUrl(value); if (bad !== undefined) return `<${name} style> names a URL that is not allowed`; }
  }
  if (name === "style") { const bad = unsafeCssUrl(text); if (bad !== undefined) return "<style> names a URL that is not allowed"; }
  return undefined;
}

// ---- React side

/** React prop name to the attribute name `vetElement` reads. */
const PROP_ATTRIBUTES: Readonly<Record<string, string>> = {
  srcSet: "srcset", imageSrcSet: "imagesrcset", formAction: "formaction", xlinkHref: "xlink:href", httpEquiv: "http-equiv",
  longDesc: "longdesc", useMap: "usemap", codeBase: "codebase",
};

function textOf(children: unknown): string {
  if (typeof children === "string") return children;
  if (Array.isArray(children)) return children.map(textOf).join("");
  return "";
}

/** The refusal for a React element (`type` a host tag), or undefined. Components and fragments are never refused here. */
export function vetReactElement(type: unknown, props: unknown): string | undefined {
  if (typeof type !== "string") return undefined;
  const record = typeof props === "object" && props !== null ? props as Record<string, unknown> : {};
  const attributes: [string, string][] = [];
  for (const [key, value] of Object.entries(record)) {
    if (key === "children" || key === "dangerouslySetInnerHTML" || key === "key" || key === "ref") continue;
    const attribute = PROP_ATTRIBUTES[key] ?? key.toLowerCase();
    if (attribute === "style" && typeof value === "object" && value !== null) {
      // A style object: `backgroundImage: "url(...)"`, `background: "image-set(...)"`: vet each value as CSS.
      attributes.push(["style", Object.values(value as Record<string, unknown>).filter((entry): entry is string => typeof entry === "string").join(";")]);
    } else if (typeof value === "string") attributes.push([attribute, value]);
    else if (value instanceof URL) attributes.push([attribute, value.href]);
  }
  const html = record["dangerouslySetInnerHTML"];
  const raw = typeof html === "object" && html !== null && "__html" in html && typeof html.__html === "string" ? html.__html : "";
  const refused = vetElement(type, attributes, `${textOf(record["children"])}${type.toLowerCase() === "style" ? raw : ""}`);
  if (refused !== undefined) return refused;
  return raw === "" ? undefined : vetHtml(raw);
}

/** The browser's own `innerHTML` setter, taken before installDomGuard replaces it: this file parses markup with it. */
const RAW_INNER_HTML = typeof Element === "undefined" ? undefined : Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")?.set;

function parseInert(html: string): HTMLTemplateElement {
  const template = document.createElement("template");
  if (RAW_INNER_HTML !== undefined) RAW_INNER_HTML.call(template, html); else template.innerHTML = html;
  return template;
}

/** The refusal for an HTML string (parsed inertly), or undefined. */
export function vetHtml(html: string): string | undefined {
  return firstRefusal(parseInert(html).content);
}

function attributesOf(element: Element): [string, string][] {
  return Array.from(element.attributes, (attribute): [string, string] => [attribute.name, attribute.value]);
}

function refusalFor(element: Element): string | undefined {
  return vetElement(element.localName, attributesOf(element), element.localName === "style" ? element.textContent ?? "" : "");
}

/** Shadow roots the page made with `attachShadow` (a closed root is not reachable through `element.shadowRoot`). */
const MADE_ROOTS = new WeakMap<Element, ShadowRoot>();

function shadowOf(element: Element): ShadowRoot | null {
  return element.shadowRoot ?? MADE_ROOTS.get(element) ?? null;
}

function templateContent(element: Element): DocumentFragment | null {
  if (element.localName !== "template") return null;
  const content = (element as HTMLTemplateElement).content as DocumentFragment | undefined;
  return content ?? null;
}

type Visit = (element: Element) => "removed" | "kept";

/**
 * Walks every element under `root`, INCLUDING the content of `<template>` elements and the shadow roots (open or made
 * by the page) that `querySelectorAll` does not enter. `visit` decides each element; `onShadow` hears every shadow root met.
 */
function walk(root: ParentNode, visit: Visit, onShadow?: (shadow: ShadowRoot) => void): void {
  for (const element of Array.from(root.querySelectorAll("*"))) {
    if (!root.contains(element)) continue; // an ancestor was removed on the way
    if (visit(element) === "removed") continue;
    const content = templateContent(element);
    if (content !== null) walk(content, visit, onShadow);
    const shadow = shadowOf(element);
    if (shadow !== null) { onShadow?.(shadow); walk(shadow, visit, onShadow); }
  }
}

function firstRefusal(root: ParentNode): string | undefined {
  let found: string | undefined;
  walk(root, (element) => {
    if (found !== undefined) return "kept";
    found = refusalFor(element);
    return "kept";
  });
  return found;
}

/** Wraps a React element-creating function so a refused host element becomes `null` (rendered as nothing). */
export function guardedElementFunction<T, A extends unknown[], R>(original: (type: T, props: unknown, ...rest: A) => R, onRefused: (reason: string) => void): (type: T, props: unknown, ...rest: A) => R | null {
  return (type, props, ...rest) => {
    const refused = vetReactElement(type, props);
    if (refused !== undefined) { onRefused(refused); return null; }
    return original(type, props, ...rest);
  };
}

// ---- DOM side

/** Removes every refused element at or under `node` (template content and shadow roots included). Returns what was removed. */
export function sanitizeNode(node: Node, removed: string[] = [], onShadow?: (shadow: ShadowRoot) => void): string[] {
  const visit: Visit = (element) => {
    const refused = refusalFor(element);
    if (refused === undefined) return "kept";
    removed.push(refused);
    element.remove();
    return "removed";
  };
  if (node.nodeType === 1) {
    const element = node as Element;
    if (visit(element) === "removed") return removed;
    const content = templateContent(element);
    if (content !== null) walk(content, visit, onShadow);
    const shadow = shadowOf(element);
    if (shadow !== null) { onShadow?.(shadow); walk(shadow, visit, onShadow); }
  }
  if (node.nodeType === 1 || node.nodeType === 11) walk(node as ParentNode, visit, onShadow);
  return removed;
}

/** `html` with every refused element taken out (serialised from an inert template). */
function cleanHtml(html: string): { html: string; removed: string[] } {
  const template = parseInert(html);
  const removed = sanitizeNode(template.content);
  return { html: removed.length === 0 ? html : template.innerHTML, removed };
}

function patchMethod<T extends object>(target: T, name: string, wrap: (original: (...args: never[]) => unknown) => (this: unknown, ...args: never[]) => unknown): void {
  const original = (target as Record<string, unknown>)[name];
  if (typeof original !== "function") return;
  Object.defineProperty(target, name, { value: wrap(original as (...args: never[]) => unknown), writable: true, configurable: true });
}

function patchSetter(target: object, name: string, wrap: (original: (this: Element, value: string) => void) => (this: Element, value: string) => void): void {
  const descriptor = Object.getOwnPropertyDescriptor(target, name);
  if (descriptor?.set === undefined) return;
  Object.defineProperty(target, name, { ...descriptor, set: wrap(descriptor.set as (this: Element, value: string) => void) });
}

export interface DomGuardOptions {
  readonly onRefused?: (reason: string) => void;
}

/** Installs the DOM-side guard on `doc`'s window. Idempotent per document. */
export function installDomGuard(doc: Document, options: DomGuardOptions = {}): void {
  const view = doc.defaultView;
  if (view === null) return;
  const marker = "__tcDomGuard";
  if ((doc as unknown as Record<string, unknown>)[marker] === true) return;
  Object.defineProperty(doc, marker, { value: true });
  const report = (reasons: string[]): void => { for (const reason of reasons) options.onRefused?.(reason); };

  // Backstop: whatever still got in (an attribute set after insertion, a path not patched) is removed as soon as it is
  // seen. It runs after the browser may already have started a prerender or preconnect, so it is NOT what closes the
  // known paths: the patches below do. Created first because every sweep below points it at the shadow roots it meets.
  const watch: MutationObserverInit = { childList: true, subtree: true, attributes: true, attributeFilter: [...WATCHED_ATTRIBUTES] };
  const observer = new view.MutationObserver((records) => {
    for (const record of records) {
      // An attribute change vets that one element only (a style update on a large subtree must stay cheap).
      if (record.type === "attributes" && record.target.nodeType === 1) {
        const refused = refusalFor(record.target as Element);
        if (refused !== undefined) { report([refused]); (record.target as Element).remove(); }
      }
      for (const added of Array.from(record.addedNodes)) report(sanitizeNode(added, [], observeShadow));
    }
  });
  function observeShadow(root: ShadowRoot): void { observer.observe(root, watch); }
  observer.observe(doc, watch);

  // Nodes inserted by the page. A refused element handed in directly is not inserted at all; a refused element
  // inside a subtree (or a fragment) is removed from it first.
  const keep = (arg: unknown): boolean => {
    if (!(arg instanceof view.Node)) return true;
    if (arg.nodeType === 1) {
      const refused = refusalFor(arg as Element);
      if (refused !== undefined) { report([refused]); return false; }
    }
    report(sanitizeNode(arg, [], observeShadow));
    return true;
  };
  const Node_ = view.Node.prototype;
  const Element_ = view.Element.prototype;
  // One node argument: nothing happens (and the node is returned, as the DOM does) when it is refused.
  for (const name of ["appendChild", "insertBefore", "replaceChild"]) {
    patchMethod(Node_, name, (original) => function guarded(this: unknown, ...args: never[]) {
      const node = (args as unknown[])[0];
      return keep(node) ? original.apply(this, args) : node;
    });
  }
  patchMethod(Element_, "insertAdjacentElement", (original) => function guarded(this: unknown, ...args: never[]) {
    const node = (args as unknown[])[1];
    return keep(node) ? original.apply(this, args) : null;
  });
  // Several arguments: refused nodes are left out.
  // `before`/`after`/`replaceWith` are ChildNode: Element, but also Text and Comment (CharacterData) and DocumentType.
  const multi = (original: (...args: never[]) => unknown) => function guarded(this: unknown, ...args: never[]) { return original.apply(this, (args as unknown[]).filter(keep) as never[]); };
  for (const name of ["append", "prepend", "replaceChildren"]) {
    for (const proto of [Element_, view.Document.prototype, view.DocumentFragment.prototype]) patchMethod(proto, name, multi);
  }
  for (const name of ["before", "after", "replaceWith"]) {
    for (const proto of [Element_, view.CharacterData.prototype, view.DocumentType.prototype]) patchMethod(proto, name, multi);
  }
  // HTML text: parsed inertly first, and only the cleaned markup is handed on.
  patchMethod(Element_, "insertAdjacentHTML", (original) => function guarded(this: unknown, ...args: never[]) {
    const [position, html] = args as unknown as [string, string];
    const clean = cleanHtml(String(html));
    report(clean.removed);
    return original.apply(this, [position, clean.html] as never[]);
  });
  // A shadow root is a separate tree the observer below does not watch: its innerHTML is patched like an element's.
  if (view.ShadowRoot !== undefined) patchSetter(view.ShadowRoot.prototype, "innerHTML", (original) => function guarded(this: Element, value: string) {
    const clean = cleanHtml(String(value));
    report(clean.removed);
    original.call(this, clean.html);
  });
  for (const name of ["innerHTML", "outerHTML"]) {
    patchSetter(Element_, name, (original) => function guarded(this: Element, value: string) {
      const clean = cleanHtml(String(value));
      report(clean.removed);
      original.call(this, clean.html);
    });
  }
  // `document.write` feeds ONE parser across calls, so a tag can start in one call and end in the next: a per-call sweep
  // cannot see it. After load it also throws the whole document away (the app with it), so no page has a use for it: refused.
  for (const name of ["write", "writeln"]) {
    patchMethod(view.Document.prototype, name, () => function guarded(this: unknown) {
      report(["document.write is not allowed"]);
      return undefined;
    });
  }
  patchMethod(view.Range.prototype, "createContextualFragment", (original) => function guarded(this: unknown, ...args: never[]) {
    const fragment = original.apply(this, args) as DocumentFragment;
    report(sanitizeNode(fragment, [], observeShadow));
    return fragment;
  });
  patchMethod(view.Range.prototype, "insertNode", (original) => function guarded(this: unknown, ...args: never[]) {
    return keep((args as unknown[])[0]) ? original.apply(this, args) : undefined;
  });
  patchMethod(view.Range.prototype, "surroundContents", (original) => function guarded(this: unknown, ...args: never[]) {
    return keep((args as unknown[])[0]) ? original.apply(this, args) : undefined;
  });
  // The newer HTML setters, on elements and shadow roots. `setHTMLUnsafe` and `Document.parseHTMLUnsafe` also parse
  // declarative shadow DOM (`<template shadowrootmode>`), which cleanHtml refuses.
  for (const proto of [Element_, view.ShadowRoot?.prototype]) {
    if (proto === undefined) continue;
    for (const name of ["setHTMLUnsafe", "setHTML"]) {
      patchMethod(proto, name, (original) => function guarded(this: unknown, ...args: never[]) {
        const clean = cleanHtml(String((args as unknown[])[0]));
        report(clean.removed);
        return original.apply(this, [clean.html, ...(args as unknown[]).slice(1)] as never[]);
      });
    }
  }
  for (const name of ["parseHTMLUnsafe", "parseHTML"]) {
    patchMethod(view.Document, name, (original) => function guarded(this: unknown, ...args: never[]) {
      const clean = cleanHtml(String((args as unknown[])[0]));
      report(clean.removed);
      return original.apply(this, [clean.html, ...(args as unknown[]).slice(1)] as never[]);
    });
  }
  // An editing command that inserts markup or an image URL.
  patchMethod(view.Document.prototype, "execCommand", (original) => function guarded(this: unknown, ...args: never[]) {
    const [command, showUi, value] = args as unknown as [string, boolean, unknown];
    const lower = String(command).toLowerCase();
    if (lower === "inserthtml") {
      const clean = cleanHtml(String(value));
      report(clean.removed);
      return original.apply(this, [command, showUi, clean.html] as never[]);
    }
    if (lower === "insertimage" && !isSafeUrl(String(value))) { report(["insertImage names a URL that is not allowed"]); return false; }
    return original.apply(this, args);
  });

  // An attribute or property the page sets on an element is checked BEFORE it is applied (an element already in the
  // document starts its request the moment the attribute lands, so a check afterwards is too late). A refused value is
  // simply not set.
  const allowed = (element: Element, name: string, value: string): boolean => {
    const lower = name.toLowerCase();
    const attributes = Array.from(element.attributes, (attribute): [string, string] => [attribute.name, attribute.value]).filter(([existing]) => existing.toLowerCase() !== lower);
    attributes.push([name, value]);
    const refused = vetElement(element.localName, attributes, element.localName === "style" ? element.textContent ?? "" : "");
    if (refused === undefined) return true;
    report([refused]);
    return false;
  };
  patchMethod(Element_, "setAttribute", (original) => function guarded(this: unknown, ...args: never[]) {
    const element = this as Element;
    const [name, value] = args as unknown as [string, string];
    return allowed(element, String(name), String(value)) ? original.apply(this, args) : undefined;
  });
  patchMethod(Element_, "setAttributeNS", (original) => function guarded(this: unknown, ...args: never[]) {
    const element = this as Element;
    const [, qualified, value] = args as unknown as [string | null, string, string];
    return allowed(element, String(qualified), String(value)) ? original.apply(this, args) : undefined;
  });
  // The same attribute written through an Attr node: `setAttributeNode(NS)`, `NamedNodeMap.setNamedItem(NS)` (the map
  // does not name its element, so the `attributes` getter records it) and the Attr's own `value`/`nodeValue`/`textContent`.
  const attrAllowed = (element: Element | null, attr: Attr, value?: string): boolean => element === null || allowed(element, attr.name, value ?? attr.value);
  for (const name of ["setAttributeNode", "setAttributeNodeNS"]) {
    patchMethod(Element_, name, (original) => function guarded(this: unknown, ...args: never[]) {
      const attr = (args as unknown[])[0];
      return !(attr instanceof view.Attr) || attrAllowed(this as Element, attr) ? original.apply(this, args) : null;
    });
  }
  const OWNERS = new WeakMap<NamedNodeMap, Element>();
  const attributesDescriptor = Object.getOwnPropertyDescriptor(Element_, "attributes");
  if (attributesDescriptor?.get !== undefined) {
    const getter = attributesDescriptor.get;
    Object.defineProperty(Element_, "attributes", { ...attributesDescriptor, get(this: Element) { const map = getter.call(this) as NamedNodeMap; OWNERS.set(map, this); return map; } });
  }
  for (const name of ["setNamedItem", "setNamedItemNS"]) {
    patchMethod(view.NamedNodeMap.prototype, name, (original) => function guarded(this: unknown, ...args: never[]) {
      const attr = (args as unknown[])[0];
      const owner = OWNERS.get(this as NamedNodeMap) ?? null;
      return !(attr instanceof view.Attr) || attrAllowed(owner, attr) ? original.apply(this, args) : null;
    });
  }
  patchSetter(view.Attr.prototype as object, "value", (original) => function guarded(this: unknown, value: string) {
    const attr = this as unknown as Attr;
    if (attrAllowed(attr.ownerElement, attr, String(value))) original.call(this as never, value);
  });
  // `nodeValue` and `textContent` are Node's accessors and also write an Attr's value.
  for (const name of ["nodeValue", "textContent"]) {
    patchSetter(Node_, name, (original) => function guarded(this: unknown, value: string) {
      const node = this as Node;
      if (node.nodeType === 2 && !attrAllowed((node as Attr).ownerElement, node as Attr, value === null ? "" : String(value))) return;
      original.call(this as never, value);
    });
  }
  const reflected: ReadonlyArray<readonly [string, string, string]> = [
    ["HTMLLinkElement", "href", "href"], ["HTMLLinkElement", "imageSrcset", "imagesrcset"], ["HTMLAnchorElement", "ping", "ping"], ["HTMLAreaElement", "ping", "ping"],
    ["HTMLImageElement", "src", "src"], ["HTMLImageElement", "srcset", "srcset"], ["HTMLMediaElement", "src", "src"], ["HTMLVideoElement", "poster", "poster"],
    ["HTMLSourceElement", "src", "src"], ["HTMLSourceElement", "srcset", "srcset"], ["HTMLTrackElement", "src", "src"], ["HTMLFormElement", "action", "action"],
    ["HTMLInputElement", "src", "src"], ["HTMLInputElement", "formAction", "formaction"], ["HTMLButtonElement", "formAction", "formaction"],
    ["HTMLObjectElement", "data", "data"], ["HTMLEmbedElement", "src", "src"], ["HTMLIFrameElement", "src", "src"], ["HTMLBaseElement", "href", "href"], ["HTMLScriptElement", "src", "src"],
  ];
  const constructors = view as unknown as Record<string, { prototype: object } | undefined>;
  for (const [constructorName, property, attribute] of reflected) {
    const proto = constructors[constructorName]?.prototype;
    if (proto === undefined) continue;
    patchSetter(proto, property, (original) => function guarded(this: Element, value: string) {
      if (allowed(this, attribute, String(value))) original.call(this, value);
    });
  }

  // A shadow root is its own tree: the page's roots are recorded (a closed root is not reachable otherwise) and watched.
  patchMethod(Element_, "attachShadow", (original) => function guarded(this: unknown, ...args: never[]) {
    const root = original.apply(this, args) as ShadowRoot;
    MADE_ROOTS.set(this as Element, root);
    observeShadow(root);
    return root;
  });

  // WebRTC sends STUN packets to a host the page names.
  for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "mozRTCPeerConnection"]) {
    try { Object.defineProperty(view, name, { value: undefined, writable: false, configurable: false }); } catch { /* already fixed */ }
  }
}
