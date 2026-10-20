/**
 * The JSX sandbox FRAME document (PLAN.md decision 6): the bridge served at
 * JSX_SANDBOX_PATH, its CSP and HTTP headers, the typed postMessage protocol,
 * and the parent-side validator. Shared by the viewer controller
 * (jsx-sandbox.ts), the Vite plugin that serves/emits the document
 * (vite.config.ts) and the tests that pin all of it.
 *
 * Shape (the same as the reviewed HTML sandbox, artifact-frame.ts):
 *
 *   viewer /viewer
 *     └─ bridge  <iframe sandbox="allow-scripts" allow="" referrerpolicy="no-referrer"
 *                        src="/jsx-sandbox.html#<128-bit nonce>">
 *          └─ child <iframe sandbox="allow-scripts" srcdoc="…">   (created by the bridge)
 *
 * Neither frame ever gets `allow-same-origin`, popups, top-navigation, forms,
 * modals or downloads, so both documents are opaque (`origin === "null"`).
 *
 * WHAT CROSSES INTO THE FRAME: the render message, and nothing else:
 * `{v,type,nonce,kind,source,modules,theme}`. `source` is the artifact text,
 * `modules` are build-manifest-verified library texts, `theme` is one of three
 * words. Never the share URL or fragment, session or delegation material,
 * keys, the sender's identity, or storage handles.
 *
 * WHAT THE ARTIFACT CAN DO: run JS, draw DOM/SVG/canvas, use data:/blob:
 * media, keep in-memory state. It cannot make any content or script request (CSP
 * `connect-src 'none'`, `default-src 'none'` for images, fonts, media, frames,
 * objects), read any viewer storage, navigate the top window, open popups,
 * submit forms or start workers.
 *
 * KNOWN LEAKS, not closed by CSP: preconnect, navigation attempts (one TCP connect
 * before the `frame-src` block), prerender (NoStatePrefetch ignores
 * `default-src 'none'` and sends an HTTP GET with author-chosen query data),
 * dns-prefetch and WebRTC (ICE sends STUN/TURN traffic to a server the page
 * chooses; the CSP `webrtc` directive is not recognised in Chromium 142 and is
 * not set). A hostile author can learn the viewer's IP, the time, and that the
 * page was opened. Mitigation is the viewer's notice above the frame
 * (artifact-notice.ts). A runtime busy loop can freeze the viewer tab. A separate
 * registrable domain for user content limits what a sandbox escape reaches; it
 * does not change any of these network signals. See docs/jsx-artifact-sharing.md.
 *
 * Message authority comes from `event.source`/`event.origin` identity checks on
 * both hops, a per-frame nonce, the protocol version and a type allowlist; any
 * other message is dropped without a reply. The nonce is NOT a secret (a
 * srcdoc child can read it through `document.baseURI`). The reserved `cap/*`
 * namespace carries an installed app's data calls (docs/tiny-app-runner.md): the
 * bridge forwards only the six known operations, bounded in size and in flight,
 * and only the parent's registered handler (`onCapability`) ever acts on them.
 * Without a handler (the share viewer) the parent drops every one.
 */

import { CAP_ID_PATTERN, CAP_LIMITS, CAP_RESULT_TYPE, CAP_TYPES, CAP_TYPE_PREFIX } from "../artifact/jsx-runtime/cap-protocol.js";
import { SANDBOX_PERMISSIONS_POLICY } from "./sandbox-permissions.js";

/** App-origin path of the bridge document (dev + build). */
export const JSX_SANDBOX_PATH = "/jsx-sandbox.html";

/**
 * Policy of the bridge document; the srcdoc child inherits it. 'unsafe-eval'
 * adds no capability inside the opaque, network-less frame and lets the
 * runtime evaluate compiled artifact code. `form-action 'none'`,
 * `frame-src 'none'` and `base-uri 'none'` close forms, navigation and base
 * rewrites; `worker-src 'none'` and `object-src 'none'` close workers and
 * plugins. See the header comment for what CSP does not cover.
 */
export const JSX_SANDBOX_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline' 'unsafe-eval'",
  "style-src 'unsafe-inline'",
  "img-src data: blob:",
  "font-src data: blob:",
  "media-src data: blob:",
  "connect-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

/**
 * The HTTP policy: the meta policy plus `frame-ancestors 'self'`, which only a
 * header can carry. `public/_headers` detaches the site-wide policy (`!`) for
 * the sandbox routes and sends exactly this value.
 */
export const JSX_SANDBOX_HTTP_CSP = `${JSX_SANDBOX_CSP}; frame-ancestors 'self'`;

export const JSX_SANDBOX_HTTP_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ["content-security-policy", JSX_SANDBOX_HTTP_CSP],
  ["permissions-policy", SANDBOX_PERMISSIONS_POLICY],
  ["x-frame-options", "SAMEORIGIN"],
  ["cache-control", "no-store"],
  ["referrer-policy", "no-referrer"],
  ["x-content-type-options", "nosniff"],
];

export const JSX_SANDBOX_PROTOCOL_VERSION = 1;
export const JSX_THEMES = ["system", "light", "dark"] as const;
export type JsxTheme = (typeof JSX_THEMES)[number];

/** Limits. The viewer enforces the same ones before sending; the bridge enforces them again. */
/** Checked by the viewer BEFORE the import scan (which is linear in the source), then by the sandbox and the bridge. */
export const JSX_MAX_SOURCE_CHARS = 512 * 1024;
export const JSX_MAX_MODULES_CHARS = 16 * 1024 * 1024;
export const JSX_MAX_ERROR_CHARS = 2048;
export const JSX_START_TIMEOUT_MS = 15_000;
/** The frame may ask the viewer to reveal its chrome at most this often (bridge and viewer both enforce it). */
export const JSX_RESTORE_CONTROLS_INTERVAL_MS = 1000;

export interface JsxRenderRequest {
  readonly v: 1;
  readonly type: "render";
  readonly nonce: string;
  readonly kind: "jsx";
  readonly source: string;
  readonly modules: Readonly<Record<string, string>>;
  readonly theme: JsxTheme;
}

/** Builds the render message. The key set is part of the contract (tested). */
export function buildRenderRequest(nonce: string, source: string, modules: Readonly<Record<string, string>>, theme: JsxTheme): JsxRenderRequest {
  return { v: 1, type: "render", nonce, kind: "jsx", source, modules, theme };
}

export type JsxFramePhase = "compile" | "import" | "runtime";

/** Everything the bridge may tell the viewer, after validation. */
export type JsxFrameMessage =
  | { readonly type: "bridge-ready" }
  | { readonly type: "ready" }
  | { readonly type: "restore-controls" }
  | { readonly type: "error"; readonly phase: JsxFramePhase; readonly message: string; readonly line?: number; readonly module?: string };

/**
 * Viewer-side validation of a bridge message. Pure so it can be tested without
 * a DOM: the caller supplies the event's source/origin identity checks.
 * Returns `undefined` for anything that is not exactly a v:1, nonce-bound,
 * allowlisted message with only its own keys; error text is truncated, never
 * trusted.
 */
export function parseFrameMessage(data: unknown, nonce: string): JsxFrameMessage | undefined {
  if (typeof data !== "object" || data === null || Array.isArray(data)) return undefined;
  if (!("v" in data) || data.v !== JSX_SANDBOX_PROTOCOL_VERSION || !("nonce" in data) || data.nonce !== nonce || !("type" in data)) return undefined;
  const keys = Object.keys(data);
  const only = (allowed: readonly string[]): boolean => keys.every((key) => allowed.includes(key));
  switch (data.type) {
    case "bridge-ready":
    case "ready":
    case "restore-controls":
      return only(["v", "type", "nonce"]) ? { type: data.type } : undefined;
    case "error": {
      if (!only(["v", "type", "nonce", "phase", "message", "line", "module"])) return undefined;
      if (!("phase" in data) || (data.phase !== "compile" && data.phase !== "import" && data.phase !== "runtime")) return undefined;
      if (!("message" in data) || typeof data.message !== "string") return undefined;
      const line = "line" in data ? data.line : undefined;
      const module = "module" in data ? data.module : undefined;
      return {
        type: "error",
        phase: data.phase,
        message: data.message.slice(0, JSX_MAX_ERROR_CHARS),
        ...(typeof line === "number" && Number.isInteger(line) && line > 0 && line <= 1_000_000 ? { line } : {}),
        ...(typeof module === "string" && module.length > 0 ? { module: module.slice(0, 200) } : {}),
      };
    }
    default:
      return undefined;
  }
}

/** A reserved capability request (`cap/*`) from the frame. v1 ships no handler: they are dropped. */
export interface JsxCapabilityMessage {
  readonly type: `cap/${string}`;
  readonly body: unknown;
}

/**
 * Viewer-side recognition of the reserved `cap/*` namespace: v:1, nonce-bound,
 * a bounded type, and no keys beyond `{v,type,nonce,body}`. The caller has
 * already checked source and origin. Whether anything is done with it is the
 * caller's registered handler (jsx-sandbox.ts); by default nothing is.
 */
export function parseCapabilityMessage(data: unknown, nonce: string): JsxCapabilityMessage | undefined {
  if (typeof data !== "object" || data === null || Array.isArray(data)) return undefined;
  if (!("v" in data) || data.v !== JSX_SANDBOX_PROTOCOL_VERSION || !("nonce" in data) || data.nonce !== nonce) return undefined;
  if (!("type" in data) || typeof data.type !== "string" || !/^cap\/[a-z0-9._-]{1,64}$/.test(data.type)) return undefined;
  if (!Object.keys(data).every((key) => key === "v" || key === "type" || key === "nonce" || key === "body")) return undefined;
  return { type: data.type as JsxCapabilityMessage["type"], body: "body" in data ? data.body : undefined };
}

/** What the parent sends back for a `cap/*` request: `{v,type:"cap/result",nonce,id,result}`. The key set is part of the contract (tested). */
export interface JsxCapabilityReply {
  readonly v: 1;
  readonly type: typeof CAP_RESULT_TYPE;
  readonly nonce: string;
  readonly id: string;
  readonly result: unknown;
}

export function buildCapabilityReply(nonce: string, id: string, result: unknown): JsxCapabilityReply {
  return { v: 1, type: CAP_RESULT_TYPE, nonce, id, result };
}

/**
 * Tokens for Tailwind's `@theme`, so `bg-tc-surface`, `text-tc-muted`,
 * `border-tc-border`, `rounded-tc-md` and `font-tc-sans` follow the TinyCloud
 * tokens (and its light/dark) inside the artifact frame.
 */
export const JSX_TAILWIND_THEME = `@theme inline {
  --default-font-family: var(--tc-font-sans);
  --default-mono-font-family: var(--tc-font-mono);
  --font-tc-sans: var(--tc-font-sans);
  --font-tc-mono: var(--tc-font-mono);
  --color-tc-page: var(--tc-color-page);
  --color-tc-surface: var(--tc-color-surface);
  --color-tc-subtle: var(--tc-color-surface-subtle);
  --color-tc-active: var(--tc-color-surface-active);
  --color-tc-text: var(--tc-color-text);
  --color-tc-muted: var(--tc-color-text-muted);
  --color-tc-border: var(--tc-color-border);
  --color-tc-accent: var(--tc-color-accent);
  --color-tc-accent-hover: var(--tc-color-accent-hover);
  --color-tc-on-accent: var(--tc-color-on-accent);
  --color-tc-success: var(--tc-color-status-success);
  --color-tc-warning: var(--tc-color-status-warning);
  --color-tc-danger: var(--tc-color-status-danger);
  --radius-tc-sm: var(--tc-radius-sm);
  --radius-tc-md: var(--tc-radius-md);
  --radius-tc-lg: var(--tc-radius-lg);
}`;

/**
 * Runs in the CHILD before any module: the lazy module registry and require
 * shim. A module file is `__TC_DEFINE__(names, factory)`; the factory runs on
 * the first `require` of any of its names, so inlining order does not matter
 * and React is one shared instance. A file with several names exports a map
 * under `default`; a single-name file exports the module itself.
 */
export const JSX_CHILD_PREAMBLE = `"use strict";
(function () {
  var defs = Object.create(null);
  function define(names, factory) {
    var entry = { names: names, factory: factory, ran: false, exports: null };
    for (var i = 0; i < names.length; i++) defs[names[i]] = entry;
  }
  function has(name) { return typeof name === "string" && defs[name] !== undefined; }
  function load(name) {
    var entry = defs[name];
    if (entry === undefined) throw new Error('Cannot find module "' + name + '"');
    if (!entry.ran) {
      entry.ran = true;
      var mod = { exports: {} };
      entry.factory(mod, mod.exports, load);
      entry.exports = mod.exports;
    }
    return entry.names.length > 1 ? entry.exports.default[name] : entry.exports;
  }
  Object.defineProperty(window, "__TC_DEFINE__", { value: define });
  Object.defineProperty(window, "__TC_HAS__", { value: has });
  Object.defineProperty(window, "__TC_REQUIRE__", { value: load });
})();`;

/** Runs last in the child: starts the runtime with the (escaped) source. */
export const JSX_CHILD_BOOT = `(function () {
  var input = JSON.parse(document.getElementById("tc-input").textContent);
  __TC_REQUIRE__("@tc/runtime").boot(input, {
    has: __TC_HAS__,
    require: __TC_REQUIRE__,
    post: function (message) { window.parent.postMessage(Object.assign({ v: 1 }, message), "*"); }
  });
})();`;

/**
 * The bridge script. Plain ES5. Exported (not only inlined) so tests execute
 * it against a mock environment and prove the guards, not merely string-match.
 * `__CHILD_PREAMBLE__`, `__CHILD_BOOT__`, `__TAILWIND_THEME__` are replaced by
 * the builder with JSON string literals.
 */
export const JSX_BRIDGE_SCRIPT = `(function () {
  "use strict";
  // SELF-DEFENSE: only an opaque-origin, sandboxed document may operate.
  var nonce = decodeURIComponent(window.location.hash.slice(1));
  if (self.origin !== "null" || !/^[0-9a-f]{32}$/.test(nonce)) return;
  // The nonce is not a secret (identity checks are what authorise a message), but the child
  // reads this URL through document.baseURI: drop the fragment so it is not handed over.
  try { window.history.replaceState(null, "", window.location.pathname + window.location.search); } catch (error) {}
  var VERSION = ${JSX_SANDBOX_PROTOCOL_VERSION};
  var THEMES = ${JSON.stringify(JSX_THEMES)};
  var MAX_SOURCE = ${JSX_MAX_SOURCE_CHARS};
  var MAX_MODULES = ${JSX_MAX_MODULES_CHARS};
  var MAX_ERROR = ${JSX_MAX_ERROR_CHARS};
  var RENDER_KEYS = ["v", "type", "nonce", "kind", "source", "modules", "theme"];
  var CAP_TYPES = ${JSON.stringify(CAP_TYPES)};
  var CAP_PREFIX = ${JSON.stringify(CAP_TYPE_PREFIX)};
  var CAP_RESULT = ${JSON.stringify(CAP_RESULT_TYPE)};
  var CAP_ID = ${CAP_ID_PATTERN.toString()};
  var CAP_MAX_BYTES = ${CAP_LIMITS.maxMessageBytes};
  var CAP_MAX_INFLIGHT = ${CAP_LIMITS.maxInFlight};
  var CAP_MAX_DEPTH = ${CAP_LIMITS.maxDepth};
  var CHILD_PREAMBLE = __CHILD_PREAMBLE__;
  var CHILD_BOOT = __CHILD_BOOT__;
  var TAILWIND_THEME = __TAILWIND_THEME__;
  var frameCss = document.getElementById("tc-frame-css");
  var css = frameCss === null ? "" : frameCss.textContent;
  var child = null;
  var rendered = false;
  var seenInitialLoad = false;
  var childReady = false;
  var errorsSent = 0;
  var capPending = Object.create(null);
  var capCount = 0;
  var lastRestore = 0;
  var RESTORE_INTERVAL = ${JSX_RESTORE_CONTROLS_INTERVAL_MS};
  function post(message) {
    window.parent.postMessage(Object.assign({ v: VERSION, nonce: nonce }, message), "*");
  }
  function destroyChild() { if (child !== null) { child.remove(); child = null; } capPending = Object.create(null); capCount = 0; }
  function isPlain(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }
  // Source and module text become script-element text: the end-tag and comment-open sequences may not survive,
  // and the JSON for the input element escapes every less-than sign.
  function inertJson(value) {
    return JSON.stringify(value).replace(/</g, "\\\\u003c").replace(/>/g, "\\\\u003e").replace(/&/g, "\\\\u0026")
      .replace(/\\u2028/g, "\\\\u2028").replace(/\\u2029/g, "\\\\u2029");
  }
  function scriptSafe(text) { return typeof text === "string" && !/<\\/script|<!-{2}/i.test(text); }
  function validRender(data) {
    if (!isPlain(data) || data.v !== VERSION || data.type !== "render" || data.nonce !== nonce || data.kind !== "jsx") return false;
    var keys = Object.keys(data);
    if (keys.length !== RENDER_KEYS.length) return false;
    for (var i = 0; i < keys.length; i++) if (RENDER_KEYS.indexOf(keys[i]) < 0) return false;
    if (typeof data.source !== "string" || data.source.length > MAX_SOURCE) return false;
    if (THEMES.indexOf(data.theme) < 0 || !isPlain(data.modules)) return false;
    var total = 0;
    var names = Object.keys(data.modules);
    if (names.length > 32 || names.indexOf("runtime") < 0) return false;
    for (var j = 0; j < names.length; j++) {
      var text = data.modules[names[j]];
      if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(names[j]) || !scriptSafe(text)) return false;
      total += text.length;
    }
    return total <= MAX_MODULES;
  }
  function show(data) {
    destroyChild();
    rendered = true;
    childReady = false;
    seenInitialLoad = false;
    var parts = ['<!DOCTYPE html><html lang="en" data-theme="' + data.theme + '"><head><meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">',
      "<style>" + css + "</style>",
      '<style type="text/tailwindcss">' + TAILWIND_THEME + "</style>",
      '</head><body><div id="root"></div><script>' + CHILD_PREAMBLE + "</script>"];
    var names = Object.keys(data.modules);
    for (var i = 0; i < names.length; i++) parts.push("<script>" + data.modules[names[i]] + "</script>");
    parts.push('<script type="application/json" id="tc-input">' + inertJson({ source: data.source, theme: data.theme }) + "</script>");
    parts.push("<script>" + CHILD_BOOT + "</script></body></html>");
    child = document.createElement("iframe");
    child.setAttribute("sandbox", "allow-scripts");
    child.setAttribute("allow", "");
    child.setAttribute("title", "Shared JSX artifact");
    child.setAttribute("referrerpolicy", "no-referrer");
    child.className = "artifact-document";
    child.addEventListener("load", function () {
      if (!seenInitialLoad) { seenInitialLoad = true; return; }
      // A later load is navigation: refuse it and close the document.
      post({ type: "error", phase: "runtime", message: "This page tried to open another page, so it was closed." });
      destroyChild();
    });
    child.srcdoc = parts.join("");
    document.body.replaceChildren(child);
  }
  // ---- cap/* (an installed app's data calls). The bridge is a bounded relay: it forwards the known operations
  // from its own child to its parent, and the parent's answers back; it decides nothing about what a call may touch.
  // capBytes: size of plain data in bytes (strings counted by length: the parent measures UTF-8 exactly),
  // -1 when it is not plain data or is nested too deeply, -2 when it is larger than the message cap.
  function capBytes(value) {
    var total = 0;
    var nodes = 0;
    var tooBig = false;
    function walk(v, depth) {
      if (depth > CAP_MAX_DEPTH) return false;
      nodes += 1;
      if (nodes > CAP_MAX_BYTES / 8) { tooBig = true; return false; }
      var kind = typeof v;
      if (v === null || kind === "undefined" || kind === "boolean") total += 8;
      else if (kind === "number") { if (!isFinite(v)) return false; total += 8; }
      else if (kind === "string") total += v.length;
      else if (kind === "object") {
        var tag = Object.prototype.toString.call(v);
        if (tag === "[object Uint8Array]") total += v.byteLength;
        else if (tag === "[object Array]") {
          for (var i = 0; i < v.length; i++) { if (!walk(v[i], depth + 1)) return false; if (total > CAP_MAX_BYTES) { tooBig = true; return false; } }
        } else if (tag === "[object Object]") {
          var proto = Object.getPrototypeOf(v);
          if (proto !== Object.prototype && proto !== null) return false;
          var keys = Object.keys(v);
          for (var j = 0; j < keys.length; j++) { total += keys[j].length; if (!walk(v[keys[j]], depth + 1)) return false; if (total > CAP_MAX_BYTES) { tooBig = true; return false; } }
        } else return false;
      } else return false;
      if (total > CAP_MAX_BYTES) { tooBig = true; return false; }
      return true;
    }
    if (walk(value, 0)) return total;
    return tooBig ? -2 : -1;
  }
  function capReply(id, result) {
    if (child !== null && child.contentWindow !== null) child.contentWindow.postMessage({ v: VERSION, type: CAP_RESULT, id: id, result: result }, "*");
  }
  function capRefuse(id, code, message) { capReply(id, { ok: false, error: { code: code, message: message } }); }
  function exactKeys(data, allowed) {
    var keys = Object.keys(data);
    if (keys.length !== allowed.length) return false;
    for (var i = 0; i < keys.length; i++) if (allowed.indexOf(keys[i]) < 0) return false;
    return true;
  }
  function capFromChild(data) {
    if (!rendered || CAP_TYPES.indexOf(data.type) < 0 || !exactKeys(data, ["v", "type", "id", "args"])) return;
    // Without a usable id there is nothing to answer, and a repeated id is a call already in flight.
    if (typeof data.id !== "string" || !CAP_ID.test(data.id) || capPending[data.id] === true) return;
    if (!isPlain(data.args)) { capRefuse(data.id, "BAD_REQUEST", "The call's arguments must be a plain object."); return; }
    var size = capBytes(data.args);
    if (size === -2) { capRefuse(data.id, "TOO_LARGE", "The call is larger than " + CAP_MAX_BYTES + " bytes."); return; }
    if (size < 0) { capRefuse(data.id, "BAD_REQUEST", "The call's arguments must be plain data."); return; }
    if (capCount >= CAP_MAX_INFLIGHT) { capRefuse(data.id, "BUSY", "More than " + CAP_MAX_INFLIGHT + " calls in flight."); return; }
    capPending[data.id] = true;
    capCount += 1;
    post({ type: data.type, body: { id: data.id, args: data.args } });
  }
  function capFromParent(data) {
    if (!isPlain(data) || data.v !== VERSION || data.nonce !== nonce || data.type !== CAP_RESULT) return;
    if (!exactKeys(data, ["v", "type", "nonce", "id", "result"])) return;
    if (typeof data.id !== "string" || capPending[data.id] !== true) return;
    if (!isPlain(data.result) || typeof data.result.ok !== "boolean") return;
    delete capPending[data.id];
    capCount -= 1;
    var size = capBytes(data.result);
    if (size === -2) capRefuse(data.id, "TOO_LARGE", "The answer is larger than " + CAP_MAX_BYTES + " bytes: ask for less (for SQL, use LIMIT).");
    else if (size < 0) capRefuse(data.id, "INTERNAL", "The runner sent an answer this app could not read.");
    else capReply(data.id, data.result);
  }
  function fromChild(data) {
    if (!isPlain(data) || data.v !== VERSION) return;
    if (typeof data.type === "string" && data.type.indexOf(CAP_PREFIX) === 0) { capFromChild(data); return; }
    if (data.type === "ready" && !childReady) { childReady = true; post({ type: "ready" }); return; }
    // A frame may ask for the chrome once a second, and only after its page has started.
    // It carries no gesture, so the viewer treats it as a request, never as a user action.
    if (data.type === "restore-controls") {
      var now = Date.now();
      if (!childReady || now - lastRestore < RESTORE_INTERVAL) return;
      lastRestore = now;
      post({ type: "restore-controls" });
      return;
    }
    if (data.type !== "error" || errorsSent >= 5) return;
    if (data.phase !== "compile" && data.phase !== "import" && data.phase !== "runtime") return;
    if (typeof data.message !== "string") return;
    errorsSent++;
    var out = { type: "error", phase: data.phase, message: data.message.slice(0, MAX_ERROR) };
    if (typeof data.line === "number" && data.line > 0 && data.line <= 1000000 && Math.floor(data.line) === data.line) out.line = data.line;
    if (typeof data.module === "string" && data.module.length > 0) out.module = data.module.slice(0, 200);
    post(out);
  }
  window.addEventListener("message", function (event) {
    if (event.source === window.parent) {
      // One render per frame: a second request would replace a running artifact.
      if (!rendered) { if (validRender(event.data)) show(event.data); return; }
      capFromParent(event.data);
      return;
    }
    if (child !== null && event.source === child.contentWindow && event.origin === "null") fromChild(event.data);
  });
  post({ type: "bridge-ready" });
})();`;

function bridgeScript(): string {
  return JSX_BRIDGE_SCRIPT
    .replace("__CHILD_PREAMBLE__", () => JSON.stringify(JSX_CHILD_PREAMBLE))
    .replace("__CHILD_BOOT__", () => JSON.stringify(JSX_CHILD_BOOT))
    .replace("__TAILWIND_THEME__", () => JSON.stringify(JSX_TAILWIND_THEME));
}

/** The runnable bridge script, placeholders filled. */
export const JSX_BRIDGE_RUNTIME_SCRIPT = bridgeScript();

/**
 * @param frameCss TinyCloud tokens + base + patterns, inlined into every artifact frame.
 */
export function buildJsxSandboxHtml(frameCss: string): string {
  if (/<\/style/i.test(frameCss)) throw new Error("frame css must not contain </style");
  return `<!DOCTYPE html>
<html lang="en" data-theme="system">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="${JSX_SANDBOX_CSP}">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Shared JSX artifact sandbox</title>
  <style id="tc-frame-css">${frameCss}</style>
  <style>
    html,body,.artifact-document{width:100%;height:100%;margin:0;border:0}
    body{overflow:hidden}
    .artifact-document{display:block}
  </style>
</head>
<body>
  <script>${JSX_BRIDGE_RUNTIME_SCRIPT.replace(/<\/script/gi, "<\\/script")}</script>
</body>
</html>`;
}
