/**
 * TinyCloud One embed contract v1, child side, for /courier. One (the parent)
 * frames this page and hands it a silent delegation; this file holds the pure
 * checks and a small controller for the message exchange. Outside embedded
 * mode nothing here runs and the page behaves as before.
 *
 * Only the contract's messages ever go to the parent: hello (this frame's
 * session DID) and request (permission entries). Mailbox content is never
 * posted anywhere.
 */
import { isRecord } from "./model.js";
import { ONE_DEV_ORIGIN, ONE_PREVIEW_ORIGIN, ONE_PRODUCTION_ORIGIN } from "./one-origins.js";

export const EMBED_VERSION = 1;
export const COURIER_APP_ID = "xyz.tinycloud.courier";
/** The child repeats hello this long before the grant expires, which asks One for a fresh grant. */
export const REGRANT_LEAD_MS = 5.5 * 60 * 1000;

/**
 * This build's One origins. Each condition reads `import.meta.env.<NAME>`
 * directly so Vite replaces it with a literal and a production build drops the
 * preview and dev origins from the bundle. The dev origin needs the dev server
 * AND `--mode one` (npm run dev:one), so a build run under NODE_ENV=test or
 * development still drops it.
 */
export const ONE_ORIGINS: readonly string[] = [
  ONE_PRODUCTION_ORIGIN,
  ...(import.meta.env.VITE_ONE_BUILD === "preview" ? [ONE_PREVIEW_ORIGIN] : []),
  ...(import.meta.env.DEV === true && import.meta.env.MODE === "one" ? [ONE_DEV_ORIGIN] : []),
];

export function isOneOrigin(origin: string, origins: readonly string[] = ONE_ORIGINS): boolean {
  return origins.includes(origin);
}

/** The app's side of a permission entry (same shape as `tc.requestPermissions`). */
export interface PermissionEntry {
  service: string;
  space?: string;
  path: string;
  actions: string[];
  skipPrefix?: boolean;
}

export type EmbedTheme = "light" | "dark";

export interface HelloMessage { v: 1; type: "tc-embed/hello"; appId: string; sessionDid: string; nonce: string }
export interface RequestMessage { v: 1; type: "tc-embed/request"; nonce: string; permissions: PermissionEntry[] }

/** One delegation per space. */
export interface SpaceGrant {
  spaceId: string;
  /** `serializeDelegation` output; applied by the caller with `deserializeDelegation`. */
  delegation: unknown;
  cid: string;
}

export interface GrantMessage { v: 1; type: "tc-embed/grant"; nonce: string; grants: SpaceGrant[]; /** Epoch milliseconds. */ expiresAt: number; theme: EmbedTheme }
export interface DeniedMessage { v: 1; type: "tc-embed/denied"; nonce: string }
export interface RevokeMessage { v: 1; type: "tc-embed/revoke" }
export interface ThemeMessage { v: 1; type: "tc-embed/theme"; theme: EmbedTheme }
export type ParentMessage = GrantMessage | DeniedMessage | RevokeMessage | ThemeMessage;

/** Embedded mode: framed, and the frame URL carries `embed=one`. */
export function isEmbeddedMode(win: { parent: unknown; location: { search: string } } & object): boolean {
  return win.parent !== win && new URLSearchParams(win.location.search).get("embed") === "one";
}

/**
 * The parent's origin from the frame's referrer (One sends `strict-origin`),
 * or null unless it is One. Null means the page stays in its normal flow and
 * posts nothing.
 */
export function parentOriginFromReferrer(referrer: string, origins: readonly string[] = ONE_ORIGINS): string | null {
  if (!referrer) return null;
  try {
    const origin = new URL(referrer).origin;
    return isOneOrigin(origin, origins) ? origin : null;
  } catch {
    return null;
  }
}

/** 16 random bytes, base64url without padding. */
export function createNonce(random: (bytes: Uint8Array) => Uint8Array = (bytes) => crypto.getRandomValues(bytes)): string {
  const bytes = random(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}


function isTheme(value: unknown): value is EmbedTheme {
  return value === "light" || value === "dark";
}

function parseSpaceGrants(value: unknown): SpaceGrant[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const grants: SpaceGrant[] = [];
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry["spaceId"] !== "string" || entry["spaceId"] === "" || typeof entry["cid"] !== "string" || entry["cid"] === "" || entry["delegation"] === undefined || entry["delegation"] === null) return null;
    grants.push({ spaceId: entry["spaceId"], delegation: entry["delegation"], cid: entry["cid"] });
  }
  return grants;
}

/** Shape check for a parent message; null for anything else (wrong version, type, or field). */
export function parseParentMessage(data: unknown): ParentMessage | null {
  if (!isRecord(data) || data["v"] !== EMBED_VERSION) return null;
  switch (data["type"]) {
    case "tc-embed/grant": {
      const grants = parseSpaceGrants(data["grants"]);
      const { nonce, expiresAt, theme } = data;
      if (grants !== null && typeof nonce === "string" && nonce !== "" && typeof expiresAt === "number" && Number.isFinite(expiresAt) && isTheme(theme)) {
        return { v: 1, type: "tc-embed/grant", nonce, grants, expiresAt, theme };
      }
      return null;
    }
    case "tc-embed/denied":
      return typeof data["nonce"] === "string" && data["nonce"] !== "" ? { v: 1, type: "tc-embed/denied", nonce: data["nonce"] } : null;
    case "tc-embed/revoke":
      return { v: 1, type: "tc-embed/revoke" };
    case "tc-embed/theme":
      return isTheme(data["theme"]) ? { v: 1, type: "tc-embed/theme", theme: data["theme"] } : null;
    default:
      return null;
  }
}

export const buildHello = (appId: string, sessionDid: string, nonce: string): HelloMessage => ({ v: 1, type: "tc-embed/hello", appId, sessionDid, nonce });
export const buildRequest = (nonce: string, permissions: PermissionEntry[]): RequestMessage => ({ v: 1, type: "tc-embed/request", nonce, permissions });

/** The slice of `window` the controller uses; a test passes a fake. */
export interface EmbedWindow {
  parent: unknown;
  location: { search: string };
  document: { referrer: string };
  addEventListener(type: "message", listener: (event: MessageEvent) => void): void;
  removeEventListener(type: "message", listener: (event: MessageEvent) => void): void;
}

export interface ParentPort {
  postMessage(message: unknown, targetOrigin: string): void;
}

export interface EmbedHandlers {
  /** A grant for the latest hello or request: apply each space's delegation, then load data. */
  onGrant(grant: GrantMessage): void;
  /** The user (or One's ceiling) refused the latest request. */
  onDenied(): void;
  /** One withdrew access: drop the delegation and key, show the signed-out state. */
  onRevoke(): void;
  onTheme(theme: EmbedTheme): void;
}

export interface EmbedControllerOptions {
  win: EmbedWindow;
  appId?: string;
  handlers: EmbedHandlers;
  /** The One origins to accept; defaults to this build's list. */
  origins?: readonly string[];
  now?: () => number;
  nonce?: () => string;
  setTimer?: (callback: () => void, ms: number) => unknown;
  clearTimer?: (timer: unknown) => void;
}

export interface EmbedController {
  /** Posts hello with a fresh nonce. */
  hello(sessionDid: string): void;
  /** Posts a request with a fresh nonce. */
  request(permissions: PermissionEntry[]): void;
  /** The grant in force, or null once revoked or past its expiry. */
  grant(): GrantMessage | null;
  stop(): void;
}

/**
 * Starts the controller, or returns null when this is not embedded mode or the
 * parent is not One (the page then runs its normal sign-in).
 *
 * Acts on a message only from `window.parent`, from the origin the referrer
 * named, with a known shape; a grant or denial must also echo the latest nonce
 * this side sent, and a grant must not be expired. Revoke ends the exchange:
 * its nonce is forgotten, so a later grant is dropped until the page says
 * hello again. After a grant, a repeat hello (same sessionDid, fresh nonce) is
 * sent REGRANT_LEAD_MS before it expires.
 */
export function startEmbedController(options: EmbedControllerOptions): EmbedController | null {
  const { win, handlers } = options;
  const appId = options.appId ?? COURIER_APP_ID;
  const now = options.now ?? Date.now;
  const makeNonce = options.nonce ?? createNonce;
  const setTimer = options.setTimer ?? ((callback: () => void, ms: number) => setTimeout(callback, ms));
  const clearTimer = options.clearTimer ?? ((timer: unknown) => clearTimeout(timer as number));

  if (!isEmbeddedMode(win)) return null;
  const parentOrigin = parentOriginFromReferrer(win.document.referrer, options.origins ?? ONE_ORIGINS);
  if (parentOrigin === null) return null;
  const parent = win.parent as ParentPort;

  let latestNonce: string | null = null;
  let current: GrantMessage | null = null;
  let sessionDid: string | null = null;
  let regrant: unknown;

  const cancelRegrant = (): void => {
    if (regrant !== undefined) clearTimer(regrant);
    regrant = undefined;
  };
  const sayHello = (): void => {
    if (sessionDid === null) return;
    latestNonce = makeNonce();
    parent.postMessage(buildHello(appId, sessionDid, latestNonce), parentOrigin);
  };

  const listener = (event: MessageEvent): void => {
    if (event.source !== win.parent || event.origin !== parentOrigin) return;
    const message = parseParentMessage(event.data);
    if (message === null) return;
    switch (message.type) {
      case "tc-embed/grant":
        if (latestNonce === null || message.nonce !== latestNonce) return;
        if (message.expiresAt <= now()) return;
        current = message;
        cancelRegrant();
        regrant = setTimer(sayHello, Math.max(0, message.expiresAt - REGRANT_LEAD_MS - now()));
        handlers.onGrant(message);
        handlers.onTheme(message.theme);
        return;
      case "tc-embed/denied":
        if (latestNonce === null || message.nonce !== latestNonce) return;
        handlers.onDenied();
        return;
      case "tc-embed/revoke":
        latestNonce = null;
        current = null;
        cancelRegrant();
        handlers.onRevoke();
        return;
      case "tc-embed/theme":
        handlers.onTheme(message.theme);
        return;
    }
  };
  win.addEventListener("message", listener);

  return {
    hello(did) {
      sessionDid = did;
      sayHello();
    },
    request(permissions) {
      latestNonce = makeNonce();
      parent.postMessage(buildRequest(latestNonce, permissions), parentOrigin);
    },
    grant() {
      if (current === null) return null;
      return current.expiresAt > now() ? current : null;
    },
    stop() {
      win.removeEventListener("message", listener);
      cancelRegrant();
      latestNonce = null;
      current = null;
      sessionDid = null;
    },
  };
}
