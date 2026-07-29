import {
  MAX_CONTENT_BYTES,
  createBearerShare,
  type CreateBearerShareResult,
} from "@tinycloud/share-cli";
import {
  CidMismatchError,
  RegistryHttpError,
} from "@tinycloud/share-registry";

const LINK_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const AUTHENTICATED_REGISTRY_PATH = "/api/share/link-only/registry";

export type CreateShare = (options: {
  readonly content: Uint8Array;
  readonly filename: string;
  readonly registryBaseUrl: string;
  readonly expiresAt: Date;
  readonly viewerOrigin: string;
  readonly fetchFn: typeof globalThis.fetch;
  readonly now?: () => number;
}) => Promise<CreateBearerShareResult>;

export type LinkOnlyFailureKind =
  | "authentication"
  | "file"
  | "storage"
  | "encryption";

export class LinkOnlyShareError extends Error {
  constructor(
    readonly kind: LinkOnlyFailureKind,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "LinkOnlyShareError";
  }
}

export interface CreateLinkOnlyShareOptions {
  readonly origin: string;
  readonly expiresAt: Date;
  /** Browser transport origin used by hermetic hosts; the link origin remains canonical. */
  readonly registryOrigin?: string;
  /** The production composer may upload byte-preserving binary files. The legacy link-only surface remains text-only by default. */
  readonly allowBinary?: boolean;
  readonly now?: () => number;
  readonly createShare?: CreateShare;
  readonly fetchFn?: typeof globalThis.fetch;
}

function readFileBytes(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      if (!(reader.result instanceof ArrayBuffer)) {
        reject(new Error("file did not produce bytes"));
        return;
      }
      resolve(new Uint8Array(reader.result));
    });
    reader.addEventListener("error", () => {
      reject(reader.error ?? new Error("file could not be read"));
    });
    reader.readAsArrayBuffer(file);
  });
}

async function validateFile(file: File, allowBinary = false): Promise<Uint8Array> {
  if (file.size === 0) throw new LinkOnlyShareError("file", "Choose a non-empty file.");
  if (file.size > MAX_CONTENT_BYTES) {
    throw new LinkOnlyShareError("file", allowBinary ? "Choose a file no larger than 100 MB." : "Choose a text or Markdown file no larger than 100 MB.");
  }
  if (!allowBinary && !/\.(?:md|markdown|txt)$/i.test(file.name)) throw new LinkOnlyShareError("file", "Choose a .txt, .md, or .markdown file.");
  let bytes: Uint8Array;
  try {
    bytes = await readFileBytes(file);
  } catch (error) {
    throw new LinkOnlyShareError(
      "file",
      "This file could not be read. Choose it again and retry.",
      { cause: error },
    );
  }
  if (!allowBinary) {
    try { new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch (error) { throw new LinkOnlyShareError("file", "This file is not valid UTF-8 text. Choose a text or Markdown file.", { cause: error }); }
  }
  return bytes;
}

function authenticatedFetch(
  fetchFn: typeof globalThis.fetch,
): typeof globalThis.fetch {
  return async (input, init) => {
    let response: Response;
    try {
      response = await fetchFn(input, {
        ...init,
        credentials: "include",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    } catch (error) {
      throw new LinkOnlyShareError(
        "storage",
        "The encrypted file could not reach TinyCloud storage. Check your connection and try again.",
        { cause: error },
      );
    }
    if (response.status === 401 || response.status === 403) {
      throw new LinkOnlyShareError(
        "authentication",
        "Your OpenKey session expired. Reload this page and sign in again.",
      );
    }
    return response;
  };
}

export async function createLinkOnlyShare(
  file: File,
  options: CreateLinkOnlyShareOptions,
): Promise<CreateBearerShareResult> {
  const content = await validateFile(file, options.allowBinary);
  const create = options.createShare ?? createBearerShare;
  const fetchFn = authenticatedFetch(options.fetchFn ?? globalThis.fetch);
  try {
    return await create({
      content,
      filename: file.name,
      registryBaseUrl: `${options.registryOrigin ?? options.origin}${AUTHENTICATED_REGISTRY_PATH}`,
      expiresAt: options.expiresAt,
      viewerOrigin: options.origin,
      fetchFn,
      ...(options.now === undefined ? {} : { now: options.now }),
    });
  } catch (error) {
    if (error instanceof LinkOnlyShareError) throw error;
    if (error instanceof RegistryHttpError || error instanceof CidMismatchError) {
      throw new LinkOnlyShareError(
        "storage",
        "TinyCloud storage did not accept the encrypted file. Try again in a moment.",
        { cause: error },
      );
    }
    throw new LinkOnlyShareError(
      "encryption",
      "This browser could not encrypt the file. Nothing was uploaded; try again in a current browser.",
      { cause: error },
    );
  }
}

/**
 * Copy a secret (a complete share URL, key fragment included) to the clipboard
 * without ever materialising it in the DOM.
 *
 * Resolving the spec's own contradiction: the UX critique tells callers to
 * reuse this helper for the recipient-side "Copy link" control (§3 P1-9),
 * while §6.3 forbids rendering the complete share URL "as text, an `<a href>`,
 * or any DOM attribute". The previous implementation violated §6.3 — it
 * assigned the URL to a `<textarea>.value` and attached that node to
 * `document.body`. Off-screen and `aria-hidden` are presentation, not
 * isolation: while attached, any script on the page (an injected third party,
 * an extension content script, a DOM-serialising error/analytics reporter, or
 * a devtools snapshot) could read the secret back out of the live tree. Both
 * rules can hold at once, so no exception is taken: reuse the helper, and make
 * the helper DOM-free with respect to the secret.
 *
 * `document.execCommand("copy")` is deprecated and, in every engine that still
 * implements it, refuses to act without a non-empty selection — which is why
 * the textarea existed. But the selected node never had to be the one holding
 * the secret: `execCommand("copy")` dispatches a cancelable `copy` event
 * first, and a handler that calls `preventDefault()` and
 * `clipboardData.setData()` replaces the payload wholesale. So we select a
 * decoy node that contains one non-breaking space and substitute the real
 * value in the event. The secret exists only as a JavaScript string and as an
 * argument to a clipboard API.
 *
 * Residual risk, stated rather than hidden:
 * - The value still reaches the system clipboard. That is the user's explicit
 *   request and the point of the control.
 * - A `copy` listener registered earlier in the capture phase on `window`
 *   could observe our `clipboardData` write. Any script able to do that
 *   already has same-origin script execution and could read the URL from
 *   memory regardless; this is not a boundary the DOM can defend.
 * - A one-character decoy node is attached for the duration of the synchronous
 *   `execCommand` call. It carries no share data.
 * - If the engine reports success but no handler delivered a payload, we throw
 *   rather than let the decoy character land on the clipboard silently.
 */
export async function copyWithFallback(value: string): Promise<void> {
  if (navigator.clipboard?.writeText !== undefined) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Clipboard permissions vary across browsers and embedded contexts.
      // Fall through to the selection-based copy path.
    }
  }

  const decoy = document.createElement("span");
  decoy.textContent = " ";
  decoy.setAttribute("aria-hidden", "true");
  Object.assign(decoy.style, {
    position: "fixed",
    inset: "0 auto auto -9999px",
    opacity: "0",
    pointerEvents: "none",
    userSelect: "text",
  });

  let delivered = false;
  const onCopy = (event: Event): void => {
    const clipboardData = (event as ClipboardEvent).clipboardData;
    if (clipboardData === null || clipboardData === undefined) return;
    event.preventDefault();
    clipboardData.setData("text/plain", value);
    delivered = true;
  };

  const selection = document.getSelection();
  const preserved: Range[] = [];
  if (selection !== null) {
    for (let index = 0; index < selection.rangeCount; index += 1) {
      preserved.push(selection.getRangeAt(index));
    }
  }

  document.addEventListener("copy", onCopy, true);
  document.body.append(decoy);
  try {
    const range = document.createRange();
    range.selectNodeContents(decoy);
    selection?.removeAllRanges();
    selection?.addRange(range);
    if (!document.execCommand("copy")) throw new Error("clipboard unavailable");
    if (!delivered) throw new Error("clipboard unavailable");
  } finally {
    document.removeEventListener("copy", onCopy, true);
    decoy.remove();
    selection?.removeAllRanges();
    for (const range of preserved) selection?.addRange(range);
  }
}

/** A live manual-copy affordance. `target` is safe to attach; it holds no share data. */
export interface ManualCopyHandle {
  /** The decoy node to place in the UI and keep selected. */
  readonly target: HTMLElement;
  /** Selects the decoy's contents so the next copy gesture applies to it. */
  readonly select: () => void;
  /** Removes the interception, clears the selection, and detaches the decoy. */
  readonly disarm: () => void;
}

/**
 * TC-334. The last-resort affordance for when `copyWithFallback` rejects —
 * i.e. both `navigator.clipboard.writeText` and scripted `execCommand("copy")`
 * were refused. The obvious implementation is a read-only `<input>` holding the
 * URL for the sender to select and copy by hand; that is what the composer used
 * to do, and it is the exposure §6.3 forbids and TC-297 removed from
 * `copyWithFallback`.
 *
 * It is also unnecessary. Every manual copy gesture a sender can perform —
 * Ctrl/Cmd+C, the context menu's Copy, the browser's Edit ▸ Copy — dispatches a
 * cancelable `copy` event, which is exactly the interception point TC-297
 * already uses. So the selected node never has to be the node holding the
 * secret here either: select a decoy, substitute the real value in the event.
 * The URL stays a JavaScript string.
 *
 * The one difference from `copyWithFallback` is lifetime. There, the decoy
 * exists for the duration of a synchronous `execCommand` call. Here it must
 * stay attached and selected until the sender presses the key, so `disarm()`
 * is the caller's responsibility. This is the reason the affordance is kept at
 * all rather than deleted: `execCommand("copy")` is refused for *scripted*
 * copies in hardened configurations (Firefox with `dom.allow_cut_copy=false`,
 * several embedded webviews) where a genuine user gesture is still honoured,
 * and that is precisely the population that reaches this path.
 *
 * Residual risk, stated rather than hidden:
 * - The interception is document-wide while armed, so it checks that the live
 *   selection is still inside the decoy before substituting. Without that, a
 *   sender copying unrelated text on the page would silently get the URL.
 * - As in `copyWithFallback`, an earlier capture-phase `copy` listener could
 *   observe the write. That attacker already has same-origin script execution.
 */
export function armManualCopy(value: string, onDelivered: () => void): ManualCopyHandle {
  const target = document.createElement("span");
  target.className = "manual-copy-target";
  // One non-breaking space: enough for a selection to exist and be visible,
  // and it carries no share data if some engine ignores our substitution.
  target.textContent = " ";
  target.setAttribute("aria-hidden", "true");

  const onCopy = (event: Event): void => {
    const clipboardData = (event as ClipboardEvent).clipboardData;
    if (clipboardData === null || clipboardData === undefined) return;
    const selection = document.getSelection();
    if (selection === null || selection.rangeCount === 0) return;
    const container = selection.getRangeAt(0).commonAncestorContainer;
    if (container !== target && !target.contains(container)) return;
    event.preventDefault();
    clipboardData.setData("text/plain", value);
    onDelivered();
  };
  document.addEventListener("copy", onCopy, true);

  const select = (): void => {
    const selection = document.getSelection();
    if (selection === null) return;
    const range = document.createRange();
    range.selectNodeContents(target);
    selection.removeAllRanges();
    selection.addRange(range);
  };

  const disarm = (): void => {
    document.removeEventListener("copy", onCopy, true);
    document.getSelection()?.removeAllRanges();
    target.remove();
  };

  return { target, select, disarm };
}
