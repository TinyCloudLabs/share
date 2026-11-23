/**
 * The runner's side of `file.save` (TC-3995): a file an app offers is shown in the runner's own bar, outside the
 * app's frame, and is saved only when the owner clicks Save there. The frame cannot press that button, and the
 * sandbox it runs in has no downloads, so there is no other way for its file to reach the disk.
 *
 * One offer waits at a time. It holds the checked bytes (src/apps/save-file.ts) until the owner saves or dismisses it,
 * or until the app stops; then they are dropped.
 */
import { type SaveFile, SAVE_FILE_TYPES, fileSizeLabel } from "./save-file.ts";
import { el } from "./view.ts";

export type SaveOutcome = "saved" | "started" | "cancelled";

/** What the browser does with a file the owner chose to save. Replaced in tests only. */
export type SaveWith = (file: SaveFile, view: Window) => Promise<SaveOutcome>;

interface SaveFilePickerWindow {
  showSaveFilePicker?: (options: { suggestedName: string; types: Array<{ description: string; accept: Record<string, string[]> }> }) => Promise<{ createWritable(): Promise<{ write(data: Blob): Promise<void>; close(): Promise<void> }> }>;
}

const DOWNLOAD_URL_LIFETIME_MS = 30_000;

/**
 * The owner picks where the file goes where the browser has a save-file picker; elsewhere the browser's own download
 * runs with the offered name. Both run inside the click on Save, in the runner's own document.
 */
export const saveWithBrowser: SaveWith = async (file, view) => {
  const blob = new Blob([file.bytes as BlobPart], { type: `${file.type};charset=utf-8` });
  const known = SAVE_FILE_TYPES[file.type];
  const picker = (view as unknown as SaveFilePickerWindow).showSaveFilePicker;
  if (typeof picker === "function" && known !== undefined) {
    let handle: Awaited<ReturnType<typeof picker>> | undefined;
    try {
      handle = await picker.call(view, { suggestedName: file.name, types: [{ description: known.label, accept: { [file.type]: [known.extension] } }] });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return "cancelled";
      // The picker is not available here (for example, a frame that may not use it): the download below still works.
    }
    if (handle !== undefined) {
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return "saved";
    }
  }
  const doc = view.document;
  const url = (view as Window & typeof globalThis).URL.createObjectURL(blob);
  const link = el("a", null, [], { href: url, download: file.name, rel: "noopener", hidden: "" });
  doc.body.append(link);
  link.click();
  link.remove();
  view.setTimeout(() => (view as Window & typeof globalThis).URL.revokeObjectURL(url), DOWNLOAD_URL_LIFETIME_MS);
  return "started";
};

/** Save stays inert for this long after an offer appears: the offer pushes the app down, and a click aimed at the app must not land on Save. */
export const SAVE_ARMING_MS = 700;
/** After the owner saves or dismisses an offer, the next one is refused (BUSY) for this long, so a double click or a re-offer loop cannot chain. */
export const OFFER_COOLDOWN_MS = 2000;
export const SAVE_TIMEOUT_MS = 60_000;

const DISMISS_STATUS = "File dismissed.";
const SAVE_TIMEOUT_STATUS = "Share stopped waiting for your browser. Check your downloads; if the file isn't there, save it.";

export interface FileOffersOptions {
  readonly view: Window;
  /** The app's name, as the runner shows it. */
  readonly appName: () => string;
  /** Sets the runner's status line. */
  readonly announce: (text: string, tone: "info" | "success" | "warning") => void;
  /** A stable element in the runner to focus when the owner chooses an action. */
  readonly focusTarget?: HTMLElement;
  readonly save?: SaveWith;
  /** Tests only: the clock the cooldown reads. */
  readonly now?: () => number;
}

export interface FileOffersView {
  /** The live region the offer's text goes into; empty (and hidden by CSS) when nothing is offered. */
  readonly region: HTMLElement;
  /** Save and Dismiss; empty when nothing is offered. */
  readonly actions: HTMLElement;
  /** True when the offer is now showing; false while an earlier one waits or the owner has only just answered one. */
  offer(file: SaveFile): boolean;
  /** Drops a waiting offer and its bytes (the app stopped, or the session ended). */
  clear(): void;
}

export function createFileOffers(options: FileOffersOptions): FileOffersView {
  const save = options.save ?? saveWithBrowser;
  const now = options.now ?? Date.now;
  const region = el("div", "run-offer-region", [], { role: "status" });
  const actions = el("div", "run-offer-actions", []);
  let pending: SaveFile | undefined;
  let saveAttempt: { timer: number } | undefined;
  let armTimer: number | undefined;
  let quietUntil = 0;

  const stopSaving = (): void => {
    options.view.clearTimeout(saveAttempt?.timer);
    saveAttempt = undefined;
  };
  const clear = (): void => {
    options.view.clearTimeout(armTimer);
    armTimer = undefined;
    pending = undefined;
    stopSaving();
    region.replaceChildren();
    actions.replaceChildren();
  };
  /** The owner answered: the offer goes and the next one waits out the cooldown. */
  const answered = (): void => {
    clear();
    quietUntil = now() + OFFER_COOLDOWN_MS;
  };

  const choose = async (file: SaveFile, saveButton: HTMLButtonElement, dismissButton: HTMLButtonElement): Promise<void> => {
    if (saveAttempt !== undefined || pending !== file || saveButton.disabled) return;
    saveButton.disabled = true;
    dismissButton.disabled = true;
    const retry = (): void => {
      stopSaving();
      saveButton.disabled = false;
      dismissButton.disabled = false;
    };
    const attempt = {
      timer: options.view.setTimeout(() => {
        retry();
        options.announce(SAVE_TIMEOUT_STATUS, "warning");
      }, SAVE_TIMEOUT_MS),
    };
    saveAttempt = attempt;
    options.focusTarget?.focus();
    try {
      const outcome = await save(file, options.view);
      if (saveAttempt !== attempt) return;
      if (outcome === "cancelled") {
        retry();
        return;
      }
      answered();
      options.announce(outcome === "saved" ? `Saved ${file.name}.` : `Started the download of ${file.name}. Your browser decides where it goes.`, "success");
    } catch {
      if (saveAttempt !== attempt) return;
      retry();
      options.announce(`Couldn't save ${file.name}. Choose Save to try again or Dismiss.`, "warning");
    }
  };

  return {
    region,
    actions,
    clear,
    offer(file): boolean {
      if (pending !== undefined || now() < quietUntil) return false;
      pending = file;
      const label = SAVE_FILE_TYPES[file.type]?.label ?? file.type;
      const saveButton = el("button", "tc-button tc-button--primary apps-button", ["Save"], { type: "button" });
      const dismissButton = el("button", "tc-button apps-button", ["Dismiss"], { type: "button" });
      saveButton.disabled = true;
      armTimer = options.view.setTimeout(() => {
        armTimer = undefined;
        if (pending === file && saveAttempt === undefined) saveButton.disabled = false;
      }, SAVE_ARMING_MS);
      saveButton.addEventListener("click", () => { void choose(file, saveButton, dismissButton); });
      dismissButton.addEventListener("click", () => {
        if (pending !== file || saveAttempt !== undefined) return;
        answered();
        options.focusTarget?.focus();
        options.announce(DISMISS_STATUS, "info");
      });
      // textContent only: the name is the app's own text.
      region.replaceChildren(el("p", "run-offer-text", [`${options.appName()} offers a file to save: ${file.name} (${label}, ${fileSizeLabel(file.bytes.byteLength)}). Nothing is saved unless you choose Save.`]));
      actions.replaceChildren(saveButton, dismissButton);
      return true;
    },
  };
}
