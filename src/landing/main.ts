import "./landing.css";
import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const year = document.querySelector<HTMLElement>("#copyright-year");

if (year) year.textContent = String(new Date().getFullYear());

const COPIED_RESET_MS = 2000;

/** Copies text via the async clipboard API, falling back to a selection-based copy. */
async function copyText(text: string, source: HTMLElement): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const selection = window.getSelection();
    if (!selection) return false;
    const range = document.createRange();
    range.selectNodeContents(source);
    selection.removeAllRanges();
    selection.addRange(range);
    return document.execCommand("copy");
  }
}

function wireCopyButton(button: HTMLButtonElement): void {
  const source = document.getElementById(button.dataset.copyTarget ?? "");
  const status = document.getElementById("copy-status");
  if (!source) return;
  let reset: number | undefined;

  button.addEventListener("click", async () => {
    window.clearTimeout(reset);
    const ok = await copyText(source.textContent ?? "", source);
    button.textContent = ok ? "Copied" : "Press Ctrl+C";
    if (ok) button.dataset.state = "copied";
    if (status) status.textContent = ok ? "Copied to clipboard" : "Copy failed; the text is selected, press Ctrl+C or Cmd+C";
    reset = window.setTimeout(() => {
      button.textContent = "Copy";
      delete button.dataset.state;
      if (status) status.textContent = "";
    }, COPIED_RESET_MS);
  });
}

document.querySelectorAll<HTMLButtonElement>("button[data-copy-target]").forEach(wireCopyButton);
