import "./landing.css";
import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import { startShareTargetRotation } from "./share-targets.js";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const year = document.querySelector<HTMLElement>("#copyright-year");

if (year) year.textContent = String(new Date().getFullYear());

const COPIED_RESET_MS = 2000;
const TOAST_MS = 5000;

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

const status = document.getElementById("copy-status");
let statusReset: number | undefined;

/** Shows a message in the polite live region, then clears it. */
function say(message: string, ms: number): void {
  if (!status) return;
  window.clearTimeout(statusReset);
  status.textContent = message;
  statusReset = window.setTimeout(() => {
    status.textContent = "";
  }, ms);
}

function wireCopyButton(button: HTMLButtonElement): void {
  const source = document.getElementById(button.dataset.copyTarget ?? "");
  if (!source) return;
  let reset: number | undefined;
  // The button is hidden in the HTML: without script there is nothing for it to do.
  button.hidden = false;

  button.addEventListener("click", async () => {
    window.clearTimeout(reset);
    const ok = await copyText(source.textContent ?? "", source);
    button.textContent = ok ? "Copied" : "Press Ctrl+C";
    if (ok) button.dataset.state = "copied";
    say(ok ? "Copied to clipboard" : "Copy failed; the text is selected, press Ctrl+C or Cmd+C", COPIED_RESET_MS);
    reset = window.setTimeout(() => {
      button.textContent = "Copy";
      delete button.dataset.state;
    }, COPIED_RESET_MS);
  });
}

/** An agent link opens normally; the click also copies the prompt, so a pasted prompt is always one step away. */
function wireAgentLinks(prompt: HTMLElement): void {
  for (const link of document.querySelectorAll<HTMLAnchorElement>("a[data-agent][data-toast]")) {
    link.addEventListener("click", async () => {
      const ok = await copyText(prompt.textContent ?? "", prompt);
      say(ok ? (link.dataset.toast ?? "") : "Copy the prompt, then paste it into your agent.", TOAST_MS);
    });
  }
}

document.querySelectorAll<HTMLButtonElement>("button[data-copy-target]").forEach(wireCopyButton);

const prompt = document.getElementById("agent-prompt");
if (prompt) wireAgentLinks(prompt);

const shareTarget = document.querySelector<HTMLElement>(".share-target");
if (shareTarget) startShareTargetRotation(shareTarget);

// Preview builds only (VITE_HERO_PREVIEW=1): switch the privacy sentence between two wordings.
// The constant is replaced at build time, so production bundles contain neither this branch nor the alternative text.
// Dynamic import is intentional: a static import would put the preview stylesheet into the production CSS.
if (import.meta.env.VITE_HERO_PREVIEW === "1") {
  void import("./preview-variant.js").then((preview) => preview.mountPrivacyVariant());
}
