import "./landing.css";
import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import { startShareTargetRotation } from "./share-targets.js";

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

// "Open your agent" row (as on slop.date): every tile also copies the prompt and says what happened.
// Muse has no link, so its button only works with JS and stays hidden without it. Desktop-only
// tiles (Cursor) hide on phones and tablets.
const agentPrompt = document.getElementById("agent-prompt");
const agentStatus = document.getElementById("agent-status");
const ua = navigator.userAgent;
const mobile = /Android|iPhone|iPad|iPod/.test(ua) || (/Macintosh|Mac OS X/.test(ua) && navigator.maxTouchPoints > 1);
document.documentElement.dataset.device = mobile ? "mobile" : "desktop";

document.querySelectorAll<HTMLElement>("[data-agent][data-toast]").forEach((agent) => {
  agent.hidden = false;
  agent.addEventListener("click", async () => {
    if (!agentPrompt) return;
    const ok = await copyText(agentPrompt.textContent ?? "", agentPrompt);
    if (agentStatus) agentStatus.textContent = ok ? (agent.dataset.toast ?? "") : "Copy the prompt, then paste it into your agent.";
  });
});

const shareTarget = document.querySelector<HTMLElement>(".share-target");
if (shareTarget) startShareTargetRotation(shareTarget);
