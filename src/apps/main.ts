import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import "./apps.css";
import { catalog } from "./catalog.ts";
import { mountApps } from "./view.ts";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const list = document.querySelector<HTMLElement>("#apps-list");
const sheet = document.querySelector<HTMLDialogElement>("#apps-sheet");
if (list !== null && sheet !== null) {
  const mounted = mountApps(list, sheet, catalog.apps);
  // The runner's Repair link: /apps/#repair=<app_id> opens the repair sheet for that app.
  const open = (): void => {
    const match = /^#repair=(.+)$/.exec(window.location.hash);
    if (match === null) return;
    let appId: string;
    try { appId = decodeURIComponent(match[1] ?? ""); } catch { return; }
    mounted.openRepair(appId);
  };
  window.addEventListener("hashchange", open);
  open();
}
