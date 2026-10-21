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
  // The runner's links: /apps/#repair=<app_id> opens the repair panel, /apps/#uninstall=<app_id> the app's details sheet.
  const open = (): void => {
    const match = /^#(repair|uninstall)=(.+)$/.exec(window.location.hash);
    if (match === null) return;
    let appId: string;
    try { appId = decodeURIComponent(match[2] ?? ""); } catch { return; }
    if (match[1] === "repair") mounted.openRepair(appId);
    else mounted.openUninstall(appId);
  };
  window.addEventListener("hashchange", open);
  open();
}
