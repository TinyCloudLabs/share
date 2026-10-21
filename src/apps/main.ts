import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import "./apps.css";
import { catalog } from "./catalog.ts";
import { mountApps } from "./view.ts";
import { applyAppsHash } from "./hash-route.ts";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const list = document.querySelector<HTMLElement>("#apps-list");
const sheet = document.querySelector<HTMLDialogElement>("#apps-sheet");
if (list !== null && sheet !== null) {
  const mounted = mountApps(list, sheet, catalog.apps);
  // The runner's links: /apps/#repair=<app_id> opens the repair panel, /apps/#uninstall=<app_id> the app's details sheet.
  window.addEventListener("hashchange", () => applyAppsHash(mounted, window.location.hash));
  applyAppsHash(mounted, window.location.hash);
}
