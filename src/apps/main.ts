import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import "./apps.css";
import { catalog } from "./catalog.ts";
import { mountApps } from "./view.ts";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const list = document.querySelector<HTMLElement>("#apps-list");
const sheet = document.querySelector<HTMLDialogElement>("#apps-sheet");
if (list !== null && sheet !== null) mountApps(list, sheet, catalog.apps);
