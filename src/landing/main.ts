import "./landing.css";
import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const year = document.querySelector<HTMLElement>("#copyright-year");

if (year) year.textContent = String(new Date().getFullYear());
