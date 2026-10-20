import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import "./apps.css";
import "./run.css";
import { mountRunner, type Runner } from "./run-view.ts";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const root = document.querySelector<HTMLElement>("#runner");

/** The app id is the address fragment: /apps/run#xyz.tinycloud.sample.healthlog. */
function appIdFromAddress(): string | null {
  const id = decodeURIComponent(window.location.hash.slice(1));
  return id === "" ? null : id;
}

if (root !== null) {
  let runner: Runner | undefined;
  const mount = (): void => {
    runner?.destroy();
    let appId: string | null;
    try { appId = appIdFromAddress(); } catch { appId = null; }
    runner = mountRunner(root, { appId });
  };
  // Another app's address replaces the running one: its session ends first.
  window.addEventListener("hashchange", mount);
  mount();
}
