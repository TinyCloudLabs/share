import "../email-share/sender.css";
import "./courier.css";
import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import { mountCourier } from "./app.js";
import type { SignInProgress } from "./session.js";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

/**
 * Markdown from the mailbox goes through Share's one sanitising pipeline (raw
 * HTML off, DOMPurify, remote images blocked, diagrams in the isolated frame)
 * into its scriptless preview frame. If that fails for a body (too large, too
 * many nodes) the body is shown as plain text, never as markup.
 */
async function renderBody(host: HTMLElement, markdown: string, label: string): Promise<void> {
  const { renderMarkdownInto } = await import("../viewer/render.js");
  try {
    await renderMarkdownInto(host, markdown, "document");
    host.querySelector("iframe")?.setAttribute("title", label);
  } catch {
    await renderMarkdownInto(host, markdown.slice(0, 64 * 1024), "source");
  }
}

const root = document.querySelector<HTMLElement>("#courier-root");
if (root !== null) {
  mountCourier(root, {
    renderBody: (host, markdown, label) => { void renderBody(host, markdown, label); },
    signIn: async (progress: SignInProgress) => {
      // OpenKey and the Web SDK load on the click, not with the page.
      const [{ loadSharePublicConfig }, { signInToCourier }] = await Promise.all([import("../email-share/config.js"), import("./session.js")]);
      return signInToCourier(await loadSharePublicConfig(), progress);
    },
  });
}
