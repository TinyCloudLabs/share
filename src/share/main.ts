import type { OpenKeyShareSession } from "./openkey-session.js";

function mountAuthentication(root: HTMLElement, proceed: (session: OpenKeyShareSession, status: HTMLElement) => Promise<void>): void {
  root.removeAttribute("aria-busy");
  root.replaceChildren();
  const shell = document.createElement("main"); shell.className = "sender-shell auth-shell";
  const header = document.createElement("header"); header.className = "sender-header auth-header";
  const kicker = document.createElement("p"); kicker.className = "sender-kicker"; kicker.textContent = "TinyCloud sharing";
  const title = document.createElement("h1"); title.className = "sender-title"; title.textContent = "Create a share.";
  const lede = document.createElement("p"); lede.className = "sender-lede"; lede.textContent = "Sign in with OpenKey, choose one file, and create a private encrypted link.";
  header.append(kicker, title, lede);
  const form = document.createElement("form"); form.className = "sender-form auth-form";
  const steps = document.createElement("ol"); steps.className = "share-progress";
  const progressSteps: ReadonlyArray<readonly [string, string]> = [["01", "Sign in"], ["02", "Upload"], ["03", "Share"]];
  for (const [number, label] of progressSteps) {
    const item = document.createElement("li");
    const marker = document.createElement("span");
    marker.textContent = number;
    item.append(marker, document.createTextNode(label));
    steps.append(item);
  }
  const badge = document.createElement("div"); badge.className = "openkey-mark"; badge.setAttribute("aria-hidden", "true"); badge.textContent = "OK";
  const heading = document.createElement("h2"); heading.textContent = "Your key opens your space";
  const copy = document.createElement("p"); copy.className = "auth-copy"; copy.textContent = "OpenKey uses your passkey to authenticate. TinyCloud receives a proof, never your private key.";
  const submit = document.createElement("button"); submit.type = "submit"; submit.className = "button button-primary auth-button"; submit.textContent = "Continue with OpenKey";
  const status = document.createElement("p"); status.className = "auth-status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  form.append(steps, badge, heading, copy, submit, status); shell.append(header, form); root.append(shell);
  form.addEventListener("submit", (event) => {
    event.preventDefault(); submit.disabled = true; status.textContent = "Loading secure sign-in…";
    void import("./openkey-session.js")
      .then(({ authenticateWithOpenKey }) => authenticateWithOpenKey((message) => { status.textContent = message; }))
      .then((session) => proceed(session, status))
      .catch((error) => { status.textContent = error instanceof Error ? error.message : "OpenKey sign-in could not be completed."; submit.disabled = false; });
  });
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
async function bootstrap(session: OpenKeyShareSession, status: HTMLElement): Promise<void> {
  status.textContent = "OpenKey verified. Preparing encrypted sharing…";
  const { mountLinkOnlyShare } = await import("./link-only.js");
  mountLinkOnlyShare(root as HTMLElement, {
    openKeyAddress: session.address,
    origin: window.location.origin,
  });
}

mountAuthentication(root, bootstrap);
