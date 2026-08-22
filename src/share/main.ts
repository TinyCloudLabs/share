import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import type { SenderHistoryRepository } from "./sender-history.js";
import type { SharePublicConfig } from "../email-share/config.js";
import { authFailureMessage, fail } from "./sender-failure.js";

const LIBRARY_ROUTE = "#/library";
const COMPOSER_ROUTE = "#/new";

interface SenderApp {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  readonly config: SharePublicConfig;
}

function mountAuthentication(root: HTMLElement, resumable: boolean, proceed: (session: OpenKeyShareSession, status: HTMLElement) => Promise<void>): void {
  root.removeAttribute("aria-busy");
  root.replaceChildren();
  const shell = document.createElement("main"); shell.className = "sender-shell auth-shell";
  const header = document.createElement("header"); header.className = "sender-header auth-header";
  const kicker = document.createElement("p"); kicker.className = "sender-kicker"; kicker.textContent = "TinyCloud sharing";
  const title = document.createElement("h1"); title.className = "sender-title"; title.textContent = "Create a share.";
  const lede = document.createElement("p"); lede.className = "sender-lede"; lede.textContent = "Sign in, choose a file, get a private link.";
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
  const heading = document.createElement("h2"); heading.textContent = resumable ? "Welcome back" : "One key, your files";
  const copy = document.createElement("p"); copy.className = "auth-copy"; copy.textContent = resumable ? "Your sharing session on this device is still active. Continue to pick up where you left off." : "Sign in with Face ID or Touch ID. No password.";
  const submit = document.createElement("button"); submit.type = "submit"; submit.className = "button button-primary auth-button"; submit.textContent = resumable ? "Continue" : "Continue with OpenKey";
  const status = document.createElement("p"); status.className = "auth-status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  form.append(steps, badge, heading, copy, submit, status); shell.append(header, form); root.append(shell);
  if (resumable) submit.focus();
  form.addEventListener("submit", (event) => {
    event.preventDefault(); submit.disabled = true; status.textContent = "Loading secure sign-in…";
    void import("./openkey-session.js")
      .then(({ authenticateWithOpenKey }) => authenticateWithOpenKey((message) => { status.textContent = message; }))
      .then((session) => proceed(session, status))
      .catch((error) => {
        // TC-335: `error.message` used to be rendered here verbatim. Everything
        // that can reject on this path speaks protocol vocabulary —
        // openkey-session's own throws (now tagged), the OpenKey SDK, and the
        // whole Web SDK bootstrap, which reaches this same catch through
        // `proceed`. The raw text is a developer detail; only the classified
        // message reaches the wall.
        console.debug("tinycloud share: sign-in failed", error);
        if (import.meta.env.VITE_SHARE_HERMETIC === "true") (window as Window & { __tinycloudAuthError?: unknown }).__tinycloudAuthError = error;
        status.textContent = authFailureMessage(error);
        submit.disabled = false;
      });
  });
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
// One persistent shell. Views render into it; only the router replaces it.
const view = document.createElement("div");
view.className = "sender-view";
let app: SenderApp | undefined;
/** Guards against a slow view winning a race with a newer route. */
let renderToken = 0;

function navigate(route: string): void {
  if (window.location.hash === route) { render(); return; }
  window.location.hash = route;
}

function renderLibrary(current: SenderApp, token: number): void {
  void import("./sender-home.js").then(({ mountSenderHome }) => {
    if (token !== renderToken) return;
    mountSenderHome(view, { session: current.session, tinycloud: current.tinycloud, history: current.history, onNavigate: navigate });
  });
}

function renderComposer(current: SenderApp, token: number): void {
  void import("./composer.js").then(({ mountShareComposer }) => {
    if (token !== renderToken) return;
    mountShareComposer(view, {
      origin: import.meta.env.VITE_SHARE_ORIGIN ?? window.location.origin,
      openKeyAddress: current.session.address,
      session: current.session,
      tinycloud: current.tinycloud,
      onBack: () => navigate(LIBRARY_ROUTE),
      persistShare: async ({ share }) => {
        if (share.record === undefined) throw new Error("share publisher returned no canonical history record");
        await current.history.save(share.record);
      },
    });
  });
}

/** The whole route table: the library is home, everything else is the composer. */
export function routeFor(hash: string): "library" | "composer" {
  return hash.startsWith(COMPOSER_ROUTE) ? "composer" : "library";
}

function render(): void {
  if (app === undefined) return;
  const token = renderToken += 1;
  if (routeFor(window.location.hash) === "composer") renderComposer(app, token);
  else renderLibrary(app, token);
}

window.addEventListener("hashchange", render);

async function bootstrap(session: OpenKeyShareSession, status: HTMLElement): Promise<void> {
  status.textContent = "Signed in. Loading your shares…";
  const [{ loadSharePublicConfig }, { createTinyCloudClient }, { SenderHistoryRepository }] = await Promise.all([
    import("../email-share/config.js"),
    import("./openkey-session.js"),
    import("./sender-history.js"),
  ]);
  const config = await loadSharePublicConfig();
  const tinycloud = await createTinyCloudClient(session, config, (message) => { status.textContent = message; });
  const unlocked = await tinycloud.vault.unlock();
  if (!unlocked.ok) throw fail("storage", "TinyCloud could not unlock the sender share library");
  app = { session, tinycloud, history: new SenderHistoryRepository(tinycloud.vault), config };
  (root as HTMLElement).replaceChildren(view);
  if (!window.location.hash.startsWith(COMPOSER_ROUTE) && window.location.hash !== LIBRARY_ROUTE) {
    // Keep the library the durable home without adding a history entry.
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${LIBRARY_ROUTE}`);
  }
  render();
}

mountAuthentication(root, false, bootstrap);
