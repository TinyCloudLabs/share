import type { AuthResult } from "@openkey/sdk";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import type { SenderHistoryRepository } from "./sender-history.js";
import type { HistoryLock } from "./history-unlock.js";
import type { NetworkSetup } from "./network-setup.js";
import type { ComposerPrefill } from "./send-again.js";
import type { SharePublicConfig } from "../email-share/config.js";
import { resetRevokeFlights } from "./revoke-flight.js";
import { resetWalletApproval } from "./wallet-approval.js";
import { authFailureMessage, fail } from "./sender-failure.js";
import { purgeLegacyReceiverStorage } from "../email-share/receiver-storage.js";
import { forgetLibraryAccount, saveLibraryAccount, savedLibraryAccount } from "./library-session.js";
import { NETWORK_SETUP_DECLINED } from "./history-copy.js";
import { NetworkSetupDeclinedError } from "./network-setup-declined.js";
import { StaleSessionError } from "./stale-session.js";

// Every page on this origin drops receiver records an earlier build left in the tab.
purgeLegacyReceiverStorage();

const LIBRARY_ROUTE = "#/library";
const COMPOSER_ROUTE = "#/new";

interface SenderApp {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  readonly historyLock: HistoryLock;
  readonly networkSetup: NetworkSetup;
  readonly config: SharePublicConfig;
}

/** `resume`: the OpenKey account of a library session saved on this device; the page then resumes it without a tap. */
function mountAuthentication(root: HTMLElement, resume: AuthResult | undefined, proceed: (session: OpenKeyShareSession, status: HTMLElement) => Promise<void>, notice?: string | Promise<string>): void {
  const resumable = resume !== undefined;
  // The first attempt rebuilds a managed key's session without opening OpenKey; Continue after a failure connects as usual.
  let reopen = resume?.keyType === "MANAGED" ? resume : undefined;
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
  const copy = document.createElement("p"); copy.className = "auth-copy"; copy.textContent = resumable ? "" : "Sign in with Face ID or Touch ID. No password.";
  const submit = document.createElement("button"); submit.type = "submit"; submit.className = "button button-primary auth-button"; submit.textContent = resumable ? "Continue" : "Continue with OpenKey";
  const status = document.createElement("p"); status.className = "auth-status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  form.append(steps, badge, heading, copy, submit, status); shell.append(header, form); root.append(shell);
  if (typeof notice === "string") status.textContent = notice;
  // A notice that settles later (OpenKey's answer to a sign-out) only fills an empty line: a sign-in already under way keeps its own status.
  else if (notice !== undefined) void notice.then((text) => { if (status.isConnected && status.textContent === "") status.textContent = text; });
  // A saved session resumes on its own (below), so there is nothing to press and nothing to claim unless that fails.
  submit.hidden = resumable;
  copy.hidden = resumable;
  form.addEventListener("submit", (event) => {
    event.preventDefault(); submit.disabled = true;
    const account = reopen; reopen = undefined;
    // A resume opens no OpenKey window: what it does first is reach the encrypted TinyCloud.
    status.textContent = account !== undefined ? "Connecting to your encrypted TinyCloud…" : "Loading secure sign-in…";
    void import("./openkey-session.js")
      .then((openkey) => account !== undefined ? openkey.reopenOpenKey(account) : openkey.authenticateWithOpenKey((message) => { status.textContent = message; }))
      .then((session) => proceed(session, status))
      .catch((error) => {
        // TC-335: `error.message` used to be rendered here verbatim. Everything
        // that can reject on this path speaks protocol vocabulary —
        // openkey-session's own throws (now tagged), the OpenKey SDK, and the
        // whole Web SDK bootstrap, which reaches this same catch through
        // `proceed`. The raw text is a developer detail; only the classified
        // message reaches the wall.
        console.debug("tinycloud share: sign-in failed");
        if (import.meta.env.VITE_SHARE_HERMETIC === "true") (window as Window & { __tinycloudAuthError?: unknown }).__tinycloudAuthError = error;
        const declined = error instanceof NetworkSetupDeclinedError;
        // Either way this device is already signed out: a resumed wall ("Welcome back") starts over as a first sign-in.
        if ((declined || error instanceof StaleSessionError) && resumable) {
          mountAuthentication(root, undefined, proceed, declined ? NETWORK_SETUP_DECLINED : undefined);
          return;
        }
        status.textContent = declined ? NETWORK_SETUP_DECLINED : error instanceof StaleSessionError ? "" : authFailureMessage(error);
        submit.hidden = false;
        submit.disabled = false;
        if (resumable) {
          copy.textContent = "Sign in with OpenKey to continue.";
          copy.hidden = false;
          submit.focus();
        }
      });
  });
  // No tap, and for a managed key no OpenKey window either: the signer is rebuilt from the saved account and the SDK
  // restores the session without an approval. Continue appears only if that fails.
  if (resumable) form.requestSubmit();
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
// One persistent shell. Views render into it; only the router replaces it.
const view = document.createElement("div");
view.className = "sender-view";
let app: SenderApp | undefined;
/** Guards against a slow view winning a race with a newer route. */
let renderToken = 0;
/** How each screen that was mounted this session lets go of what it listens to; run at sign-out. */
const screenEnds = new Set<() => void>();

/** Held between the library and the composer for one "Send the link again"; read once by the composer. */
let pendingPrefill: ComposerPrefill | undefined;

function navigate(route: string): void {
  if (window.location.hash === route) { render(); return; }
  window.location.hash = route;
}

function renderLibrary(current: SenderApp, token: number): void {
  void Promise.all([import("./sender-home.js"), import("./node-status.js")]).then(([{ mountSenderHome, endSenderLibrary }, { createNodeStatusReader }]) => {
    if (token !== renderToken) return;
    screenEnds.add(endSenderLibrary);
    mountSenderHome(view, { session: current.session, tinycloud: current.tinycloud, history: current.history, historyLock: current.historyLock, onNavigate: navigate, onSendAgain: (prefill) => { pendingPrefill = prefill; navigate(COMPOSER_ROUTE); }, statusReader: createNodeStatusReader(current.tinycloud, current.session.address) });
  });
}

function renderComposer(current: SenderApp, token: number): void {
  void import("./composer.js").then(({ mountShareComposer, endShareComposer }) => {
    if (token !== renderToken) return;
    screenEnds.add(endShareComposer);
    const prefill = pendingPrefill;
    pendingPrefill = undefined;
    mountShareComposer(view, {
      ...(prefill === undefined ? {} : { prefill }),
      origin: import.meta.env.VITE_SHARE_ORIGIN ?? window.location.origin,
      openKeyAddress: current.session.address,
      session: current.session,
      tinycloud: current.tinycloud,
      onBack: () => navigate(LIBRARY_ROUTE),
      persistShare: async ({ share }) => {
        if (share.record === undefined) throw new Error("share publisher returned no canonical history record");
        // The first save needs the account's encryption network; an account that has it is not asked anything.
        await current.networkSetup.ensure();
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

/** Ends the session on this device the way Sign out does, locally and first: the client's session key and the saved session, then the remembered account. OpenKey is not contacted. */
async function endSessionHere(tinycloud: ShareTinyCloud): Promise<void> {
  try { await tinycloud.signOut(); } catch { /* The SDK clears the saved session in its own `finally`. */ }
  forgetLibraryAccount();
}

async function bootstrap(session: OpenKeyShareSession, status: HTMLElement): Promise<void> {
  status.textContent = "Connecting to your encrypted TinyCloud…";
  const [{ loadSharePublicConfig }, { createTinyCloudClient }, { SenderHistoryRepository }, { createNetworkSetup }, { historyLock, holdsWholeNetworkAccess }] = await Promise.all([
    import("../email-share/config.js"),
    import("./openkey-session.js"),
    import("./sender-history.js"),
    import("./network-setup.js"),
    import("./history-unlock.js"),
  ]);
  const config = await loadSharePublicConfig();
  const tinycloud = await createTinyCloudClient(session, config, (message) => { status.textContent = message; });
  // A session saved before Share stopped asking for the whole encryption network still holds it, and the SDK restores it as is.
  // It is not kept: this device is signed out and the person signs in again, which asks for the current set only.
  // OpenKey is not asked to stop a renewal here because none can exist: such a session predates the share/-only sign-in, and
  // only that sign-in asks for a renewal, whose restores re-issue its own share/-only grant.
  if (holdsWholeNetworkAccess(tinycloud, session.address)) {
    await endSessionHere(tinycloud);
    throw new StaleSessionError();
  }
  // Signed in only now: the session is restored and the node has accepted it, or a fresh sign-in was approved.
  status.textContent = "Signed in. Loading your shares…";
  // The SDK has saved the session; remember whose it is, so the next load resumes without opening OpenKey.
  saveLibraryAccount(session.auth);
  const unlocked = await tinycloud.vault.unlock();
  if (!unlocked.ok) throw fail("storage", "TinyCloud could not unlock the sender share library");
  // A new account has no encryption network yet: set it up now, so its first link is saved. An account that has one is asked nothing.
  const networkSetup = createNetworkSetup(tinycloud, session, (message) => { status.textContent = message; });
  try {
    await networkSetup.ensure();
  } catch (error) {
    if (error instanceof NetworkSetupDeclinedError) {
      // Declined: this is a sign-in that did not complete, so a reload shows a clean first sign-in.
      // If the owner left renewal on, OpenKey keeps that renewal (share/ decrypt) for a session key this
      // device has now forgotten, as after an unconfirmed Sign out. Stopping it needs OpenKey's confirm window, so it is not
      // asked here; it ends at its limit or under Renewing permissions in OpenKey settings.
      await endSessionHere(tinycloud);
      throw error;
    }
    // Anything else (the node not answering) leaves the library to show its own state, and the first save asks again.
  }
  app = { session, tinycloud, history: new SenderHistoryRepository(tinycloud.vault), historyLock: historyLock(tinycloud, session), networkSetup, config };
  const chromeScope = document.createElement("div");
  (root as HTMLElement).replaceChildren(chromeScope, view);
  void import("./sender-chrome.js").then(({ mountSenderChrome }) => {
    mountSenderChrome(chromeScope, {
      session, tinycloud,
      onSignedOut: (notice) => {
        // The session is gone: no screen may keep using it, and nothing in memory may start another request with it.
        app = undefined; renderToken += 1; view.replaceChildren(); forgetLibraryAccount();
        // Nor may anything it left running block the next sign-in: revokes in flight, the open wallet request, and the screens' listeners.
        resetRevokeFlights(); resetWalletApproval();
        for (const end of screenEnds) end();
        screenEnds.clear();
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
        mountAuthentication(root as HTMLElement, undefined, bootstrap, notice);
      },
    });
  });
  if (!window.location.hash.startsWith(COMPOSER_ROUTE) && window.location.hash !== LIBRARY_ROUTE) {
    // Keep the library the durable home without adding a history entry.
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${LIBRARY_ROUTE}`);
  }
  render();
}

// A library session saved on this device resumes on its own; otherwise the sign-in wall.
mountAuthentication(root, savedLibraryAccount(), bootstrap);
