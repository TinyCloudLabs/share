/**
 * The /courier page: sign-in, the signed-in shell and its four screens.
 *
 * State lives in this tab's memory only. Nothing about the mailbox (a handle,
 * a thread id, a body) goes in the address bar, storage or the console, and
 * the session is disposed on sign-out and when the page goes away.
 */
import { createAnnouncer } from "../share/announcer.js";
import { confirmDialog } from "../share/confirm-dialog.js";
import { showApprovalHint } from "../share/approval-hint.js";
import { el, status, type ViewContext } from "./dom.js";
import type { ThreadRef } from "./model.js";
import { renderNeeds } from "./screen-needs.js";
import { renderOrders } from "./screen-orders.js";
import { renderThread, renderThreads } from "./screen-threads.js";
import { loadOverview, type Overview } from "./service.js";
import { signInFailureMessage, type CourierSession, type SignInProgress } from "./session.js";
import { StoreError } from "./store.js";

export interface CourierDeps {
  signIn(progress: SignInProgress): Promise<CourierSession>;
  renderBody(host: HTMLElement, markdown: string, label: string): void;
  now?(): number;
}

type Screen = "threads" | "needs" | "orders";
const TABS: readonly { id: Screen; label: string }[] = [
  { id: "threads", label: "Threads" },
  { id: "needs", label: "Needs you" },
  { id: "orders", label: "Orders" },
];

export const NO_SPACE_COPY = "Your TinyCloud \"agents\" space is not set up yet. Sign in once at Share (share.tinycloud.xyz/share), or run `tc space host agents`, then come back.";
const SIGNED_OUT_NOTICE = "Signed out. Courier's session and your OpenKey sign-in on this device were cleared. Your threads and approvals are unchanged.";
const SIGNED_OUT_PARTIAL_NOTICE = "Signed out of Courier, and its session was cleared. OpenKey didn't confirm that it ended its own sign-in, so sign out there too if this is a shared device.";
const REFRESH_AFTER_HIDDEN_MS = 30_000;

function loadFailure(error: unknown): string {
  const code = error instanceof StoreError ? error.code : "failed";
  if (code === "no-space") return NO_SPACE_COPY;
  if (code === "denied") return "This session isn't allowed to read your mailbox. Sign out and sign in again.";
  if (code === "timeout" || code === "unreachable") return "We couldn't reach your TinyCloud. Try again.";
  return "We couldn't load your mailbox. Try again.";
}

export function mountCourier(root: HTMLElement, deps: CourierDeps): void {
  const doc = root.ownerDocument;
  const now = deps.now ?? Date.now;
  const announcer = createAnnouncer(doc, "cr-announcer");
  let session: CourierSession | undefined;
  let teardown: (() => void) | undefined;

  const showSignedOut = (notice?: string): void => {
    teardown?.(); teardown = undefined;
    announcer.clear();
    root.replaceChildren();
    root.setAttribute("aria-busy", "false");
    const main = el(doc, "main", "sender-shell auth-shell");
    const header = el(doc, "header", "sender-header auth-header");
    header.append(el(doc, "p", "sender-kicker", "TinyCloud Courier"), el(doc, "h1", "sender-title", "Your agents' threads."), el(doc, "p", "sender-lede", "Read the conversations your agent has with a paired peer's agent, approve what needs you, and set your standing orders."));
    const form = el(doc, "section", "sender-form auth-form");
    form.setAttribute("aria-label", "Sign in");
    const mark = el(doc, "div", "openkey-mark", "OK"); mark.setAttribute("aria-hidden", "true");
    form.append(mark, el(doc, "h2", undefined, "Sign in to read and decide"));
    form.append(el(doc, "p", "auth-copy", "Sign in with OpenKey. This page can read your agent mailbox. It writes only two things, and only when you click: your approval decisions and your standing orders. It never reads a peer's space."));
    const button = el(doc, "button", "button button-primary auth-button", "Continue with OpenKey"); button.type = "button";
    const line = el(doc, "p", "auth-status"); line.setAttribute("role", "status"); line.setAttribute("aria-live", "polite");
    if (notice !== undefined) line.textContent = notice;
    form.append(button, line, announcer.element);
    main.append(header, form);
    root.append(main);

    let hint: ReturnType<typeof showApprovalHint> | undefined;
    button.addEventListener("click", () => {
      if (button.disabled) return;
      button.disabled = true; button.setAttribute("aria-busy", "true");
      line.textContent = "Opening OpenKey…";
      const progress: SignInProgress = {
        status: (message) => { line.textContent = message; },
        approval: (open) => {
          hint?.dispose(); hint = undefined;
          if (open) hint = showApprovalHint(form, { text: "Approve in the OpenKey window to sign in", lineClass: "sender-approval-line", timeoutCopy: "OpenKey didn't answer in time. Try again." });
        },
      };
      deps.signIn(progress).then((signedIn) => {
        hint?.dispose(); hint = undefined;
        session = signedIn;
        void showSignedIn(signedIn);
      }, (error: unknown) => {
        hint?.dispose(); hint = undefined;
        const failure = signInFailureMessage(error);
        line.replaceChildren();
        line.append(status(doc, failure.neutral ? "info" : "danger", failure.message));
        announcer.say(failure.message);
        button.disabled = false; button.removeAttribute("aria-busy");
      });
    });
  };

  const showSignedIn = async (signedIn: CourierSession): Promise<void> => {
    teardown?.();
    announcer.clear();
    root.replaceChildren();
    root.setAttribute("aria-busy", "false");
    let screen: Screen = "threads";
    let thread: ThreadRef & { subject?: string } | undefined;
    let overview: Overview | undefined;
    let loadError: string | undefined;
    let loading = false;
    let hiddenAt: number | undefined;
    let closed = false;

    const bar = el(doc, "nav", "sender-chrome tc-toolbar"); bar.setAttribute("aria-label", "Account");
    const account = el(doc, "span", "sender-account tc-badge tc-badge--mono", signedIn.address.length > 12 ? `${signedIn.address.slice(0, 6)}…${signedIn.address.slice(-4)}` : signedIn.address);
    account.title = "Signed in with OpenKey";
    const signOut = el(doc, "button", "button button-secondary tc-button tc-button--compact sender-signout", "Sign out"); signOut.type = "button";
    bar.append(account, signOut);
    const main = el(doc, "main", "sender-shell cr-shell");
    const tabs = el(doc, "div", "cr-tabs"); tabs.setAttribute("role", "tablist"); tabs.setAttribute("aria-label", "Courier");
    const panel = el(doc, "div", "cr-panel"); panel.setAttribute("role", "tabpanel");
    main.append(tabs, panel, announcer.element);
    root.append(bar, main);

    const ctx: ViewContext = {
      doc, store: signedIn.store, announcer, now,
      renderBody: (host, markdown, label) => deps.renderBody(host, markdown, label),
      refresh: () => load(),
      openThread: (ref) => { screen = "threads"; thread = ref; paint(); },
      showNeedsYou: () => { screen = "needs"; thread = undefined; paint(); },
    };

    const tabButtons = new Map<Screen, HTMLButtonElement>();
    const paintTabs = (): void => {
      const pending = overview?.requests.filter((card) => card.standing === "pending").length ?? 0;
      for (const tab of TABS) {
        let button = tabButtons.get(tab.id);
        if (button === undefined) {
          button = el(doc, "button", "cr-tab"); button.type = "button"; button.setAttribute("role", "tab");
          const id = tab.id;
          button.addEventListener("click", () => { screen = id; thread = undefined; paint(); });
          button.addEventListener("keydown", (event) => {
            const at = TABS.findIndex((entry) => entry.id === id);
            const next = event.key === "ArrowRight" ? at + 1 : event.key === "ArrowLeft" ? at - 1 : event.key === "Home" ? 0 : event.key === "End" ? TABS.length - 1 : undefined;
            if (next === undefined) return;
            event.preventDefault();
            const target = TABS[(next + TABS.length) % TABS.length]!;
            screen = target.id; thread = undefined; paint(); tabButtons.get(target.id)?.focus();
          });
          tabButtons.set(tab.id, button);
          tabs.append(button);
        }
        const selected = tab.id === screen;
        button.setAttribute("aria-selected", String(selected));
        button.tabIndex = selected ? 0 : -1;
        button.textContent = tab.id === "needs" && pending > 0 ? `Needs you · ${pending}` : tab.label;
        button.classList.toggle("cr-tab--attention", tab.id === "needs" && pending > 0);
        if (selected) panel.setAttribute("aria-label", tab.label);
      }
    };

    const paint = (): void => {
      paintTabs();
      panel.setAttribute("aria-busy", String(loading));
      if (loadError !== undefined) {
        const retry = el(doc, "button", "button button-secondary tc-button tc-button--compact", "Try again"); retry.type = "button";
        retry.addEventListener("click", () => { void load(); });
        panel.replaceChildren(status(doc, "danger", loadError), retry);
        return;
      }
      if (overview === undefined) { panel.replaceChildren(el(doc, "p", "cr-muted", "Loading your mailbox…")); return; }
      if (thread !== undefined) { panel.replaceChildren(renderThread(ctx, overview.threads.find((entry) => entry.peer === thread?.peer && entry.threadId === thread.threadId) ?? thread, () => { thread = undefined; paint(); })); return; }
      panel.replaceChildren(screen === "threads" ? renderThreads(ctx, overview) : screen === "needs" ? renderNeeds(ctx, overview) : renderOrders(ctx, overview));
    };

    const load = async (): Promise<void> => {
      if (loading || closed) return;
      loading = true;
      try {
        overview = await loadOverview(signedIn.store, now());
        loadError = undefined;
      } catch (error) {
        loadError = loadFailure(error);
        overview = undefined;
      } finally {
        loading = false;
      }
      if (!closed) paint();
    };

    const onVisibility = (): void => {
      if (doc.visibilityState === "hidden") { hiddenAt = now(); return; }
      // Coming back to the tab: pick up new requests, but never repaint over a decision in progress.
      const typing = Array.from(panel.querySelectorAll<HTMLTextAreaElement>(".cr-note-input")).some((field) => field.value !== "");
      if (hiddenAt !== undefined && now() - hiddenAt > REFRESH_AFTER_HIDDEN_MS && screen !== "orders" && thread === undefined && !typing) void load();
      hiddenAt = undefined;
    };
    doc.addEventListener("visibilitychange", onVisibility);
    teardown = () => {
      closed = true;
      doc.removeEventListener("visibilitychange", onVisibility);
    };

    signOut.addEventListener("click", () => {
      if (signOut.disabled) return;
      void confirmDialog(root, {
        title: "Sign out of Courier?",
        paragraphs: ["This ends your OpenKey sign-in on this device and clears Courier's session in this tab. Your threads, approvals and orders stay as they are."],
        confirmLabel: "Sign out", opener: signOut,
        onConfirm: () => {
          signOut.disabled = true; signOut.textContent = "Signing out…";
          announcer.say("Signing out…");
          void signedIn.signOut().then((remoteEnded) => {
            session = undefined;
            showSignedOut(remoteEnded ? SIGNED_OUT_NOTICE : SIGNED_OUT_PARTIAL_NOTICE);
          });
        },
      });
    });

    paint();
    await load();
  };

  showSignedOut();
  doc.defaultView?.addEventListener("pagehide", () => { void session?.dispose(); });
}
