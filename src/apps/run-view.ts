/**
 * The runner page: house-style chrome around an installed app's sandbox frame.
 *
 * Everything that comes from the catalog, a manifest or the app is set with
 * textContent (or a validated https href); there is no innerHTML, so Trusted Types
 * stays required for scripts. The chrome lives in THIS document, outside the frame:
 * the frame is an isolated, clipped box stacked below it (run.css), so nothing the
 * app draws can hide or cover the provenance line, the sign-out button or the status.
 *
 * Why the runner has its own provenance line instead of the share viewer's
 * dismissable "this page runs the sender's code" notice (artifact-notice.ts): that
 * notice is for strangers' pages and can be dismissed and remembered in the browser.
 * An installed app is the person's own saved copy of code a catalog entry shipped, so
 * the line says where it came from and what the sandbox is, always, and is not
 * dismissable; the privacy limits of the sandbox (what a sandboxed page can still
 * reveal) are one click away in the same words the viewer uses.
 */
import { type CatalogEntry, availabilityOf, catalog, versionLabel } from "./catalog.ts";
import { consentFor } from "./consent.ts";
import { createCapabilityBridge, type CapabilityBridge } from "./bridge.ts";
import { type RunFailure, type RunPorts, type RunProgress, type RunningApp, RunError, openApp, catalogEntryFor, APP_ID } from "./run.ts";
import { createRunPorts } from "./run-session.ts";
import { loadManifest } from "./manifest.ts";
import { accessSection, el, noticeList } from "./view.ts";
import { runnerHref } from "./install-plan.ts";
import { CAUTION, KNOWN_LIMITS } from "./limits.ts";
import { APPROVAL_SLOW_COPY, APPROVAL_SLOW_AFTER_MS } from "../share/approval-hint.js";
import type { JsxCapabilityReply } from "../viewer/jsx-sandbox.js";
import { type RenderJsxOptions, renderJsxPage } from "../viewer/jsx-render.js";

export const APPS_HREF = "/apps/";

type Tone = "info" | "success" | "warning" | "danger";

interface Screen {
  readonly title: string;
  readonly lines: readonly string[];
  /** A short technical note under the lines (set with textContent). */
  readonly detail?: string | undefined;
  readonly retry?: string | undefined;
  readonly toApps?: boolean | undefined;
  /** Where "Repair" goes (the install sheet in repair mode), for a refusal that replacing the code files fixes. */
  readonly repairHref?: string | undefined;
  /** Command lines shown as code, one per line (set with textContent). */
  readonly commands?: readonly string[] | undefined;
  readonly tone?: Tone;
}

const OPEN_AGAIN = (name: string): string => `Open ${name} again`;

/** The plain screen for each way an open can end without starting the app. */
export function failureScreen(reason: RunFailure, name: string, detail?: string, appId?: string): Screen {
  switch (reason) {
    case "unknown-app": return { title: "We don't know this app", lines: ["This address doesn't match an app in the catalog."], toApps: true };
    case "unavailable": return { title: "This app is temporarily unavailable", lines: [detail ?? "It has been switched off for now.", "Nothing was started."], toApps: true };
    case "not-installed": return { title: "This app needs to be installed first", lines: [`${name} isn't saved in your TinyCloud yet. Install it from the apps page, then open it here.`], toApps: true };
    case "damaged": return { title: "Your saved copy of this app can't be used", lines: ["Its files in your TinyCloud are incomplete, or were edited into something this page can't read. Nothing was started."], toApps: true, detail };
    case "code-mismatch": return {
      title: "This app's code doesn't match the pinned version",
      lines: ["Remove it and install again.", "Repair replaces the app's code files with the pinned version. Your data is untouched. Nothing was started."],
      toApps: true, detail, tone: "danger", ...(appId === undefined ? {} : { repairHref: `${APPS_HREF}#repair=${encodeURIComponent(appId)}` }),
    };
    case "not-listed": return {
      title: "This version of the app isn't in the catalog any more",
      lines: [
        "You installed a version that has since been replaced or removed, so what it asks for can't be checked and it can't be repaired from here. Nothing was started.",
        `To remove it, delete the files under ${appId ?? "<app id>"}/app/ in your TinyCloud (your data in the other folders stays), then install the listed version. With the CLI:`,
      ],
      toApps: true,
      commands: [`tinycloud kv list --space applications --prefix ${appId ?? "<app id>"}/app/`, "tinycloud kv delete --space applications <each key listed>"],
    };
    case "catalog-unavailable": return { title: "Couldn't check this app against the catalog", lines: ["Check your connection and try again. Nothing was started."], retry: "Try again" };
    case "widened": return {
      title: "This app asks for more than it did when you installed it",
      lines: ["Your saved copy of its manifest asks for permissions the catalog version doesn't. Nothing was started and nothing more was signed.", "If you didn't change it yourself, don't use this copy. Repair replaces the app's code files, manifest.json included, with the catalog's. Your data is untouched."],
      toApps: true, detail: detail === undefined ? undefined : `First difference: ${detail}`, tone: "danger", ...(appId === undefined ? {} : { repairHref: `${APPS_HREF}#repair=${encodeURIComponent(appId)}` }),
    };
    case "unsupported": return { title: "This app asks for something this page can't give it", lines: ["Nothing was started."], toApps: true, detail };
    case "cancelled": return { title: "Sign-in cancelled", lines: ["Nothing was started."], retry: OPEN_AGAIN(name) };
    case "timeout": return { title: "OpenKey didn't answer in time", lines: ["Nothing was started. Try again."], retry: OPEN_AGAIN(name) };
    case "busy": return { title: "Another OpenKey request is waiting", lines: ["Finish or cancel it, then try again."], retry: OPEN_AGAIN(name) };
    case "wrong-account": return { title: "That approval came from a different account", lines: ["It wasn't the account that signed in, so nothing was started."], retry: OPEN_AGAIN(name), tone: "danger" };
    case "failed": return { title: "We couldn't open this app", lines: ["Nothing was started. Try again."], retry: OPEN_AGAIN(name) };
  }
}

/** Status line for each step of an open. */
export function progressText(progress: RunProgress, name: string): string {
  switch (progress.phase) {
    case "checking": return `Checking ${name}…`;
    case "reading": return progress.approval ? `Approve in the OpenKey window (1 of 2) so Share can read ${name} from your TinyCloud` : "Opening OpenKey…";
    case "saving": return `Saving ${name}'s files to your TinyCloud (${progress.done} of ${progress.total})…`;
    case "verifying": return `Checking your copy of ${name} against the catalog…`;
    case "starting": return progress.approval ? `Approve in the OpenKey window (2 of 2) to start ${name} with the permissions listed here` : `Starting ${name}…`;
  }
}

function gitHostPath(repo: string): string {
  return repo.replace(/^https:\/\//, "").replace(/\.git$/, "");
}

/** "This app was installed from <source>@<commit>…": from the catalog entry, never from the editable install record. */
export function provenanceText(entry: CatalogEntry): string {
  return `This app was installed from ${gitHostPath(entry.source.repo)}@${entry.source.commit.slice(0, 7)} (${versionLabel(entry)}, bundle ${entry.bundle.digest.slice(0, 12)}). It runs in a sandbox and can use only what's listed under “What this app can do”.`;
}

export interface RunnerOptions {
  /** The app id from the address, or null when there is none. */
  readonly appId: string | null;
  readonly ports?: RunPorts;
  readonly now?: () => number;
  /** Tests only: the library manifest and fetch the frame loads its modules with. */
  readonly frame?: Pick<RenderJsxOptions, "manifest" | "fetch" | "slowAfterMs">;
}

export interface Runner {
  destroy(): void;
}

export function mountRunner(root: HTMLElement, options: RunnerOptions): Runner {
  const doc = root.ownerDocument;
  const view = doc.defaultView ?? window;
  const now = options.now ?? Date.now;
  const ports = options.ports ?? createRunPorts();
  const appId = options.appId;
  const entry = appId === null ? undefined : catalogEntryFor(appId, ports.catalog ?? catalog.apps);

  // ---- chrome (always visible, outside the frame)
  const title = el("h1", "run-title", [entry?.name ?? "Open an app"], { tabindex: "-1" });
  const provenance = el("p", "run-provenance", [entry === undefined ? "Open an app from the apps page. Each one runs in a sandbox." : provenanceText(entry)]);
  const openAnother = el("a", "tc-button apps-button", ["Open another app"], { href: APPS_HREF });
  const signOut = el("button", "tc-button apps-button", ["Sign out of this app"], { type: "button" });
  signOut.disabled = true;
  // The live region exists from the start and only its content changes, so each change is announced.
  const status = el("div", "run-status-region", [], { role: "status" });
  const access = el("details", "apps-files run-details", [el("summary", null, ["What this app can do"])]);
  access.hidden = true;
  const reveal = el("details", "apps-files run-details", [el("summary", null, ["What a sandboxed page can still reveal"]), el("p", null, ["The sandbox blocks the requests a page makes itself, but some browser requests can't be blocked, so a page can still reveal that you opened it: your IP address and the time."]), el("p", null, [KNOWN_LIMITS])]);
  const bar = el("section", "run-bar tc-panel", [
    el("div", "run-bar__top", [title, el("div", "run-actions", [openAnother, signOut])]),
    provenance,
    el("p", "run-caution", [CAUTION]),
    status,
  ], { "aria-label": "App details" });
  // Below the app, where it never pushes the app off the screen; open on the start screen, closed while it runs.
  const info = el("section", "run-info", [access, reveal], { "aria-label": "About this app" });
  const stage = el("div", "run-stage", [], { role: "region", "aria-label": entry === undefined ? "App" : entry.name });
  root.replaceChildren(bar, stage, info);

  const setStatus = (text: string, tone: Tone = "info"): void => {
    status.replaceChildren(...(text === "" ? [] : [el("p", `tc-status tc-status--${tone} run-status`, [text])]));
  };

  // ---- state
  let attempt = 0;
  let running: RunningApp | undefined;
  let bridge: CapabilityBridge | undefined;
  let frameCleanup: (() => void) | undefined;
  let expiryTimer: number | undefined;
  let slowTimer: number | undefined;
  let live = false;
  let destroyed = false;

  const stopFrame = (): void => {
    live = false;
    view.clearTimeout(expiryTimer);
    expiryTimer = undefined;
    bridge?.close();
    bridge = undefined;
    frameCleanup?.();
    frameCleanup = undefined;
    stage.replaceChildren();
    const ended = running;
    running = undefined;
    signOut.disabled = true;
    // The session ends with the frame. Fire and forget: the sign-out has its own short wait.
    if (ended !== undefined) void ended.session.end().catch(() => undefined);
  };

  const showScreen = (screen: Screen, onRetry?: () => void): void => {
    const heading = el("h2", "run-screen__title", [screen.title], { tabindex: "-1" });
    const parts: HTMLElement[] = [heading, ...screen.lines.map((line) => el("p", null, [line]))];
    if (screen.commands !== undefined) parts.push(el("p", "run-screen__detail", screen.commands.flatMap((line, index) => [...(index === 0 ? [] : [el("br", null)]), el("code", null, [line])])));
    if (screen.detail !== undefined) parts.push(el("p", "run-screen__detail", [el("code", null, [screen.detail])]));
    const actions: HTMLElement[] = [];
    if (screen.retry !== undefined && onRetry !== undefined) {
      const retry = el("button", "tc-button tc-button--primary apps-button", [screen.retry], { type: "button" });
      retry.addEventListener("click", onRetry);
      actions.push(retry);
    }
    if (screen.repairHref !== undefined) actions.push(el("a", `tc-button${actions.length === 0 ? " tc-button--primary" : ""} apps-button`, ["Repair"], { href: screen.repairHref }));
    if (screen.toApps === true) actions.push(el("a", `tc-button ${actions.length === 0 ? "tc-button--primary " : ""}apps-button`, ["Go to Apps"], { href: APPS_HREF }));
    if (actions.length > 0) parts.push(el("div", "run-screen__actions", actions));
    const alert = screen.tone === "danger";
    stage.replaceChildren(el("section", `run-screen tc-panel${alert ? " run-screen--danger" : ""}`, parts, alert ? { role: "alert" } : {}));
    heading.focus();
  };

  const accessLists = (manifest: unknown, forEntry: CatalogEntry): void => {
    const consent = consentFor(forEntry, manifest, ports.catalog ?? catalog.apps);
    access.replaceChildren(el("summary", null, ["What this app can do"]), ...(forEntry.sample === true ? [el("p", "tc-status tc-status--warning apps-notice", ["Sample app: use throwaway data only."])] : []), ...noticeList(consent.notices), accessSection("It can read", "Nothing.", consent.runtime.read), accessSection("It can change", "Nothing. This app can't change your data.", consent.runtime.change));
    access.hidden = false;
  };

  const expire = (): void => {
    const name = running?.app.name ?? entry?.name ?? "the app";
    stopFrame();
    setStatus("Your session expired: open the app again.", "warning");
    showScreen({ title: "Your session expired", lines: ["Your session expired: open the app again. Nothing was lost: what the app saved is in your TinyCloud."], retry: OPEN_AGAIN(name) }, begin);
  };

  const signOutNow = (): void => {
    const name = running?.app.name ?? entry?.name ?? "the app";
    stopFrame();
    setStatus("Signed out of this app.", "info");
    showScreen({ title: "Signed out of this app", lines: ["Its session is over. Nothing was changed in your TinyCloud."], retry: OPEN_AGAIN(name) }, begin);
  };
  signOut.addEventListener("click", signOutNow);
  // The tab is going away (or into the back/forward cache): the session ends with it, and a restored page says so.
  const onPageHide = (): void => { if (running !== undefined) signOutNow(); };
  view.addEventListener("pagehide", onPageHide);

  const paint = (mine: number, progress: RunProgress): void => {
    if (mine !== attempt || entry === undefined) return;
    const approval = (progress.phase === "reading" || progress.phase === "starting") && progress.approval;
    const base = progressText(progress, entry.name);
    setStatus(base, "info");
    view.clearTimeout(slowTimer);
    // The same "can't see the OpenKey window?" help the other pages give after a while.
    if (approval) slowTimer = view.setTimeout(() => { if (mine === attempt) setStatus(`${base}. ${APPROVAL_SLOW_COPY}`, "info"); }, APPROVAL_SLOW_AFTER_MS);
  };

  function begin(): void {
    if (entry === undefined || appId === null) return;
    stopFrame();
    const mine = ++attempt;
    stage.replaceChildren(el("div", "run-working tc-panel", [el("div", "tc-skeleton run-working__bar", [], { "aria-hidden": "true" }), el("p", null, ["Opening…"])], { "aria-busy": "true" }));
    paint(mine, { phase: "checking" });
    void openApp(appId, ports, (progress) => paint(mine, progress)).then(
      (result) => {
        view.clearTimeout(slowTimer);
        if (mine !== attempt || destroyed) { void result.session.end().catch(() => undefined); return; }
        start(result, mine);
      },
      (error: unknown) => {
        view.clearTimeout(slowTimer);
        if (mine !== attempt || destroyed) return;
        const failure = error instanceof RunError ? error : new RunError("failed", { cause: error });
        const screen = failureScreen(failure.reason, entry.name, failure.detail, appId);
        setStatus(screen.title, screen.tone === "danger" ? "danger" : "warning");
        showScreen(screen, begin);
      },
    );
  }

  function start(result: RunningApp, mine: number): void {
    running = result;
    live = true;
    title.textContent = result.app.name;
    accessLists(result.app.signing, result.app.entry);
    // The lists stay one click away; the app itself gets the room.
    access.open = false;
    signOut.disabled = false;
    let reply: JsxCapabilityReply | undefined;
    bridge = createCapabilityBridge({
      appId: result.app.appId,
      authorize: result.app.authorize,
      data: result.session.data,
      reply: (id, answer) => reply?.(id, answer),
      isLive: () => live && now() < result.session.expiresAt,
    });
    const current = bridge;
    stage.replaceChildren();
    setStatus(`Starting ${result.app.name}…`, "info");
    void renderJsxPage(stage, result.app.source, {
      ...(options.frame ?? {}),
      filename: "app.jsx",
      title: `${result.app.name} (installed app)`,
      frameClassName: "run-frame",
      onCleanup: (cleanup) => { frameCleanup = cleanup; },
      onCapability: (request, answer) => { reply = answer; current.handle(request); },
      onState: (state) => {
        if (mine !== attempt) return;
        if (state === "running") {
          const until = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(result.session.expiresAt));
          setStatus(`${result.app.name} is running. Its session lasts until about ${until}.`, "success");
        } else {
          setStatus(`${result.app.name} stopped. Open it again to restart it.`, "warning");
          signOut.disabled = false;
        }
      },
    });
    expiryTimer = view.setTimeout(expire, Math.max(0, Math.min(result.session.expiresAt - now(), 2 ** 31 - 1)));
  }

  // ---- first screen
  if (appId === null || !APP_ID.test(appId) || entry === undefined) {
    setStatus("");
    showScreen(failureScreen("unknown-app", appId ?? ""));
  } else if (!availabilityOf(entry).available) {
    // The kill switch: a disabled entry opens nothing, and says why.
    const availability = availabilityOf(entry);
    setStatus("");
    showScreen(failureScreen("unavailable", entry.name, availability.available ? undefined : availability.reason, appId));
  } else {
    const start0 = el("section", "run-screen tc-panel", [], { "aria-busy": "true" });
    stage.replaceChildren(start0);
    void loadManifest(entry).then((loaded) => {
      if (destroyed || attempt !== 0) return;
      start0.removeAttribute("aria-busy");
      if (!loaded.ok) {
        showScreen({ title: "Couldn't check this app against the catalog", lines: [loaded.reason === "mismatch" ? "Its manifest doesn't match the catalog, so it can't be opened." : "Check your connection and try again."], retry: loaded.reason === "mismatch" ? undefined : "Try again", tone: "danger" }, () => { window.location.reload(); });
        return;
      }
      accessLists(loaded.manifest, entry);
      mountStart(loaded.manifest);
    });
  }

  function mountStart(manifest: unknown): void {
    if (entry === undefined) return;
    const go = el("button", "tc-button tc-button--primary apps-button", ["Continue"], { type: "button" });
    go.addEventListener("click", begin);
    // The plain statements (changes to its own tables, reads of another app) come before Continue; the full lists are below.
    const consent = consentFor(entry, manifest, ports.catalog ?? catalog.apps);
    stage.replaceChildren(el("section", "run-screen tc-panel", [
      el("h2", "run-screen__title", [`Open ${entry.name}`], { tabindex: "-1" }),
      el("p", null, [entry.description]),
      ...(entry.sample === true ? [el("p", "tc-status tc-status--warning apps-notice", ["Sample app: use throwaway data only."])] : []),
      ...noticeList(consent.notices),
      el("p", null, ["It runs in a sandbox. It can use only what's listed under “What this app can do” below, and only while this page is open, for one hour at most."]),
      el("p", "run-caution", [CAUTION]),
      el("p", null, ["OpenKey asks you to approve twice: once so Share can read the app from your TinyCloud, then once to start it with those permissions."]),
      el("div", "run-screen__actions", [go]),
    ]));
    access.open = true;
  }

  return {
    destroy(): void {
      view.removeEventListener("pagehide", onPageHide);
      destroyed = true;
      attempt += 1;
      view.clearTimeout(slowTimer);
      stopFrame();
    },
  };
}

export { runnerHref };
