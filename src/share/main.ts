import type { OpenKeyShareSession, ShareTinyCloud, UploadCapability } from "./openkey-session.js";
import { loadAuthenticatedCapabilities } from "./capability-list.js";
import type { SenderHistoryRepository } from "./sender-history.js";
import { contentFilename, contentMediaType, contentMode } from "./composer-model.js";

const LIBRARY_ROUTE = "#/library";
const COMPOSER_ROUTE = "#/new";
/** Set once the sign-in ceremony is running, so the session probe never interrupts it. */
let signInStarted = false;

interface SenderApp {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  readonly capabilities: readonly UploadCapability[];
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
  const copy = document.createElement("p"); copy.className = "auth-copy"; copy.textContent = resumable ? "You're still signed in to OpenKey. Continue to pick up where you left off." : "Sign in with Face ID or Touch ID. No password.";
  const submit = document.createElement("button"); submit.type = "submit"; submit.className = "button button-primary auth-button"; submit.textContent = resumable ? "Continue" : "Continue with OpenKey";
  const status = document.createElement("p"); status.className = "auth-status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  form.append(steps, badge, heading, copy, submit, status); shell.append(header, form); root.append(shell);
  if (resumable) submit.focus();
  form.addEventListener("submit", (event) => {
    event.preventDefault(); signInStarted = true; submit.disabled = true; status.textContent = "Loading secure sign-in…";
    void import("./openkey-session.js")
      .then(({ authenticateWithOpenKey }) => authenticateWithOpenKey((message) => { status.textContent = message; }))
      .then((session) => proceed(session, status))
      .catch((error) => {
        const message = error instanceof Error ? error.message : (typeof error === "string" ? error : ((error as { readonly message?: unknown } | null)?.message ?? "OpenKey sign-in could not be completed."));
        if (import.meta.env.VITE_SHARE_HERMETIC === "true") (window as Window & { __tinycloudAuthError?: unknown }).__tinycloudAuthError = error;
        status.textContent = typeof message === "string" ? message : "OpenKey sign-in could not be completed.";
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

function navigate(route: string): void {
  if (window.location.hash === route) { render(); return; }
  window.location.hash = route;
}

function renderLibrary(current: SenderApp): void {
  void import("./sender-home.js").then(({ mountSenderHome }) => {
    mountSenderHome(view, { session: current.session, tinycloud: current.tinycloud, history: current.history, onNavigate: navigate });
  });
}

function renderComposer(current: SenderApp): void {
  void Promise.all([import("./composer.js"), import("./sender-history.js"), import("../email-share/config.js")]).then(([{ mountShareComposer }, { createSenderHistoryRecord }, { loadSharePublicConfig }]) => {
    mountShareComposer(view, {
      origin: import.meta.env.VITE_SHARE_ORIGIN ?? window.location.origin,
      registryOrigin: window.location.origin,
      openKeyAddress: current.session.address,
      session: current.session,
      tinycloud: current.tinycloud,
      onBack: () => navigate(LIBRARY_ROUTE),
      loadCapabilities: async () => current.capabilities.map((candidate) => ({ capabilityId: candidate.capabilityId ?? "", scope: candidate.scope as unknown as Record<string, unknown>, source: candidate.source, policy: candidate.policy as never })),
      notify: async ({ share, deliveryAuthorization }) => {
        if (deliveryAuthorization === undefined) throw new Error("We couldn't send that email. The link above still works.");
        const config = await loadSharePublicConfig();
        const response = await fetch(`${config.credentialsOrigin}/share/v2`, {
          method: "POST",
          credentials: "omit",
          redirect: "error",
          referrerPolicy: "no-referrer",
          headers: { accept: "application/json", "content-type": "application/json" },
          body: JSON.stringify({ authorization: deliveryAuthorization.authorization, proof: deliveryAuthorization.proof, shareUrl: share.url }),
        });
        if (!response.ok) throw new Error("We couldn't send that email. The link above still works.");
      },
      persistShare: async ({ share, model }) => {
        const expiresAt = share.expiresAt ?? model.expiresAt;
        const recipient = model.recipient.kind === "bearer" ? { kind: "bearer" as const } : { kind: model.recipient.kind, value: model.recipient.value! };
        // The stored history taxonomy stays exactly as it was: the content
        // union is mapped back to it here, at the persistence boundary.
        const record = await createSenderHistoryRecord({ id: crypto.randomUUID().replace(/-/g, ""), url: share.url, cid: share.cid, format: share.format, createdAt: new Date().toISOString(), expiresAt, name: contentFilename(model.content), mediaType: contentMediaType(model.content), sourceKind: contentMode(model.content), recipient, actions: model.permissions, delegationCid: share.delegationCid ?? null, revokedAt: null });
        await current.history.save(record);
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
  if (routeFor(window.location.hash) === "composer") renderComposer(app);
  else renderLibrary(app);
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
  const capabilities = await loadAuthenticatedCapabilities();
  const tinycloud = await createTinyCloudClient(session, config, capabilities, (message) => { status.textContent = message; });
  app = { session, tinycloud, history: new SenderHistoryRepository(tinycloud.vault), capabilities };
  (root as HTMLElement).replaceChildren(view);
  if (!window.location.hash.startsWith(COMPOSER_ROUTE) && window.location.hash !== LIBRARY_ROUTE) {
    // Keep the library the durable home without adding a history entry.
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${LIBRARY_ROUTE}`);
  }
  render();
}

/**
 * A live sign-in is detectable without any prompt: the share session cookie
 * and the OpenKey account session are both plain credentialed reads.
 *
 * It is *not* enough to rebuild the session. `OpenKey.connect()` always opens
 * the OpenKey flow, `signMessage` always needs the passkey, and the Web SDK
 * signs a fresh SIWE message on `signIn()` — the SDK exposes no promptless
 * restore. So a positive probe is used to shorten the wall to a single
 * "Continue", never to fake a session that does not exist in this tab.
 */
async function detectResumableSession(): Promise<boolean> {
  const shareSession = await fetch("/api/share/capabilities", { credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" }).then((response) => response.ok).catch(() => false);
  if (!shareSession) return false;
  try {
    // OpenKey.isConnected() is exactly this read. Calling it directly keeps
    // the multi-megabyte SDK chunk out of the first paint of every visit.
    const response = await fetch(`${import.meta.env.VITE_OPENKEY_ORIGIN ?? "https://openkey.so"}/api/auth/session`, { credentials: "include", cache: "no-store" });
    if (!response.ok) return false;
    return (await response.json() as { readonly user?: unknown }).user !== undefined;
  } catch { return false; }
}

mountAuthentication(root, false, bootstrap);
void detectResumableSession().then((resumable) => { if (resumable && app === undefined && !signInStarted) mountAuthentication(root as HTMLElement, true, bootstrap); });
