/**
 * Unattended OpenKey passkey sign-in, via a CDP virtual WebAuthn authenticator.
 *
 * Adapted from the `openkey-passkey-test` skill. The only new part is the
 * mailbox: OpenKey's registration OTP is read from a Mailinator public inbox
 * instead of Guerrilla Mail, so the same address family is used for the
 * account and (in stage 2) for the share recipient.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { newInbox, waitForMessage, extractOtp } from "./mailinator.mjs";
import { redactString } from "./redact.mjs";

export const OPENKEY_ORIGIN = process.env.OPENKEY_ORIGIN ?? "https://openkey.so";

const PASSKEY_NAME = /(?:passkey|security key)/i;
const NON_PASSKEY_NAME = /(?:email|google|apple|github|twitter|facebook|social)/i;

/** Click only a semantic passkey/key choice; email and social choices are never fallbacks. */
async function clickPasskeyChoice(frame, log) {
  const buttons = frame.getByRole("button");
  const count = await buttons.count().catch(() => 0);
  for (let index = 0; index < count; index += 1) {
    const button = buttons.nth(index);
    const name = (await button.getAttribute("aria-label").catch(() => null)) ?? (await button.textContent().catch(() => ""));
    const normalized = (name ?? "").replace(/\s+/g, " ").trim();
    if (!PASSKEY_NAME.test(normalized) || NON_PASSKEY_NAME.test(normalized)) continue;
    if (!(await button.isVisible().catch(() => false))) continue;
    log(`[openkey frame] clicking semantic passkey choice ${JSON.stringify(normalized)}`);
    await button.click().catch((error) => log(`[openkey frame] passkey click failed: ${redactString(error.message)}`));
    return true;
  }
  return false;
}

/** Attach a virtual internal authenticator to `context` and return its CDP handle. */
export async function attachVirtualAuthenticator(context, page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

/**
 * Re-install a previously captured credential.
 *
 * `signCount` is bumped to wall-clock seconds: OpenKey rejects a stale
 * authenticator counter, which is the failure mode that makes a saved
 * credential look like "Passkey not found".
 */
export async function restoreCredential(cdp, authenticatorId, credential) {
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: { ...credential, signCount: Math.floor(Date.now() / 1000) },
  });
}

/**
 * Register a brand-new OpenKey account end to end with no human in the loop.
 * Returns `{ address, inbox, credential }`; persist it and reuse via
 * `restoreCredential` on later runs.
 */
export async function registerFreshAccount(page, cdp, authenticatorId, log) {
  const { inbox, address } = newInbox("tcshare-acct");
  log(`[openkey] registering with ${address}`);

  await page.goto(`${OPENKEY_ORIGIN}/auth/register`, { waitUntil: "domcontentloaded" });
  await page.locator("#email").fill(address);
  await page.getByRole("button", { name: /continue with email/i }).click();
  log("[openkey] submitted email, waiting for OTP");

  const { text } = await waitForMessage(inbox, (_message, body) => extractOtp(body) !== undefined, {
    timeoutMs: 180_000,
    log,
  });
  const otp = extractOtp(text);
  log("[openkey] OTP <redacted>");

  await page.locator("#otp").fill(otp);
  await page.getByRole("button", { name: /^verify$/i }).click();

  // Copy drifts: this was "Register Passkey" in the original skill and is
  // "Create a passkey" as of 2026-07. Match both rather than pinning one.
  const registerButton = page.getByRole("button", { name: /create a passkey|register passkey/i });
  await registerButton.waitFor({ timeout: 60_000 });
  await registerButton.click();

  // The virtual authenticator answers the create ceremony silently, so the
  // credential appearing is the only reliable "done" signal.
  const deadline = Date.now() + 90_000;
  let credentials = [];
  while (Date.now() < deadline) {
    await page.waitForTimeout(2_000);
    ({ credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId }));
    if (credentials.length > 0) break;
  }
  if (credentials.length === 0) {
    const state = await page.evaluate(() => document.body.innerText.slice(0, 500)).catch(() => "");
    throw new Error(`virtual authenticator captured no credential; page said ${JSON.stringify(state)}`);
  }
  log(`[openkey] passkey registered (${credentials.length} credential)`);

  // Leave the registration wizard in a settled state before we navigate away.
  for (const name of [/^continue$/i, /^done$/i, /go to dashboard/i]) {
    const button = page.getByRole("button", { name }).first();
    if (await button.isVisible().catch(() => false)) {
      await button.click().catch(() => {});
      await page.waitForTimeout(1_500);
      break;
    }
  }
  return { address, inbox, credential: credentials[0] };
}

/** Load a saved account from disk, or `undefined`. */
export function loadAccount(path) {
  if (!existsSync(path)) return undefined;
  return JSON.parse(readFileSync(path, "utf8"));
}

export function saveAccount(path, account) {
  writeFileSync(path, JSON.stringify(account, null, 2));
}

/**
 * Keep answering OpenKey prompts for the whole run, not just during sign-in.
 *
 * The owner/addressed share path needs a wallet signature *mid-compose*
 * (`createOwnerDelegation`), which reopens the OpenKey iframe long after the
 * sign-in ceremony is over. Without something watching, that prompt sits
 * unanswered until the SDK gives up with `{code: TIMEOUT}` and the composer
 * shows "Something went wrong creating this link."
 *
 * Returns a stop function.
 */
export function startOpenKeyAutopilot(page, log, intervalMs = 1_000) {
  let stopped = false;
  const seen = new Set();
  const loop = async () => {
    while (!stopped) {
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
      if (stopped || page.isClosed()) return;
      for (const frame of page.frames()) {
        if (!/openkey/.test(frame.url())) continue;
        if (await clickPasskeyChoice(frame, log)) continue;
        for (const name of [/^sign(?: this)? message$/i, /sign message/i, /use this key/i, /select (?:a )?key/i, /generate (?:a )?key/i, /^approve$/i, /^allow$/i, /^confirm$/i]) {
          const button = frame.getByRole("button", { name }).first();
          if (!(await button.isVisible().catch(() => false))) continue;
          const key = `${frame.url()}::${name}`;
          if (!seen.has(key)) {
            seen.add(key);
            log(`[autopilot] clicking ${name} in ${frame.url().slice(0, 60)}`);
          }
          await button.click().catch(() => {});
          await new Promise((resolve) => setTimeout(resolve, 1_000));
          break;
        }
      }
    }
  };
  void loop();
  return () => { stopped = true; };
}

/**
 * Drive the share sender's auth wall to a signed-in composer.
 *
 * The OpenKey ceremony runs inside an iframe on `openkey.so`; we poll every
 * frame for the buttons it puts up and click whichever appears.
 *
 * `until: "session"` stops as soon as the host has issued the share session
 * cookie (`POST /api/share/auth/openkey` → 200). That is everything the
 * registry needs; `until: "app"` (the default) waits for the sender chrome,
 * which additionally requires the Web SDK bootstrap to finish.
 */
export async function signInToShare(page, { appUrl, log, timeoutMs = 420_000, until = "app" }) {
  let sessionIssued = false;
  page.on("response", (response) => {
    if (response.url().endsWith("/api/share/auth/openkey") && response.request().method() === "POST" && response.ok()) sessionIssued = true;
  });
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  const authButton = page.locator("button.auth-button");
  await authButton.waitFor({ timeout: 60_000 });
  await page.waitForFunction(() => {
    const button = document.querySelector("button.auth-button");
    return button !== null && !button.disabled;
  }, undefined, { timeout: 60_000 });
  log(`[share] clicking "${(await authButton.textContent())?.trim()}"`);
  await authButton.click();

  const deadline = Date.now() + timeoutMs;
  let lastFrameText = "";
  let lastStatus = "";
  let lastTick = 0;
  while (Date.now() < deadline) {
    if (Date.now() - lastTick > 15_000) {
      lastTick = Date.now();
      const frames = [];
      for (const frame of page.frames()) {
        if (!/openkey/.test(frame.url())) continue;
        const buttons = await frame.evaluate(() => [...document.querySelectorAll("button")].map((button) => `${button.innerText.trim().replace(/\s+/g, " ")}${button.disabled ? "[disabled]" : ""}${button.offsetParent === null ? "[hidden]" : ""}`)).catch((error) => [`<evaluate failed: ${error.message}>`]);
        frames.push(`${frame.url()} :: ${JSON.stringify(buttons)}`);
      }
      // If the main thread is blocked (a spinning WASM call) this evaluate
      // times out; if it returns, the page is idle and awaiting something.
      const mainThread = await Promise.race([
        page.evaluate(() => ({ alive: true, status: document.querySelector("p.auth-status")?.textContent ?? "", iframes: [...document.querySelectorAll("iframe")].map((frame) => `${frame.src}|display=${getComputedStyle(frame).display}`), storage: Object.keys(localStorage) })),
        new Promise((resolve) => setTimeout(() => resolve({ alive: false }), 5_000)),
      ]).catch((error) => ({ alive: false, error: error.message }));
      log(`[tick] frames=${page.frames().length} openkey=${frames.length} main=${JSON.stringify(mainThread)} ${frames.join(" || ")}`);
    }
    const status = await page.locator("p.auth-status").textContent().catch(() => "");
    if (status && status !== lastStatus) {
      lastStatus = status;
      log(`[share] auth status: ${status}`);
    }
    // The Web SDK's space-creation confirmation. `TinyCloudWeb` always installs
    // `ModalSpaceCreationHandler`, which overrides `autoCreateSpace: true`, and
    // `confirmSpaceCreation` awaits a promise only a DOM click can resolve —
    // with no timeout. The modal is a shadow-DOM custom element, so nothing in
    // the light DOM reveals it. A real user would click it; so does the harness.
    const modal = await page.evaluate(() => {
      const host = document.querySelector("tinycloud-space-modal");
      if (host === null || host.shadowRoot === null) return null;
      const text = host.shadowRoot.textContent?.replace(/\s+/g, " ").trim().slice(0, 300) ?? "";
      const buttons = [...host.shadowRoot.querySelectorAll("button")].map((button) => `${button.dataset.action ?? "?"}:${button.textContent?.trim()}`);
      return { text, buttons };
    }).catch(() => null);
    if (modal !== null) {
      log(`[space modal] ${JSON.stringify(modal)}`);
      const clicked = await page.evaluate(() => {
        const host = document.querySelector("tinycloud-space-modal");
        const button = host?.shadowRoot?.querySelector('button[data-action="create"]') ?? host?.shadowRoot?.querySelector("button");
        if (button === null || button === undefined) return false;
        button.click();
        return true;
      }).catch(() => false);
      log(`[space modal] create clicked=${clicked}`);
      await page.waitForTimeout(2_000);
    }

    if (until === "session" && sessionIssued) {
      log("[share] share session cookie issued — stopping before the Web SDK bootstrap");
      return;
    }
    if (await page.locator("main.composer-shell, main.sender-home, form.composer-form").count() > 0) {
      log("[share] signed in — sender chrome rendered");
      return;
    }
    for (const frame of page.frames()) {
      if (!/openkey/.test(frame.url())) continue;
      const text = await frame.evaluate(() => document.body?.innerText ?? "").catch(() => "");
      if (text && text !== lastFrameText) {
        lastFrameText = text;
        log(`[openkey frame] ${text.slice(0, 400).replace(/\n+/g, " | ")}`);
      }
      // Priority order. "Use a passkey instead" is the 2026-07 entry point on
      // the embed's chooser; "Continue with email" must never be picked, which
      // is why the continue matcher is anchored.
      if (await clickPasskeyChoice(frame, log)) {
        await page.waitForTimeout(1_500);
        continue;
      }
      for (const name of [/^sign(?: this)? message$/i, /sign message/i, /use this key/i, /select (?:a )?key/i, /generate (?:a )?key/i, /^approve$/i, /^allow$/i, /^connect$/i, /^confirm$/i]) {
        const button = frame.getByRole("button", { name }).first();
        if (!(await button.isVisible().catch(() => false))) continue;
        log(`[openkey frame] clicking ${name}`);
        await button.click().catch((error) => log(`[openkey frame] click failed: ${redactString(error.message)}`));
        await page.waitForTimeout(1_500);
        break;
      }
    }
    await page.waitForTimeout(1_500);
  }
  const status = await page.locator("p.auth-status").textContent().catch(() => "");
  throw new Error(`sign-in did not complete within ${timeoutMs}ms; last auth status: ${JSON.stringify(status)}`);
}
