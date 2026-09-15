/**
 * Recipient half of the TC-500 production-origin gate.
 *
 * The sender creates an addressed invitation through the candidate build, then
 * this script opens the mailed URL in a fresh profile. It deliberately accepts
 * the invitation and expected original file as explicit inputs so it cannot
 * accidentally create authority or deliver mail while a dependent deployment
 * is not ready.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import puppeteer from "puppeteer";
import { inspectShare } from "@tinycloud/share-sdk";
import { verifyOwnerNodeBinding } from "@tinycloud/sdk-core";
import { startCandidateServer } from "./candidate-server.mjs";
import {
  auditRecipientTrace,
  PRODUCTION_CREDENTIALS_ORIGIN,
  PRODUCTION_LOCATION_REGISTRY_ORIGIN,
} from "./recipient-trace.mjs";

let failureReported = false;
function reportRedactedFailure() {
  if (failureReported) return;
  failureReported = true;
  // Never echo an exception: browser/navigation errors can include the full
  // invitation fragment, while acquisition errors can include mailbox input.
  console.error("[tc500] production recipient gate failed; sensitive details withheld");
  process.exitCode = 1;
}
process.on("uncaughtException", reportRedactedFailure);
process.on("unhandledRejection", reportRedactedFailure);

const RUN = process.env.TC500_E2E_RUN;
const invitation = process.env.TC500_E2E_SHARE_URL;
const recipientEmail = process.env.TC500_E2E_RECIPIENT_EMAIL;
const expectedFile = process.env.TC500_E2E_EXPECTED_FILE;

if (RUN !== "1") throw new Error("refusing live production-origin run: set TC500_E2E_RUN=1");
if (invitation === undefined || recipientEmail === undefined || expectedFile === undefined) {
  throw new Error("TC500_E2E_SHARE_URL, TC500_E2E_RECIPIENT_EMAIL, and TC500_E2E_EXPECTED_FILE are required");
}
if (!recipientEmail.endsWith("@mailinator.com")) throw new Error("recipient must be a disposable @mailinator.com inbox");
const expected = readFileSync(resolve(expectedFile));
if (expected.length === 0 || ![...expected].some((byte) => byte === 0 || byte > 0x7f)) {
  throw new Error("expected file must contain non-UTF-8 bytes (the byte-exact gate would otherwise be meaningless)");
}

const parsedInvitation = new URL(invitation);
if (parsedInvitation.origin !== "https://share.tinycloud.xyz" || parsedInvitation.pathname !== "/s/inline" || !parsedInvitation.hash.includes("p=")) {
  throw new Error("expected an addressed https://share.tinycloud.xyz/s/inline#… invitation");
}

const productionConfig = JSON.parse(readFileSync(resolve("dist/.well-known/tinycloud-share/config.json"), "utf8"));
if (
  productionConfig.shareOrigin !== "https://share.tinycloud.xyz"
  || productionConfig.credentialsOrigin !== PRODUCTION_CREDENTIALS_ORIGIN
  || productionConfig.registryOrigin !== PRODUCTION_LOCATION_REGISTRY_ORIGIN
) {
  throw new Error("candidate production origins are not the reviewed production trust tuple");
}

let addressedEnvelope;
await inspectShare(invitation, {
  expectedOrigin: "https://share.tinycloud.xyz",
  onResolvedAddressedEnvelope: (envelope) => { addressedEnvelope = envelope; },
});
if (addressedEnvelope?.version !== 3) throw new Error("invitation is not a verified Policy/v3 envelope");
const ownerNodeOrigin = new URL(addressedEnvelope.target.origin).origin;
if (ownerNodeOrigin !== addressedEnvelope.target.origin || ownerNodeOrigin === parsedInvitation.origin) {
  throw new Error("invitation owner Node origin is not canonical and independent");
}
// This performs the SDK's subject-signature verification and proves the
// envelope owner, Node origin, and Node DID agree with the signed Location
// Registry record before the browser receives any credential or authority.
await verifyOwnerNodeBinding({
  registryUrl: PRODUCTION_LOCATION_REGISTRY_ORIGIN,
  ownerDid: addressedEnvelope.policy.ownerDid,
  nodeOrigin: ownerNodeOrigin,
  nodeDid: addressedEnvelope.target.nodeAudience,
});

const temporary = mkdtempSync(join(tmpdir(), "tc500-recipient-"));
const cert = join(temporary, "candidate.pem");
const key = join(temporary, "candidate-key.pem");
// A per-run, self-signed cert is pinned to this Chrome process by SPKI. It
// never changes the system trust store or any DNS resolver.
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=share.tinycloud.xyz", "-days", "1"], { stdio: "ignore" });
const spki = execFileSync("sh", ["-c", `openssl x509 -pubkey -noout -in '${cert}' | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64`], { encoding: "utf8" }).trim();
const server = await startCandidateServer({ root: resolve("dist"), key: readFileSync(key), cert: readFileSync(cert) });

const trace = [];
let browser;
try {
  browser = await puppeteer.launch({
    headless: process.env.HEADED !== "1",
    args: [
      `--host-resolver-rules=MAP share.tinycloud.xyz 127.0.0.1:${server.port}`,
      `--ignore-certificate-errors-spki-list=${spki}`,
      "--disable-quic",
      "--no-proxy-server",
    ],
  });
  const page = await browser.newPage();
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.protocol === "https:" || url.protocol === "http:") trace.push({ method: request.method(), origin: url.origin, path: url.pathname });
  });
  // Browser messages are attacker-controlled and may contain the fragment,
  // email, or OTP. Record only severity counts; never emit message text.
  const browserConsoleCounts = {};
  page.on("console", (message) => {
    const type = message.type();
    browserConsoleCounts[type] = (browserConsoleCounts[type] ?? 0) + 1;
  });
  await page.goto(invitation, { waitUntil: "domcontentloaded" });

  // The published SDK owns this inline Shadow-DOM control and the OC transport.
  // The host neither receives nor sends acquisition locators/verifiers.
  const interactionDeadline = Date.now() + 180_000;
  let emailSubmitted = false;
  while (Date.now() < interactionDeadline && !emailSubmitted) {
    emailSubmitted = await page.evaluate((email) => {
      const host = document.querySelector("tinycloud-credential-acquisition");
      const root = host?.shadowRoot;
      const input = root?.querySelector("input");
      const button = [...(root?.querySelectorAll("button") ?? [])].find((candidate) => !candidate.hasAttribute("disabled"));
      if (!(input instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) return false;
      input.focus(); input.value = email; input.dispatchEvent(new Event("input", { bubbles: true, composed: true })); button.click(); return true;
    }, recipientEmail).catch(() => false);
    if (!emailSubmitted) await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
  }
  if (!emailSubmitted) throw new Error("SDK credential acquisition control did not become ready for the recipient email");

  // The caller supplies the mailbox OTP only from the Mailinator message
  // actually received for this invitation; keeping mailbox access outside this
  // helper avoids committing a mail API token or a simulated credential path.
  const otp = process.env.TC500_E2E_MAILBOX_OTP;
  if (otp === undefined || !/^\d{6}$/.test(otp)) throw new Error("TC500_E2E_MAILBOX_OTP must be the six-digit code from the delivered message");
  const otpDeadline = Date.now() + 180_000;
  let otpSubmitted = false;
  while (Date.now() < otpDeadline && !otpSubmitted) {
    otpSubmitted = await page.evaluate((code) => {
      const host = document.querySelector("tinycloud-credential-acquisition");
      const root = host?.shadowRoot;
      const input = root?.querySelector("input");
      const button = [...(root?.querySelectorAll("button") ?? [])].find((candidate) => !candidate.hasAttribute("disabled"));
      if (!(input instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) return false;
      input.focus(); input.value = code; input.dispatchEvent(new Event("input", { bubbles: true, composed: true })); button.click(); return true;
    }, otp).catch(() => false);
    if (!otpSubmitted) await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
  }
  if (!otpSubmitted) throw new Error("SDK credential acquisition control did not accept the mailbox OTP");

  await page.waitForSelector(".viewer-download", { timeout: 180_000 });
  // Puppeteer does not expose Playwright's waitForEvent. Configure Chrome's
  // default download directory through CDP, then click the real post-render
  // control and read its file from disk below.
  const cdp = await page.createCDPSession();
  await cdp.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: temporary });
  await page.click(".viewer-download");
  const downloadDeadline = Date.now() + 30_000;
  let downloaded;
  while (Date.now() < downloadDeadline) {
    downloaded = readdirSync(temporary)
      .filter((name) => !["candidate.pem", "candidate-key.pem"].includes(name))
      .map((name) => join(temporary, name))
      .find((name) => { try { return readFileSync(name).length === expected.length; } catch { return false; } });
    if (downloaded !== undefined) break;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  if (downloaded === undefined) throw new Error("browser did not finish the original-file download");
  const actual = readFileSync(downloaded);
  if (!actual.equals(expected)) throw new Error("local downloaded bytes differ from the sender's exact non-UTF-8 file");

  const audit = auditRecipientTrace(trace, ownerNodeOrigin);
  console.log(JSON.stringify({
    result: "passed",
    expectedSha256: createHash("sha256").update(expected).digest("hex"),
    ...audit,
    browserConsoleCounts,
  }, null, 2));
} finally {
  await browser?.close();
  await server.close();
  // Deliberately leave the short-lived directory for the invoking runner to
  // trash after it has collected artifacts; never recursively delete a broad path.
  console.log(`[tc500] temporary artifacts: ${temporary}`);
}
